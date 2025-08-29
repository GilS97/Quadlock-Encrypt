#!/usr/bin/env python3
"""
QuadLock Encrypt — chiffrement de fichiers et répertoires avec support de 5 algorithmes
====================================================================================

Ce fichier fournit :
 - Implémentation d'une clé maître (MK) scindée via Shamir (k-of-n)
 - Support des algorithmes : aes-gcm, chacha20-poly1305, xchacha20-poly1305, aes-siv, hybrid-rsa
 - Derivation par HKDF d'une clé par fichier (contexte inclut algo + chemin)
 - Format sécurisé : concaténation meta+contenu chiffrée en une seule opération AEAD (évite réutilisation du nonce)
 - CLI complète (generate-shares, encrypt, decrypt) avec option --algo et options pour clés RSA

Dépendances :
  pip install cryptography pycryptodome

Fichier fourni avec script bash d'exécution (voir `run_quadlock.sh` joint).

Note sécurité rapide :
 - Le code évite désormais la double-encryption avec le même nonce. Il dérive une clé par fichier
   en incluant le chemin et l'algo dans le contexte HKDF.
 - AES-SIV est fourni comme mode misuse-resistant (PyCryptodome).
 - Hybrid RSA chiffre une clé éphémère symétrique par OAEP.

Usage résumé (après installation):
  python quadlock_encrypt.py generate-shares --k 4 --n 6 --out shares.json
  python quadlock_encrypt.py encrypt --path ./mon_dossier --shares-file shares.json --algo xchacha20-poly1305
  python quadlock_encrypt.py decrypt --path ./mon_dossier --shares-file shares.json --algo xchacha20-poly1305


=============================================================================
CODE PYTHON
=============================================================================
"""
from __future__ import annotations
import argparse
import base64
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Tuple, Optional

# Cryptography primitives
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305, XChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

# PyCryptodome (Shamir + SIV)
try:
    from Crypto.Protocol.SecretSharing import Shamir
    from Crypto.Cipher import AES as CryptoAES
    _HAS_PYCRYPTODOME = True
except Exception:
    Shamir = None
    CryptoAES = None
    _HAS_PYCRYPTODOME = False

MAGIC = b"QLK2"  # identifiant format (version 2)
AAD = b"quadlock-file-v2"
NONCE_SIZE = 12
XNONCE_SIZE = 24
KEY_SIZE = 32  # 256 bits
SUFFIX = ".qlock"

@dataclass
class ShareSet:
    threshold: int
    total: int
    shares: List[str]

# ------------------------ Helpers base64 ------------------------
def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode('utf-8').rstrip('=')

def b64d(s: str) -> bytes:
    pad = '=' * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + pad)

# ----------------- Shamir k-of-n (PyCryptodome) -----------------
def generate_master_key() -> bytes:
    return os.urandom(KEY_SIZE)

def split_key_shamir(master_key: bytes, k: int, n: int) -> List[str]:
    if not _HAS_PYCRYPTODOME:
        raise RuntimeError("PyCryptodome requis : pip install pycryptodome")
    if len(master_key) != KEY_SIZE:
        raise ValueError("master_key doit faire 32 octets")
    shares = Shamir.split(k, n, master_key)
    out = []
    for (idx, part) in shares:
        out.append(f"{idx}:{b64e(part)}")
    return out

def combine_shares_shamir(shares: Iterable[str]) -> bytes:
    if not _HAS_PYCRYPTODOME:
        raise RuntimeError("PyCryptodome requis : pip install pycryptodome")
    parsed: List[Tuple[int, bytes]] = []
    for s in shares:
        if ':' not in s:
            raise ValueError(f"Part invalide: {s}")
        idx_str, b64 = s.split(':', 1)
        idx = int(idx_str)
        part = b64d(b64)
        parsed.append((idx, part))
    mk = Shamir.combine(parsed)
    if len(mk) != KEY_SIZE:
        raise ValueError("Clé recombinée de longueur inattendue")
    return mk

# ------------------ HKDF key derivation ------------------
def derive_file_key(master_key: bytes, algo: str, relative_path: str, length: int = KEY_SIZE) -> bytes:
    """Derive une clé par fichier et por algo, via HKDF-SHA256.

    info inclut AAD | algo | path pour isoler les clés.
    """
    info = AAD + b"|" + algo.encode('utf-8') + b"|" + relative_path.encode('utf-8')
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info)
    return hkdf.derive(master_key)

# ------------------ AEAD: encrypt/decrypt helpers ------------------
def _build_payload(meta: dict, plaintext: bytes) -> bytes:
    meta_bytes = json.dumps(meta, ensure_ascii=False).encode('utf-8')
    return len(meta_bytes).to_bytes(4, 'big') + meta_bytes + plaintext

def _split_payload(payload: bytes) -> Tuple[dict, bytes]:
    meta_len = int.from_bytes(payload[:4], 'big')
    meta_bytes = payload[4:4+meta_len]
    pt = payload[4+meta_len:]
    meta = json.loads(meta_bytes.decode('utf-8'))
    return meta, pt

# AES-GCM
def encrypt_aes_gcm(file_key: bytes, plaintext: bytes, meta: dict) -> bytes:
    payload = _build_payload(meta, plaintext)
    nonce = os.urandom(NONCE_SIZE)
    aes = AESGCM(file_key)
    ct = aes.encrypt(nonce, payload, AAD)
    return nonce + ct

def decrypt_aes_gcm(file_key: bytes, blob: bytes) -> Tuple[bytes, dict]:
    nonce = blob[:NONCE_SIZE]
    ct = blob[NONCE_SIZE:]
    payload = AESGCM(file_key).decrypt(nonce, ct, AAD)
    meta, pt = _split_payload(payload)
    return pt, meta

# ChaCha20-Poly1305
def encrypt_chacha20(file_key: bytes, plaintext: bytes, meta: dict) -> bytes:
    payload = _build_payload(meta, plaintext)
    nonce = os.urandom(NONCE_SIZE)
    cc = ChaCha20Poly1305(file_key)
    ct = cc.encrypt(nonce, payload, AAD)
    return nonce + ct

def decrypt_chacha20(file_key: bytes, blob: bytes) -> Tuple[bytes, dict]:
    nonce = blob[:NONCE_SIZE]
    ct = blob[NONCE_SIZE:]
    payload = ChaCha20Poly1305(file_key).decrypt(nonce, ct, AAD)
    meta, pt = _split_payload(payload)
    return pt, meta

# XChaCha20-Poly1305
def encrypt_xchacha20(file_key: bytes, plaintext: bytes, meta: dict) -> bytes:
    payload = _build_payload(meta, plaintext)
    nonce = os.urandom(XNONCE_SIZE)
    xc = XChaCha20Poly1305(file_key)
    ct = xc.encrypt(nonce, payload, AAD)
    return nonce + ct

def decrypt_xchacha20(file_key: bytes, blob: bytes) -> Tuple[bytes, dict]:
    nonce = blob[:XNONCE_SIZE]
    ct = blob[XNONCE_SIZE:]
    payload = XChaCha20Poly1305(file_key).decrypt(nonce, ct, AAD)
    meta, pt = _split_payload(payload)
    return pt, meta

# AES-SIV (misuse-resistant) via PyCryptodome
def encrypt_aes_siv(file_key: bytes, plaintext: bytes, meta: dict) -> bytes:
    if not _HAS_PYCRYPTODOME:
        raise RuntimeError("PyCryptodome requis pour AES-SIV : pip install pycryptodome")
    # PyCryptodome SIV expects key length 16,24,32 (AES key). For SIV we can use 32 bytes.
    payload = _build_payload(meta, plaintext)
    # AES SIV mode will produce ciphertext and tag; PyCryptodome provides encrypt_and_digest
    cipher = CryptoAES.new(file_key, CryptoAES.MODE_SIV)
    ciphertext, tag = cipher.encrypt_and_digest(payload)
    # store nonce if any (SIV in PyCryptodome exposes cipher.nonce for some modes) -- store tag at end
    # We'll store: tag_len(1)=len(tag) || tag || ciphertext
    return len(tag).to_bytes(1, 'big') + tag + ciphertext

def decrypt_aes_siv(file_key: bytes, blob: bytes) -> Tuple[bytes, dict]:
    if not _HAS_PYCRYPTODOME:
        raise RuntimeError("PyCryptodome requis pour AES-SIV : pip install pycryptodome")
    tag_len = blob[0]
    tag = blob[1:1+tag_len]
    ct = blob[1+tag_len:]
    cipher = CryptoAES.new(file_key, CryptoAES.MODE_SIV)
    # PyCryptodome SIV mode expects decrypt_and_verify? We'll use decrypt_and_verify
    # However AES.MODE_SIV in PyCryptodome exposes decrypt_and_verify for associated data.
    payload = cipher.decrypt_and_verify(ct, tag)
    meta, pt = _split_payload(payload)
    return pt, meta

# Hybrid RSA-OAEP + AES-GCM
def encrypt_hybrid_rsa(pubkey_pem: bytes, plaintext: bytes, meta: dict) -> bytes:
    # ephemeral symmetric key
    eph = os.urandom(KEY_SIZE)
    payload = _build_payload(meta, plaintext)
    nonce = os.urandom(NONCE_SIZE)
    ct = AESGCM(eph).encrypt(nonce, payload, AAD)
    # encrypt ephemeral with RSA-OAEP
    pub = serialization.load_pem_public_key(pubkey_pem)
    enc_eph = pub.encrypt(
        eph,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    # store: len_enc(4) || enc_eph || nonce || ct
    return len(enc_eph).to_bytes(4, 'big') + enc_eph + nonce + ct

def decrypt_hybrid_rsa(privkey_pem: bytes, privkey_password: Optional[bytes], blob: bytes) -> Tuple[bytes, dict]:
    off = 0
    klen = int.from_bytes(blob[off:off+4], 'big'); off += 4
    enc_eph = blob[off:off+klen]; off += klen
    nonce = blob[off:off+NONCE_SIZE]; off += NONCE_SIZE
    ct = blob[off:]
    priv = serialization.load_pem_private_key(privkey_pem, password=privkey_password)
    eph = priv.decrypt(enc_eph, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    payload = AESGCM(eph).decrypt(nonce, ct, AAD)
    meta, pt = _split_payload(payload)
    return pt, meta

# Dispatcher
def encrypt_blob_for_algo(master_key: bytes, algo: str, relative_path: str, plaintext: bytes, meta: dict, pubkey_pem: Optional[bytes]=None) -> bytes:
    if algo == 'aes-gcm':
        file_key = derive_file_key(master_key, algo, relative_path)
        return MAGIC + b'aes:' + encrypt_aes_gcm(file_key, plaintext, meta)
    elif algo == 'chacha20-poly1305':
        file_key = derive_file_key(master_key, algo, relative_path)
        return MAGIC + b'cha:' + encrypt_chacha20(file_key, plaintext, meta)
    elif algo == 'xchacha20-poly1305':
        file_key = derive_file_key(master_key, algo, relative_path)
        return MAGIC + b'xch:' + encrypt_xchacha20(file_key, plaintext, meta)
    elif algo == 'aes-siv':
        # SIV uses same derived key length; it's misuse-resistant
        file_key = derive_file_key(master_key, algo, relative_path, length=KEY_SIZE)
        return MAGIC + b'siv:' + encrypt_aes_siv(file_key, plaintext, meta)
    elif algo == 'hybrid-rsa':
        if pubkey_pem is None:
            raise ValueError("pubkey required for hybrid-rsa")
        return MAGIC + b'hyb:' + encrypt_hybrid_rsa(pubkey_pem, plaintext, meta)
    else:
        raise ValueError(f"Unknown algo: {algo}")

def decrypt_blob_for_algo(master_key: bytes, algo_hint: Optional[str], relative_path: str, blob: bytes, privkey_pem: Optional[bytes]=None, privkey_password: Optional[bytes]=None) -> Tuple[bytes, dict]:
    if not blob.startswith(MAGIC):
        raise ValueError("Fichier non reconnu (MAGIC mismatch)")
    off = len(MAGIC)
    tag = blob[off:off+4]; off += 4
    if tag == b'aes:':
        algo = 'aes-gcm'
        ct = blob[off:]
        file_key = derive_file_key(master_key, algo, relative_path)
        return decrypt_aes_gcm(file_key, ct)
    elif tag == b'cha:':
        algo = 'chacha20-poly1305'
        ct = blob[off:]
        file_key = derive_file_key(master_key, algo, relative_path)
        return decrypt_chacha20(file_key, ct)
    elif tag == b'xch:':
        algo = 'xchacha20-poly1305'
        ct = blob[off:]
        file_key = derive_file_key(master_key, algo, relative_path)
        return decrypt_xchacha20(file_key, ct)
    elif tag == b'siv:':
        algo = 'aes-siv'
        ct = blob[off:]
        file_key = derive_file_key(master_key, algo, relative_path, length=KEY_SIZE)
        return decrypt_aes_siv(file_key, ct)
    elif tag == b'hyb:':
        algo = 'hybrid-rsa'
        ct = blob[off:]
        if privkey_pem is None:
            raise ValueError("privkey required for hybrid-rsa decryption")
        return decrypt_hybrid_rsa(privkey_pem, privkey_password, ct)
    else:
        raise ValueError("Algorithme inconnu dans l'entête")

# ------------------ File/Directory operations ------------------
def encrypt_path(master_key: bytes, path: Path, algo: str, pubkey_pem: Optional[bytes]=None, delete_clear: bool=True) -> None:
    if path.is_file():
        _encrypt_file(master_key, path, algo, pubkey_pem, delete_clear)
    else:
        for p in path.rglob('*'):
            if p.is_file() and not p.name.endswith(SUFFIX):
                _encrypt_file(master_key, p, algo, pubkey_pem, delete_clear)

def _encrypt_file(master_key: bytes, file_path: Path, algo: str, pubkey_pem: Optional[bytes], delete_clear: bool) -> None:
    with open(file_path, 'rb') as f:
        data = f.read()
    stat = file_path.stat()
    # meta: stocké chiffré dans le payload
    meta = {
        "name": file_path.name,
        "mtime": int(stat.st_mtime),
        "size": len(data),
        "algo": algo,
        "v": 2,
    }
    rel = str(file_path)
    blob = encrypt_blob_for_algo(master_key, algo, rel, data, meta, pubkey_pem)
    out_path = file_path.with_suffix(file_path.suffix + SUFFIX)
    with open(out_path, 'wb') as f:
        f.write(blob)
    if delete_clear:
        os.remove(file_path)

def decrypt_path(master_key: bytes, path: Path, privkey_pem: Optional[bytes]=None, privkey_password: Optional[bytes]=None) -> None:
    if path.is_file():
        _decrypt_file(master_key, path, privkey_pem, privkey_password)
    else:
        for p in path.rglob(f'*{SUFFIX}'):
            if p.is_file():
                _decrypt_file(master_key, p, privkey_pem, privkey_password)

def _decrypt_file(master_key: bytes, enc_path: Path, privkey_pem: Optional[bytes], privkey_password: Optional[bytes]) -> None:
    with open(enc_path, 'rb') as f:
        blob = f.read()
    # we need the original relative path for HKDF context - use stored name in meta after decryption
    # but derive_file_key requires the relative_path; since we used the actual path while encrypting,
    # we will provide the current path as relative; this is consistent if the file is decrypted in same location.
    rel = str(enc_path.with_suffix(''))  # best-effort placeholder
    pt, meta = decrypt_blob_for_algo(master_key, None, rel, blob, privkey_pem, privkey_password)
    orig_name = meta.get("name") or enc_path.stem
    out_path = enc_path.with_name(orig_name)
    if out_path.exists():
        out_path = enc_path.with_name(f"{orig_name}.restored")
    with open(out_path, 'wb') as f:
        f.write(pt)
    mtime = meta.get("mtime")
    if isinstance(mtime, int):
        try:
            os.utime(out_path, (mtime, mtime))
        except Exception:
            pass
    os.remove(enc_path)

# --------------------------- CLI -----------------------------
def cmd_generate_shares(args: argparse.Namespace) -> None:
    mk = generate_master_key()
    shares = split_key_shamir(mk, args.k, args.n)
    payload = {"threshold": args.k, "total": args.n, "shares": shares, "note": "Conservez séparément."}
    text = json.dumps(payload, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(text, encoding='utf-8')
        print(f"Parts écrites dans {args.out}")
    else:
        print(text)

def _reconstruct_mk_from_shares(share_strings: List[str]) -> bytes:
    if len(share_strings) < 1:
        raise SystemExit("Aucune part fournie")
    return combine_shares_shamir(share_strings)

def cmd_encrypt(args: argparse.Namespace) -> None:
    mk = _reconstruct_mk_from_shares(args.shares)
    target = Path(args.path)
    if not target.exists():
        raise SystemExit(f"Chemin introuvable: {target}")
    pubkey_pem = None
    if args.algo == 'hybrid-rsa':
        if not args.pubkey:
            raise SystemExit("--pubkey requis pour hybrid-rsa")
        pubkey_pem = Path(args.pubkey).read_bytes()
    encrypt_path(mk, target, args.algo, pubkey_pem, delete_clear=not args.no_delete)
    print("Chiffrement terminé.")

def cmd_decrypt(args: argparse.Namespace) -> None:
    mk = _reconstruct_mk_from_shares(args.shares)
    target = Path(args.path)
    if not target.exists():
        raise SystemExit(f"Chemin introuvable: {target}")
    privkey_pem = None
    privkey_password = None
    if args.algo == 'hybrid-rsa':
        if not args.privkey:
            raise SystemExit("--privkey requis pour hybrid-rsa")
        privkey_pem = Path(args.privkey).read_bytes()
        if args.privkey_password:
            privkey_password = args.privkey_password.encode('utf-8')
    decrypt_path(mk, target, privkey_pem, privkey_password)
    print("Déchiffrement terminé.")

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="QuadLock Encrypt — multi-algo (k-of-n Shamir)")
    sub = p.add_subparsers(dest='cmd', required=True)

    g = sub.add_parser('generate-shares', help='Générer n parts (k nécessaires)')
    g.add_argument('--k', type=int, default=4, help='Seuil k (min parts requises)')
    g.add_argument('--n', type=int, default=6, help='Nombre total de parts')
    g.add_argument('--out', type=str, help='Fichier de sortie (JSON)')
    g.set_defaults(func=cmd_generate_shares)

    e = sub.add_parser('encrypt', help='Chiffrer un fichier ou un dossier')
    e.add_argument('--path', required=True, help='Chemin fichier/dossier à chiffrer')
    e.add_argument('--shares', nargs='+', required=True, help='Au moins k parts Shamir (ou utilisez --shares-file dans wrapper)')
    e.add_argument('--algo', default='aes-gcm', choices=['aes-gcm','chacha20-poly1305','xchacha20-poly1305','aes-siv','hybrid-rsa'], help='Algo de chiffrement')
    e.add_argument('--pubkey', help='Fichier PEM de la clé publique (requis pour hybrid-rsa)')
    e.add_argument('--no-delete', action='store_true', help='Ne pas supprimer le fichier clair après chiffrement')
    e.set_defaults(func=cmd_encrypt)

    d = sub.add_parser('decrypt', help='Déchiffrer un fichier ou un dossier')
    d.add_argument('--path', required=True, help='Chemin fichier/dossier à déchiffrer (.qlock)')
    d.add_argument('--shares', nargs='+', required=True, help='Au moins k parts Shamir')
    d.add_argument('--algo', default='aes-gcm', choices=['aes-gcm','chacha20-poly1305','xchacha20-poly1305','aes-siv','hybrid-rsa'], help='Algo (utile pour hybrid-rsa)')
    d.add_argument('--privkey', help='Fichier PEM de la clé privée (requis pour hybrid-rsa)')
    d.add_argument('--privkey-password', help='Mot de passe pour la clé privée PEM si chiffrée')
    d.set_defaults(func=cmd_decrypt)

    return p

def main(argv: List[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)

if __name__ == '__main__':
    main()

