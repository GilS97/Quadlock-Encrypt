# quadlock_encrypt.py
#!/usr/bin/env python3
"""
Quadlock Encrypt - Application de chiffrement multi-couches avec partage de secret Shamir
Auteur: Assistant Claude
Version: 1.0
"""

import os
import sys
import json
import base64
import secrets
import hashlib
import argparse
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from datetime import datetime

# Imports pour la cryptographie
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import blowfish

# Pour le partage de secret de Shamir
from secretsharing import SecretSharer


class QuadlockCrypto:
    """Classe principale pour les opérations cryptographiques multi-couches"""
    
    def __init__(self, config: Dict = None):
        self.config = config or self._default_config()
        self.key_derivation_iterations = self.config.get('pbkdf2_iterations', 100000)
        self.salt_size = self.config.get('salt_size', 32)
        
    def _default_config(self) -> Dict:
        """Configuration par défaut"""
        return {
            'algorithms': ['AES-GCM', 'ChaCha20', 'XChaCha20', 'Blowfish', 'RSA'],
            'shamir_shares': 5,
            'shamir_threshold': 3,
            'pbkdf2_iterations': 100000,
            'salt_size': 32,
            'rsa_key_size': 4096
        }
    
    def generate_master_key(self, password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
        """Génère la clé maître à partir d'un mot de passe"""
        if salt is None:
            salt = secrets.token_bytes(self.salt_size)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.key_derivation_iterations,
        )
        key = kdf.derive(password.encode())
        return key, salt
    
    def generate_layer_keys(self, master_key: bytes) -> Dict[str, bytes]:
        """Génère les clés pour chaque couche de chiffrement"""
        keys = {}
        
        # Dérivation de clés pour chaque algorithme
        for i, algo in enumerate(self.config['algorithms']):
            # Utilise HKDF pour dériver des clés spécifiques
            info = f"quadlock-{algo}-{i}".encode()
            derived = hashlib.pbkdf2_hmac('sha256', master_key, info, 10000, 32)
            keys[algo] = derived
            
        return keys
    
    def generate_rsa_keypair(self) -> Tuple[bytes, bytes]:
        """Génère une paire de clés RSA"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.config['rsa_key_size']
        )
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem, public_pem
    
    def encrypt_data_multi_layer(self, data: bytes, password: str) -> Dict:
        """Chiffre les données avec toutes les couches"""
        print("🔐 Début du chiffrement multi-couches...")
        
        # Génération de la clé maître
        master_key, salt = self.generate_master_key(password)
        layer_keys = self.generate_layer_keys(master_key)
        
        # Données à chiffrer
        current_data = data
        metadata = {
            'original_size': len(data),
            'layers': [],
            'salt': base64.b64encode(salt).decode(),
            'timestamp': datetime.now().isoformat()
        }
        
        # Couche 1: AES-GCM
        if 'AES-GCM' in self.config['algorithms']:
            print("  └─ Couche AES-GCM...")
            nonce = secrets.token_bytes(12)
            aesgcm = AESGCM(layer_keys['AES-GCM'])
            current_data = aesgcm.encrypt(nonce, current_data, None)
            metadata['layers'].append({
                'algorithm': 'AES-GCM',
                'nonce': base64.b64encode(nonce).decode()
            })
        
        # Couche 2: ChaCha20-Poly1305
        if 'ChaCha20' in self.config['algorithms']:
            print("  └─ Couche ChaCha20-Poly1305...")
            nonce = secrets.token_bytes(12)
            chacha = ChaCha20Poly1305(layer_keys['ChaCha20'])
            current_data = chacha.encrypt(nonce, current_data, None)
            metadata['layers'].append({
                'algorithm': 'ChaCha20',
                'nonce': base64.b64encode(nonce).decode()
            })
        
        # Couche 3: XChaCha20 (simulé avec Fernet pour la compatibilité)
        if 'XChaCha20' in self.config['algorithms']:
            print("  └─ Couche XChaCha20 (Fernet)...")
            fernet_key = base64.urlsafe_b64encode(layer_keys['XChaCha20'])
            f = Fernet(fernet_key)
            current_data = f.encrypt(current_data)
            metadata['layers'].append({
                'algorithm': 'XChaCha20'
            })
        
        # Couche 4: Blowfish
        if 'Blowfish' in self.config['algorithms']:
            print("  └─ Couche Blowfish...")
            cipher = blowfish.Cipher(layer_keys['Blowfish'])
            # Padding pour Blowfish (blocs de 8 bytes)
            padding_length = 8 - (len(current_data) % 8)
            if padding_length != 8:
                current_data += bytes([padding_length] * padding_length)
            
            encrypted_blocks = b""
            for i in range(0, len(current_data), 8):
                block = current_data[i:i+8]
                encrypted_blocks += b"".join(cipher.encrypt_ecb(block))
            current_data = encrypted_blocks
            metadata['layers'].append({
                'algorithm': 'Blowfish',
                'padding': padding_length if padding_length != 8 else 0
            })
        
        # Couche 5: RSA (pour de petites données ou clé symétrique)
        if 'RSA' in self.config['algorithms'] and len(current_data) < 400:
            print("  └─ Couche RSA...")
            private_key_pem, public_key_pem = self.generate_rsa_keypair()
            
            public_key = serialization.load_pem_public_key(public_key_pem)
            current_data = public_key.encrypt(
                current_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            metadata['layers'].append({
                'algorithm': 'RSA',
                'private_key': base64.b64encode(private_key_pem).decode()
            })
        
        # Génération des parts Shamir pour la clé maître
        print("🔑 Génération des parts Shamir...")
        master_key_hex = master_key.hex()
        shares = SecretSharer.split_secret(
            master_key_hex,
            self.config['shamir_threshold'],
            self.config['shamir_shares']
        )
        
        result = {
            'encrypted_data': base64.b64encode(current_data).decode(),
            'metadata': metadata,
            'shamir_shares': shares,
            'config': self.config
        }
        
        print("✅ Chiffrement terminé!")
        return result
    
    def decrypt_data_multi_layer(self, encrypted_package: Dict, shamir_shares: List[str]) -> bytes:
        """Déchiffre les données en inversant toutes les couches"""
        print("🔓 Début du déchiffrement multi-couches...")
        
        # Reconstruction de la clé maître avec Shamir
        print("🔑 Reconstruction de la clé maître...")
        if len(shamir_shares) < encrypted_package['config']['shamir_threshold']:
            raise ValueError(f"Nombre insuffisant de parts Shamir: {len(shamir_shares)} fournie(s), {encrypted_package['config']['shamir_threshold']} requise(s)")
        
        master_key_hex = SecretSharer.recover_secret(shamir_shares[:encrypted_package['config']['shamir_threshold']])
        master_key = bytes.fromhex(master_key_hex)
        
        # Génération des clés de couches
        layer_keys = self.generate_layer_keys(master_key)
        
        # Déchiffrement des données
        current_data = base64.b64decode(encrypted_package['encrypted_data'])
        metadata = encrypted_package['metadata']
        
        # Inversion des couches (ordre inverse)
        for layer in reversed(metadata['layers']):
            algo = layer['algorithm']
            print(f"  └─ Décryptage couche {algo}...")
            
            if algo == 'RSA':
                private_key_pem = base64.b64decode(layer['private_key'])
                private_key = serialization.load_pem_private_key(private_key_pem, password=None)
                current_data = private_key.decrypt(
                    current_data,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
            
            elif algo == 'Blowfish':
                cipher = blowfish.Cipher(layer_keys['Blowfish'])
                decrypted_blocks = b""
                for i in range(0, len(current_data), 8):
                    block = current_data[i:i+8]
                    decrypted_blocks += b"".join(cipher.decrypt_ecb(block))
                
                # Suppression du padding
                padding_length = layer.get('padding', 0)
                if padding_length > 0:
                    decrypted_blocks = decrypted_blocks[:-padding_length]
                current_data = decrypted_blocks
            
            elif algo == 'XChaCha20':
                fernet_key = base64.urlsafe_b64encode(layer_keys['XChaCha20'])
                f = Fernet(fernet_key)
                current_data = f.decrypt(current_data)
            
            elif algo == 'ChaCha20':
                nonce = base64.b64decode(layer['nonce'])
                chacha = ChaCha20Poly1305(layer_keys['ChaCha20'])
                current_data = chacha.decrypt(nonce, current_data, None)
            
            elif algo == 'AES-GCM':
                nonce = base64.b64decode(layer['nonce'])
                aesgcm = AESGCM(layer_keys['AES-GCM'])
                current_data = aesgcm.decrypt(nonce, current_data, None)
        
        print("✅ Déchiffrement terminé!")
        return current_data


class QuadlockApp:
    """Application principale Quadlock Encrypt"""
    
    def __init__(self):
        self.crypto = None
        self.config_file = Path("quadlock_config.json")
    
    def load_config(self, config_path: str = None) -> Dict:
        """Charge la configuration depuis un fichier"""
        if config_path:
            config_file = Path(config_path)
        else:
            config_file = self.config_file
        
        if config_file.exists():
            with open(config_file, 'r') as f:
                return json.load(f)
        return {}
    
    def save_config(self, config: Dict, config_path: str = None):
        """Sauvegarde la configuration dans un fichier"""
        if config_path:
            config_file = Path(config_path)
        else:
            config_file = self.config_file
        
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
    
    def encrypt_file(self, input_path: str, password: str, output_path: str = None, config: Dict = None):
        """Chiffre un fichier"""
        input_file = Path(input_path)
        if not input_file.exists():
            raise FileNotFoundError(f"Fichier introuvable: {input_path}")
        
        # Configuration
        if config:
            self.crypto = QuadlockCrypto(config)
        else:
            self.crypto = QuadlockCrypto(self.load_config())
        
        # Lecture du fichier
        print(f"📖 Lecture de {input_file.name}...")
        with open(input_file, 'rb') as f:
            data = f.read()
        
        # Chiffrement
        encrypted_package = self.crypto.encrypt_data_multi_layer(data, password)
        
        # Sauvegarde
        if output_path is None:
            output_path = str(input_file) + '.qlk'
        
        with open(output_path, 'w') as f:
            json.dump(encrypted_package, f, indent=2)
        
        print(f"💾 Fichier chiffré sauvegardé: {output_path}")
        
        # Sauvegarde des parts Shamir
        shares_file = str(Path(output_path).with_suffix('.shares'))
        with open(shares_file, 'w') as f:
            f.write("QUADLOCK ENCRYPT - PARTS DE CLÉ SHAMIR\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Fichier: {input_file.name}\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Parts requises: {encrypted_package['config']['shamir_threshold']}/{encrypted_package['config']['shamir_shares']}\n\n")
            
            for i, share in enumerate(encrypted_package['shamir_shares'], 1):
                f.write(f"Part {i}: {share}\n")
            
            f.write("\n⚠️  CONSERVEZ CES PARTS EN SÉCURITÉ ET SÉPARÉMENT!")
        
        print(f"🔑 Parts Shamir sauvegardées: {shares_file}")
        
        return output_path, shares_file
    
    def decrypt_file(self, input_path: str, shares: List[str], output_path: str = None):
        """Déchiffre un fichier"""
        input_file = Path(input_path)
        if not input_file.exists():
            raise FileNotFoundError(f"Fichier introuvable: {input_path}")
        
        # Chargement du package chiffré
        print(f"📖 Chargement de {input_file.name}...")
        with open(input_file, 'r') as f:
            encrypted_package = json.load(f)
        
        # Initialisation du crypto avec la config du package
        self.crypto = QuadlockCrypto(encrypted_package['config'])
        
        # Déchiffrement
        decrypted_data = self.crypto.decrypt_data_multi_layer(encrypted_package, shares)
        
        # Sauvegarde
        if output_path is None:
            # Retire l'extension .qlk
            output_path = str(input_file).replace('.qlk', '_decrypted')
            if output_path == str(input_file):  # Si pas d'extension .qlk
                output_path = str(input_file) + '_decrypted'
        
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)
        
        print(f"💾 Fichier déchiffré sauvegardé: {output_path}")
        return output_path
    
    def create_default_config(self):
        """Crée une configuration par défaut"""
        config = {
            'algorithms': ['AES-GCM', 'ChaCha20', 'XChaCha20', 'Blowfish', 'RSA'],
            'shamir_shares': 5,
            'shamir_threshold': 3,
            'pbkdf2_iterations': 100000,
            'salt_size': 32,
            'rsa_key_size': 4096,
            'version': '1.0',
            'created': datetime.now().isoformat()
        }
        
        self.save_config(config)
        print(f"✅ Configuration par défaut créée: {self.config_file}")
        return config


def main():
    """Interface en ligne de commande"""
    parser = argparse.ArgumentParser(
        description="Quadlock Encrypt - Chiffrement multi-couches avec partage Shamir",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  %(prog)s encrypt document.pdf --password "motdepasse123"
  %(prog)s decrypt document.pdf.qlk --shares part1 part2 part3
  %(prog)s config --create
  %(prog)s config --show
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commandes disponibles')
    
    # Commande encrypt
    encrypt_parser = subparsers.add_parser('encrypt', help='Chiffrer un fichier')
    encrypt_parser.add_argument('file', help='Fichier à chiffrer')
    encrypt_parser.add_argument('--password', '-p', required=True, help='Mot de passe de chiffrement')
    encrypt_parser.add_argument('--output', '-o', help='Fichier de sortie (optionnel)')
    encrypt_parser.add_argument('--config', '-c', help='Fichier de configuration personnalisé')
    
    # Commande decrypt
    decrypt_parser = subparsers.add_parser('decrypt', help='Déchiffrer un fichier')
    decrypt_parser.add_argument('file', help='Fichier chiffré (.qlk)')
    decrypt_parser.add_argument('--shares', '-s', nargs='+', required=True, help='Parts de clé Shamir')
    decrypt_parser.add_argument('--output', '-o', help='Fichier de sortie (optionnel)')
    
    # Commande config
    config_parser = subparsers.add_parser('config', help='Gestion de la configuration')
    config_parser.add_argument('--create', action='store_true', help='Créer une configuration par défaut')
    config_parser.add_argument('--show', action='store_true', help='Afficher la configuration actuelle')
    config_parser.add_argument('--file', help='Fichier de configuration spécifique')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    app = QuadlockApp()
    
    try:
        if args.command == 'encrypt':
            config = None
            if args.config:
                config = app.load_config(args.config)
            
            output_file, shares_file = app.encrypt_file(
                args.file, 
                args.password, 
                args.output, 
                config
            )
            print(f"\n🎉 Chiffrement réussi!")
            print(f"📁 Fichier chiffré: {output_file}")
            print(f"🔑 Parts Shamir: {shares_file}")
        
        elif args.command == 'decrypt':
            output_file = app.decrypt_file(args.file, args.shares, args.output)
            print(f"\n🎉 Déchiffrement réussi!")
            print(f"📁 Fichier restauré: {output_file}")
        
        elif args.command == 'config':
            if args.create:
                app.create_default_config()
            elif args.show:
                config = app.load_config(args.file)
                print("Configuration actuelle:")
                print(json.dumps(config, indent=2, ensure_ascii=False))
            else:
                config_parser.print_help()
    
    except Exception as e:
        print(f"❌ Erreur: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()