# 🔐 Quadlock Encrypt

Quadlock Encrypt est une application de **chiffrement/déchiffrement de fichiers et répertoires** basée sur **quatre à cinq systèmes de chiffrement différents**, protégée par un mécanisme de **clé à verrous multiples (Shamir’s Secret Sharing)**.

Ce projet vise à fournir un niveau de sécurité avancé grâce à :

* **Multi-cryptage en cascade** (AES-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305, Blowfish, RSA/OAEP).
* **Partage de clé en n fragments** (seules k parts sont nécessaires pour déchiffrer).
* **Compatibilité multiplateforme** : Linux, macOS, Windows.

---

## 📂 Structure du projet

```
quadlock-encrypt/
│── quadlock_encrypt.py       # Code Python principal
│── run_quadlock.sh           # Script Bash (Linux/macOS)
│── run_quadlock.ps1          # Script PowerShell (Windows)
│── README.md                 # Documentation
```

---

## ⚙️ Prérequis

### Linux / macOS

* Python ≥ 3.8 installé par défaut (sinon `sudo apt install python3` ou `brew install python3`)

### Windows

* Télécharger [Python officiel](https://www.python.org/downloads/)
* Vérifier avec :

```powershell
python --version
```

---

## 🚀 Installation des dépendances

### Linux / macOS

```bash
chmod +x run_quadlock.sh
./run_quadlock.sh setup
```

### Windows (PowerShell)

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
.\run_quadlock.ps1 setup
```

---

## 🔑 Génération des parts de clé (Shamir)

Exemple : 6 parts générées, 4 nécessaires pour reconstituer la clé.

### Linux / macOS

```bash
./run_quadlock.sh generate-shares --k 4 --n 6 --out shares.json
```

### Windows (PowerShell)

```powershell
.\run_quadlock.ps1 generate-shares --k 4 --n 6 --out shares.json
```

---

## 🔒 Chiffrement

Chiffre un fichier ou répertoire avec un des algorithmes disponibles :

* `aes-gcm`
* `chacha20-poly1305`
* `xchacha20-poly1305`
* `blowfish`
* `rsa-oaep`

### Linux / macOS

```bash
./run_quadlock.sh encrypt --path ./data --shares-file shares.json --algo aes-gcm
```

### Windows (PowerShell)

```powershell
.\run_quadlock.ps1 encrypt --path .\data --shares-file shares.json --algo aes-gcm
```

---

## 🔓 Déchiffrement

### Linux / macOS

```bash
./run_quadlock.sh decrypt --path ./data --shares-file shares.json
```

### Windows (PowerShell)

```powershell
.\run_quadlock.ps1 decrypt --path .\data --shares-file shares.json
```

---

## 🛠️ Exemple complet

1. Générer des parts de clé (6 parts, 4 requises)

   ```bash
   ./run_quadlock.sh generate-shares --k 4 --n 6 --out shares.json
   ```

2. Chiffrer un dossier avec **ChaCha20-Poly1305**

   ```bash
   ./run_quadlock.sh encrypt --path ./secret_docs --shares-file shares.json --algo chacha20-poly1305
   ```

3. Déchiffrer le même dossier

   ```bash
   ./run_quadlock.sh decrypt --path ./secret_docs --shares-file shares.json
   ```

---

## 📌 Notes

* Les fichiers chiffrés portent l’extension `.enc`.
* Il faut **au moins k parts** pour déchiffrer.
* Le projet est conçu pour gérer aussi bien les **petits fichiers** que des **répertoires complets**.

