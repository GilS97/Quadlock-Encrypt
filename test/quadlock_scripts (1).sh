# install.sh
#!/bin/bash
# Script d'installation pour Quadlock Encrypt

echo "🔐 Installation de Quadlock Encrypt"
echo "=================================="

# Vérification de Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 n'est pas installé. Veuillez l'installer d'abord."
    exit 1
fi

echo "✅ Python 3 détecté: $(python3 --version)"

# Création de l'environnement virtuel
echo "📦 Création de l'environnement virtuel..."
python3 -m venv quadlock_env

# Activation de l'environnement
source quadlock_env/bin/activate

# Installation des dépendances
echo "📥 Installation des dépendances..."
pip install --upgrade pip

# Liste des packages requis
cat > requirements.txt << EOF
cryptography>=41.0.0
blowfish>=0.6.3
secretsharing>=0.2.6
argparse
pathlib
EOF

pip install -r requirements.txt

# Création des scripts de lancement
cat > quadlock.sh << 'EOF'
#!/bin/bash
# Script de lancement Quadlock Encrypt

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/quadlock_env/bin/activate"
python3 "$SCRIPT_DIR/quadlock_encrypt.py" "$@"
EOF

chmod +x quadlock.sh

# Script Windows
cat > quadlock.bat << 'EOF'
@echo off
set SCRIPT_DIR=%~dp0
call "%SCRIPT_DIR%quadlock_env\Scripts\activate.bat"
python "%SCRIPT_DIR%quadlock_encrypt.py" %*
EOF

# Script de chiffrement batch
cat > encrypt_batch.sh << 'EOF'
#!/bin/bash
# Script de chiffrement en lot

if [ $# -lt 2 ]; then
    echo "Usage: $0 <dossier> <mot_de_passe>"
    echo "Exemple: $0 /home/user/documents motdepasse123"
    exit 1
fi

FOLDER="$1"
PASSWORD="$2"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -d "$FOLDER" ]; then
    echo "❌ Dossier introuvable: $FOLDER"
    exit 1
fi

echo "🔐 Chiffrement en lot du dossier: $FOLDER"
echo "======================================="

find "$FOLDER" -type f \( -name "*.pdf" -o -name "*.doc" -o -name "*.docx" -o -name "*.txt" -o -name "*.jpg" -o -name "*.png" \) | while read file; do
    echo "📄 Chiffrement: $(basename "$file")"
    "$SCRIPT_DIR/quadlock.sh" encrypt "$file" --password "$PASSWORD"
done

echo "✅ Chiffrement en lot terminé!"
EOF

chmod +x encrypt_batch.sh

# Script de déchiffrement batch
cat > decrypt_batch.sh << 'EOF'
#!/bin/bash
# Script de déchiffrement en lot

if [ $# -lt 4 ]; then
    echo "Usage: $0 <dossier> <part1> <part2> <part3> [part4] [part5]"
    echo "Exemple: $0 /home/user/encrypted part1 part2 part3"
    exit 1
fi

FOLDER="$1"
shift
SHARES=("$@")
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -d "$FOLDER" ]; then
    echo "❌ Dossier introuvable: $FOLDER"
    exit 1
fi

echo "🔓 Déchiffrement en lot du dossier: $FOLDER"
echo "========================================="

find "$FOLDER" -name "*.qlk" | while read file; do
    echo "📄 Déchiffrement: $(basename "$file")"
    "$SCRIPT_DIR/quadlock.sh" decrypt "$file" --shares "${SHARES[@]}"
done

echo "✅ Déchiffrement en lot terminé!"
EOF

chmod +x decrypt_batch.sh

# Script de test
cat > test_quadlock.sh << 'EOF'
#!/bin/bash
# Script de test pour Quadlock Encrypt

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "🧪 Test de Quadlock Encrypt"
echo "============================"

# Création d'un fichier de test
echo "Ceci est un fichier de test pour Quadlock Encrypt!" > test_file.txt
echo "Il contient du texte sensible à protéger." >> test_file.txt

# Test de chiffrement
echo "1. Test de chiffrement..."
"$SCRIPT_DIR/quadlock.sh" encrypt test_file.txt --password "testpassword123"

if [ -f "test_file.txt.qlk" ] && [ -f "test_file.txt.shares" ]; then
    echo "✅ Chiffrement réussi!"
    
    # Lecture des parts Shamir
    echo "2. Lecture des parts Shamir..."
    SHARE1=$(sed -n '7p' test_file.txt.shares | cut -d' ' -f2-)
    SHARE2=$(sed -n '8p' test_file.txt.shares | cut -d' ' -f2-)
    SHARE3=$(sed -n '9p' test_file.txt.shares | cut -d' ' -f2-)
    
    echo "   Part 1: ${SHARE1:0:20}..."
    echo "   Part 2: ${SHARE2:0:20}..."
    echo "   Part 3: ${SHARE3:0:20}..."
    
    # Test de déchiffrement
    echo "3. Test de déchiffrement..."
    "$SCRIPT_DIR/quadlock.sh" decrypt test_file.txt.qlk --shares "$SHARE1" "$SHARE2" "$SHARE3"
    
    if [ -f "test_file.txt_decrypted" ]; then
        echo "✅ Déchiffrement réussi!"
        
        # Vérification de l'intégrité
        echo "4. Vérification de l'intégrité..."
        if cmp -s test_file.txt test_file.txt_decrypted; then
            echo "✅ Test complet réussi! Les fichiers sont identiques."
        else
            echo "❌ Erreur: Les fichiers diffèrent!"
        fi
        
        # Nettoyage
        rm -f test_file.txt test_file.txt.qlk test_file.txt.shares test_file.txt_decrypted
    else
        echo "❌ Déchiffrement échoué!"
    fi
else
    echo "❌ Chiffrement échoué!"
fi
EOF

chmod +x test_quadlock.sh

# Script de sauvegarde des clés
cat > backup_keys.sh << 'EOF'
#!/bin/bash
# Script de sauvegarde des parts de clés Shamir

if [ $# -ne 1 ]; then
    echo "Usage: $0 <dossier_destination>"
    echo "Exemple: $0 /media/usb/backup_keys"
    exit 1
fi

BACKUP_DIR="$1"
DATE=$(date +"%Y%m%d_%H%M%S")
BACKUP_NAME="quadlock_keys_$DATE"

mkdir -p "$BACKUP_DIR/$BACKUP_NAME"

echo "💾 Sauvegarde des clés Quadlock"
echo "==============================="
echo "Destination: $BACKUP_DIR/$BACKUP_NAME"

# Recherche des fichiers .shares
find . -name "*.shares" -print0 | while IFS= read -r -d '' file; do
    echo "📁 Copie: $(basename "$file")"
    cp "$file" "$BACKUP_DIR/$BACKUP_NAME/"
done

# Création d'un fichier d'inventaire
find "$BACKUP_DIR/$BACKUP_NAME" -name "*.shares" > "$BACKUP_DIR/$BACKUP_NAME/inventaire.txt"

echo "✅ Sauvegarde terminée!"
echo "📊 Fichiers sauvegardés: $(wc -l < "$BACKUP_DIR/$BACKUP_NAME/inventaire.txt")"
echo "📍 Emplacement: $BACKUP_DIR/$BACKUP_NAME"

# Création d'une archive chiffrée (optionnel)
read -p "Créer une archive chiffrée? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    read -s -p "Mot de passe pour l'archive: " ARCHIVE_PASSWORD
    echo
    tar -czf - -C "$BACKUP_DIR" "$BACKUP_NAME" | openssl enc -aes-256-cbc -salt -k "$ARCHIVE_PASSWORD" -out "$BACKUP_DIR/$BACKUP_NAME.tar.gz.enc"
    rm -rf "$BACKUP_DIR/$BACKUP_NAME"
    echo "🔐 Archive chiffrée créée: $BACKUP_DIR/$BACKUP_NAME.tar.gz.enc"
fi
EOF

# Script de récupération d'urgence
cat > emergency_decrypt.sh << 'EOF'
#!/bin/bash
# Script de récupération d'urgence

echo "🚨 QUADLOCK ENCRYPT - RÉCUPÉRATION D'URGENCE"
echo "============================================="

if [ ! -f "quadlock_encrypt.py" ]; then
    echo "❌ Application Quadlock non trouvée dans ce répertoire!"
    exit 1
fi

echo "Ce script vous aide à déchiffrer vos fichiers même sans les scripts normaux."
echo

# Demande du fichier à déchiffrer
read -p "📁 Chemin vers le fichier .qlk à déchiffrer: " ENCRYPTED_FILE
if [ ! -f "$ENCRYPTED_FILE" ]; then
    echo "❌ Fichier introuvable: $ENCRYPTED_FILE"
    exit 1
fi

echo
echo "🔑 Saisissez vos parts de clé Shamir (minimum 3):"
SHARES=()
for i in {1..9}; do
    read -p "Part $i (entrée vide pour terminer): " SHARE
    if [ -z "$SHARE" ]; then
        break
    fi
    SHARES+=("$SHARE")
done

if [ ${#SHARES[@]} -lt 3 ]; then
    echo "❌ Vous devez fournir au moins 3 parts de clé!"
    exit 1
fi

echo
echo "🔓 Tentative de déchiffrement..."

# Activation de l'environnement si disponible
if [ -d "quadlock_env" ]; then
    source quadlock_env/bin/activate
fi

python3 quadlock_encrypt.py decrypt "$ENCRYPTED_FILE" --shares "${SHARES[@]}"

if [ $? -eq 0 ]; then
    echo "✅ Récupération d'urgence réussie!"
else
    echo "❌ Échec de la récupération. Vérifiez vos parts de clé."
fi
EOF

chmod +x emergency_decrypt.sh

# Script de vérification de l'intégrité
cat > verify_integrity.sh << 'EOF'
#!/bin/bash
# Script de vérification de l'intégrité des fichiers chiffrés

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "🔍 Vérification de l'intégrité Quadlock"
echo "======================================="

if [ $# -eq 0 ]; then
    echo "Recherche des fichiers .qlk dans le répertoire courant..."
    FILES=$(find . -name "*.qlk" -type f)
else
    FILES="$@"
fi

TOTAL=0
VALID=0
INVALID=0

for file in $FILES; do
    if [ -f "$file" ]; then
        echo -n "📄 $(basename "$file"): "
        
        # Vérification de la structure JSON
        if python3 -c "import json; json.load(open('$file'))" 2>/dev/null; then
            echo "✅ Structure valide"
            ((VALID++))
        else
            echo "❌ Structure corrompue"
            ((INVALID++))
        fi
        ((TOTAL++))
    fi
done

echo
echo "📊 Résultat de la vérification:"
echo "   Total: $TOTAL fichiers"
echo "   Valides: $VALID"
echo "   Corrompus: $INVALID"

if [ $INVALID -gt 0 ]; then
    echo "⚠️  Des fichiers corrompus ont été détectés!"
    exit 1
else
    echo "✅ Tous les fichiers sont intègres."
fi
EOF

chmod +x verify_integrity.sh

# Configuration par défaut
cat > default_config.json << 'EOF'
{
  "algorithms": [
    "AES-GCM",
    "ChaCha20",
    "XChaCha20",
    "Blowfish",
    "RSA"
  ],
  "shamir_shares": 5,
  "shamir_threshold": 3,
  "pbkdf2_iterations": 100000,
  "salt_size": 32,
  "rsa_key_size": 4096,
  "version": "1.0",
  "description": "Configuration par défaut Quadlock Encrypt",
  "security_level": "high",
  "compatibility": {
    "min_python_version": "3.7",
    "required_packages": [
      "cryptography>=41.0.0",
      "blowfish>=0.6.3",
      "secretsharing>=0.2.6"
    ]
  }
}
EOF

echo "✅ Installation terminée!"
echo
echo "📋 Fichiers créés:"
echo "   - quadlock_encrypt.py (application principale)"
echo "   - quadlock.sh / quadlock.bat (lanceurs)"
echo "   - encrypt_batch.sh (chiffrement en lot)"
echo "   - decrypt_batch.sh (déchiffrement en lot)"
echo "   - test_quadlock.sh (script de test)"
echo "   - backup_keys.sh (sauvegarde des clés)"
echo "   - emergency_decrypt.sh (récupération d'urgence)"
echo "   - verify_integrity.sh (vérification d'intégrité)"
echo "   - default_config.json (configuration par défaut)"
echo "   - requirements.txt (dépendances Python)"
echo
echo "🚀 Pour commencer:"
echo "   1. ./test_quadlock.sh (test complet)"
echo "   2. ./quadlock.sh encrypt monfichier.pdf --password motdepasse"
echo "   3. ./quadlock.sh decrypt monfichier.pdf.qlk --shares part1 part2 part3"
echo
echo "📖 Pour plus d'aide: ./quadlock.sh --help"