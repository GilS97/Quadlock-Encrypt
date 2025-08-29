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
echo "📊 Fich