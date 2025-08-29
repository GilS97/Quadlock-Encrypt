# Quadlock Encrypt - Documentation Complète

## 📋 Table des matières
1. [Installation](#installation)
2. [Utilisation de base](#utilisation-de-base)
3. [Configuration avancée](#configuration-avancée)
4. [Scripts d'aide](#scripts-daide)
5. [Sécurité](#sécurité)
6. [Dépannage](#dépannage)
7. [FAQ](#faq)

## 🔧 Installation

### Prérequis
- Python 3.7 ou supérieur
- pip (gestionnaire de paquets Python)
- 50 MB d'espace disque libre

### Installation automatique
```bash
# Télécharger et exécuter le script d'installation
curl -O https://raw.githubusercontent.com/votre-repo/quadlock/main/install.sh
chmod +x install.sh
./install.sh
```

### Installation manuelle
```bash
# Cloner ou télécharger les fichiers
git clone https://github.com/votre-repo/quadlock-encrypt.git
cd quadlock-encrypt

# Créer l'environnement virtuel
python3 -m venv quadlock_env
source quadlock_env/bin/activate  # Linux/macOS
# ou
quadlock_env\Scripts\activate.bat  # Windows

# Installer les dépendances
pip install -r requirements.txt
```

## 🚀 Utilisation de base

### Chiffrement d'un fichier
```bash
# Chiffrement simple
./quadlock.sh encrypt document.pdf --password "motdepasse123"

# Avec fichier de sortie personnalisé
./quadlock.sh encrypt document.pdf --password "motdepasse123" --output document_securise.qlk

# Avec configuration personnalisée
./quadlock.sh encrypt document.pdf --password "motdepasse123" --config ma_config.json
```

### Déchiffrement d'un fichier
```bash
# Les 3 parts minimum sont requises (par défaut)
./quadlock.sh decrypt document.pdf.qlk \
  --shares "1-58f8e5..." "2-7a9b2c..." "3-e4d7f1..."

# Avec plus de parts (plus sécurisé)
./quadlock.sh decrypt document.pdf.qlk \
  --shares "1-58f8e5..." "2-7a9b2c..." "3-e4d7f1..." "4-b8c9d2..." "5-f3a6e8..."
```

### Gestion de la configuration
```bash
# Créer une configuration par défaut
./quadlock.sh config --create

# Afficher la configuration actuelle
./quadlock.sh config --show

# Utiliser une configuration spécifique
./quadlock.sh config --show --file ma_config_perso.json
```

## ⚙️ Configuration avancée

### Structure du fichier de configuration
```json
{
  "algorithms": ["AES-GCM", "ChaCha20", "XChaCha20", "Blowfish", "RSA"],
  "shamir_shares": 7,
  "shamir_threshold": 4,
  "pbkdf2_iterations": 150000,
  "salt_size": 64,
  "rsa_key_size": 4096,
  "security_level": "maximum"
}
```

### Niveaux de sécurité prédéfinis

#### Niveau Standard (rapide)
```json
{
  "algorithms": ["AES-GCM", "ChaCha20"],
  "shamir_shares": 3,
  "shamir_threshold": 2,
  "pbkdf2_iterations": 50000,
  "salt_size": 16,
  "security_level": "standard"
}
```

#### Niveau Élevé (équilibré)
```json
{
  "algorithms": ["AES-GCM", "ChaCha20", "XChaCha20", "Blowfish"],
  "shamir_shares": 5,
  "shamir_threshold": 3,
  "pbkdf2_iterations": 100000,
  "salt_size": 32,
  "security_level": "high"
}
```

#### Niveau Maximum (très sécurisé)
```json
{
  "algorithms": ["AES-GCM", "ChaCha20", "XChaCha20", "Blowfish", "RSA"],
  "shamir_shares": 9,
  "shamir_threshold": 5,
  "pbkdf2_iterations": 200000,
  "salt_size": 64,
  "rsa_key_size": 4096,
  "security_level": "maximum"
}
```

## 🛠️ Scripts d'aide

### Script de chiffrement en lot
```bash
# Chiffrer tous les PDF d'un dossier
./encrypt_batch.sh /home/user/documents "motdepasse123"

# Le script traite automatiquement les types de fichiers courants:
# PDF, DOC, DOCX, TXT, JPG, PNG, etc.
```

### Script de déchiffrement en lot
```bash
# Déchiffrer tous les fichiers .qlk d'un dossier
./decrypt_batch.sh /home/user/encrypted "part1" "part2" "part3"
```

### Script de test complet
```bash
# Teste toute la chaîne chiffrement/déchiffrement
./test_quadlock.sh

# Résultat attendu:
# ✅ Test complet réussi! Les fichiers sont identiques.
```

### Script de sauvegarde des clés
```bash
# Sauvegarde toutes les parts de clés dans un dossier sécurisé
./backup_keys.sh /media/usb/backup_keys

# Crée optionnellement une archive chiffrée
```

### Script de récupération d'urgence
```bash
# En cas de problème avec les scripts normaux
./emergency_decrypt.sh

# Interface interactive pour la récupération
```

### Script de vérification d'intégrité
```bash
# Vérifie tous les fichiers .qlk du répertoire
./verify_integrity.sh

# Ou vérification de fichiers spécifiques
./verify_integrity.sh fichier1.qlk fichier2.qlk
```

## 🔐 Sécurité

### Algorithmes utilisés
1. **AES-256-GCM** : Standard militaire, authentification intégrée
2. **ChaCha20-Poly1305** : Alternative moderne à AES, résistant aux attaques par canal auxiliaire
3. **XChaCha20-Poly1305** : Version étendue avec nonce de 192 bits
4. **Blowfish-CBC** : Algorithme éprouvé, blocs de 64 bits
5. **RSA-OAEP-4096** : Chiffrement asymétrique pour petites données

### Partage de secret de Shamir
- **Principe** : La clé maître est divisée en n parts, k parts suffisent pour la reconstituer
- **Avantages** :
  - Redondance : perte de quelques parts tolérée
  - Distribution sécurisée : aucune part ne révèle d'information seule
  - Seuil configurable : équilibre entre sécurité et praticité

### Bonnes pratiques de sécurité

#### Mots de passe
- **Longueur minimum** : 12 caractères
- **Complexité** : majuscules, minuscules, chiffres, symboles
- **Unicité** : différent pour chaque lot de fichiers importants
- **Stockage** : gestionnaire de mots de passe recommandé

#### Stockage des parts Shamir
- **Séparation physique** : stockage sur différents supports
- **Redondance** : copies multiples des parts critiques
- **Sécurité** : chiffrement des supports de stockage
- **Documentation** : inventaire sécurisé des emplacements

#### Environnement d'exécution
- **Système à jour** : patches de sécurité appliqués
- **Antivirus** : protection en temps réel active
- **Réseau** : déconnexion recommandée pendant les opérations
- **Nettoyage** : suppression sécurisée des fichiers temporaires

## 🔧 Dépannage

### Erreurs communes

#### "Nombre insuffisant de parts Shamir"
```bash
# Erreur
❌ Erreur: Nombre insuffisant de parts Shamir: 2 fournie(s), 3 requise(s)

# Solution
# Fournir au moins le nombre minimum de parts configuré
./quadlock.sh decrypt fichier.qlk --shares part1 part2 part3
```

#### "Fichier introuvable"
```bash
# Vérifier l'existence du fichier
ls -la fichier.qlk

# Vérifier les permissions
chmod 644 fichier.qlk
```

#### "Erreur de déchiffrement"
- Vérifier l'exactitude des parts Shamir (pas de caractères manquants/ajoutés)
- S'assurer que les parts correspondent bien au fichier
- Vérifier l'intégrité du fichier .qlk

#### "Dépendances manquantes"
```bash
# Réinstaller les dépendances
source quadlock_env/bin/activate
pip install -r requirements.txt --force-reinstall
```

### Problèmes de performance

#### Chiffrement lent
- **Cause** : paramètres PBKDF2 trop élevés
- **Solution** : réduire `pbkdf2_iterations` dans la config
- **Équilibre** : sécurité vs performance

#### Gros fichiers
- **Limite** : RSA activé sur fichiers > 400 bytes
- **Solution** : désactiver RSA pour gros fichiers dans la config
- **Alternative** : traitement par chunks (développement futur)

### Récupération de données

#### Fichier .qlk corrompu
```bash
# Vérifier l'intégrité
./verify_integrity.sh fichier.qlk

# Tentative de réparation manuelle
python3 -c "
import json
with open('fichier.qlk', 'r') as f:
    data = json.load(f)
print('Structure JSON valide')
"
```

#### Parts Shamir perdues
- **Situation** : moins de k parts disponibles
- **Solutions** :
  - Rechercher d'autres copies/sauvegardes
  - Récupération depuis sauvegardes chiffrées
  - **Dernier recours** : attaque par force brute (non recommandée)

## ❓ FAQ

### Questions générales

**Q: Puis-je changer le nombre de parts Shamir après chiffrement ?**
R: Non, le nombre de parts est fixé au moment du chiffrement. Il faut déchiffrer puis rechiffrer avec une nouvelle configuration.

**Q: Les fichiers chiffrés sont-ils compatibles entre différentes versions ?**
R: Les versions mineures sont rétro-compatibles. Les versions majeures peuvent nécessiter une migration.

**Q: Puis-je utiliser Quadlock sur différents systèmes d'exploitation ?**
R: Oui, l'application est compatible Linux, macOS et Windows avec Python 3.7+.

**Q: Quelle est la taille maximale des fichiers supportés ?**
R: Théoriquement illimitée, mais les performances dépendent de la RAM disponible. Recommandé : < 1 GB par fichier.

### Questions de sécurité

**Q: Les algorithmes utilisés sont-ils sûrs ?**
R: Oui, tous les algorithmes sont approuvés par les standards cryptographiques modernes (NIST, RFC).

**Q: Que se passe-t-il si j'oublie mon mot de passe ?**
R: Le mot de passe ne peut pas être récupéré. Les parts Shamir sont nécessaires ET le mot de passe original.

**Q: Quelqu'un peut-il déchiffrer mes fichiers sans les parts ?**
R: Avec les algorithmes et paramètres par défaut, c'est computationnellement impossible avec la technologie actuelle.

**Q: Dois-je faire confiance à cette application ?**
R: Le code source est ouvert et auditable. Vous pouvez le réviser ou le faire auditer par des experts.

### Questions techniques

**Q: Puis-je désactiver certains algorithmes ?**
R: Oui, modifiez la liste `algorithms` dans la configuration. Minimum recommandé : 2 algorithmes.

**Q: Comment créer ma propre configuration ?**
R: Copiez `default_config.json`, modifiez les paramètres, et utilisez `--config` lors du chiffrement.

**Q: Les métadonnées des fichiers sont-elles préservées ?**
R: Les métadonnées système (date, permissions) ne sont pas préservées dans la version actuelle.

---

## 📞 Support

### Signalement de bugs
- **GitHub Issues** : [lien vers votre repo]
- **Email** : security@votre-domaine.com (pour les problèmes de sécurité)

### Contributions
- **Pull Requests** : bienvenues sur GitHub
- **Tests** : ajoutez des tests pour toute nouvelle fonctionnalité
- **Documentation** : aidez à améliorer cette documentation

### Licence
Ce projet est sous licence MIT. Voir le fichier `LICENSE` pour les détails.

---

**⚠️ Avertissement de sécurité** : Aucun système n'est parfait. Effectuez toujours des sauvegardes multiples de vos données importantes et testez régulièrement vos procédures de récupération.