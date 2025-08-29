#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Script d’exécution pour Quadlock Encrypt (Windows PowerShell).

.DESCRIPTION
    Permet d’installer les dépendances Python et de lancer les commandes
    de chiffrement/déchiffrement avec Quadlock Encrypt.

.COMMANDS
    setup                 Installe les dépendances Python.
    generate-shares       Génère des parts Shamir.
    encrypt               Chiffre un fichier ou un répertoire.
    decrypt               Déchiffre un fichier ou un répertoire.
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$Command,
    [string]$path,
    [string]$sharesFile,
    [string]$algo,
    [int]$k,
    [int]$n,
    [string]$out
)

# Fonction pour vérifier Python
function Check-Python {
    Write-Host "🔎 Vérification de Python..."
    try {
        python --version
    } catch {
        Write-Error "❌ Python n’est pas installé ou pas dans le PATH. Installe-le avant de continuer."
        exit 1
    }
}

switch ($Command) {

    "setup" {
        Check-Python
        Write-Host "📦 Installation des dépendances..."
        python -m pip install --upgrade pip
        python -m pip install cryptography pycryptodome secretsharing
        Write-Host "✅ Installation terminée."
    }

    "generate-shares" {
        Check-Python
        if (-not $k -or -not $n -or -not $out) {
            Write-Error "⚠️ Utilisation: .\run_quadlock.ps1 generate-shares --k 4 --n 6 --out shares.json"
            exit 1
        }
        python quadlock_encrypt.py generate-shares --k $k --n $n --out $out
    }

    "encrypt" {
        Check-Python
        if (-not $path -or -not $sharesFile -or -not $algo) {
            Write-Error "⚠️ Utilisation: .\run_quadlock.ps1 encrypt --path .\data --shares-file shares.json --algo aes-gcm"
            exit 1
        }
        python quadlock_encrypt.py encrypt --path $path --shares-file $sharesFile --algo $algo
    }

    "decrypt" {
        Check-Python
        if (-not $path -or -not $sharesFile) {
            Write-Error "⚠️ Utilisation: .\run_quadlock.ps1 decrypt --path .\data --shares-file shares.json"
            exit 1
        }
        python quadlock_encrypt.py decrypt --path $path --shares-file $sharesFile
    }

    default {
        Write-Host "❌ Commande inconnue : $Command"
        Write-Host "👉 Commandes disponibles : setup, generate-shares, encrypt, decrypt"
    }
}
