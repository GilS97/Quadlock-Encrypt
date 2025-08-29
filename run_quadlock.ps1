param (
    [string]$Command,
    [string]$path,
    [string]$sharesFile,
    [string]$algo,
    [int]$k,
    [int]$n,
    [string]$out
)

function Setup {
    Write-Host "Installation des dependances Python..."
    python -m pip install --upgrade pip
    pip install cryptography pycryptodome secretsharing
}

switch ($Command) {
    "setup" {
        Setup
    }
    "generate-shares" {
        if (-not $k -or -not $n -or -not $out) {
            Write-Host "Utilisation: .\run_quadlock.ps1 generate-shares --k [int] --n [int] --out [fichier.json]"
            exit 1
        }
        python quadlock_encrypt.py generate-shares --k $k --n $n --out $out
    }
    "encrypt" {
        if (-not $path -or -not $sharesFile -or -not $algo) {
            Write-Host "Utilisation: .\run_quadlock.ps1 encrypt --path [fichier|repertoire] --shares-file [fichier.json] --algo [aes-gcm|chacha20-poly1305|xchacha20-poly1305|blowfish|rsa-oaep]"
            exit 1
        }
        python quadlock_encrypt.py encrypt --path $path --shares-file $sharesFile --algo $algo
    }
    "decrypt" {
        if (-not $path -or -not $sharesFile) {
            Write-Host "Utilisation: .\run_quadlock.ps1 decrypt --path [fichier|repertoire] --shares-file [fichier.json]"
            exit 1
        }
        python quadlock_encrypt.py decrypt --path $path --shares-file $sharesFile
    }
    default {
        Write-Host "Commande inconnue. Utilisation:"
        Write-Host "  .\run_quadlock.ps1 setup"
        Write-Host "  .\run_quadlock.ps1 generate-shares --k [int] --n [int] --out [fichier.json]"
        Write-Host "  .\run_quadlock.ps1 encrypt --path [fichier|repertoire] --shares-file [fichier.json] --algo [algo]"
        Write-Host "  .\run_quadlock.ps1 decrypt --path [fichier|repertoire] --shares-file [fichier.json]"
    }
}
