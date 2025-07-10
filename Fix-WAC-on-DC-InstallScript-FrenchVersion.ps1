# Chemin du log à surveiller
$logPath = "C:\ProgramData\WindowsAdminCenter\Logs\Configuration.log"

# Récupérer la taille initiale du fichier log (en bytes)
$initialLogSize = 0
if (Test-Path $logPath) {
    $initialLogSize = (Get-Item $logPath).Length
} else {
    Write-Host "Le fichier log n'existe pas encore. Il sera créé durant l'exécution." -ForegroundColor Yellow
}

Write-Host "Importation du module..." -ForegroundColor Cyan
Import-Module .\Fix-WAC-on-DC-EditedModule.psm1
Write-Host "Module importé." -ForegroundColor Green
function Show-Separator {
    Write-Host ""
    Write-Host "------------------------------------------" -ForegroundColor DarkGray
    Write-Host ""
}
Show-Separator
Write-Host "Activation du WAC PS Remoting..." -ForegroundColor Cyan
Enable-WACPSRemoting
Write-Host "Activation terminée." -ForegroundColor Green

Show-Separator

Write-Host "Enregistrement du CredSSP local..." -ForegroundColor Cyan
Register-WACLocalCredSSP
Write-Host "CredSSP enregistré." -ForegroundColor Green

Show-Separator

Write-Host "Configuration du Security Descriptor..." -ForegroundColor Cyan
Set-WACServiceSecurityDescriptor
Write-Host "Security Descriptor configuré." -ForegroundColor Green

Show-Separator

Write-Host "Démarrage du service WAC..." -ForegroundColor Cyan
Start-WACService
Write-Host "Service WAC démarré." -ForegroundColor Green

Show-Separator

# Attente courte pour laisser le log s'écrire (ajuster si besoin)
Start-Sleep -Seconds 2
# Récupérer la taille finale du fichier log
if (Test-Path $logPath) {
    $finalLogSize = (Get-Item $logPath).Length

    if ($finalLogSize -gt $initialLogSize) {
        # Lire uniquement les nouvelles lignes ajoutées
        $fs = [System.IO.File]::Open($logPath, 'Open', 'Read', 'ReadWrite')
        $fs.Seek($initialLogSize, [System.IO.SeekOrigin]::Begin) | Out-Null
        $sr = New-Object System.IO.StreamReader($fs)
        $newLogContent = $sr.ReadToEnd()
        $sr.Close()
        $fs.Close()

        Write-Host "Nouvelles entrées dans le log Configuration.log :" -ForegroundColor Magenta
        Write-Host $newLogContent
    } else {
        Write-Host "Aucun nouveau contenu détecté dans le log." -ForegroundColor Yellow
    }
} else {
    Write-Host "Le fichier log est introuvable." -ForegroundColor Red
}
