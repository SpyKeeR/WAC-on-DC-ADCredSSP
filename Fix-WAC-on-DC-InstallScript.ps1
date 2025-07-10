# Path to the log file to monitor
$logPath = "C:\ProgramData\WindowsAdminCenter\Logs\Configuration.log"

# Get initial log file size (in bytes)
$initialLogSize = 0
if (Test-Path $logPath) {
    $initialLogSize = (Get-Item $logPath).Length
} else {
    Write-Host "Log file doesn't exist yet. It will be created during execution." -ForegroundColor Yellow
}

Write-Host "Importing module..." -ForegroundColor Cyan
Import-Module .\Fix-WAC-on-DC-EditedModule.psm1
Write-Host "Module imported." -ForegroundColor Green
function Show-Separator {
    Write-Host ""
    Write-Host "------------------------------------------" -ForegroundColor DarkGray
    Write-Host ""
}
Show-Separator
Write-Host "Enabling WAC PS Remoting..." -ForegroundColor Cyan
Enable-WACPSRemoting
Write-Host "Remoting enabled." -ForegroundColor Green

Show-Separator

Write-Host "Registering local CredSSP..." -ForegroundColor Cyan
Register-WACLocalCredSSP
Write-Host "CredSSP registered." -ForegroundColor Green

Show-Separator

Write-Host "Setting Security Descriptor..." -ForegroundColor Cyan
Set-WACServiceSecurityDescriptor
Write-Host "Security Descriptor configured." -ForegroundColor Green

Show-Separator

Write-Host "Strating WAC service..." -ForegroundColor Cyan
Start-WACService
Write-Host "WAC service started." -ForegroundColor Green

Show-Separator

# Short wait to let the log file be written (adjust if needed)
Start-Sleep -Seconds 2
# Get final log file size
if (Test-Path $logPath) {
    $finalLogSize = (Get-Item $logPath).Length

    if ($finalLogSize -gt $initialLogSize) {
        # Read only the newly added lines
        $fs = [System.IO.File]::Open($logPath, 'Open', 'Read', 'ReadWrite')
        $fs.Seek($initialLogSize, [System.IO.SeekOrigin]::Begin) | Out-Null
        $sr = New-Object System.IO.StreamReader($fs)
        $newLogContent = $sr.ReadToEnd()
        $sr.Close()
        $fs.Close()

        Write-Host "New entries in Configuration.log:" -ForegroundColor Magenta
        Write-Host $newLogContent
    } else {
        Write-Host "No new content detected in the log." -ForegroundColor Yellow
    }
} else {
    Write-Host "Log file not found." -ForegroundColor Red
}
