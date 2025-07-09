# Primeira compilação
.\build.ps1
$hash1 = (Get-FileHash .\dist\GerenciadorSSH_1.2.11.exe).Hash

# Segunda compilação
.\build.ps1
$hash2 = (Get-FileHash .\dist\GerenciadorSSH_1.2.11.exe).Hash

# Comparação
Write-Host "Hash 1: $hash1"
Write-Host "Hash 2: $hash2"
Write-Host "Iguais? $($hash1 -eq $hash2)"