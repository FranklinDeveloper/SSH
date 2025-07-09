# Configurações
$origem = "C:\Users\ext.f.tadeu\OneDrive - Profarma\Documentos\GitHub\Cobol\SSH"
$tempDir = "C:\temp_build"
$scriptPrincipal = "Cobol_Python_v1.2.11_Final.py"
$nomeExecutavel = "GerenciadorSSH_1.2.11"
$iconFile = "icon.ico"

# 1. Obter diretório atual do script
$scriptDir = $PSScriptRoot
if (-not $scriptDir) {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
}

# Salvar localização atual
$originalLocation = Get-Location

# 2. Limpar e recriar diretório temporário
if (Test-Path $tempDir) {
    Set-Location -Path $env:TEMP -ErrorAction Stop
    Remove-Item $tempDir -Recurse -Force -ErrorAction Stop
}
New-Item -ItemType Directory -Path $tempDir -Force -ErrorAction Stop

# 3. Copiar arquivos e entrar no diretório temporário
Copy-Item -Path "$origem\*" -Destination $tempDir -Recurse -Force -ErrorAction Stop
Set-Location $tempDir -ErrorAction Stop

# 4. Verificar arquivos essenciais
if (-not (Test-Path $iconFile)) {
    Write-Host "ERRO: Arquivo de ícone não encontrado: $iconFile"
    exit 1
}

if (-not (Test-Path $scriptPrincipal)) {
    Write-Host "ERRO: Script principal não encontrado: $scriptPrincipal"
    exit 1
}

# 5. Compilar com log detalhado
$logFile = "pyinstaller.log"
$iconPath = Resolve-Path $iconFile
Write-Host "Iniciando compilação PyInstaller..."
pyinstaller --noconfirm --onefile --windowed --icon "$iconPath" --name "$nomeExecutavel" "$scriptPrincipal" 2>&1 | Tee-Object -FilePath $logFile

# Verificar status da compilação
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERRO na compilação PyInstaller. Verifique o log: $logFile"
    Write-Host "Últimas 10 linhas do log:"
    Get-Content $logFile | Select-Object -Last 10
    exit 1
}

# 6. Verificar executável
$exePath = "dist\$nomeExecutavel.exe"
if (-not (Test-Path $exePath)) {
    Write-Host "ERRO: Executável não encontrado: $exePath"
    Write-Host "Conteúdo do diretório dist:"
    Get-ChildItem -Path "dist" | Format-Table
    exit 1
}

# 7. Normalização
$exeFullPath = Resolve-Path $exePath
python "$scriptDir\normalize_exe.py" "$exeFullPath"

# 8. Gerar hash
$hash = (Get-FileHash -Path $exeFullPath -Algorithm SHA256).Hash
$hashFile = "$exeFullPath.sha256"
$hash | Out-File -FilePath $hashFile -Encoding utf8
Write-Host "Hash gerado: $hash"
Write-Host "Arquivo SHA256 salvo: $hashFile"

# 9. Copiar resultados de volta
$destinoDist = "$origem\dist"
if (-not (Test-Path $destinoDist)) {
    New-Item -ItemType Directory -Path $destinoDist -Force | Out-Null
}
Copy-Item -Path "dist\*" -Destination $destinoDist -Force

# Voltar ao diretório original
Set-Location $originalLocation

Write-Host "Build concluído com sucesso!"