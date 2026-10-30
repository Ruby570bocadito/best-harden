<#
=============================================================================
 Prueba de punta a punta de install.ps1 y "bastion update" contra un espejo
 local de releases (http://127.0.0.1, el único HTTP que admiten).

   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\test-installer.ps1 -BuildDir build

 BuildDir debe tener bastion-9.0.0.exe y bastion-9.0.1.exe. Necesita
 administrador e instala de verdad en Program Files: se niega a ejecutarse
 si Bastion ya está instalado. Para CI y máquinas desechables.
=============================================================================
#>
param(
    [Parameter(Mandatory)][string]$BuildDir,
    [int]$Port = 8098
)
$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent $PSScriptRoot
$Installer = Join-Path $PSScriptRoot 'install.ps1'
$Url = "http://127.0.0.1:$Port"
$InstallDir = Join-Path $env:ProgramFiles 'Bastion'
$Exe = Join-Path $InstallDir 'bastion.exe'
$DataDir = Join-Path $env:ProgramData 'Bastion'
$Work = Join-Path ([IO.Path]::GetTempPath()) ('bastion-test-' + [Guid]::NewGuid().ToString('N'))

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw 'Necesita administrador (sin él, install.ps1 abre una ventana de UAC).' }
foreach ($d in $InstallDir, $DataDir) {
    if (Test-Path $d) { throw "Ya existe ${d}: esta prueba lo borraría (usa una máquina desechable)." }
}
$arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'amd64' }
$asset = "bastion_windows_$arch.zip"

function Pass([string]$m) { Write-Host "  [OK] $m" -ForegroundColor Green }
function Fail([string]$m) { throw "FALLO: $m" }

# Ejecuta install.ps1 en Windows PowerShell 5.1 (el que trae Windows) y
# devuelve su salida; $LASTEXITCODE queda con su código.
function Invoke-Installer {
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $out = & $ps -NoProfile -ExecutionPolicy Bypass -File $Installer -NoScan @args 2>&1 | Out-String
    Write-Host $out
    return $out
}
function Get-InstalledVersion { (& $Exe version --short | Select-Object -First 1).Trim() }

$server = $null
try {
    # 1. Espejo con la misma estructura que GitHub Releases
    $mirror = Join-Path $Work 'mirror'
    foreach ($v in '9.0.0', '9.0.1') {
        $d = Join-Path $mirror "download\v$v"
        $pkg = Join-Path $Work "pkg-$v"
        New-Item -ItemType Directory -Force -Path $d, $pkg | Out-Null
        Copy-Item (Join-Path $BuildDir "bastion-$v.exe") (Join-Path $pkg 'bastion.exe')
        Compress-Archive -Path (Join-Path $pkg 'bastion.exe') -DestinationPath (Join-Path $d $asset)
        $hash = (Get-FileHash -Algorithm SHA256 (Join-Path $d $asset)).Hash.ToLower()
        Set-Content -Path (Join-Path $d 'checksums.txt') -Value "$hash  $asset" -Encoding ascii
    }
    New-Item -ItemType Directory -Force -Path (Join-Path $mirror 'latest\download') | Out-Null
    Set-Content -Path (Join-Path $mirror 'latest\download\version.txt') -Value 'v9.0.1' -Encoding ascii
    $python = (Get-Command python -ErrorAction Stop).Source
    $server = Start-Process -FilePath $python -ArgumentList @('-m', 'http.server', $Port, '--bind', '127.0.0.1', '--directory', $mirror) -PassThru -WindowStyle Hidden
    $deadline = (Get-Date).AddSeconds(20)
    while ($true) {
        try { Invoke-RestMethod "$Url/latest/download/version.txt" | Out-Null; break } catch {
            if ((Get-Date) -gt $deadline) { throw 'el espejo local no arrancó' }
            Start-Sleep -Milliseconds 300
        }
    }

    # 2. Casos
    Write-Host '== Instalar una versión concreta'
    Invoke-Installer -ReleasesUrl $Url -Version 9.0.0 | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "install.ps1 terminó con $LASTEXITCODE" }
    if ((Get-InstalledVersion) -ne '9.0.0') { Fail "se esperaba 9.0.0, hay $(Get-InstalledVersion)" }
    if (-not (Test-Path $DataDir)) { Fail 'init no preparó ProgramData\Bastion' }
    if (([Environment]::GetEnvironmentVariable('Path', 'Machine') -split ';') -notcontains $InstallDir) { Fail 'no se añadió al PATH del sistema' }
    Pass 'v9.0.0 instalada, preparada y en el PATH'

    Write-Host '== Actualizar a la última con el instalador'
    Invoke-Installer -ReleasesUrl $Url | Out-Null
    if ((Get-InstalledVersion) -ne '9.0.1') { Fail "se esperaba 9.0.1, hay $(Get-InstalledVersion)" }
    Pass 'actualizada a v9.0.1'

    Write-Host '== Sin cambios si ya está en la última'
    $out = Invoke-Installer -ReleasesUrl $Url
    # Sin acentos: powershell.exe 5.1 lee install.ps1 (UTF-8 sin BOM) como ANSI.
    if ($out -notmatch 'instalado y actualizado') { Fail 'debería decir que ya está actualizado' }
    Pass 'no reinstala sin -Force'

    Write-Host '== bastion update desde v9.0.0 (con el ejecutable en uso)'
    Invoke-Installer -ReleasesUrl $Url -Version 9.0.0 | Out-Null
    & $Exe update --releases-url $Url --no-color
    if ($LASTEXITCODE -ne 0) { Fail "bastion update terminó con $LASTEXITCODE" }
    if ((Get-InstalledVersion) -ne '9.0.1') { Fail "update no actualizó: $(Get-InstalledVersion)" }
    Pass 'bastion update instaló v9.0.1'

    Write-Host '== Una descarga manipulada no se instala'
    Invoke-Installer -ReleasesUrl $Url -Version 9.0.0 | Out-Null
    $zip = Join-Path $mirror "download\v9.0.1\$asset"
    Copy-Item $zip "$Work\orig.zip"
    Add-Content -Path $zip -Value 'x' -Encoding ascii
    Invoke-Installer -ReleasesUrl $Url | Out-Null
    if ($LASTEXITCODE -eq 0) { Fail 'install.ps1 aceptó un archivo con otra suma' }
    if ((Get-InstalledVersion) -ne '9.0.0') { Fail 'el binario cambió pese al error' }
    & $Exe update --releases-url $Url --no-color
    if ($LASTEXITCODE -eq 0) { Fail 'bastion update aceptó un archivo con otra suma' }
    if ((Get-InstalledVersion) -ne '9.0.0') { Fail 'update cambió el binario pese al error' }
    Copy-Item "$Work\orig.zip" $zip -Force
    Pass 'install.ps1 y update rechazan la suma que no coincide'

    Write-Host '== HTTP fuera del propio equipo se rechaza'
    Invoke-Installer -ReleasesUrl 'http://example.com/releases' | Out-Null
    if ($LASTEXITCODE -eq 0) { Fail 'aceptó http:// remoto' }
    Pass 'solo https:// (o loopback)'

    Write-Host '== Instalación sin conexión (-Local), también con ruta relativa'
    Push-Location (Join-Path $mirror 'download\v9.0.1')
    try { Invoke-Installer -Local ".\$asset" | Out-Null } finally { Pop-Location }
    if ((Get-InstalledVersion) -ne '9.0.1') { Fail '-Local no instaló 9.0.1' }
    Copy-Item (Join-Path $mirror "download\v9.0.0\$asset") (Join-Path $Work $asset)
    Invoke-Installer -Local (Join-Path $Work $asset) | Out-Null
    if ($LASTEXITCODE -eq 0) { Fail '-Local sin checksums.txt debe fallar' }
    Invoke-Installer -Local (Join-Path $Work $asset) -Insecure | Out-Null
    if ((Get-InstalledVersion) -ne '9.0.0') { Fail '-Local -Insecure no instaló' }
    Pass '-Local exige checksums.txt salvo con -Insecure'

    Write-Host '== Desinstalar'
    Invoke-Installer -Uninstall | Out-Null
    if (Test-Path $Exe) { Fail 'el binario sigue ahí' }
    if (-not (Test-Path $DataDir)) { Fail 'sin -Purge se conserva la configuración' }
    if (([Environment]::GetEnvironmentVariable('Path', 'Machine') -split ';') -contains $InstallDir) { Fail 'sigue en el PATH del sistema' }
    Invoke-Installer -Uninstall -Purge | Out-Null
    if (Test-Path $DataDir) { Fail '-Purge no borró los datos' }
    Pass 'desinstalado (y purgado)'

    Write-Host ''
    Write-Host 'Instalador y actualización: todo correcto' -ForegroundColor Green
} finally {
    if ($server) { Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue }
    Remove-Item -Recurse -Force $InstallDir, $DataDir, $Work -ErrorAction SilentlyContinue
    $path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $new = ($path -split ';' | Where-Object { $_ -and $_ -ne $InstallDir }) -join ';'
    if ($new -ne $path) { [Environment]::SetEnvironmentVariable('Path', $new, 'Machine') }
}
