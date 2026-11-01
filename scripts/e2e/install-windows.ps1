<#
=============================================================================
 Prueba de punta a punta de install.ps1 y "adarve update" (CI, como administrador).

   go run ./scripts/e2e/mkmirror -out $env:RUNNER_TEMP\e2e
   powershell -File scripts\e2e\install-windows.ps1 -Dir $env:RUNNER_TEMP\e2e

 Usa el espejo firmado con la clave de prueba que deja mkmirror. Modifica el
 sistema (instala Adarve, crea y borra una instalación falsa de Bastion,
 tareas programadas y el PATH): solo en una máquina desechable, como un
 runner del CI.
=============================================================================
#>
param([Parameter(Mandatory)][string]$Dir)
$ErrorActionPreference = 'Stop'
if ($env:CI -ne 'true' -and $env:ADARVE_E2E_OK -ne '1') { throw 'Modifica el sistema: solo en CI (o con ADARVE_E2E_OK=1)' }
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw 'Necesita una consola de administrador' }
[Console]::OutputEncoding = [Text.Encoding]::UTF8

$Port = 8765
$Url = "http://127.0.0.1:$Port"
$Exe = Join-Path $env:ProgramFiles 'Adarve\adarve.exe'
$Data = Join-Path $env:ProgramData 'Adarve'
$OldDir = Join-Path $env:ProgramFiles 'Bastion'
$OldData = Join-Path $env:ProgramData 'Bastion'

function Step([string]$m) { Write-Host "`n== $m" -ForegroundColor Cyan }
function Pass([string]$m) { Write-Host "  [OK] $m" -ForegroundColor Green }
function Fail([string]$m) { throw $m }
function Check([bool]$ok, [string]$m) { if ($ok) { Pass $m } else { Fail $m } }
# El instalador en su propio proceso, como lo lanzaría un usuario: devuelve
# el código de salida y la salida.
function Install([string[]]$Arguments) {
    # Con 'Stop', Windows PowerShell 5.1 convierte cada línea que el
    # instalador escribe en stderr (un aviso) en una excepción.
    $ErrorActionPreference = 'Continue'
    $out = & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Dir 'install.ps1') -ReleasesUrl $Url -NoScan -NoOpen @Arguments 2>&1 |
        ForEach-Object { "$_" } | Out-String
    $code = $LASTEXITCODE
    Write-Host $out
    return @{ Code = $code; Out = $out }
}
# adarve con sus argumentos; devuelve el código de salida (los errores van a
# stderr: mismo motivo que en Install).
function Adarve([string[]]$Arguments) {
    $ErrorActionPreference = 'Continue'
    & $Exe @Arguments 2>&1 | ForEach-Object { "$_" } | Write-Host
    return $LASTEXITCODE
}
function Version { if (Test-Path $Exe) { (& $Exe version --short | Select-Object -First 1).Trim() } else { 'ninguna' } }
function ExpectVersion([string]$v) { $got = Version; Check ($got -eq $v) "versión $v (instalada: $got)" }
function Task([string]$path) { Get-ScheduledTask -TaskPath $path -TaskName 'Escaneo diario' -ErrorAction SilentlyContinue }

$server = Start-Process -FilePath python -ArgumentList @('-m', 'http.server', $Port, '--bind', '127.0.0.1', '--directory', (Join-Path $Dir 'mirror')) -PassThru -WindowStyle Hidden
try {
    foreach ($i in 1..50) {
        try { Invoke-WebRequest -UseBasicParsing "$Url/latest/download/version.txt" | Out-Null; break } catch { Start-Sleep -Milliseconds 100 }
    }

    Step 'Una instalación antigua de Bastion'
    New-Item -ItemType Directory -Force -Path $OldDir, (Join-Path $OldData 'reports') | Out-Null
    Copy-Item (Join-Path $env:SystemRoot 'System32\where.exe') (Join-Path $OldDir 'bastion.exe')
    '{"schema":"bastion.report/v1"}' | Set-Content -Encoding utf8 (Join-Path $OldData 'reports\antiguo.json')
    'profile: auto' | Set-Content -Encoding utf8 (Join-Path $OldData 'config.yaml')
    # Como la dejaba Bastion: solo Administradores y SYSTEM (sin herencia).
    & icacls.exe $OldData /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' /T /Q | Out-Null
    $path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    [Environment]::SetEnvironmentVariable('Path', "$path;$OldDir", 'Machine')
    $action = New-ScheduledTaskAction -Execute (Join-Path $OldDir 'bastion.exe') -Argument 'schedule run'
    $trigger = New-ScheduledTaskTrigger -Daily -At '07:45'
    Register-ScheduledTask -TaskPath '\Bastion\' -TaskName 'Escaneo diario' -Action $action -Trigger $trigger -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
    Pass 'Bastion con datos, configuración, PATH y ronda diaria a las 07:45'

    Step '1. Instalar v9.9.8 y migrar desde Bastion'
    $r = Install @('-Version', 'v9.9.8')
    Check ($r.Code -eq 0) 'el instalador termina bien'
    ExpectVersion '9.9.8'
    Check (Test-Path (Join-Path $Data 'reports\antiguo.json')) 'informes trasladados a ProgramData\Adarve'
    Check (Test-Path (Join-Path $Data 'config.yaml')) 'configuración trasladada'
    Check (-not (Test-Path $OldData)) 'ProgramData\Bastion retirado'
    Check (-not (Test-Path $OldDir)) 'Program Files\Bastion retirado'
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine') -split ';'
    Check ($machinePath -notcontains $OldDir) 'Bastion fuera del PATH'
    Check ($machinePath -contains (Split-Path $Exe)) 'Adarve en el PATH'
    Check ($null -eq (Task '\Bastion\')) 'tarea de Bastion retirada'
    $t = Task '\Adarve\'
    Check ($null -ne $t) 'tarea de Adarve creada'
    Check (([datetime]$t.Triggers[0].StartBoundary).ToString('HH:mm') -eq '07:45') 'ronda diaria de Adarve a las 07:45'

    Step '2. Volver a ejecutar el instalador (ya está al día con esa versión)'
    $r = Install @('-Version', 'v9.9.8')
    # install.ps1 no lleva BOM: ejecutado como fichero, Windows PowerShell 5.1
    # lo lee como ANSI y la «á» sale como dos caracteres.
    Check ($r.Code -eq 0 -and $r.Out -match 'ya est.{1,2} instalado') 'no reinstala'

    Step '3. adarve update a la última versión firmada'
    Check ((Adarve @('update', '--releases-url', $Url, '--no-color')) -eq 0) 'update termina bien'
    ExpectVersion '9.9.9'

    Step '4. Releases que se deben rechazar'
    Check ((Install @('-Version', 'v9.9.7', '-Force')).Code -ne 0) 'rechaza checksums.txt manipulado'
    Check ((Install @('-Version', 'v9.9.7', '-Force', '-Insecure')).Code -ne 0) '-Insecure no acepta una firma inválida'
    Check ((Install @('-Version', 'v9.9.6', '-Force')).Code -ne 0) 'rechaza una release sin firma'
    Check ((Adarve @('update', '--releases-url', $Url, '--version', 'v9.9.7', '--force', '--no-color')) -ne 0) 'update rechaza una firma inválida'
    Check ((Adarve @('update', '--releases-url', $Url, '--version', 'v9.9.6', '--force', '--no-color')) -ne 0) 'update rechaza una release sin firma'
    ExpectVersion '9.9.9'

    Step '5. Release sin firma con -Insecure (versiones anteriores a la firma)'
    Check ((Install @('-Version', 'v9.9.6', '-Force', '-Insecure')).Code -eq 0) 'instala con -Insecure'
    ExpectVersion '9.9.6'

    Step '6. Instalación sin conexión (-Local)'
    $zip = (Get-ChildItem (Join-Path $Dir 'local') -Filter 'adarve_windows_*.zip' | Select-Object -First 1).FullName
    Check ((Install @('-Local', $zip, '-Force')).Code -eq 0) 'instala desde el .zip local'
    ExpectVersion '9.9.8'
    $sig = Join-Path $Dir 'local\checksums.txt.sig'
    Move-Item $sig "$sig.bak"
    Check ((Install @('-Local', $zip, '-Force')).Code -ne 0) '-Local sin checksums.txt.sig rechazado'
    Move-Item "$sig.bak" $sig

    Step '7. Desinstalar'
    Check ((Install @('-Uninstall')).Code -eq 0) 'desinstala'
    Check (-not (Test-Path $Exe)) 'adarve.exe eliminado'
    Check ($null -eq (Task '\Adarve\')) 'ronda diaria retirada'
    Check (Test-Path $Data) 'datos conservados sin -Purge'
    Check ((Install @('-Uninstall', '-Purge')).Code -eq 0) 'desinstala con -Purge'
    Check (-not (Test-Path $Data)) '-Purge borra los datos'

    Write-Host "`nInstalador de Windows: todo correcto" -ForegroundColor Green
} finally {
    Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
}
