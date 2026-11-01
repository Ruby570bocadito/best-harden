<#
=============================================================================
 Prueba de punta a punta de deploy/windows/Deploy-Adarve.ps1 y de los
 scripts de Intune (CI, como administrador).

   go run ./scripts/e2e/mkmirror -out $env:RUNNER_TEMP\e2e
   powershell -File scripts\e2e\deploy-windows.ps1 -Dir $env:RUNNER_TEMP\e2e

 Monta, con la release v9.9.8 firmada con la clave de prueba de mkmirror, la
 carpeta que se publicaría en un recurso compartido o en el paquete de
 Intune. Instala Adarve, programa la ronda diaria y aplica (y deshace) la
 ola 1 de harden: solo en una máquina desechable, como un runner del CI.
=============================================================================
#>
param([Parameter(Mandatory)][string]$Dir)
$ErrorActionPreference = 'Stop'
if ($env:CI -ne 'true' -and $env:ADARVE_E2E_OK -ne '1') { throw 'Modifica el sistema: solo en CI (o con ADARVE_E2E_OK=1)' }
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw 'Necesita una consola de administrador' }
[Console]::OutputEncoding = [Text.Encoding]::UTF8

$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$Exe = Join-Path $env:ProgramW6432 'Adarve\adarve.exe'
$Log = Join-Path $env:ProgramData 'Adarve-despliegue.log'
$PS64 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
# El agente de Intune ejecuta las aplicaciones Win32 y las Remediations en
# un PowerShell de 32 bits.
$PS32 = Join-Path $env:SystemRoot 'SysWOW64\WindowsPowerShell\v1.0\powershell.exe'

function Step([string]$m) { Write-Host "`n== $m" -ForegroundColor Cyan }
function Pass([string]$m) { Write-Host "  [OK] $m" -ForegroundColor Green }
function Fail([string]$m) { throw $m }
function Check([bool]$ok, [string]$m) { if ($ok) { Pass $m } else { Fail $m } }
# Run ejecuta un script en su propio proceso de PowerShell y devuelve el
# código de salida y la salida.
function Run([string]$PowerShell, [string]$Script, [string[]]$Arguments) {
    # Con 'Stop', Windows PowerShell 5.1 convierte cada línea de stderr en
    # una excepción.
    $ErrorActionPreference = 'Continue'
    $out = & $PowerShell -NoProfile -ExecutionPolicy Bypass -File $Script @Arguments 2>&1 | ForEach-Object { "$_" } | Out-String
    $code = $LASTEXITCODE
    Write-Host $out
    return @{ Code = $code; Out = $out }
}
function Adarve([string[]]$Arguments) {
    $ErrorActionPreference = 'Continue'
    & $Exe @Arguments 2>&1 | ForEach-Object { "$_" } | Write-Host
    return $LASTEXITCODE
}
function Version { if (Test-Path $Exe) { (& $Exe version --short | Select-Object -First 1).Trim() } else { 'ninguna' } }
function ExpectVersion([string]$v) { $got = Version; Check ($got -eq $v) "versión $v (instalada: $got)" }
function TaskAt {
    $t = Get-ScheduledTask -TaskPath '\Adarve\' -TaskName 'Escaneo diario' -ErrorAction SilentlyContinue
    if ($t) { return ([datetime]$t.Triggers[0].StartBoundary).ToString('HH:mm') }
    return 'sin tarea'
}
# Intune ejecuta el script tal cual: aquí se cambia su línea de ajustes
# ($Version, $MinScore) en una copia.
function IntuneScript([string]$Name, [string]$Pattern, [string]$Replacement) {
    $text = [IO.File]::ReadAllText((Join-Path $Root "deploy\intune\$Name"))
    $new = [regex]::Replace($text, $Pattern, $Replacement)
    if ($new -eq $text) { Fail "no se pudo ajustar $Name" }
    $dst = Join-Path $Dir ('intune-{0}-{1}' -f [guid]::NewGuid().ToString('N').Substring(0, 8), $Name)
    [IO.File]::WriteAllText($dst, $new, (New-Object Text.UTF8Encoding $true))
    return $dst
}
function Score([string]$Out) { return [int]([regex]::Match($Out, 'Adarve (\d+)/100').Groups[1].Value) }

Step 'La carpeta de despliegue (recurso compartido o paquete de Intune)'
$Pkg = Join-Path $Dir 'paquete'
New-Item -ItemType Directory -Force -Path $Pkg | Out-Null
Copy-Item (Join-Path $Dir 'local\*') $Pkg
Copy-Item (Join-Path $Dir 'install.ps1') $Pkg
Copy-Item (Join-Path $Root 'deploy\windows\Deploy-Adarve.ps1') $Pkg
$Deploy = Join-Path $Pkg 'Deploy-Adarve.ps1'
Get-ChildItem $Pkg | ForEach-Object { Write-Host "  $($_.Name)" }

Step '1. Desplegar v9.9.8 desde un PowerShell de 32 bits'
$r = Run $PS32 $Deploy @('-Version', 'v9.9.8', '-At', '06:30')
Check ($r.Code -eq 0) 'el despliegue termina bien'
ExpectVersion '9.9.8'
Check (-not (Test-Path (Join-Path ${env:ProgramFiles(x86)} 'Adarve'))) 'nada en Program Files (x86)'
Check ((TaskAt) -eq '06:30') 'ronda diaria a las 06:30'
Check ((Get-Content -LiteralPath $Log -Raw -Encoding UTF8) -match 'Adarve v9\.9\.8 instalado') 'queda en el registro'

Step '2. Repetirlo no cambia nada (la GPO lo ejecuta en cada arranque)'
$r = Run $PS64 $Deploy @('-Version', 'v9.9.8', '-At', '06:30')
Check ($r.Code -eq 0) 'termina bien'
Check ($r.Out -match 'ya est.{1,2} instalado' -and $r.Out -notmatch 'Instalando|Actualizando') 'no reinstala'
Check ($r.Out -match 'ya est.{1,2} programada a las 06:30') 'no vuelve a programar la ronda'

Step '3. Cambiar la hora de la ronda'
$r = Run $PS64 $Deploy @('-Version', 'v9.9.8', '-At', '07:15')
Check ($r.Code -eq 0 -and (TaskAt) -eq '07:15') 'ronda diaria a las 07:15'

Step '4. Lo que se debe rechazar'
$r = Run $PS64 $Deploy @('-Version', 'v9.9.9')
Check ($r.Code -eq 1 -and $r.Out -match 'es de otra versi') 'un .zip de otra versión que la pedida'
ExpectVersion '9.9.8'
Check ((Run $PS64 $Deploy @('-Version', 'latest')).Code -eq 1) 'sin versión concreta'
Check ((Run $PS64 $Deploy @('-Version', 'v9.9.8', '-At', '25:00')).Code -eq 1) 'hora inválida'
$noSig = Join-Path $Dir 'paquete-sin-firma'
Copy-Item $Pkg $noSig -Recurse
Remove-Item (Join-Path $noSig 'checksums.txt.sig')
$r = Run $PS64 (Join-Path $noSig 'Deploy-Adarve.ps1') @('-Version', 'v9.9.9')
Check ($r.Code -eq 1 -and $r.Out -match 'checksums\.txt\.sig') 'sin la firma no se instala'
ExpectVersion '9.9.8'

Step '5. Intune: regla de detección de la aplicación Win32'
$det = IntuneScript 'Detect-Adarve.ps1' '(?m)^\$Version = ''[^'']*''' '$$Version = ''v9.9.8'''
$r = Run $PS32 $det @()
Check ($r.Code -eq 0 -and $r.Out.Trim() -eq 'Adarve v9.9.8') 'detecta la versión desplegada (32 bits)'
$r = Run $PS64 $det @()
Check ($r.Code -eq 0 -and $r.Out.Trim() -eq 'Adarve v9.9.8') 'detecta la versión desplegada (64 bits)'
$other = IntuneScript 'Detect-Adarve.ps1' '(?m)^\$Version = ''[^'']*''' '$$Version = ''v9.9.9'''
$r = Run $PS32 $other @()
Check ($r.Code -ne 0 -and -not $r.Out.Trim()) 'otra versión: no la da por instalada'

Step '6. Intune: Remediations'
$easy = IntuneScript 'Detect-Postura.ps1' '(?m)^\$MinScore = \d+' '$$MinScore = 1'
$r = Run $PS32 $easy @()
Check ($r.Code -eq 0 -and $r.Out -match 'Adarve \d+/100 \(') 'puntuación del equipo; por encima del umbral, sin problemas'
$strict = IntuneScript 'Detect-Postura.ps1' '(?m)^\$MinScore = \d+' '$$MinScore = 100'
$r = Run $PS32 $strict @()
Check ($r.Code -eq 1 -and $r.Out -match 'umbral 100') 'por debajo del umbral: con problemas'
$before = Score $r.Out
$r = Run $PS32 (Join-Path $Root 'deploy\intune\Remediate-Postura.ps1') @()
Check ($r.Code -eq 0 -and $r.Out -match 'chg-\d{8}-\d{6}') 'aplica la ola 1 y dice cómo deshacerla'
$after = Score (Run $PS32 $strict @()).Out
Check ($after -gt $before) "la puntuación sube ($before -> $after)"
Check ((Adarve @('rollback', '--yes', '--no-color')) -eq 0) 'adarve rollback la deshace'
$restored = Score (Run $PS32 $strict @()).Out
Check ($restored -eq $before) "vuelve a la puntuación de antes ($restored)"

Step '7. Desinstalar'
Check ((Run $PS64 (Join-Path $Pkg 'install.ps1') @('-Uninstall')).Code -eq 0) 'desinstala'
Check ((Run $PS32 $det @()).Code -ne 0) 'la regla de detección ya no la encuentra'

Write-Host "`nDespliegue en Windows: todo correcto" -ForegroundColor Green
# El paso del CI termina con el código del último programa ejecutado, y es
# la regla de detección de arriba, que debía fallar: aquí todo ha ido bien.
exit 0
