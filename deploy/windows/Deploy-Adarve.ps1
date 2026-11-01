<#
=============================================================================
 Adarve · despliegue en Windows sin interacción

 Instala o actualiza Adarve a una versión fija desde una carpeta (un recurso
 compartido, el paquete de una aplicación Win32 de Intune o una copia
 local) y programa la ronda diaria. Es lo que ejecutan la GPO, Intune y
 Ansible (docs/17-guia-de-operacion.md), como SYSTEM o administrador:

   powershell.exe -NoProfile -ExecutionPolicy Bypass -File Deploy-Adarve.ps1 -Version v0.5.0

 La carpeta (-Source; por defecto, la del script) lleva el instalador y los
 ficheros de la release, sin cambiar:

   install.ps1                  scripts/install.ps1 del repositorio
   checksums.txt                de la release
   checksums.txt.sig            de la release: sin la firma no se instala
   adarve_windows_amd64.zip
   adarve_windows_arm64.zip     solo si hay equipos ARM

 Se puede ejecutar en cada arranque: si esa versión ya está instalada y
 programada, no cambia nada. install.ps1 comprueba la firma de checksums.txt
 y la suma del .zip antes de instalar.

 Parámetros:
   -Version <vX.Y.Z>   versión que debe quedar instalada (obligatoria)
   -Source <carpeta>   dónde están los ficheros (por defecto, la del script)
   -At <HH:MM>         hora de la ronda diaria (por defecto, 09:00)
   -NoSchedule         no programar la ronda diaria
   -Log <fichero>      registro (por defecto, C:\ProgramData\Adarve-despliegue.log)

 Código de salida: 0 si Adarve queda instalado en esa versión (y la ronda
 programada); 1 si no, con el motivo en el registro.
=============================================================================
#>
param(
    [Parameter(Mandatory = $true)][string]$Version,
    [string]$Source = $PSScriptRoot,
    [string]$At = '09:00',
    [switch]$NoSchedule,
    [string]$Log = (Join-Path $env:ProgramData 'Adarve-despliegue.log')
)

$ErrorActionPreference = 'Stop'

function Write-Log([string]$Message) {
    $line = '{0:yyyy-MM-dd HH:mm:ss}  {1}' -f (Get-Date), $Message
    Write-Host $line
    try { Add-Content -LiteralPath $Log -Value $line -Encoding UTF8 } catch { }
}

# Invoke-Exe ejecuta un programa, deja su salida en el registro y devuelve
# su código de salida. Con 'Stop', Windows PowerShell 5.1 convierte cada
# línea que un programa escribe en stderr en una excepción.
function Invoke-Exe([string]$File, [string[]]$Arguments) {
    $ErrorActionPreference = 'Continue'
    & $File @Arguments 2>&1 | ForEach-Object { Write-Log "    $_" }
    return $LASTEXITCODE
}

# Get-ProgramFiles es la carpeta de programas de 64 bits también desde un
# PowerShell de 32 bits (el agente de Intune instala así las aplicaciones
# Win32), donde $env:ProgramFiles es «Program Files (x86)».
function Get-ProgramFiles {
    if ($env:ProgramW6432) { return $env:ProgramW6432 }
    return $env:ProgramFiles
}

# La misma elección que install.ps1: el .zip debe ser el de este equipo.
function Get-AdarveArch {
    $a = $env:PROCESSOR_ARCHITEW6432
    if (-not $a) { $a = $env:PROCESSOR_ARCHITECTURE }
    switch ($a) {
        'AMD64' { return 'amd64' }
        'ARM64' { return 'arm64' }
        default { throw "Arquitectura no soportada: $a (soportadas: AMD64, ARM64)" }
    }
}

# Get-InstalledVersion devuelve la versión instalada (vX.Y.Z) o $null.
function Get-InstalledVersion([string]$Exe) {
    if (-not (Test-Path -LiteralPath $Exe)) { return $null }
    $ErrorActionPreference = 'Continue'
    $v = & $Exe version --short 2>$null | Select-Object -First 1
    if ($LASTEXITCODE -ne 0 -or -not $v) { return $null }
    return 'v' + ([string]$v).Trim().TrimStart('v')
}

# Test-Scheduled indica si la ronda diaria ya está programada a esa hora.
function Test-Scheduled([string]$Exe, [string]$At) {
    $ErrorActionPreference = 'Continue'
    $out = & $Exe schedule status --no-color 2>&1 | Out-String
    return ($LASTEXITCODE -eq 0 -and $out -match ('a las ' + [regex]::Escape($At) + '\b'))
}

try {
    if ($Version -notmatch '^v?\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$') { throw "Versión no válida: '$Version' (se espera vX.Y.Z)" }
    $Version = 'v' + $Version.TrimStart('v')
    if (-not $NoSchedule -and $At -notmatch '^([01]\d|2[0-3]):[0-5]\d$') { throw "Hora no válida: '$At' (se espera HH:MM)" }
    if ((Test-Path -LiteralPath $Log) -and (Get-Item -LiteralPath $Log).Length -gt 1MB) {
        Move-Item -LiteralPath $Log -Destination "$Log.1" -Force
    }
    Write-Log "Adarve $Version en $env:COMPUTERNAME desde $Source"

    $exe = Join-Path (Get-ProgramFiles) 'Adarve\adarve.exe'
    $current = Get-InstalledVersion $exe
    if ($current -eq $Version) {
        Write-Log "Adarve $Version ya está instalado"
    } else {
        $installer = Join-Path $Source 'install.ps1'
        $zip = Join-Path $Source ('adarve_windows_{0}.zip' -f (Get-AdarveArch))
        foreach ($f in @($installer, $zip, (Join-Path $Source 'checksums.txt'), (Join-Path $Source 'checksums.txt.sig'))) {
            if (-not (Test-Path -LiteralPath $f)) { throw "Falta $f (¿existe y lo pueden leer los equipos?)" }
        }
        if ($current) { Write-Log "Actualizando Adarve $current -> $Version" } else { Write-Log "Instalando Adarve $Version" }
        # En su propio proceso: install.ps1 termina con exit 1 si algo falla.
        $code = Invoke-Exe (Join-Path $PSHOME 'powershell.exe') @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $installer, '-Local', $zip, '-NoScan', '-NoOpen')
        if ($code -ne 0) { throw "install.ps1 terminó con el código $code" }
        $current = Get-InstalledVersion $exe
        if ($current -ne $Version) { throw "Tras instalar, la versión es '$current' y no ${Version}: el .zip de $Source es de otra versión" }
        Write-Log "Adarve $Version instalado en $exe"
    }

    if (-not $NoSchedule) {
        if (Test-Scheduled $exe $At) {
            Write-Log "La ronda diaria ya está programada a las $At"
        } else {
            $code = Invoke-Exe $exe @('schedule', 'enable', '--at', $At, '--no-color')
            if ($code -ne 0) { throw "adarve schedule enable terminó con el código $code" }
            Write-Log "Ronda diaria programada a las $At"
        }
    }
    Write-Log 'Listo'
    exit 0
} catch {
    Write-Log "ERROR: $($_.Exception.Message)"
    exit 1
}
