<#
=============================================================================
 Adarve · instalador para Windows 10/11 y Windows Server 2016-2025

 Instala o actualiza Adarve, lo prepara y lanza un primer escaneo.
 Abre PowerShell como administrador y pega:

   irm https://raw.githubusercontent.com/Ruby570bocadito/adarve/main/scripts/install.ps1 | iex

 Con opciones:

   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/Ruby570bocadito/adarve/main/scripts/install.ps1))) -NoScan
   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/Ruby570bocadito/adarve/main/scripts/install.ps1))) -Uninstall

 Parámetros:
   -Version <tag>       versión concreta (por defecto: la última)
   -NoScan              no lanzar el primer escaneo
   -NoOpen              no abrir el informe HTML al terminar
   -Force               reinstalar aunque ya esté en la última versión
   -Local <archivo>     instalar desde un .zip local (sin conexión; necesita
                        checksums.txt en la misma carpeta)
   -Insecure            instalar aunque la release no esté firmada (las
                        anteriores a la v0.5) o, con -Local, aunque no haya
                        checksums.txt; una firma inválida se rechaza siempre
   -Repo <owner/nombre> repositorio de GitHub
   -ReleasesUrl <url>   espejo interno de releases (https://…)
   -Uninstall [-Purge]  desinstalar (con -Purge borra también config e informes)

 Variables equivalentes: ADARVE_VERSION, ADARVE_NO_SCAN=1, ADARVE_REPO,
 ADARVE_RELEASES_URL.

 Seguridad: antes de instalar se comprueba la firma de checksums.txt
 (checksums.txt.sig, con la clave pública de Test-Signature) y la suma SHA-256
 del .zip descargado.
=============================================================================
#>
param(
    [string]$Version = $(if ($env:ADARVE_VERSION) { $env:ADARVE_VERSION } else { 'latest' }),
    [string]$Repo = $(if ($env:ADARVE_REPO) { $env:ADARVE_REPO } else { 'Ruby570bocadito/adarve' }),
    [string]$ReleasesUrl = $env:ADARVE_RELEASES_URL,
    [string]$Local,
    [switch]$NoScan,
    [switch]$NoOpen,
    [switch]$Force,
    [switch]$Uninstall,
    [switch]$Purge,
    [switch]$Insecure
)

function Install-Adarve {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'   # Invoke-WebRequest es mucho más rápido sin barra

    # Windows PowerShell 5.1 no activa TLS 1.2 por defecto en sistemas antiguos.
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    } catch { }

    $ScriptUrl  = "https://raw.githubusercontent.com/$Repo/main/scripts/install.ps1"
    if ($Repo -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') { throw "Repositorio no válido: $Repo (formato owner/nombre)" }
    if (-not $ReleasesUrl) { $ReleasesUrl = "https://github.com/$Repo/releases" }
    $ReleasesUrl = $ReleasesUrl.TrimEnd('/')
    # Las sumas viajan por el mismo canal que el binario: sin TLS no
    # protegerían de nada. HTTP solo hacia el propio equipo (pruebas).
    if ($ReleasesUrl -notmatch '^https://' -and $ReleasesUrl -notmatch '^http://(127\.0\.0\.1|localhost)(:\d+)?(/|$)') {
        throw "La dirección de releases debe usar https:// ($ReleasesUrl)"
    }
    if ($Version -ne 'latest') { $Version = ConvertTo-AdarveTag $Version }
    # El proceso elevado arranca en otra carpeta: una ruta relativa dejaría
    # de apuntar al archivo.
    if ($Local) { $Local = (Resolve-Path -LiteralPath $Local -ErrorAction Stop).Path }
    $InstallDir = Join-Path $env:ProgramFiles 'Adarve'
    $Exe        = Join-Path $InstallDir 'adarve.exe'
    $DataDir    = Join-Path $env:ProgramData 'Adarve'

    Write-Banner

    # --- Elevación ------------------------------------------------------------
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Step 'Se necesitan permisos de administrador: se abrirá una ventana elevada (UAC)'
        # Cada valor va entre comillas simples con las suyas duplicadas, y la
        # orden completa viaja codificada (-EncodedCommand): una ruta o un
        # valor con comillas o espacios no puede romperla ni inyectar código.
        $flags = @()
        if ($Version -ne 'latest') { $flags += '-Version ' + (ConvertTo-PSLiteral $Version) }
        if ($Local)       { $flags += '-Local ' + (ConvertTo-PSLiteral $Local) }
        if ($ReleasesUrl -ne "https://github.com/$Repo/releases") { $flags += '-ReleasesUrl ' + (ConvertTo-PSLiteral $ReleasesUrl) }
        if ($NoScan)      { $flags += '-NoScan' }
        if ($NoOpen)      { $flags += '-NoOpen' }
        if ($Force)       { $flags += '-Force' }
        if ($Uninstall)   { $flags += '-Uninstall' }
        if ($Purge)       { $flags += '-Purge' }
        if ($Insecure)    { $flags += '-Insecure' }
        $flags += '-Repo ' + (ConvertTo-PSLiteral $Repo)
        if ($PSCommandPath) {
            $cmd = '& ' + (ConvertTo-PSLiteral $PSCommandPath) + ' ' + ($flags -join ' ')
        } else {
            $cmd = '& ([scriptblock]::Create((Invoke-RestMethod ' + (ConvertTo-PSLiteral $ScriptUrl) + '))) ' + ($flags -join ' ')
        }
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
        Start-Process -FilePath (Get-PowerShellExe) -Verb RunAs -ArgumentList @('-NoProfile', '-NoExit', '-EncodedCommand', $encoded)
        return
    }

    if ($Uninstall) { Uninstall-Adarve -InstallDir $InstallDir -DataDir $DataDir; return }

    $arch = Get-AdarveArch
    $asset = "adarve_windows_$arch.zip"
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("adarve-" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp | Out-Null

    # adarve.exe escribe UTF-8; sin esto PowerShell lee su salida con la
    # página de códigos OEM y los acentos salen corruptos.
    $prevEncoding = [Console]::OutputEncoding
    try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { }

    try {
        # --- 1. Versión objetivo y versión instalada ------------------------
        $current = $null
        if (Test-Path $Exe) { $current = (& $Exe version --short 2>$null | Select-Object -First 1) }

        $zip = Join-Path $tmp $asset
        $doInstall = $true
        if ($Local) {
            Write-Step "Instalación sin conexión desde $Local"
            if (-not (Test-Path $Local)) { throw "No existe $Local" }
            Copy-Item -LiteralPath $Local $zip
            $sums = Join-Path (Split-Path -Parent $Local) 'checksums.txt'
            if (Test-Path -LiteralPath $sums) {
                $sig = $null
                if (Test-Path -LiteralPath "$sums.sig") { $sig = [IO.File]::ReadAllBytes("$sums.sig") }
                Test-Signature -Sums ([IO.File]::ReadAllBytes($sums)) -Sig $sig
                Test-Checksum -File $zip -Asset $asset -Sums (Get-Content -LiteralPath $sums -Raw)
            }
            elseif ($Insecure) { Write-Warn 'No hay checksums.txt junto al archivo: se instala SIN verificar la integridad (-Insecure)' }
            else { throw 'No hay checksums.txt junto al archivo: descárgalo de la misma release para verificarlo (o usa -Insecure bajo tu responsabilidad)' }
        } else {
            if ($Version -eq 'latest') {
                Write-Step "Buscando la última versión en $ReleasesUrl"
                $Version = ([string](Invoke-RestMethod -UseBasicParsing "$ReleasesUrl/latest/download/version.txt")).Trim()
                if (-not $Version) { throw 'version.txt vacío' }
                $Version = ConvertTo-AdarveTag $Version
            }
            if ($current -and ($current.TrimStart('v') -eq $Version.TrimStart('v')) -and -not $Force) {
                Write-Ok "Adarve $Version ya está instalado y actualizado"
                $doInstall = $false
            } else {
                if ($current) { Write-Step "Actualizando Adarve $current -> $Version ($arch)" }
                else { Write-Step "Instalando Adarve $Version ($arch)" }
                $base = "$ReleasesUrl/download/$Version"
                # Los bytes exactos: la firma es de ese fichero, no de su texto.
                $sumsFile = Join-Path $tmp 'checksums.txt'
                Invoke-WebRequest -UseBasicParsing -Uri "$base/checksums.txt" -OutFile $sumsFile
                $sig = $null
                try {
                    Invoke-WebRequest -UseBasicParsing -Uri "$base/checksums.txt.sig" -OutFile "$sumsFile.sig"
                    $sig = [IO.File]::ReadAllBytes("$sumsFile.sig")
                } catch { }
                Test-Signature -Sums ([IO.File]::ReadAllBytes($sumsFile)) -Sig $sig
                $sums = [IO.File]::ReadAllText($sumsFile)
                Invoke-WebRequest -UseBasicParsing -Uri "$base/$asset" -OutFile $zip
                Test-Checksum -File $zip -Asset $asset -Sums $sums
            }
        }

        if ($doInstall) {
            $extract = Join-Path $tmp 'x'
            Expand-Archive -Path $zip -DestinationPath $extract -Force
            $new = Get-ChildItem -Path $extract -Recurse -Filter 'adarve.exe' | Select-Object -First 1
            if (-not $new) { throw 'El archivo no contiene adarve.exe' }
            New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
            # Un ejecutable en uso no se puede sobrescribir pero sí renombrar.
            # Si la copia falla, se recupera el anterior: nunca queda la
            # instalación sin adarve.exe.
            $hadOld = Test-Path -LiteralPath $Exe
            if ($hadOld) {
                Remove-Item -LiteralPath "$Exe.old" -Force -ErrorAction SilentlyContinue
                Move-Item -LiteralPath $Exe "$Exe.old" -Force
            }
            try {
                Copy-Item -LiteralPath $new.FullName $Exe -Force
            } catch {
                if ($hadOld) {
                    Remove-Item -LiteralPath $Exe -Force -ErrorAction SilentlyContinue
                    Move-Item -LiteralPath "$Exe.old" $Exe -Force
                }
                throw "No se pudo copiar adarve.exe en $InstallDir (se mantiene la versión anterior): $($_.Exception.Message)"
            }
            Unblock-File $Exe -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath "$Exe.old" -Force -ErrorAction SilentlyContinue
            Write-Ok "Instalado en $Exe ($(& $Exe version --short))"
            Add-ToMachinePath $InstallDir
        }

        # --- 2. Preparación -------------------------------------------------
        Write-Step 'Preparando Adarve'
        & $Exe init --no-color | ForEach-Object { "  $_" }
        if ($LASTEXITCODE -ne 0) { throw 'adarve init falló' }
        Remove-Bastion -Exe $Exe

        # --- 3. Primer escaneo (solo lectura) ---------------------------------
        if (-not $NoScan) {
            Write-Step 'Primer escaneo (solo lectura: no se modifica nada)'
            $scanArgs = @('scan', '--save')
            if (-not $NoOpen -and [Environment]::UserInteractive) { $scanArgs += '--open' }
            & $Exe @scanArgs
        }

        Write-Summary
    } finally {
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
        try { [Console]::OutputEncoding = $prevEncoding } catch { }
    }
}

function ConvertTo-PSLiteral([string]$s) {
    # Cadena literal de PowerShell: entre comillas simples, sin expansión.
    return "'" + ($s -replace "'", "''") + "'"
}

function ConvertTo-AdarveTag([string]$v) {
    # vX.Y.Z[-pre] (acepta 0.2.0); nada más, porque va en las URLs.
    $t = 'v' + $v.Trim().TrimStart('v')
    if ($t -notmatch '^v\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$') { throw "Versión no válida: $v (ejemplo: v0.3.2)" }
    return $t
}

function Get-PowerShellExe {
    $p = (Get-Process -Id $PID).Path
    if ($p) { return $p }
    return (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe')
}

function Get-AdarveArch {
    $a = $env:PROCESSOR_ARCHITEW6432
    if (-not $a) { $a = $env:PROCESSOR_ARCHITECTURE }
    switch ($a) {
        'AMD64' { return 'amd64' }
        'ARM64' { return 'arm64' }
        default { throw "Arquitectura no soportada: $a (soportadas: AMD64, ARM64)" }
    }
}

# Test-Signature comprueba la firma de checksums.txt (ECDSA P-256 sobre
# SHA-256, en DER) con la clave pública de las releases: la misma que
# internal/selfupdate/release-signing.pub (un test lo comprueba), aquí como
# las coordenadas X e Y del punto en base64. Necesita .NET Framework 4.7 o
# posterior (Windows 10 1709 en adelante lo trae).
function Test-Signature([byte[]]$Sums, [byte[]]$Sig) {
    if (-not $Sig) {
        if (-not $Insecure) { throw 'La release no está firmada (falta checksums.txt.sig). Para instalar igualmente una versión sin firma, usa -Insecure' }
        Write-Warn 'Release sin firma: solo se verifica la suma SHA-256 (-Insecure)'
        return
    }
    $q = New-Object System.Security.Cryptography.ECPoint
    $q.X = [Convert]::FromBase64String('NavP7OxSrWmDs7jZimtPx56gl24SmPwVLAnoo+XKfzk=')
    $q.Y = [Convert]::FromBase64String('ZfXMaVkOPyrDTzcOoKK5Cs+Vh6UASl/6nOAObVnnS0w=')
    $p = New-Object System.Security.Cryptography.ECParameters
    $p.Curve = [System.Security.Cryptography.ECCurve+NamedCurves]::nistP256
    $p.Q = $q
    $ec = [System.Security.Cryptography.ECDsa]::Create($p)
    try {
        $ok = $ec.VerifyData($Sums, (ConvertFrom-DerSignature $Sig), [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    } catch { $ok = $false } finally { $ec.Dispose() }
    if (-not $ok) { throw 'La firma de checksums.txt no es válida: la release no la publicó Adarve o se ha manipulado. Instalación abortada.' }
    Write-Ok 'Firma de la release verificada'
}

# ConvertFrom-DerSignature pasa una firma ECDSA de DER (lo que escribe
# openssl) a r||s de 32 bytes cada uno (lo que espera .NET).
function ConvertFrom-DerSignature([byte[]]$Der) {
    if ($Der.Length -lt 8 -or $Der[0] -ne 0x30) { throw 'Firma con formato no válido' }
    $i = 2
    if ($Der[1] -band 0x80) { $i += $Der[1] -band 0x7f }
    $out = New-Object byte[] 64
    foreach ($half in 0, 1) {
        if ($i + 2 -gt $Der.Length -or $Der[$i] -ne 0x02) { throw 'Firma con formato no válido' }
        $len = [int]$Der[$i + 1]
        if ($len -lt 1 -or $i + 2 + $len -gt $Der.Length) { throw 'Firma con formato no válido' }
        $skip = [Math]::Max(0, $len - 32)
        for ($k = 0; $k -lt $skip; $k++) { if ($Der[$i + 2 + $k] -ne 0) { throw 'Firma con formato no válido' } }
        $n = $len - $skip
        [Array]::Copy($Der, $i + 2 + $skip, $out, $half * 32 + (32 - $n), $n)
        $i += 2 + $len
    }
    return ,$out
}

function Test-Checksum([string]$File, [string]$Asset, [string]$Sums) {
    $want = $null
    foreach ($line in ($Sums -split "`r?`n")) {
        $parts = $line.Trim() -split '\s+'
        if ($parts.Count -eq 2 -and $parts[1].TrimStart('*') -eq $Asset) { $want = $parts[0].ToLower() }
    }
    if (-not $want) { throw "checksums.txt no contiene $Asset" }
    $got = (Get-FileHash -Algorithm SHA256 -Path $File).Hash.ToLower()
    if ($got -ne $want) { throw "La suma SHA-256 no coincide (esperada $want, obtenida $got). Instalación abortada." }
    Write-Ok 'Suma SHA-256 verificada'
}

function Add-ToMachinePath([string]$Dir) {
    $path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $parts = $path -split ';' | Where-Object { $_ }
    if ($parts -notcontains $Dir) {
        [Environment]::SetEnvironmentVariable('Path', (($parts + $Dir) -join ';'), 'Machine')
        Write-Ok "$Dir añadido al PATH del sistema"
    }
    if (($env:Path -split ';') -notcontains $Dir) { $env:Path = "$env:Path;$Dir" }
}

# Adarve se llamaba antes Bastion: retira el ejecutable antiguo y pasa el
# análisis programado al nombre nuevo, a la misma hora. Las carpetas de
# datos las traslada "adarve init".
function Remove-Bastion([string]$Exe) {
    $old = Get-ScheduledTask -TaskPath '\Bastion\' -TaskName 'Escaneo diario' -ErrorAction SilentlyContinue
    if ($old) {
        $at = '09:00'
        if ($old.Triggers.Count -gt 0 -and $old.Triggers[0].StartBoundary) { $at = ([datetime]$old.Triggers[0].StartBoundary).ToString('HH:mm') }
        # "schedule enable" retira también la tarea de Bastion.
        & $Exe schedule enable --at $at | Out-Null
        if ($LASTEXITCODE -eq 0) { Write-Ok "Análisis diario de Bastion pasado a Adarve ($at)" }
        else { Write-Warn "No se pudo pasar el análisis diario de Bastion: ejecuta 'adarve schedule enable --at $at'" }
        # Aunque no se haya podido programar Adarve, la tarea de Bastion se
        # retira: ejecutaría un bastion.exe que se borra justo debajo.
        Get-ScheduledTask -TaskPath '\Bastion\' -TaskName 'Escaneo diario' -ErrorAction SilentlyContinue |
            Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
    }
    Remove-Item 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\Bastion' -Recurse -ErrorAction SilentlyContinue
    $oldDir = Join-Path $env:ProgramFiles 'Bastion'
    if (Test-Path -LiteralPath (Join-Path $oldDir 'bastion.exe')) {
        Remove-Item -Recurse -Force -LiteralPath $oldDir -ErrorAction SilentlyContinue
        if (-not (Test-Path -LiteralPath $oldDir)) { Write-Ok "Retirado $oldDir (Bastion es ahora Adarve)" }
        else { Write-Warn "No se pudo borrar $oldDir (¿bastion.exe en uso?): bórralo a mano" }
    }
    $path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $new = ($path -split ';' | Where-Object { $_ -and $_ -ne $oldDir }) -join ';'
    if ($new -ne $path) { [Environment]::SetEnvironmentVariable('Path', $new, 'Machine') }
}

function Uninstall-Adarve([string]$InstallDir, [string]$DataDir) {
    Write-Step 'Desinstalando Adarve'
    # El análisis programado y el origen del Visor de eventos.
    $task = Get-ScheduledTask -TaskPath '\Adarve\' -TaskName 'Escaneo diario' -ErrorAction SilentlyContinue
    if ($task) {
        $task | Unregister-ScheduledTask -Confirm:$false
        Write-Ok 'Quitado el análisis programado'
    }
    Remove-Item 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\Adarve' -Recurse -ErrorAction SilentlyContinue
    if (Test-Path $InstallDir) {
        Remove-Item -Recurse -Force $InstallDir
        Write-Ok "Eliminado $InstallDir"
    } else {
        Write-Warn "No se encontró $InstallDir"
    }
    $path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $new = ($path -split ';' | Where-Object { $_ -and $_ -ne $InstallDir }) -join ';'
    if ($new -ne $path) { [Environment]::SetEnvironmentVariable('Path', $new, 'Machine') }
    if ($Purge) {
        Remove-Item -Recurse -Force $DataDir -ErrorAction SilentlyContinue
        Write-Ok "Eliminado $DataDir"
    } else {
        Write-Host "  Se conservan la configuración y los informes en $DataDir. Usa -Purge para borrarlos." -ForegroundColor DarkGray
    }
}

function Write-Banner {
    Write-Host ''
    Write-Host '  ADARVE' -ForegroundColor Cyan -NoNewline
    Write-Host '  · hardening para Windows, Windows Server y Linux' -ForegroundColor DarkGray
    Write-Host ''
}
function Write-Step([string]$m) { Write-Host '==> ' -ForegroundColor Cyan -NoNewline; Write-Host $m -ForegroundColor White }
function Write-Ok([string]$m)   { Write-Host '  [OK] ' -ForegroundColor Green -NoNewline; Write-Host $m }
function Write-Warn([string]$m) { Write-Host '  [!] ' -ForegroundColor Yellow -NoNewline; Write-Host $m }

function Write-Summary {
    Write-Host ''
    Write-Host '  Adarve está listo.' -ForegroundColor Green
    Write-Host ''
    Write-Host '  Comandos útiles (PowerShell como administrador)'
    Write-Host '    adarve scan                 auditar el equipo'
    Write-Host '    adarve scan --save --open   informe visual (HTML)'
    Write-Host '    adarve rules show <ID>      detalle y remediación de un control'
    Write-Host '    adarve update               actualizar Adarve y sus reglas'
    Write-Host ''
    Write-Host '  Vuelve a ejecutar este mismo comando en cualquier momento para actualizar.' -ForegroundColor DarkGray
    Write-Host ''
}

if ($env:ADARVE_NO_SCAN -eq '1') { $NoScan = [switch]$true }

try {
    Install-Adarve
} catch {
    Write-Host ''
    Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ''
    # Código de salida 1 para la automatización. Con "irm | iex" no hay
    # fichero de script y exit cerraría la ventana del usuario: solo se
    # deja $LASTEXITCODE.
    $global:LASTEXITCODE = 1
    if ($PSCommandPath) { exit 1 }
}
