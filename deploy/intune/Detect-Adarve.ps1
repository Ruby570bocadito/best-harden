# Regla de detección de la aplicación Win32 de Intune (script personalizado).
# Adarve cuenta como instalado si adarve.exe existe y es la versión que se
# despliega. Intune no pasa parámetros a este script: cambia $Version cuando
# actualices el paquete. Ver docs/17-guia-de-operacion.md.
$Version = 'v0.5.0'

# En PowerShell de 32 bits, $env:ProgramFiles es «Program Files (x86)».
$pf = if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles }
$exe = Join-Path $pf 'Adarve\adarve.exe'
if (Test-Path -LiteralPath $exe) {
    $v = & $exe version --short 2>$null | Select-Object -First 1
    if ($LASTEXITCODE -eq 0 -and ([string]$v).Trim().TrimStart('v') -eq $Version.TrimStart('v')) {
        # Intune da la aplicación por instalada si el script escribe algo
        # y termina con 0.
        Write-Output "Adarve $Version"
        exit 0
    }
}
exit 1
