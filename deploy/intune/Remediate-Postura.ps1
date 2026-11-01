# Remediations de Intune · corrección: aplica la ola 1 de «adarve harden»
# (cambios de riesgo de rotura nulo o bajo). No toca los que pueden cortar
# el acceso remoto ni las claves que gestiona una GPO. Cada ejecución queda
# en «adarve history» y se deshace con «adarve rollback <ID>».
# Pruébalo antes en un grupo piloto. Ver docs/17-guia-de-operacion.md.
$pf = if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles }
$exe = Join-Path $pf 'Adarve\adarve.exe'
if (-not (Test-Path -LiteralPath $exe)) {
    Write-Output "Adarve: no hay $exe"
    exit 1
}
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$out = & $exe harden --apply --yes --wave 1 --no-color 2>&1 | ForEach-Object { "$_" }
$code = $LASTEXITCODE
# Intune guarda hasta 2048 caracteres: el resumen está en las últimas líneas.
$lines = @($out | Where-Object { $_.Trim() } | ForEach-Object { $_.Trim() })
Write-Output (($lines | Select-Object -Last 8) -join ' | ')
exit $code
