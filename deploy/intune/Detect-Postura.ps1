# Remediations de Intune · detección: escanea el equipo (solo lectura) y
# escribe una línea con la puntuación, que Intune muestra por equipo. Si la
# puntuación es menor que $MinScore, termina con 1 («con problemas») e
# Intune ejecuta Remediate-Postura.ps1, si lo has asignado.
# Ver docs/17-guia-de-operacion.md.
$MinScore = 80

# Los textos van sin tildes: Intune recoge la salida con la página de
# códigos de la consola.
$pf = if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles }
$exe = Join-Path $pf 'Adarve\adarve.exe'
if (-not (Test-Path -LiteralPath $exe)) {
    Write-Output "Adarve: no hay $exe"
    exit 1
}
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$json = & $exe scan --format json --no-color 2>$null | Out-String
$code = $LASTEXITCODE
try { $r = $json | ConvertFrom-Json } catch { $r = $null }
if ($code -ne 0 -or -not $r) {
    Write-Output "Adarve: error en el escaneo (codigo $code)"
    exit 1
}
$s = $r.score
if (-not $s.scored) {
    Write-Output 'Adarve: no hay controles evaluados'
    exit 1
}
Write-Output ('Adarve {0}/100 ({1}) - {2} fallidos de {3} - perfil {4} - umbral {5}' -f $s.value, $s.grade, $s.failed, $s.total, $r.profile.id, $MinScore)
if ($s.value -lt $MinScore) { exit 1 }
exit 0
