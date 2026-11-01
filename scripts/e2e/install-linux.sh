#!/usr/bin/env bash
# =============================================================================
#  Prueba de punta a punta de install.sh y "adarve update" (CI, como root).
#
#    go run ./scripts/e2e/mkmirror -out /tmp/e2e
#    sudo bash scripts/e2e/install-linux.sh /tmp/e2e
#
#  Usa el espejo firmado con la clave de prueba que deja mkmirror. Modifica el
#  sistema (instala Adarve, crea y borra una instalación falsa de Bastion):
#  solo en una máquina desechable, como un runner del CI.
# =============================================================================
set -euo pipefail

E="${1:?uso: install-linux.sh <carpeta de mkmirror>}"
[ "$(id -u)" -eq 0 ] || { echo "necesita root" >&2; exit 1; }
[ "${CI:-}" = "true" ] || [ "${ADARVE_E2E_OK:-}" = "1" ] || { echo "modifica el sistema: solo en CI (o con ADARVE_E2E_OK=1)" >&2; exit 1; }

PORT=8765
URL="http://127.0.0.1:${PORT}"
INSTALL=(bash "$E/install.sh" --releases-url "$URL" --no-scan)
BIN=/usr/local/bin/adarve
step() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
pass() { printf '  \033[32m✓\033[0m %s\n' "$*"; }
fail() { printf '  \033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }
version() { "$BIN" version --short 2>/dev/null || echo "ninguna"; }
expect_version() { [ "$(version)" = "$1" ] && pass "versión $1" || fail "versión $(version), se esperaba $1"; }

python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$E/mirror" >/dev/null 2>&1 &
SERVER=$!
trap 'kill $SERVER 2>/dev/null || true' EXIT
for _ in $(seq 1 50); do curl -fsS "$URL/latest/download/version.txt" >/dev/null 2>&1 && break; sleep 0.1; done

step "Una instalación antigua de Bastion"
cp /bin/true /usr/local/bin/bastion
mkdir -p /var/lib/bastion/reports /etc/bastion
echo '{"schema":"bastion.report/v1"}' > /var/lib/bastion/reports/antiguo.json
echo 'profile: auto' > /etc/bastion/config.yaml
cat > /etc/systemd/system/bastion-scan.service <<'UNIT'
[Service]
Type=oneshot
ExecStart=/usr/local/bin/bastion schedule run
UNIT
cat > /etc/systemd/system/bastion-scan.timer <<'UNIT'
[Timer]
OnCalendar=*-*-* 07:45:00
[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable --now bastion-scan.timer >/dev/null 2>&1
pass "Bastion con datos, configuración y ronda diaria a las 07:45"

step "1. Instalar v9.9.8 (como con curl | bash) y migrar desde Bastion"
bash -s -- --releases-url "$URL" --no-scan --version v9.9.8 < "$E/install.sh"
expect_version 9.9.8
[ -f /var/lib/adarve/reports/antiguo.json ] && pass "informes trasladados a /var/lib/adarve" || fail "faltan los informes en /var/lib/adarve"
[ ! -e /var/lib/bastion ] && pass "/var/lib/bastion retirado" || fail "/var/lib/bastion sigue ahí"
[ -f /etc/adarve/config.yaml ] && [ ! -e /etc/bastion ] && pass "configuración trasladada a /etc/adarve" || fail "configuración no trasladada"
[ ! -e /usr/local/bin/bastion ] && pass "binario de Bastion retirado" || fail "/usr/local/bin/bastion sigue ahí"
[ ! -e /etc/systemd/system/bastion-scan.timer ] && pass "temporizador de Bastion retirado" || fail "bastion-scan.timer sigue ahí"
grep -q 'OnCalendar=\*-\*-\* 07:45' /etc/systemd/system/adarve-scan.timer && pass "ronda diaria de Adarve a las 07:45" || fail "adarve-scan.timer no está a las 07:45"
systemctl is-enabled adarve-scan.timer >/dev/null && pass "adarve-scan.timer activado" || fail "adarve-scan.timer no está activado"
[ "$(stat -c %a /var/lib/adarve)" = 750 ] && [ "$(stat -c %U /var/lib/adarve)" = root ] && pass "/var/lib/adarve: root, 750" || fail "permisos de /var/lib/adarve: $(stat -c '%U %a' /var/lib/adarve)"

step "2. Volver a ejecutar el instalador (ya está al día con esa versión)"
out="$("${INSTALL[@]}" --version v9.9.8 < /dev/null)"
grep -q "ya está instalado" <<<"$out" && pass "no reinstala" || fail "debería decir que ya está instalado"

step "3. adarve update a la última versión firmada"
"$BIN" update --releases-url "$URL" --no-color
expect_version 9.9.9

step "4. Releases que se deben rechazar"
if "${INSTALL[@]}" --version v9.9.7 --force < /dev/null; then fail "instaló una release con checksums.txt manipulado"; fi
expect_version 9.9.9
if "${INSTALL[@]}" --version v9.9.7 --force --insecure < /dev/null; then fail "--insecure no debe aceptar una firma inválida"; fi
if "${INSTALL[@]}" --version v9.9.6 --force < /dev/null; then fail "instaló una release sin firma"; fi
if "$BIN" update --releases-url "$URL" --version v9.9.7 --force --no-color; then fail "update aceptó una firma inválida"; fi
if "$BIN" update --releases-url "$URL" --version v9.9.6 --force --no-color; then fail "update aceptó una release sin firma"; fi
expect_version 9.9.9
pass "manipulada y sin firma rechazadas, también con --insecure si la firma es inválida"

step "5. Release sin firma con --insecure (versiones anteriores a la firma)"
"${INSTALL[@]}" --version v9.9.6 --force --insecure < /dev/null
expect_version 9.9.6

step "6. Instalación sin conexión (--local)"
"${INSTALL[@]}" --local "$(ls "$E"/local/adarve_linux_*.tar.gz)" --force < /dev/null
expect_version 9.9.8
mv "$E/local/checksums.txt.sig" "$E/local/sig.bak"
if "${INSTALL[@]}" --local "$(ls "$E"/local/adarve_linux_*.tar.gz)" --force < /dev/null; then fail "--local sin firma debe rechazarse"; fi
mv "$E/local/sig.bak" "$E/local/checksums.txt.sig"
pass "--local sin checksums.txt.sig rechazado"

step "7. Desinstalar"
"${INSTALL[@]}" --uninstall < /dev/null
[ ! -e "$BIN" ] && pass "binario eliminado" || fail "$BIN sigue ahí"
[ ! -e /etc/systemd/system/adarve-scan.timer ] && pass "ronda diaria retirada" || fail "adarve-scan.timer sigue ahí"
[ -d /var/lib/adarve ] && pass "datos conservados sin --purge" || fail "se borraron los datos sin --purge"
"${INSTALL[@]}" --uninstall --purge < /dev/null
[ ! -e /var/lib/adarve ] && [ ! -e /etc/adarve ] && pass "--purge borra datos y configuración" || fail "--purge no lo borró todo"

printf '\n\033[1;32mInstalador de Linux: todo correcto\033[0m\n'
