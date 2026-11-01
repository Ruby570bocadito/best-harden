#!/usr/bin/env bash
# =============================================================================
#  Prueba de punta a punta de install.sh y "adarve update" (CI, como root).
#
#    go run ./scripts/e2e/mkmirror -out /tmp/e2e
#    sudo bash scripts/e2e/install-linux.sh /tmp/e2e
#
#  Usa el espejo firmado con la clave de prueba que deja mkmirror. Modifica el
#  sistema (instala Adarve, crea y borra una instalación falsa de Bastion,
#  cambia los permisos de /usr/local/bin): solo en una máquina desechable,
#  como un runner del CI.
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
# check <descripción> <orden…>: la orden debe terminar bien.
check() {
  local what="$1"; shift
  if "$@"; then pass "$what"; else fail "$what"; fi
}
# refuse <descripción> <orden…>: la orden debe fallar.
refuse() {
  local what="$1"; shift
  if "$@"; then fail "$what"; else pass "$what"; fi
}
version() { "$BIN" version --short 2>/dev/null || echo "ninguna"; }
expect_version() {
  local got; got="$(version)"
  if [ "$got" = "$1" ]; then pass "versión $1"; else fail "versión ${got}, se esperaba $1"; fi
}
absent() { [ ! -e "$1" ]; }
timer_at() { grep -q "OnCalendar=\*-\*-\* $2" "$1"; }

python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$E/mirror" >/dev/null 2>&1 &
SERVER=$!
trap 'kill $SERVER 2>/dev/null || true' EXIT
for _ in $(seq 1 50); do curl -fsS "$URL/latest/download/version.txt" >/dev/null 2>&1 && break; sleep 0.1; done

# fake_bastion simula una instalación de Bastion con su ronda diaria a las 07:45.
fake_bastion() {
  cp /bin/true /usr/local/bin/bastion
  mkdir -p /var/lib/bastion/reports /etc/bastion
  echo '{"schema":"bastion.report/v1"}' > /var/lib/bastion/reports/antiguo.json
  echo 'profile: auto' > /etc/bastion/config.yaml
  printf '[Service]\nType=oneshot\nExecStart=/usr/local/bin/bastion schedule run\n' > /etc/systemd/system/bastion-scan.service
  printf '[Timer]\nOnCalendar=*-*-* 07:45:00\n[Install]\nWantedBy=timers.target\n' > /etc/systemd/system/bastion-scan.timer
  systemctl daemon-reload
  systemctl enable --now bastion-scan.timer >/dev/null 2>&1
}

step "0. /usr/local/bin escribible por todos (como en el runner): no se programa Adarve, pero se retira la ronda de Bastion"
chmod 0777 /usr/local/bin
fake_bastion
"${INSTALL[@]}" --version v9.9.8 < /dev/null
check "ronda de Bastion retirada aunque no se pueda programar Adarve" absent /etc/systemd/system/bastion-scan.timer
check "Adarve no se programa con un binario que otros pueden cambiar" absent /etc/systemd/system/adarve-scan.timer
"${INSTALL[@]}" --uninstall --purge < /dev/null
# Lo normal: /usr/local/bin solo lo modifica root.
chmod 0755 /usr/local/bin

step "Una instalación antigua de Bastion"
fake_bastion
pass "Bastion con datos, configuración y ronda diaria a las 07:45"

step "1. Instalar v9.9.8 (como con curl | bash) y migrar desde Bastion"
bash -s -- --releases-url "$URL" --no-scan --version v9.9.8 < "$E/install.sh"
expect_version 9.9.8
check "informes trasladados a /var/lib/adarve" test -f /var/lib/adarve/reports/antiguo.json
check "/var/lib/bastion retirado" absent /var/lib/bastion
check "configuración trasladada a /etc/adarve" test -f /etc/adarve/config.yaml
check "/etc/bastion retirado" absent /etc/bastion
check "binario de Bastion retirado" absent /usr/local/bin/bastion
check "temporizador de Bastion retirado" absent /etc/systemd/system/bastion-scan.timer
check "ronda diaria de Adarve a las 07:45" timer_at /etc/systemd/system/adarve-scan.timer 07:45
check "adarve-scan.timer activado" systemctl is-enabled --quiet adarve-scan.timer
check "/var/lib/adarve es de root" test "$(stat -c %U /var/lib/adarve)" = root
check "/var/lib/adarve tiene permisos 750" test "$(stat -c %a /var/lib/adarve)" = 750

step "2. Volver a ejecutar el instalador (ya está al día con esa versión)"
out="$("${INSTALL[@]}" --version v9.9.8 < /dev/null)"
check "no reinstala" grep -q "ya está instalado" <<<"$out"

step "3. adarve update a la última versión firmada"
"$BIN" update --releases-url "$URL" --no-color
expect_version 9.9.9

step "4. Releases que se deben rechazar"
refuse "rechaza checksums.txt manipulado" "${INSTALL[@]}" --version v9.9.7 --force
refuse "--insecure no acepta una firma inválida" "${INSTALL[@]}" --version v9.9.7 --force --insecure
refuse "rechaza una release sin firma" "${INSTALL[@]}" --version v9.9.6 --force
refuse "update rechaza una firma inválida" "$BIN" update --releases-url "$URL" --version v9.9.7 --force --no-color
refuse "update rechaza una release sin firma" "$BIN" update --releases-url "$URL" --version v9.9.6 --force --no-color
expect_version 9.9.9

step "5. Release sin firma con --insecure (versiones anteriores a la firma)"
"${INSTALL[@]}" --version v9.9.6 --force --insecure < /dev/null
expect_version 9.9.6

step "6. Instalación sin conexión (--local)"
archive="$(ls "$E"/local/adarve_linux_*.tar.gz)"
"${INSTALL[@]}" --local "$archive" --force < /dev/null
expect_version 9.9.8
mv "$E/local/checksums.txt.sig" "$E/local/sig.bak"
refuse "--local sin checksums.txt.sig rechazado" "${INSTALL[@]}" --local "$archive" --force
mv "$E/local/sig.bak" "$E/local/checksums.txt.sig"

step "7. Desinstalar"
"${INSTALL[@]}" --uninstall < /dev/null
check "binario eliminado" absent "$BIN"
check "ronda diaria retirada" absent /etc/systemd/system/adarve-scan.timer
check "datos conservados sin --purge" test -d /var/lib/adarve
"${INSTALL[@]}" --uninstall --purge < /dev/null
check "--purge borra los datos" absent /var/lib/adarve
check "--purge borra la configuración" absent /etc/adarve

printf '\n\033[1;32mInstalador de Linux: todo correcto\033[0m\n'
