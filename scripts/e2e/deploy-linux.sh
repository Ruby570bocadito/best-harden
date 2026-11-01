#!/usr/bin/env bash
# =============================================================================
#  Prueba de punta a punta de deploy/ansible/adarve.yml (CI).
#
#    go run ./scripts/e2e/mkmirror -out /tmp/e2e
#    CI=true bash scripts/e2e/deploy-linux.sh /tmp/e2e
#
#  ansible-playbook contra este mismo equipo (conexión local y sudo) con el
#  espejo firmado con la clave de prueba que deja mkmirror. Instala Adarve y
#  programa la ronda diaria: solo en una máquina desechable, como un runner
#  del CI.
# =============================================================================
set -euo pipefail

E="${1:?uso: deploy-linux.sh <carpeta de mkmirror>}"
[ "${CI:-}" = "true" ] || [ "${ADARVE_E2E_OK:-}" = "1" ] || { echo "modifica el sistema: solo en CI (o con ADARVE_E2E_OK=1)" >&2; exit 1; }
command -v ansible-playbook >/dev/null || { echo "falta ansible-playbook (apt install ansible-core)" >&2; exit 1; }

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PORT=8766
URL="http://127.0.0.1:${PORT}"
BIN=/usr/local/bin/adarve
OUT="$(mktemp -d)"
export ANSIBLE_NOCOLOR=1 ANSIBLE_HOST_KEY_CHECKING=False
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
timer_at() { grep -q "OnCalendar=\*-\*-\* $1" /etc/systemd/system/adarve-scan.timer; }
# play <-e …>: el playbook contra este equipo; deja la salida en $OUT/play.log.
play() {
  ansible-playbook -i localhost, -c local "$ROOT/deploy/ansible/adarve.yml" \
    -e "adarve_releases_url=$URL" -e "adarve_installer=$E/install.sh" \
    -e "adarve_reports_dir=$OUT/informes" "$@" >"$OUT/play.log" 2>&1
  local rc=$?
  cat "$OUT/play.log"
  return "$rc"
}
# recap_changed <n>: el resumen del playbook dice changed=<n>.
recap_changed() { grep -Eq "^localhost +: ok=[0-9]+ +changed=$1 " "$OUT/play.log"; }
log_has() { grep -q "$1" "$OUT/play.log"; }

# En el runner, /usr/local/bin es escribible por todos, y Adarve no programa
# la ronda con un binario que otros pueden cambiar. En un servidor normal
# solo lo modifica root.
sudo chmod 0755 /usr/local/bin

python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$E/mirror" >/dev/null 2>&1 &
SERVER=$!
trap 'kill $SERVER 2>/dev/null || true' EXIT
for _ in $(seq 1 50); do curl -fsS "$URL/latest/download/version.txt" >/dev/null 2>&1 && break; sleep 0.1; done

step "1. Desplegar v9.9.8 con la ronda a las 06:30"
check "el playbook termina bien" play -e adarve_version=v9.9.8 -e adarve_schedule_at=06:30
expect_version 9.9.8
check "ronda diaria a las 06:30" timer_at 06:30
check "adarve-scan.timer activado" systemctl is-enabled --quiet adarve-scan.timer
check "informe del equipo en el controlador" grep -q '"adarve.report/v1"' "$OUT/informes/localhost.json"
check "el informe es JSON" python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$OUT/informes/localhost.json"
check "la ronda queda en la historia del equipo" sudo sh -c 'ls /var/lib/adarve/reports/adarve-*.json >/dev/null'

step "2. Repetirlo no cambia nada"
check "el playbook termina bien" play -e adarve_version=v9.9.8 -e adarve_schedule_at=06:30
check "changed=0" recap_changed 0

step "3. Cambiar la hora de la ronda y actualizar a v9.9.9"
check "el playbook termina bien" play -e adarve_version=v9.9.9 -e adarve_schedule_at=07:15
expect_version 9.9.9
check "ronda diaria a las 07:15" timer_at 07:15
check "changed=2 (instalar y programar)" recap_changed 2

step "4. Lo que se debe rechazar"
refuse "sin versión concreta" play -e adarve_version=latest
# Sin la «ó»: Ansible puede escribir el mensaje con la tilde escapada (ó).
check "explica qué falta" log_has "Indica una versi"
refuse "hora inválida" play -e adarve_version=v9.9.9 -e adarve_schedule_at=25:00
refuse "release manipulada (v9.9.7)" play -e adarve_version=v9.9.7
expect_version 9.9.9
refuse "release sin firma (v9.9.6)" play -e adarve_version=v9.9.6
expect_version 9.9.9
refuse "puntuación por debajo del mínimo" play -e adarve_version=v9.9.9 -e adarve_min_score=100
check "dice qué equipo no llega" log_has "localhost no llega a 100"
check "y aun así trae su informe" test -s "$OUT/informes/localhost.json"

printf '\n\033[1;32mDespliegue con Ansible: todo correcto\033[0m\n'
