#!/usr/bin/env bash
# =============================================================================
#  Prueba de punta a punta del dead-man switch (CI, como root).
#
#    go build -o /tmp/adarve ./cmd/adarve
#    sudo env CI=true bash scripts/e2e/deadman-linux.sh /tmp/adarve
#
#  Aplica un cambio de acceso remoto (SSH) con harden en una terminal
#  simulada, corta la sesión sin confirmar y simula un reinicio: el dead-man
#  switch, armado como servicio de systemd, debe deshacer el cambio al vencer
#  el plazo y retirarse. Después comprueba que confirmar lo desarma. Instala
#  Adarve en /usr/local/bin y cambia la configuración de sshd: solo en una
#  máquina desechable, como un runner del CI.
# =============================================================================
set -euo pipefail

SRC="${1:?uso: deadman-linux.sh <binario de adarve>}"
[ "$(id -u)" -eq 0 ] || { echo "necesita root" >&2; exit 1; }
[ "${CI:-}" = "true" ] || [ "${ADARVE_E2E_OK:-}" = "1" ] || { echo "modifica el sistema: solo en CI (o con ADARVE_E2E_OK=1)" >&2; exit 1; }
[ -d /run/systemd/system ] || { echo "necesita systemd" >&2; exit 1; }

BIN=/usr/local/bin/adarve
# MaxAuthTries <= 4: OpenSSH trae 6, así que en un runner recién creado falla.
RULE=LNX-SSH-003
DROPIN=/etc/ssh/sshd_config.d/00-bastion.conf
SNAPSHOTS=/var/lib/adarve/snapshots
T="$(mktemp -d)"
step() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
pass() { printf '  \033[32m✓\033[0m %s\n' "$*"; }
fail() { printf '  \033[31m✗ %s\033[0m\n' "$*" >&2; [ -f "$T/harden.log" ] && sed 's/^/    | /' "$T/harden.log" >&2; exit 1; }
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
trap 'pkill -KILL -f "^$BIN harden" 2>/dev/null || true' EXIT

# El dead-man switch solo se arma como servicio con un binario que solo root
# puede cambiar (en el runner, /usr/local/bin es escribible por todos).
chmod 0755 /usr/local/bin
install -m 0755 -o root -g root "$SRC" "$BIN"

# harden_start lanza harden en una terminal simulada (script): pide «s» para
# aplicar y «confirmar» para mantener el acceso remoto, y eso se le escribe
# por el descriptor 3. Deja la pantalla en $T/harden.log.
harden_start() {
  rm -f "$T/entrada" "$T/harden.log"
  mkfifo "$T/entrada"
  exec 3<>"$T/entrada"
  script -qfec "$BIN harden --profile linux-server-l1 --rule $RULE --include-remote --apply --confirm-timeout 45s --no-color" \
    "$T/harden.log" <"$T/entrada" >/dev/null 2>&1 &
  HARDEN=$!
}
# wait_text <texto>: espera (hasta 60 s) a que harden lo escriba.
wait_text() {
  for _ in $(seq 1 300); do
    grep -qF -- "$1" "$T/harden.log" 2>/dev/null && return 0
    sleep 0.2
  done
  return 1
}
# latest_change: el cambio más reciente (los ID ordenan por fecha).
latest_change() {
  local last=""
  for d in "$SNAPSHOTS"/chg-*; do [ -d "$d" ] && last="$d"; done
  basename "$last"
}
dropin_state() { if [ -e "$DROPIN" ]; then sha256sum <"$DROPIN"; else echo ausente; fi; }
# wait_state <estado>: espera (hasta 90 s) a que el drop-in de sshd quede así.
wait_state() {
  for _ in $(seq 1 450); do
    [ "$(dropin_state)" = "$1" ] && return 0
    sleep 0.2
  done
  return 1
}
unit() { echo "adarve-deadman@$1.service"; }
enabled() { systemctl is-enabled --quiet "$(unit "$1")"; }
active() { systemctl is-active --quiet "$(unit "$1")"; }
# wait_disarmed <cambio>: espera (hasta 30 s) a que deje de estar activado.
wait_disarmed() {
  for _ in $(seq 1 150); do
    enabled "$1" || return 0
    sleep 0.2
  done
  return 1
}
manifest_has() { grep -Eq "\"$2\": ?true" "$SNAPSHOTS/$1/manifest.json"; }

BEFORE="$(dropin_state)"

step "1. Cambio de SSH con el dead-man switch, y la sesión se corta sin confirmar"
harden_start
check "harden pide confirmación para aplicar" wait_text "[s/N]"
printf 's\n' >&3
check "arma el dead-man switch como tarea del sistema" wait_text "armado como tarea del sistema"
check "aplica el cambio y pide confirmar el acceso" wait_text "Escribe confirmar"
ID="$(latest_change)"
check "el cambio $ID tiene su servicio" test -n "$ID"
check "activado para cada arranque" enabled "$ID"
check "en marcha fuera de la sesión" active "$ID"
refuse "el cambio de SSH está aplicado" test "$(dropin_state)" = "$BEFORE"
# Se corta la sesión: harden muere sin confirmar ni deshacer nada.
pkill -KILL -f "^$BIN harden" || fail "harden ya no estaba esperando la confirmación"
wait "$HARDEN" 2>/dev/null || true
exec 3>&-
check "el servicio sigue en marcha sin harden" active "$ID"

step "2. Reinicio antes del plazo"
# El reinicio mata el proceso sin dejarle terminar…
systemctl kill --signal=KILL "$(unit "$ID")"
for _ in $(seq 1 50); do active "$ID" || break; sleep 0.1; done
refuse "el proceso del dead-man switch ha muerto" active "$ID"
check "y sigue activado para el arranque" enabled "$ID"
# …y al arrancar, systemd lo vuelve a lanzar (WantedBy=multi-user.target).
systemctl start "$(unit "$ID")"
check "al vencer el plazo deshace el cambio de SSH" wait_state "$BEFORE"
check "y se retira: no volverá a arrancar" wait_disarmed "$ID"
check "el manifiesto dice que actuó el dead-man switch" manifest_has "$ID" deadman_fired
check "deadman.log lo cuenta" grep -q "cambios de acceso remoto deshechos" "$SNAPSHOTS/$ID/deadman.log"

step "3. Confirmar el acceso remoto desarma el dead-man switch"
harden_start
check "harden pide confirmación para aplicar" wait_text "[s/N]"
printf 's\n' >&3
check "aplica el cambio y pide confirmar el acceso" wait_text "Escribe confirmar"
ID2="$(latest_change)"
refuse "es otro cambio" test "$ID2" = "$ID"
check "con su servicio en marcha" active "$ID2"
printf 'confirmar\n' >&3
check "harden termina bien" wait "$HARDEN"
exec 3>&-
check "dice que mantiene el cambio" wait_text "Acceso remoto confirmado"
refuse "el cambio de SSH se mantiene" test "$(dropin_state)" = "$BEFORE"
refuse "el dead-man switch ya no arranca con el equipo" enabled "$ID2"
refuse "ni sigue en marcha" active "$ID2"
check "el manifiesto lo da por confirmado" manifest_has "$ID2" confirmed

step "4. adarve rollback deshace el cambio confirmado"
check "rollback termina bien" "$BIN" rollback --yes --no-color "$ID2"
check "SSH queda como al principio" test "$(dropin_state)" = "$BEFORE"

printf '\n\033[1;32mDead-man switch: todo correcto\033[0m\n'
