#!/usr/bin/env bash
# =============================================================================
#  Prueba de punta a punta de install.sh y "bastion update" contra un espejo
#  local de releases (http://127.0.0.1, el único HTTP que admiten).
#
#    sudo scripts/test-installer.sh
#
#  Compila dos versiones (v9.0.0 y v9.0.1) con go, salvo que BUILD_DIR ya
#  tenga bastion-9.0.0 y bastion-9.0.1. Instala en un prefijo temporal, pero
#  "bastion init" usa /etc/bastion y /var/lib/bastion (y el instalador puede
#  enlazar /usr/bin/bastion) y la prueba los borra: se niega a ejecutarse si
#  ya existen. Para CI y máquinas desechables.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${PORT:-8098}"
URL="http://127.0.0.1:${PORT}"
WORK="$(mktemp -d)"
PREFIX="$WORK/bin"
BIN="$PREFIX/bastion"
BUILD_DIR="${BUILD_DIR:-$WORK/build}"
SERVER=""

[ "$(id -u)" -eq 0 ] || { echo "necesita root (install.sh lo exige)"; exit 1; }
case "$(uname -m)" in x86_64 | amd64) ARCH=amd64 ;; aarch64 | arm64) ARCH=arm64 ;; *) exit 1 ;; esac
ASSET="bastion_linux_${ARCH}.tar.gz"

for d in /etc/bastion /var/lib/bastion /usr/bin/bastion; do
  [ ! -e "$d" ] || { echo "ya existe $d: esta prueba lo borraría (usa una máquina desechable)"; exit 1; }
done

cleanup() {
  [ -n "$SERVER" ] && kill "$SERVER" 2>/dev/null || true
  # install.sh enlaza /usr/bin/bastion si secure_path de sudo no incluye el prefijo.
  case "$(readlink /usr/bin/bastion 2>/dev/null)" in "$WORK"/*) rm -f /usr/bin/bastion ;; esac
  rm -rf /etc/bastion /var/lib/bastion "$WORK"
}
trap cleanup EXIT

pass() { printf '  ✓ %s\n' "$*"; }
fail() {
  printf '  ✗ %s\n' "$*" >&2
  exit 1
}
installer() { bash "$ROOT/scripts/install.sh" --prefix "$PREFIX" --no-scan "$@" </dev/null; }

# 1. Dos versiones del binario
mkdir -p "$BUILD_DIR"
for v in 9.0.0 9.0.1; do
  if [ ! -x "$BUILD_DIR/bastion-$v" ]; then
    (cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -trimpath \
      -ldflags "-X github.com/Ruby570bocadito/bastion/internal/version.Version=$v" \
      -o "$BUILD_DIR/bastion-$v" ./cmd/bastion)
  fi
done

# 2. Espejo con la misma estructura que GitHub Releases
mirror() { # mirror <versión> <dir>
  local d="$2/download/v$1" pkg="$WORK/pkg-$1"
  mkdir -p "$d" "$pkg"
  cp "$BUILD_DIR/bastion-$1" "$pkg/bastion"
  tar -czf "$d/$ASSET" -C "$pkg" bastion
  (cd "$d" && sha256sum "$ASSET" >checksums.txt)
}
M="$WORK/mirror"
mirror 9.0.0 "$M"
mirror 9.0.1 "$M"
mkdir -p "$M/latest/download"
echo v9.0.1 >"$M/latest/download/version.txt"
python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$M" >/dev/null 2>&1 &
SERVER=$!
for _ in $(seq 1 50); do curl -fs "$URL/latest/download/version.txt" >/dev/null && break; sleep 0.2; done

version() { "$BIN" version --short </dev/null; }

# 3. Casos
echo "== Instalar una versión concreta"
installer --releases-url "$URL" --version 9.0.0
[ "$(version)" = "9.0.0" ] || fail "se esperaba 9.0.0, hay $(version)"
[ -d /etc/bastion ] || fail "init no preparó /etc/bastion"
pass "v9.0.0 instalada y preparada"

echo "== Actualizar a la última con el instalador"
installer --releases-url "$URL"
[ "$(version)" = "9.0.1" ] || fail "se esperaba 9.0.1, hay $(version)"
pass "actualizada a v9.0.1"

echo "== Sin cambios si ya está en la última"
out="$(installer --releases-url "$URL")"
grep -q "ya está instalado" <<<"$out" || fail "debería decir que ya está actualizado"
pass "no reinstala sin --force"

echo "== bastion update desde v9.0.0"
installer --releases-url "$URL" --version 9.0.0
"$BIN" update --releases-url "$URL" --no-color </dev/null
[ "$(version)" = "9.0.1" ] || fail "update no actualizó: $(version)"
pass "bastion update instaló v9.0.1"

echo "== Una descarga manipulada no se instala"
installer --releases-url "$URL" --version 9.0.0
cp "$M/download/v9.0.1/$ASSET" "$WORK/orig.tar.gz"
printf 'x' >>"$M/download/v9.0.1/$ASSET"
if installer --releases-url "$URL" 2>/dev/null; then fail "install.sh aceptó un archivo con otra suma"; fi
[ "$(version)" = "9.0.0" ] || fail "el binario cambió pese al error"
if "$BIN" update --releases-url "$URL" --no-color </dev/null 2>/dev/null; then fail "bastion update aceptó un archivo con otra suma"; fi
[ "$(version)" = "9.0.0" ] || fail "update cambió el binario pese al error"
cp "$WORK/orig.tar.gz" "$M/download/v9.0.1/$ASSET"
pass "install.sh y update rechazan la suma que no coincide"

echo "== HTTP fuera del propio equipo se rechaza"
if installer --releases-url "http://example.com/releases" 2>/dev/null; then fail "aceptó http:// remoto"; fi
pass "solo https:// (o loopback)"

echo "== Instalación sin conexión (--local)"
installer --local "$M/download/v9.0.1/$ASSET"
[ "$(version)" = "9.0.1" ] || fail "--local no instaló 9.0.1"
cp "$M/download/v9.0.0/$ASSET" "$WORK/$ASSET"
if installer --local "$WORK/$ASSET" 2>/dev/null; then fail "--local sin checksums.txt debe fallar"; fi
installer --local "$WORK/$ASSET" --insecure
[ "$(version)" = "9.0.0" ] || fail "--local --insecure no instaló"
pass "--local exige checksums.txt salvo con --insecure"

echo "== Desinstalar"
installer --uninstall
[ ! -e "$BIN" ] || fail "el binario sigue ahí"
[ -d /etc/bastion ] || fail "sin --purge se conserva la configuración"
installer --uninstall --purge || true
[ ! -e /etc/bastion ] && [ ! -e /var/lib/bastion ] || fail "--purge no borró los datos"
pass "desinstalado (y purgado)"

echo
echo "✓ Instalador y actualización: todo correcto"
