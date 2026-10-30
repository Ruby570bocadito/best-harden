#!/usr/bin/env bash
# =============================================================================
#  Bastion · instalador para Linux
#
#  Instala o actualiza Bastion, lo prepara y lanza un primer escaneo:
#
#    curl -fsSL https://raw.githubusercontent.com/Ruby570bocadito/bastion/main/scripts/install.sh | sudo bash
#
#  Con opciones:
#
#    curl -fsSL .../install.sh | sudo bash -s -- --no-scan
#    curl -fsSL .../install.sh | sudo bash -s -- --version v0.2.0
#    curl -fsSL .../install.sh | sudo bash -s -- --uninstall
#
#  Opciones:
#    --version <tag>        versión concreta (por defecto: la última)
#    --no-scan              no lanzar el primer escaneo
#    --force                reinstalar aunque ya esté en la última versión
#    --local <archivo>      instalar desde un .tar.gz local (sin conexión; necesita
#                           checksums.txt en la misma carpeta)
#    --insecure             con --local, instalar aunque no haya checksums.txt
#    --repo <owner/nombre>  repositorio de GitHub
#    --releases-url <url>   espejo interno de releases (https://…)
#    --prefix <dir>         directorio del binario (por defecto /usr/local/bin)
#    --uninstall [--purge]  desinstalar (con --purge borra también config e informes)
#
#  Variables equivalentes: BASTION_VERSION, BASTION_NO_SCAN=1, BASTION_REPO,
#  BASTION_RELEASES_URL, BASTION_PREFIX.
#
#  Seguridad: el archivo descargado se verifica contra checksums.txt
#  (SHA-256) antes de instalarse. Si prefieres revisar el script antes de
#  ejecutarlo: descárgalo, léelo y ejecútalo con "sudo bash install.sh".
# =============================================================================

# Todo va dentro de main(): si la descarga se corta a medias, bash no
# ejecuta nada (la llamada a main está en la última línea).
main() {
  set -euo pipefail

  REPO="${BASTION_REPO:-Ruby570bocadito/bastion}"
  VERSION="${BASTION_VERSION:-latest}"
  RELEASES_URL="${BASTION_RELEASES_URL:-}"
  PREFIX="${BASTION_PREFIX:-/usr/local/bin}"
  NO_SCAN="${BASTION_NO_SCAN:-0}"
  FORCE=0
  LOCAL=""
  UNINSTALL=0
  PURGE=0
  INSECURE=0

  while [ $# -gt 0 ]; do
    case "$1" in
      --version)      VERSION="${2:?falta la versión}"; shift 2 ;;
      --no-scan)      NO_SCAN=1; shift ;;
      --force)        FORCE=1; shift ;;
      --local)        LOCAL="${2:?falta el archivo}"; shift 2 ;;
      --repo)         REPO="${2:?falta el repositorio}"; shift 2 ;;
      --releases-url) RELEASES_URL="${2:?falta la URL}"; shift 2 ;;
      --prefix)       PREFIX="${2:?falta el directorio}"; shift 2 ;;
      --uninstall)    UNINSTALL=1; shift ;;
      --purge)        PURGE=1; shift ;;
      --insecure)     INSECURE=1; shift ;;
      -h|--help)      sed -n '2,33p' "${BASH_SOURCE[0]:-/dev/null}" 2>/dev/null || true; return 0 ;;
      *)              die "opción desconocida: $1" ;;
    esac
  done
  [ -n "$RELEASES_URL" ] || RELEASES_URL="https://github.com/${REPO}/releases"
  RELEASES_URL="${RELEASES_URL%/}"
  # Las sumas viajan por el mismo canal que el binario: sin TLS no
  # protegerían de nada. HTTP solo hacia el propio equipo (pruebas).
  case "$RELEASES_URL" in
    https://*|http://127.0.0.1|http://127.0.0.1[:/]*|http://localhost|http://localhost[:/]*) ;;
    *) die "la dirección de releases debe usar https:// (${RELEASES_URL})" ;;
  esac
  case "$REPO" in
    */*/*|/*|*/|*[!A-Za-z0-9_./-]*) die "repositorio no válido: ${REPO} (formato owner/nombre)" ;;
    */*) ;;
    *) die "repositorio no válido: ${REPO} (formato owner/nombre)" ;;
  esac
  if [ "$VERSION" != "latest" ]; then
    VERSION="$(normalize_version "$VERSION")"
  fi
  BIN="${PREFIX}/bastion"

  setup_colors
  banner

  [ "$(uname -s)" = "Linux" ] || die "este instalador es para Linux. En Windows usa install.ps1."
  [ "$(id -u)" -eq 0 ] || die "necesita privilegios de root. Ejecuta:  curl -fsSL <url>/install.sh | sudo bash"

  if [ "$UNINSTALL" -eq 1 ]; then
    uninstall
    return 0
  fi

  ARCH="$(detect_arch)"
  ASSET="bastion_linux_${ARCH}.tar.gz"
  TMP="$(mktemp -d)"
  trap 'rm -rf "$TMP"' EXIT

  # 1. Versión objetivo y versión instalada
  CURRENT=""
  if [ -x "$BIN" ]; then
    CURRENT="$("$BIN" version --short 2>/dev/null </dev/null || true)"
  fi

  if [ -n "$LOCAL" ]; then
    step "Instalación sin conexión desde ${LOCAL}"
    [ -f "$LOCAL" ] || die "no existe ${LOCAL}"
    cp "$LOCAL" "$TMP/$ASSET"
    verify_local "$LOCAL"
    install_from_archive
  else
    need_downloader
    if [ "$VERSION" = "latest" ]; then
      step "Buscando la última versión en ${RELEASES_URL}"
      VERSION="$(fetch_text "${RELEASES_URL}/latest/download/version.txt" | tr -d '[:space:]')" \
        || die "no se pudo consultar la última versión (¿hay releases publicadas en ${REPO}?)"
      [ -n "$VERSION" ] || die "version.txt vacío"
      VERSION="$(normalize_version "$VERSION")"
    fi
    if [ -n "$CURRENT" ] && [ "${CURRENT#v}" = "${VERSION#v}" ] && [ "$FORCE" -eq 0 ]; then
      ok "Bastion ${VERSION} ya está instalado y actualizado"
    else
      if [ -n "$CURRENT" ]; then
        step "Actualizando Bastion ${CURRENT} → ${VERSION} (${ARCH})"
      else
        step "Instalando Bastion ${VERSION} (${ARCH})"
      fi
      download_and_verify
      install_from_archive
    fi
  fi

  # 2. Preparación: directorios, configuración y permisos
  step "Preparando Bastion"
  "$BIN" init --no-color </dev/null | sed 's/^/  /'
  ensure_sudo_path

  # 3. Primer escaneo (solo lectura)
  if [ "$NO_SCAN" != "1" ]; then
    step "Primer escaneo (solo lectura: no se modifica nada)"
    "$BIN" scan --save </dev/null || warn "el escaneo terminó con errores"
  fi

  summary
}

# ----------------------------------------------------------------------------

setup_colors() {
  if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    B=$'\033[1m'; D=$'\033[2m'; R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; C=$'\033[36m'; N=$'\033[0m'
  else
    B=""; D=""; R=""; G=""; Y=""; C=""; N=""
  fi
}

banner() {
  printf '\n  %s%s▲ BASTION%s  %s· hardening para Windows, Windows Server y Linux%s\n\n' "$B" "$C" "$N" "$D" "$N"
}

step() { printf '%s==>%s %s%s%s\n' "$C" "$N" "$B" "$*" "$N"; }
ok()   { printf '  %s✓%s %s\n' "$G" "$N" "$*"; }
warn() { printf '  %s!%s %s\n' "${Y:-}" "${N:-}" "$*" >&2; }
die()  { printf '\n  %s✗ Error:%s %s\n\n' "${R:-}" "${N:-}" "$*" >&2; exit 1; }

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64)  echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    *) die "arquitectura no soportada: $(uname -m) (soportadas: amd64, arm64)" ;;
  esac
}

need_downloader() {
  if command -v curl >/dev/null 2>&1; then
    DL=curl
  elif command -v wget >/dev/null 2>&1; then
    DL=wget
  else
    die "se necesita curl o wget"
  fi
}

fetch_text() {
  if [ "$DL" = curl ]; then curl -fsSL --retry 3 "$1"; else wget -qO- "$1"; fi
}

fetch_file() {
  if [ "$DL" = curl ]; then curl -fSL --retry 3 --progress-bar -o "$2" "$1"; else wget -q --show-progress -O "$2" "$1"; fi
}

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    die "se necesita sha256sum o shasum para verificar la descarga"
  fi
}

check_sum() { # check_sum <archivo> <checksums.txt>
  local want got
  want="$(awk -v f="$ASSET" '$2 == f || $2 == "*"f {print $1}' "$2")"
  [ -n "$want" ] || die "checksums.txt no contiene ${ASSET}"
  got="$(sha256 "$1")"
  [ "$want" = "$got" ] || die "la suma SHA-256 no coincide (esperada ${want}, obtenida ${got}). Instalación abortada."
  ok "Suma SHA-256 verificada"
}

download_and_verify() {
  local base="${RELEASES_URL}/download/${VERSION}"
  fetch_text "${base}/checksums.txt" > "$TMP/checksums.txt" || die "no se pudo descargar checksums.txt de ${base}"
  fetch_file "${base}/${ASSET}" "$TMP/$ASSET" || die "no se pudo descargar ${ASSET}"
  check_sum "$TMP/$ASSET" "$TMP/checksums.txt"
}

verify_local() {
  local sums
  sums="$(dirname "$1")/checksums.txt"
  if [ -f "$sums" ]; then
    check_sum "$TMP/$ASSET" "$sums"
  elif [ "$INSECURE" -eq 1 ]; then
    warn "no hay checksums.txt junto a $1: se instala SIN verificar la integridad (--insecure)"
  else
    die "no hay checksums.txt junto a $1: descárgalo de la misma release para verificar el archivo (o usa --insecure bajo tu responsabilidad)"
  fi
}

# normalize_version deja la etiqueta como vX.Y.Z[-pre] (acepta 0.2.0) y
# rechaza cualquier otra cosa: forma parte de las URLs de descarga.
normalize_version() {
  local v="v${1#v}"
  printf '%s' "$v" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$' \
    || die "versión no válida: $1 (ejemplo: v0.3.2)"
  printf '%s' "$v"
}

install_from_archive() {
  tar -xzf "$TMP/$ASSET" -C "$TMP" bastion 2>/dev/null || tar -xzf "$TMP/$ASSET" -C "$TMP"
  [ -f "$TMP/bastion" ] || die "el archivo no contiene el binario bastion"
  mkdir -p "$PREFIX"
  # Reemplazo atómico: un escaneo en curso sigue usando el binario anterior.
  install -m 0755 "$TMP/bastion" "${BIN}.new"
  mv -f "${BIN}.new" "$BIN"
  ok "Instalado en ${BIN} ($("$BIN" version --short </dev/null))"
}

# En RHEL y derivados, sudo usa secure_path sin /usr/local/bin: se crea un
# enlace en /usr/bin para que "sudo bastion" funcione.
ensure_sudo_path() {
  local sp
  sp="$(grep -hs '^[[:space:]]*Defaults[[:space:]].*secure_path' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | tail -n1 || true)"
  if [ -n "$sp" ] && ! printf '%s' "$sp" | grep -q "$PREFIX"; then
    if [ -L /usr/bin/bastion ] && [ "$(readlink /usr/bin/bastion)" = "$BIN" ]; then
      return 0
    fi
    if [ ! -e /usr/bin/bastion ] || [ -L /usr/bin/bastion ]; then
      ln -sf "$BIN" /usr/bin/bastion
      ok "Enlace /usr/bin/bastion creado (sudo secure_path no incluye ${PREFIX})"
    fi
  fi
}

uninstall() {
  step "Desinstalando Bastion"
  # El análisis programado (temporizador de systemd o cron).
  if [ -f /etc/systemd/system/bastion-scan.timer ]; then
    systemctl disable --now bastion-scan.timer >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/bastion-scan.timer /etc/systemd/system/bastion-scan.service
    systemctl daemon-reload >/dev/null 2>&1 || true
    ok "Quitado el análisis programado"
  fi
  if [ -f /etc/cron.d/bastion ]; then
    rm -f /etc/cron.d/bastion
    ok "Quitado el análisis programado"
  fi
  if [ -L /usr/bin/bastion ] && [ "$(readlink /usr/bin/bastion)" = "$BIN" ]; then
    rm -f /usr/bin/bastion
  fi
  if [ -f "$BIN" ]; then
    rm -f "$BIN"
    ok "Eliminado ${BIN}"
  else
    warn "no se encontró ${BIN}"
  fi
  if [ "$PURGE" -eq 1 ]; then
    rm -rf /etc/bastion /var/lib/bastion
    ok "Eliminados /etc/bastion y /var/lib/bastion"
  else
    printf '  %sSe conservan la configuración (/etc/bastion) y los informes (/var/lib/bastion). Usa --purge para borrarlos.%s\n' "$D" "$N"
  fi
}

summary() {
  printf '\n  %s%s✓ Bastion está listo.%s\n\n' "$B" "$G" "$N"
  printf '  %sComandos útiles%s\n' "$B" "$N"
  printf '    sudo bastion scan                 auditar el equipo\n'
  printf '    sudo bastion scan --save --open   informe visual (HTML)\n'
  printf '    sudo bastion rules show <ID>      detalle y remediación de un control\n'
  printf '    sudo bastion update               actualizar Bastion y sus reglas\n'
  printf '\n  %sVuelve a ejecutar este mismo comando en cualquier momento para actualizar.%s\n\n' "$D" "$N"
}

main "$@"
