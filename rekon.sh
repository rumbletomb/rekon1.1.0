#!/usr/bin/env bash
# REKON - Orquestador de reconocimiento y enumeracion para laboratorios autorizados.
# No incluye explotacion, fuerza bruta de credenciales, DoS ni acciones destructivas.

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly REKON_VERSION="1.1.0"
readonly REKON_NAME="REKON"
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
readonly SCRIPT_DIR

TARGET=""
TARGET_TYPE=""
TARGET_SLUG=""
URL_TARGET=""
SCOPE_DOMAIN=""
WORDLIST_ROOT=""
PROFILE="balanced"
OUTPUT_BASE="./rekon-output"
RESUME_DIR=""
RUN_DIR=""
NON_INTERACTIVE=0
ACCEPT_AUTHORIZED_USE=0
DRY_RUN=0
NO_COLOR=0
DOCTOR_ONLY=0
SELF_TEST=0
RESUME=0
EXTERNAL_OSINT=1
ONLY_MODULES=""
SKIP_MODULES=""
THREADS_OVERRIDE=""
RATE_OVERRIDE=""
MAX_HOSTS_OVERRIDE=""
TCP_PORTS_OVERRIDE=""
UDP_PORTS_OVERRIDE=""
INSTALL_MODE="ask"
PRIVILEGED_SCAN_MODE="ask"
PRIVILEGED_SCANS=0
USER_BIN_DIR="${REKON_BIN_DIR:-${HOME:-/tmp}/.local/bin}"

THREADS=20
RATE=50
MAX_HOSTS=100
MAX_WEB_TARGETS=20
CRAWL_DEPTH=3
FFUF_MAXTIME=600
STEP_TIMEOUT=1800
DNS_WL_LIMIT=20000
DIR_WL_LIMIT=50000
FILE_WL_LIMIT=50000
PARAM_WL_LIMIT=10000
RESOLVER_WL_LIMIT=5000
TCP_PORT_SPEC="top1000"
UDP_PORT_SPEC="top50"
ENABLE_ACTIVE=1
ENABLE_FUZZ=1
ENABLE_SAFE_NUCLEI=1
FFUF_RECURSION_DEPTH=0

META_DIR=""
TARGET_DIR=""
PASSIVE_DIR=""
DNS_DIR=""
PORTS_DIR=""
SERVICES_DIR=""
HTTP_DIR=""
CRAWL_DIR=""
FUZZ_DIR=""
TLS_DIR=""
OBS_DIR=""
REPORT_DIR=""
LOG_DIR=""
STATE_DIR=""
COMMAND_LOG=""
EXECUTION_LOG=""
MODULE_STATUS_FILE=""
SCAN_TARGETS=""
LIVE_URLS=""

WL_SUBDOMAINS=""
WL_VHOSTS=""
WL_DIRS=""
WL_FILES=""
WL_PARAMS=""
WL_RESOLVERS=""

declare -a WL_PATHS=()
declare -a WL_NAMES=()
declare -a WL_SIZES=()
declare -a INSTALL_PRIV_PREFIX=()
declare -a SCAN_PRIV_PREFIX=()

if [[ -t 1 ]]; then
  C_RESET=$'\033[0m'
  C_RED=$'\033[31m'
  C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'
  C_BLUE=$'\033[34m'
  C_BOLD=$'\033[1m'
else
  C_RESET="" C_RED="" C_GREEN="" C_YELLOW="" C_BLUE="" C_BOLD=""
fi

usage() {
  cat <<'USAGE'
REKON - reconocimiento y enumeracion profesional para laboratorios autorizados

Uso interactivo:
  ./rekon.sh

Uso no interactivo:
  ./rekon.sh -t lab.example -w /usr/share/wordlists \
    -p balanced --accept-authorized-use --non-interactive

Opciones:
  -t, --target VALOR          IPv4, IPv6, hostname o FQDN exacto (no CIDR)
  -w, --wordlists DIR         Raiz que contiene diccionarios
  -o, --output DIR            Directorio base de resultados
  -p, --profile PERFIL        passive | balanced | deep
      --threads N             Sobrescribe concurrencia del perfil
      --rate N                Peticiones/paquetes por segundo maximos
      --max-hosts N           Maximo de hosts descubiertos que se procesan
      --tcp-ports ESPEC       top50|top100|top200|top1000|all|LISTA|none
      --udp-ports ESPEC       top50|top100|top200|top1000|all|LISTA|none
      --install-deps          Instala las dependencias que falten antes del recon
      --no-install            No pregunta ni instala dependencias
      --sudo-scans            Autoriza sudo para SYN, UDP y deteccion de SO
      --no-sudo-scans         Fuerza TCP connect y omite UDP privilegiado
      --no-external-osint     No enviar el dominio a fuentes pasivas externas
      --only LISTA            Solo modulos indicados, separados por comas
      --skip LISTA            Omite modulos indicados, separados por comas
      --resume DIR            Reanuda un directorio de ejecucion existente
      --dry-run               Plan completo sin emitir trafico de red
      --non-interactive       No solicitar datos por consola
      --accept-authorized-use Confirma laboratorio/alcance autorizado
      --doctor                Inventario de dependencias y salida
      --self-test             Pruebas internas sin red
      --no-color              Desactiva colores
  -h, --help                  Ayuda
  -V, --version               Version

Modulos:
  target, passive, dns, ports, services, http, crawl, fuzz, tls,
  observations, screenshots, report

Limites deliberados:
  - No acepta CIDR, rangos ni listas de objetivos.
  - Solo usa GET/HEAD para descubrimiento web.
  - No realiza fuerza bruta de credenciales, explotacion, DoS ni OAST.
USAGE
}

now_iso() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

log() {
  local level=$1 color=$2
  shift 2
  printf '%s[%s] %-5s%s %s\n' "$color" "$(now_iso)" "$level" "$C_RESET" "$*" >&2
  if [[ -n ${EXECUTION_LOG:-} ]]; then
    printf '%s\t%s\t%s\n' "$(now_iso)" "$level" "$*" >>"$EXECUTION_LOG" 2>/dev/null || true
  fi
}

info() { log INFO "$C_BLUE" "$*"; }
ok() { log OK "$C_GREEN" "$*"; }
warn() { log WARN "$C_YELLOW" "$*"; }
die() { log ERROR "$C_RED" "$*"; exit 1; }

parse_positive_int() {
  [[ $1 =~ ^[1-9][0-9]*$ ]] || die "Se esperaba un entero positivo: $1"
}

valid_port_spec() {
  local spec=${1,,} part start end
  local -a parts=()
  ((${#spec} <= 4096)) || return 1
  case "$spec" in
    none|all|top50|top100|top200|top1000) return 0 ;;
  esac
  [[ $spec =~ ^[0-9,-]+$ ]] || return 1
  [[ $spec != ,* && $spec != *, && $spec != *,,* ]] || return 1
  IFS=, read -r -a parts <<<"$spec"
  ((${#parts[@]} > 0)) || return 1
  for part in "${parts[@]}"; do
    if [[ $part =~ ^([0-9]+)-([0-9]+)$ ]]; then
      ((${#BASH_REMATCH[1]} <= 5 && ${#BASH_REMATCH[2]} <= 5)) || return 1
      start=$((10#${BASH_REMATCH[1]})); end=$((10#${BASH_REMATCH[2]}))
      ((start >= 1 && end <= 65535 && start <= end)) || return 1
    elif [[ $part =~ ^[0-9]+$ ]]; then
      ((${#part} <= 5)) || return 1
      start=$((10#$part)); ((start >= 1 && start <= 65535)) || return 1
    else
      return 1
    fi
  done
}

parse_args() {
  while (($#)); do
    case "$1" in
      -t|--target) (($# >= 2)) || die "Falta valor para $1"; TARGET=$2; shift 2 ;;
      -w|--wordlists) (($# >= 2)) || die "Falta valor para $1"; WORDLIST_ROOT=$2; shift 2 ;;
      -o|--output) (($# >= 2)) || die "Falta valor para $1"; OUTPUT_BASE=$2; shift 2 ;;
      -p|--profile) (($# >= 2)) || die "Falta valor para $1"; PROFILE=${2,,}; shift 2 ;;
      --threads) (($# >= 2)) || die "Falta valor para $1"; parse_positive_int "$2"; THREADS_OVERRIDE=$2; shift 2 ;;
      --rate) (($# >= 2)) || die "Falta valor para $1"; parse_positive_int "$2"; RATE_OVERRIDE=$2; shift 2 ;;
      --max-hosts) (($# >= 2)) || die "Falta valor para $1"; parse_positive_int "$2"; MAX_HOSTS_OVERRIDE=$2; shift 2 ;;
      --tcp-ports) (($# >= 2)) || die "Falta valor para $1"; valid_port_spec "$2" || die "Especificacion TCP no valida: $2"; TCP_PORTS_OVERRIDE=${2,,}; shift 2 ;;
      --udp-ports) (($# >= 2)) || die "Falta valor para $1"; valid_port_spec "$2" || die "Especificacion UDP no valida: $2"; UDP_PORTS_OVERRIDE=${2,,}; shift 2 ;;
      --install-deps) INSTALL_MODE="yes"; shift ;;
      --no-install) INSTALL_MODE="no"; shift ;;
      --sudo-scans) PRIVILEGED_SCAN_MODE="yes"; shift ;;
      --no-sudo-scans) PRIVILEGED_SCAN_MODE="no"; shift ;;
      --no-external-osint) EXTERNAL_OSINT=0; shift ;;
      --only) (($# >= 2)) || die "Falta valor para $1"; ONLY_MODULES=${2,,}; shift 2 ;;
      --skip) (($# >= 2)) || die "Falta valor para $1"; SKIP_MODULES=${2,,}; shift 2 ;;
      --resume) (($# >= 2)) || die "Falta valor para $1"; RESUME=1; RESUME_DIR=$2; shift 2 ;;
      --dry-run) DRY_RUN=1; shift ;;
      --non-interactive) NON_INTERACTIVE=1; shift ;;
      --accept-authorized-use) ACCEPT_AUTHORIZED_USE=1; shift ;;
      --doctor) DOCTOR_ONLY=1; shift ;;
      --self-test) SELF_TEST=1; shift ;;
      --no-color) NO_COLOR=1; shift ;;
      -h|--help) usage; exit 0 ;;
      -V|--version) printf '%s %s\n' "$REKON_NAME" "$REKON_VERSION"; exit 0 ;;
      --) shift; break ;;
      *) die "Opcion desconocida: $1" ;;
    esac
  done
}

configure_colors() {
  if ((NO_COLOR)); then
    C_RESET="" C_RED="" C_GREEN="" C_YELLOW="" C_BLUE="" C_BOLD=""
  fi
}

configure_profile() {
  case "$PROFILE" in
    passive)
      THREADS=8 RATE=10 MAX_HOSTS=50 MAX_WEB_TARGETS=10 CRAWL_DEPTH=1
      FFUF_MAXTIME=0 STEP_TIMEOUT=600 DNS_WL_LIMIT=0 DIR_WL_LIMIT=0
      FILE_WL_LIMIT=0 PARAM_WL_LIMIT=0 RESOLVER_WL_LIMIT=0
      TCP_PORT_SPEC="none" UDP_PORT_SPEC="none"
      ENABLE_ACTIVE=0 ENABLE_FUZZ=0 ENABLE_SAFE_NUCLEI=0
      FFUF_RECURSION_DEPTH=0
      ;;
    balanced)
      THREADS=20 RATE=50 MAX_HOSTS=100 MAX_WEB_TARGETS=25 CRAWL_DEPTH=3
      FFUF_MAXTIME=600 STEP_TIMEOUT=1800 DNS_WL_LIMIT=20000 DIR_WL_LIMIT=50000
      FILE_WL_LIMIT=50000 PARAM_WL_LIMIT=10000 RESOLVER_WL_LIMIT=5000
      TCP_PORT_SPEC="top1000" UDP_PORT_SPEC="top50"
      ENABLE_ACTIVE=1 ENABLE_FUZZ=1 ENABLE_SAFE_NUCLEI=1
      FFUF_RECURSION_DEPTH=0
      ;;
    deep)
      THREADS=35 RATE=100 MAX_HOSTS=300 MAX_WEB_TARGETS=75 CRAWL_DEPTH=5
      FFUF_MAXTIME=1800 STEP_TIMEOUT=7200 DNS_WL_LIMIT=100000 DIR_WL_LIMIT=200000
      FILE_WL_LIMIT=200000 PARAM_WL_LIMIT=30000 RESOLVER_WL_LIMIT=20000
      TCP_PORT_SPEC="all" UDP_PORT_SPEC="top200"
      ENABLE_ACTIVE=1 ENABLE_FUZZ=1 ENABLE_SAFE_NUCLEI=1
      FFUF_RECURSION_DEPTH=2
      ;;
    *) die "Perfil no valido: $PROFILE (passive, balanced o deep)" ;;
  esac

  [[ -n $THREADS_OVERRIDE ]] && THREADS=$THREADS_OVERRIDE
  [[ -n $RATE_OVERRIDE ]] && RATE=$RATE_OVERRIDE
  [[ -n $MAX_HOSTS_OVERRIDE ]] && MAX_HOSTS=$MAX_HOSTS_OVERRIDE
  [[ -n $TCP_PORTS_OVERRIDE ]] && TCP_PORT_SPEC=$TCP_PORTS_OVERRIDE
  [[ -n $UDP_PORTS_OVERRIDE ]] && UDP_PORT_SPEC=$UDP_PORTS_OVERRIDE

  ((THREADS <= 200)) || die "--threads no puede superar 200"
  ((RATE <= 10000)) || die "--rate no puede superar 10000"
  ((MAX_HOSTS <= 5000)) || die "--max-hosts no puede superar 5000"
}

valid_ipv4() {
  local ip=$1 octet
  local -a octets=()
  [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS=. read -r -a octets <<<"$ip"
  for octet in "${octets[@]}"; do
    ((10#$octet <= 255)) || return 1
  done
}

valid_ipv6() {
  local ip=$1
  [[ $ip == *:* && $ip != *%* && $ip =~ ^[0-9A-Fa-f:.]+$ ]] || return 1
  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import ipaddress,sys; sys.exit(0 if ipaddress.ip_address(sys.argv[1]).version == 6 else 1)' "$ip" 2>/dev/null
  else
    [[ $ip == *:*:* ]]
  fi
}

valid_hostname() {
  local host=$1 label
  local -a labels=()
  ((${#host} >= 1 && ${#host} <= 253)) || return 1
  [[ $host =~ ^[A-Za-z0-9.-]+$ ]] || return 1
  [[ $host != .* && $host != *. && $host != *..* ]] || return 1
  IFS=. read -r -a labels <<<"$host"
  for label in "${labels[@]}"; do
    ((${#label} >= 1 && ${#label} <= 63)) || return 1
    [[ $label =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]] || return 1
  done
}

classify_target() {
  local value=$1
  [[ -n $value ]] || return 1
  [[ $value != *[[:space:]]* && $value != */* && $value != *,* && $value != *\** ]] || return 1
  [[ $value != *://* && $value != *'?'* && $value != *'#'* && $value != *'@'* ]] || return 1
  value=${value%.}
  if [[ $value =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    valid_ipv4 "$value" || return 1
    TARGET_TYPE="ipv4"
  elif [[ $value == *:* ]]; then
    valid_ipv6 "$value" || return 1
    TARGET_TYPE="ipv6"
  elif valid_hostname "$value"; then
    if [[ $value == *.* ]]; then TARGET_TYPE="fqdn"; else TARGET_TYPE="hostname"; fi
  else
    return 1
  fi
  TARGET=${value,,}
}

interactive_inputs() {
  if [[ -z $TARGET ]]; then
    ((NON_INTERACTIVE)) && die "Falta --target en modo no interactivo"
    read -r -p "Objetivo exacto (IPv4, IPv6, hostname o FQDN): " TARGET
  fi
  classify_target "$TARGET" || die "Objetivo no valido. No se admiten URL, CIDR, rangos, listas ni comodines."

  if [[ -z $WORDLIST_ROOT ]]; then
    ((NON_INTERACTIVE)) && die "Falta --wordlists en modo no interactivo"
    read -r -e -p "Directorio raiz de diccionarios (/usr/share/seclists): " WORDLIST_ROOT
    [[ -n $WORDLIST_ROOT ]] || WORDLIST_ROOT="/usr/share/seclists"
  fi

  if [[ -z ${PROFILE:-} ]]; then PROFILE="balanced"; fi
  if ((NON_INTERACTIVE == 0)) && [[ $PROFILE == balanced ]]; then
    local selected
    read -r -p "Perfil [passive/balanced/deep] (balanced): " selected
    [[ -n $selected ]] && PROFILE=${selected,,}
  fi
}

resolve_wordlist_root() {
  [[ -d $WORDLIST_ROOT && -r $WORDLIST_ROOT ]] || die "Directorio de diccionarios no accesible tras instalar dependencias: $WORDLIST_ROOT"
  WORDLIST_ROOT=$(cd -- "$WORDLIST_ROOT" && pwd -P)
  printf '%s\n' "$WORDLIST_ROOT" >"$META_DIR/wordlist-root.txt"
}

confirm_authorization() {
  ((ACCEPT_AUTHORIZED_USE)) && return 0
  if ((NON_INTERACTIVE)); then
    die "En modo no interactivo debes incluir --accept-authorized-use"
  fi
  printf '\n%sUso autorizado exclusivamente%s\n' "$C_BOLD" "$C_RESET"
  printf 'REKON emitira trafico de enumeracion contra el objetivo exacto y sus subdominios.\n'
  printf 'Confirma que es un laboratorio propio/autorizado escribiendo: LAB AUTORIZADO\n'
  local answer
  read -r -p "> " answer
  [[ $answer == "LAB AUTORIZADO" ]] || die "Autorizacion no confirmada; no se ha ejecutado ningun reconocimiento."
}

safe_slug() {
  local value=${1,,}
  value=${value//:/_}
  value=${value//./_}
  value=${value//[^a-z0-9_-]/_}
  printf '%.80s' "$value"
}

init_run() {
  TARGET_SLUG=$(safe_slug "$TARGET")
  if [[ $TARGET_TYPE == ipv6 ]]; then URL_TARGET="[$TARGET]"; else URL_TARGET=$TARGET; fi
  if [[ $TARGET_TYPE == fqdn || $TARGET_TYPE == hostname ]]; then SCOPE_DOMAIN=$TARGET; fi

  if ((RESUME)); then
    [[ -d $RESUME_DIR ]] || die "No existe el directorio de reanudacion: $RESUME_DIR"
    RUN_DIR=$(cd -- "$RESUME_DIR" && pwd -P)
    if [[ -s $RUN_DIR/00-meta/target.txt ]]; then
      local previous_target
      previous_target=$(<"$RUN_DIR/00-meta/target.txt")
      [[ $previous_target == "$TARGET" ]] || die "El directorio pertenece a otro objetivo: $previous_target"
    fi
  else
    mkdir -p -- "$OUTPUT_BASE"
    OUTPUT_BASE=$(cd -- "$OUTPUT_BASE" && pwd -P)
    RUN_DIR="$OUTPUT_BASE/${TARGET_SLUG}_$(date -u +%Y%m%dT%H%M%SZ)"
    mkdir -p "$RUN_DIR"
  fi

  META_DIR="$RUN_DIR/00-meta"
  TARGET_DIR="$RUN_DIR/01-target"
  PASSIVE_DIR="$RUN_DIR/02-passive"
  DNS_DIR="$RUN_DIR/03-dns"
  PORTS_DIR="$RUN_DIR/04-ports"
  SERVICES_DIR="$RUN_DIR/05-services"
  HTTP_DIR="$RUN_DIR/06-http"
  CRAWL_DIR="$RUN_DIR/07-crawl"
  FUZZ_DIR="$RUN_DIR/08-fuzzing"
  TLS_DIR="$RUN_DIR/09-tls"
  OBS_DIR="$RUN_DIR/10-observations"
  REPORT_DIR="$RUN_DIR/report"
  LOG_DIR="$RUN_DIR/logs"
  STATE_DIR="$RUN_DIR/state"
  mkdir -p "$META_DIR/wordlists" "$TARGET_DIR" "$PASSIVE_DIR" "$DNS_DIR" "$PORTS_DIR" \
    "$SERVICES_DIR" "$HTTP_DIR/headers" "$CRAWL_DIR" "$FUZZ_DIR" "$TLS_DIR" \
    "$OBS_DIR" "$REPORT_DIR" "$LOG_DIR" "$STATE_DIR"

  COMMAND_LOG="$LOG_DIR/commands.tsv"
  EXECUTION_LOG="$LOG_DIR/execution.log"
  MODULE_STATUS_FILE="$META_DIR/modules.tsv"
  SCAN_TARGETS="$META_DIR/scan-targets.txt"
  LIVE_URLS="$HTTP_DIR/live-urls.txt"
  touch "$COMMAND_LOG" "$EXECUTION_LOG" "$MODULE_STATUS_FILE"
  if [[ ! -s $COMMAND_LOG ]]; then printf 'started_at\tended_at\tduration_s\tstatus\tstep\tcommand\n' >"$COMMAND_LOG"; fi
  if [[ ! -s $MODULE_STATUS_FILE ]]; then printf 'module\tstatus\ttimestamp\n' >"$MODULE_STATUS_FILE"; fi

  printf '%s\n' "$TARGET" >"$META_DIR/target.txt"
  printf '%s\n' "$TARGET_TYPE" >"$META_DIR/target-type.txt"
  printf '%s\n' "$PROFILE" >"$META_DIR/profile.txt"
  printf '%s\n' "$WORDLIST_ROOT" >"$META_DIR/wordlist-root.txt"
  printf '%s\n' "$REKON_VERSION" >"$META_DIR/rekon-version.txt"
  printf '%s\n' "$TARGET" >"$SCAN_TARGETS"
}

format_command() {
  local item out=""
  for item in "$@"; do
    printf -v item '%q' "$item"
    out+="$item "
  done
  printf '%s' "${out% }"
}

run_cmd() {
  local step=$1 outfile=$2 errfile=$3 timeout_s=$4
  shift 4
  local stdin_file=""
  if [[ ${1:-} == --stdin ]]; then
    (($# >= 3)) || { warn "Invocacion interna sin comando para $step"; return 2; }
    stdin_file=$2
    shift 2
  fi
  local -a cmd=("$@")
  local started ended duration rc command_text
  mkdir -p "$(dirname "$outfile")" "$(dirname "$errfile")"
  : >"$outfile"
  : >"$errfile"
  command_text=$(format_command "${cmd[@]}")
  if [[ -n $stdin_file ]]; then
    local quoted_stdin
    printf -v quoted_stdin '%q' "$stdin_file"
    command_text+=" < $quoted_stdin"
  fi
  started=$(now_iso)
  info "$step"

  if ((DRY_RUN)); then
    printf '%s\t%s\t0\tPLANNED\t%s\t%s\n' "$started" "$started" "$step" "$command_text" >>"$COMMAND_LOG"
    printf '[DRY-RUN] %s\n' "$command_text" >"$outfile"
    return 0
  fi

  local start_epoch end_epoch
  start_epoch=$(date +%s)
  set +e
  if command -v timeout >/dev/null 2>&1; then
    if [[ -n $stdin_file ]]; then
      timeout --foreground --signal=TERM --kill-after=10s "${timeout_s}s" "${cmd[@]}" <"$stdin_file" >"$outfile" 2>"$errfile"
    else
      timeout --foreground --signal=TERM --kill-after=10s "${timeout_s}s" "${cmd[@]}" >"$outfile" 2>"$errfile"
    fi
    rc=$?
  else
    if [[ -n $stdin_file ]]; then
      "${cmd[@]}" <"$stdin_file" >"$outfile" 2>"$errfile"
    else
      "${cmd[@]}" >"$outfile" 2>"$errfile"
    fi
    rc=$?
  fi
  set -e
  end_epoch=$(date +%s)
  ended=$(now_iso)
  duration=$((end_epoch - start_epoch))
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$started" "$ended" "$duration" "$rc" "$step" "$command_text" >>"$COMMAND_LOG"
  if ((rc == 0)); then
    ok "$step completado (${duration}s)"
  elif ((rc == 124 || rc == 137)); then
    warn "$step alcanzo el tiempo limite (${timeout_s}s)"
  else
    warn "$step termino con codigo $rc; consulta $errfile"
  fi
  return "$rc"
}

choose_install_mode() {
  [[ $INSTALL_MODE == ask ]] || return 0
  if ((NON_INTERACTIVE)); then
    INSTALL_MODE="no"
    info "Instalacion automatica desactivada en modo no interactivo; usa --install-deps para autorizarla"
    return 0
  fi
  local tool missing=0 answer
  local -a expected=(curl jq dig whois nmap subfinder dnsx naabu httpx katana nuclei ffuf gobuster feroxbuster arjun)
  for tool in "${expected[@]}"; do command -v "$tool" >/dev/null 2>&1 || ((missing+=1)); done
  if ((missing == 0)); then
    INSTALL_MODE="no"
    info "La pila principal de herramientas ya esta disponible"
    return 0
  fi
  printf '\nFaltan %s herramientas de la pila recomendada.\n' "$missing"
  printf 'La instalacion usa el gestor del sistema, PDTM/Go y pipx; puede solicitar sudo.\n'
  read -r -p "¿Instalar ahora las dependencias que falten? [S/n]: " answer
  case "${answer,,}" in n|no) INSTALL_MODE="no" ;; *) INSTALL_MODE="yes" ;; esac
}

prepare_install_privilege() {
  INSTALL_PRIV_PREFIX=()
  ((EUID == 0)) && return 0
  if ((DRY_RUN)); then
    INSTALL_PRIV_PREFIX=(sudo)
    return 0
  fi
  command -v sudo >/dev/null 2>&1 || { warn "No hay sudo; se omiten los paquetes del sistema"; return 1; }
  INSTALL_PRIV_PREFIX=(sudo)
  run_cmd "Validacion de privilegios para instalar" "$LOG_DIR/sudo-install.stdout" "$LOG_DIR/sudo-install.err" 120 sudo -v
}

install_apt_requirements() {
  local -a requested=(
    bash coreutils curl jq dnsutils whois nmap iputils-ping traceroute openssl
    ca-certificates git unzip build-essential python3 python3-venv python3-pip pipx
    golang-go libpcap-dev openssh-client amass assetfinder ffuf gobuster feroxbuster
    whatweb wafw00f sslscan seclists masscan testssl.sh smbclient ldap-utils
    nfs-common rpcbind dnsrecon massdns chromium pandoc
  )
  local -a available=()
  local package
  run_cmd "Actualizacion del indice APT" "$LOG_DIR/apt-update.stdout" "$LOG_DIR/apt-update.err" 1800 \
    "${INSTALL_PRIV_PREFIX[@]}" apt-get update || true
  if ((DRY_RUN)); then
    available=("${requested[@]}")
  else
    for package in "${requested[@]}"; do
      apt-cache show "$package" >/dev/null 2>&1 && available+=("$package")
    done
  fi
  ((${#available[@]} > 0)) || { warn "APT no encontro paquetes compatibles"; return 0; }
  run_cmd "Instalacion de dependencias APT" "$LOG_DIR/apt-install.stdout" "$LOG_DIR/apt-install.err" 7200 \
    "${INSTALL_PRIV_PREFIX[@]}" env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${available[@]}" || true
}

install_dnf_requirements() {
  local -a packages=(bash coreutils curl jq bind-utils whois nmap iputils traceroute openssl ca-certificates git unzip python3 python3-pip pipx golang libpcap-devel openssh-clients masscan)
  run_cmd "Instalacion de dependencias DNF" "$LOG_DIR/dnf-install.stdout" "$LOG_DIR/dnf-install.err" 7200 \
    "${INSTALL_PRIV_PREFIX[@]}" dnf install -y "${packages[@]}" || true
}

install_pacman_requirements() {
  local -a packages=(bash coreutils curl jq bind whois nmap iputils traceroute openssl ca-certificates git unzip python python-pipx go libpcap openssh masscan)
  run_cmd "Instalacion de dependencias Pacman" "$LOG_DIR/pacman-install.stdout" "$LOG_DIR/pacman-install.err" 7200 \
    "${INSTALL_PRIV_PREFIX[@]}" pacman -Syu --needed --noconfirm "${packages[@]}" || true
}

install_go_tool() {
  local binary=$1 module=$2
  command -v "$binary" >/dev/null 2>&1 && return 0
  if ((DRY_RUN == 0)) && ! command -v go >/dev/null 2>&1; then
    warn "Go no esta disponible; no se puede instalar $binary"
    return 0
  fi
  run_cmd "Instalacion Go: $binary" "$LOG_DIR/install-go-$binary.stdout" "$LOG_DIR/install-go-$binary.err" 3600 \
    env GOBIN="$USER_BIN_DIR" go install "$module" || true
}

install_go_recon_stack() {
  local tool pdtm_bin pd_install_csv
  local -a pd_tools=(subfinder dnsx httpx naabu katana nuclei) pd_missing_tools=()
  for tool in "${pd_tools[@]}"; do
    if [[ $tool == httpx ]]; then
      installed_pd_httpx_ready || pd_missing_tools+=("$tool")
    else
      command -v "$tool" >/dev/null 2>&1 || pd_missing_tools+=("$tool")
    fi
  done
  if ((${#pd_missing_tools[@]} > 0)); then
    install_go_tool pdtm github.com/projectdiscovery/pdtm/cmd/pdtm@latest
    pdtm_bin=$(command -v pdtm 2>/dev/null || printf '%s/pdtm' "$USER_BIN_DIR")
    pd_install_csv=$(IFS=,; printf '%s' "${pd_missing_tools[*]}")
    if ((DRY_RUN)) || [[ -x $pdtm_bin ]]; then
      run_cmd "Instalacion ProjectDiscovery con PDTM" "$LOG_DIR/pdtm-install.stdout" "$LOG_DIR/pdtm-install.err" 7200 \
        "$pdtm_bin" -i "$pd_install_csv" -bp "$USER_BIN_DIR" -nc || true
    fi
  fi

  install_go_tool ffuf github.com/ffuf/ffuf/v2@latest
  install_go_tool gobuster github.com/OJ/gobuster/v3@latest
  install_go_tool assetfinder github.com/tomnomnom/assetfinder@latest
  install_go_tool gau github.com/lc/gau/v2/cmd/gau@latest
  install_go_tool waybackurls github.com/tomnomnom/waybackurls@latest
  install_go_tool hakrawler github.com/hakluke/hakrawler@latest
  install_go_tool gowitness github.com/sensepost/gowitness@latest
  install_go_tool puredns github.com/d3mondev/puredns/v2@latest
}

install_python_recon_stack() {
  command -v arjun >/dev/null 2>&1 && return 0
  if ((DRY_RUN == 0)) && ! command -v pipx >/dev/null 2>&1; then
    warn "pipx no esta disponible; no se puede instalar Arjun"
    return 0
  fi
  run_cmd "Instalacion Python aislada: Arjun" "$LOG_DIR/pipx-arjun.stdout" "$LOG_DIR/pipx-arjun.err" 1800 \
    env PIPX_BIN_DIR="$USER_BIN_DIR" pipx install arjun || true
}

install_requirements() {
  [[ $INSTALL_MODE == yes ]] || { info "Instalacion de dependencias omitida"; return 0; }
  info "Instalando dependencias antes de iniciar el reconocimiento"
  if ((DRY_RUN == 0)); then mkdir -p -- "$USER_BIN_DIR"; fi
  export PATH="$USER_BIN_DIR:$PATH"

  if command -v apt-get >/dev/null 2>&1; then
    if prepare_install_privilege; then install_apt_requirements; fi
  elif command -v dnf >/dev/null 2>&1; then
    if prepare_install_privilege; then install_dnf_requirements; fi
  elif command -v pacman >/dev/null 2>&1; then
    if prepare_install_privilege; then install_pacman_requirements; fi
  else
    warn "Gestor de paquetes no reconocido; se intentaran solo instalaciones de usuario"
  fi

  install_go_recon_stack
  install_python_recon_stack
  ok "Fase de instalacion finalizada; los fallos opcionales constan en logs/"
}

configure_scan_privileges() {
  SCAN_PRIV_PREFIX=()
  PRIVILEGED_SCANS=0
  if ((ENABLE_ACTIVE == 0)) || [[ $TCP_PORT_SPEC == none && $UDP_PORT_SPEC == none ]]; then
    {
      printf 'setting\tvalue\n'
      printf 'privileged_scans\t0\n'
      printf 'tcp_ports\t%s\n' "$TCP_PORT_SPEC"
      printf 'udp_ports\t%s\n' "$UDP_PORT_SPEC"
    } >"$META_DIR/scan-policy.tsv"
    return 0
  fi
  if [[ $PRIVILEGED_SCAN_MODE == ask ]]; then
    if ((EUID == 0)); then
      PRIVILEGED_SCAN_MODE="yes"
    elif ((NON_INTERACTIVE)); then
      PRIVILEGED_SCAN_MODE="no"
    else
      local answer
      printf '\nLos escaneos SYN/UDP y la deteccion de SO requieren privilegios raw.\n'
      read -r -p "¿Autorizar sudo exclusivamente para esos escaneos? [s/N]: " answer
      case "${answer,,}" in s|si|sí|y|yes) PRIVILEGED_SCAN_MODE="yes" ;; *) PRIVILEGED_SCAN_MODE="no" ;; esac
    fi
  fi

  if [[ $PRIVILEGED_SCAN_MODE == yes ]]; then
    if ((EUID == 0)); then
      PRIVILEGED_SCANS=1
    elif ((DRY_RUN)); then
      PRIVILEGED_SCANS=1; SCAN_PRIV_PREFIX=(sudo)
    elif command -v sudo >/dev/null 2>&1; then
      SCAN_PRIV_PREFIX=(sudo)
      if run_cmd "Validacion de privilegios para escaneos raw" "$LOG_DIR/sudo-scan.stdout" "$LOG_DIR/sudo-scan.err" 120 sudo -v; then
        PRIVILEGED_SCANS=1
      else
        SCAN_PRIV_PREFIX=()
        warn "No se pudieron obtener privilegios; se usara TCP connect y se omitira UDP"
      fi
    else
      warn "sudo no esta disponible; se usara TCP connect y se omitira UDP"
    fi
  fi
  {
    printf 'setting\tvalue\n'
    printf 'privileged_scans\t%s\n' "$PRIVILEGED_SCANS"
    printf 'tcp_ports\t%s\n' "$TCP_PORT_SPEC"
    printf 'udp_ports\t%s\n' "$UDP_PORT_SPEC"
  } >"$META_DIR/scan-policy.tsv"
}

tool_ready() {
  ((DRY_RUN)) && return 0
  command -v "$1" >/dev/null 2>&1
}

installed_pd_httpx_ready() {
  command -v httpx >/dev/null 2>&1 || return 1
  timeout 5 httpx -version 2>&1 | grep -Eqi 'projectdiscovery|current version|httpx version'
}

pd_httpx_ready() {
  ((DRY_RUN)) && return 0
  installed_pd_httpx_ready
}

doctor() {
  local output=${1:-/dev/stdout}
  local -a tools=(bash timeout curl jq dig host getent whois ping traceroute tracepath nmap masscan naabu subfinder assetfinder amass findomain dnsrecon dnsx puredns massdns gobuster httpx katana gau waybackurls hakrawler ffuf feroxbuster arjun whatweb wafw00f nuclei testssl.sh testssl sslscan openssl gowitness rpcinfo showmount smbclient ldapsearch python3 pipx go pdtm pandoc)
  local tool status path note
  {
    printf 'tool\tstatus\tpath_or_note\n'
    for tool in "${tools[@]}"; do
      note=""
      if command -v "$tool" >/dev/null 2>&1; then
        status="OK"; path=$(command -v "$tool")
        if [[ $tool == httpx ]] && ! installed_pd_httpx_ready; then
          status="WARN"; note="parece ser el paquete Python, no ProjectDiscovery"
        fi
        printf '%s\t%s\t%s%s\n' "$tool" "$status" "$path" "${note:+ ($note)}"
      else
        printf '%s\tMISSING\t-\n' "$tool"
      fi
    done
  } >"$output"
}

inventory_wordlists() {
  local path base size lower
  WL_PATHS=() WL_NAMES=() WL_SIZES=()
  info "Inventariando diccionarios bajo $WORDLIST_ROOT"
  while IFS= read -r -d '' path; do
    [[ $path != *$'\n'* && $path != *$'\t'* ]] || continue
    base=${path##*/}
    lower=${base,,}
    case "$lower" in
      *.txt|*.lst|*.dic|*.wordlist|*.words) ;;
      *) continue ;;
    esac
    size=$(stat -c '%s' "$path" 2>/dev/null || printf '0')
    ((size >= 20 && size <= 536870912)) || continue
    WL_PATHS+=("$path") WL_NAMES+=("$lower") WL_SIZES+=("$size")
  done < <(find -L "$WORDLIST_ROOT" -type f -readable -print0 2>/dev/null)
  ((${#WL_PATHS[@]} > 0)) || warn "No se encontraron diccionarios de texto compatibles"
  printf 'path\tsize_bytes\n' >"$META_DIR/wordlist-inventory.tsv"
  local i
  for ((i=0; i<${#WL_PATHS[@]}; i++)); do
    printf '%s\t%s\n' "${WL_PATHS[i]}" "${WL_SIZES[i]}" >>"$META_DIR/wordlist-inventory.tsv"
  done
}

wordlist_score() {
  local role=$1 path=${2,,} name=${3,,} size=$4 score=0
  if [[ $path == *password* || $path == *rockyou* || $path == *credential* || $path == *hashes* || $path == *leak* ]]; then
    printf '%s' -100000; return
  fi
  case "$role" in
    subdomains|vhosts)
      [[ $path == *dns* ]] && ((score+=25))
      [[ $path == *subdomain* ]] && ((score+=45))
      [[ $path == *discovery* ]] && ((score+=10))
      [[ $name == *subdomains-top1million-20000* ]] && ((score+=160))
      [[ $name == *subdomains-top1million-110000* ]] && ((score+=145))
      [[ $name == *dns-jhaddix* ]] && ((score+=150))
      [[ $name == *bitquark* ]] && ((score+=120))
      [[ $name == *namelist* ]] && ((score+=55))
      ;;
    dirs)
      [[ $path == *web-content* || $path == *web_content* ]] && ((score+=35))
      [[ $name == *raft-medium-directories* ]] && ((score+=180))
      [[ $name == *directory-list-2.3-medium* ]] && ((score+=170))
      [[ $name == *directories* ]] && ((score+=80))
      [[ $name == common.txt ]] && ((score+=65))
      ;;
    files)
      [[ $path == *web-content* || $path == *web_content* ]] && ((score+=35))
      [[ $name == *raft-medium-files* ]] && ((score+=180))
      [[ $name == *raft-medium-words* ]] && ((score+=130))
      [[ $name == *files* ]] && ((score+=80))
      [[ $name == *quickhits* ]] && ((score+=70))
      ;;
    params)
      [[ $name == *burp-parameter-names* ]] && ((score+=190))
      [[ $name == *parameter* ]] && ((score+=115))
      [[ $name == *params* ]] && ((score+=100))
      ;;
    resolvers)
      [[ $name == resolvers.txt ]] && ((score+=200))
      [[ $name == *resolver* ]] && ((score+=150))
      [[ $name == *public-dns* || $name == *public_dns* ]] && ((score+=120))
      [[ $path == *dnsvalidator* || $path == *dns-validator* ]] && ((score+=80))
      ;;
  esac
  ((size < 200)) && ((score-=50))
  if ((score > 0)) && [[ $PROFILE == balanced ]]; then
    ((size >= 1000 && size <= 20000000)) && ((score+=20))
    ((size > 100000000)) && ((score-=30))
  elif ((score > 0)) && [[ $PROFILE == deep ]]; then
    ((size >= 10000)) && ((score+=25))
  fi
  printf '%s' "$score"
}

pick_wordlist() {
  local role=$1 best_score=-100001 best_path="" i score
  for ((i=0; i<${#WL_PATHS[@]}; i++)); do
    score=$(wordlist_score "$role" "${WL_PATHS[i]}" "${WL_NAMES[i]}" "${WL_SIZES[i]}")
    if ((score > best_score)); then best_score=$score; best_path=${WL_PATHS[i]}; fi
  done
  if ((best_score <= 0)); then printf '%s' ""; else printf '%s' "$best_path"; fi
}

prepare_wordlist() {
  local role=$1 source=$2 limit=$3 destination
  destination="$META_DIR/wordlists/$role.txt"
  [[ -n $source && -r $source && $limit -gt 0 ]] || { printf '%s' ""; return; }
  awk -v max="$limit" '
    { sub(/\r$/, "") }
    /^[[:space:]]*($|#)/ { next }
    { print; count++; if (count >= max) exit }
  ' "$source" >"$destination"
  [[ -s $destination ]] || { rm -f "$destination"; printf '%s' ""; return; }
  printf '%s' "$destination"
}

select_wordlists() {
  inventory_wordlists
  local src_sub src_vhost src_dirs src_files src_params src_resolvers
  src_sub=$(pick_wordlist subdomains)
  src_vhost=$(pick_wordlist vhosts)
  src_dirs=$(pick_wordlist dirs)
  src_files=$(pick_wordlist files)
  src_params=$(pick_wordlist params)
  src_resolvers=$(pick_wordlist resolvers)

  WL_SUBDOMAINS=$(prepare_wordlist subdomains "$src_sub" "$DNS_WL_LIMIT")
  WL_VHOSTS=$(prepare_wordlist vhosts "$src_vhost" "$DNS_WL_LIMIT")
  WL_DIRS=$(prepare_wordlist directories "$src_dirs" "$DIR_WL_LIMIT")
  WL_FILES=$(prepare_wordlist files "$src_files" "$FILE_WL_LIMIT")
  WL_PARAMS=$(prepare_wordlist parameters "$src_params" "$PARAM_WL_LIMIT")
  WL_RESOLVERS=$(prepare_wordlist resolvers "$src_resolvers" "$RESOLVER_WL_LIMIT")

  printf 'role\tsource\tprepared\tlines\n' >"$META_DIR/selected-wordlists.tsv"
  local role source prepared lines
  for role in subdomains vhosts directories files parameters resolvers; do
    case "$role" in
      subdomains) source=$src_sub; prepared=$WL_SUBDOMAINS ;;
      vhosts) source=$src_vhost; prepared=$WL_VHOSTS ;;
      directories) source=$src_dirs; prepared=$WL_DIRS ;;
      files) source=$src_files; prepared=$WL_FILES ;;
      parameters) source=$src_params; prepared=$WL_PARAMS ;;
      resolvers) source=$src_resolvers; prepared=$WL_RESOLVERS ;;
    esac
    lines=0; [[ -n $prepared && -f $prepared ]] && lines=$(wc -l <"$prepared")
    printf '%s\t%s\t%s\t%s\n' "$role" "${source:--}" "${prepared:--}" "$lines" >>"$META_DIR/selected-wordlists.tsv"
    if [[ -n $prepared ]]; then ok "Diccionario $role: $source ($lines entradas)"; else warn "Sin diccionario adecuado para $role"; fi
  done
}

in_scope_host() {
  local host=${1,,}
  host=${host%.}
  if [[ $TARGET_TYPE == ipv4 || $TARGET_TYPE == ipv6 ]]; then
    [[ $host == "$TARGET" ]]
  else
    [[ $host == "$SCOPE_DOMAIN" || $host == *."$SCOPE_DOMAIN" ]]
  fi
}

special_use_domain() {
  local domain=${1,,}
  case "$domain" in
    localhost|*.localhost|*.local|*.internal|*.lan|*.home|*.home.arpa|*.test|*.invalid|*.example|example.com|*.example.com|example.net|*.example.net|example.org|*.example.org|*.onion|*.corp|*.intranet) return 0 ;;
    *) return 1 ;;
  esac
}

normalize_hosts() {
  local input=$1 output=$2 host
  : >"$output"
  while IFS= read -r host; do
    host=${host//$'\r'/}
    [[ $host == "Found: "* ]] && host=${host#Found: }
    host=${host#\*.}
    host=${host%%[[:space:]]*}
    host=${host,,}
    [[ -n $host ]] || continue
    if in_scope_host "$host"; then
      printf '%s\n' "$host"
    fi
  done <"$input" | LC_ALL=C sort -u | awk -v max="$MAX_HOSTS" 'NR <= max' >"$output"
}

module_enabled() {
  local module=$1
  if [[ -n $ONLY_MODULES && ",${ONLY_MODULES}," != *",${module},"* ]]; then return 1; fi
  if [[ -n $SKIP_MODULES && ",${SKIP_MODULES}," == *",${module},"* ]]; then return 1; fi
  return 0
}

run_module() {
  local module=$1 function=$2 marker
  marker="$STATE_DIR/$module.done"
  if ! module_enabled "$module"; then
    info "Modulo $module omitido por seleccion"
    printf '%s\tSKIPPED\t%s\n' "$module" "$(now_iso)" >>"$MODULE_STATUS_FILE"
    return 0
  fi
  if ((RESUME)) && [[ -f $marker ]]; then
    info "Modulo $module ya completado; se reutiliza"
    printf '%s\tRESUMED\t%s\n' "$module" "$(now_iso)" >>"$MODULE_STATUS_FILE"
    return 0
  fi
  info "===== MODULO: $module ====="
  if "$function"; then
    touch "$marker"
    printf '%s\tOK\t%s\n' "$module" "$(now_iso)" >>"$MODULE_STATUS_FILE"
  else
    printf '%s\tFAILED\t%s\n' "$module" "$(now_iso)" >>"$MODULE_STATUS_FILE"
    warn "Modulo $module finalizo con incidencias"
  fi
}

module_target() {
  local out err record
  if tool_ready getent; then
    run_cmd "Resolucion del objetivo" "$TARGET_DIR/getent.txt" "$LOG_DIR/getent.err" 30 getent ahosts "$TARGET" || true
  fi
  if tool_ready dig; then
    if [[ $TARGET_TYPE == ipv4 || $TARGET_TYPE == ipv6 ]]; then
      run_cmd "DNS inverso" "$TARGET_DIR/reverse-dns.txt" "$LOG_DIR/reverse-dns.err" 30 dig +noall +answer -x "$TARGET" || true
    else
      for record in A AAAA CNAME MX NS SOA TXT CAA SRV; do
        out="$TARGET_DIR/dns-${record,,}.txt"; err="$LOG_DIR/dns-${record,,}.err"
        run_cmd "DNS $record" "$out" "$err" 30 dig +nocmd "$TARGET" "$record" +noall +answer || true
      done
    fi
  fi
  if tool_ready whois; then
    run_cmd "WHOIS/RIR" "$TARGET_DIR/whois.txt" "$LOG_DIR/whois.err" 90 whois "$TARGET" || true
  fi
  if ((ENABLE_ACTIVE)); then
    if tool_ready ping; then
      local -a ping_family=()
      [[ $TARGET_TYPE == ipv6 ]] && ping_family=(-6)
      run_cmd "Comprobacion de alcance ICMP" "$TARGET_DIR/ping.txt" "$LOG_DIR/ping.err" 20 \
        ping "${ping_family[@]}" -c 3 -W 2 "$TARGET" || true
    fi
    if tool_ready traceroute; then
      local -a trace_family=()
      [[ $TARGET_TYPE == ipv6 ]] && trace_family=(-6)
      run_cmd "Ruta de red" "$TARGET_DIR/traceroute.txt" "$LOG_DIR/traceroute.err" 90 \
        traceroute "${trace_family[@]}" -n -m 20 -q 1 -w 2 "$TARGET" || true
    elif tool_ready tracepath; then
      run_cmd "Ruta de red" "$TARGET_DIR/tracepath.txt" "$LOG_DIR/tracepath.err" 90 \
        tracepath -n "$TARGET" || true
    fi
  fi
  return 0
}

module_passive() {
  local candidates="$PASSIVE_DIR/candidates.raw.txt"
  : >"$candidates"
  if [[ $TARGET_TYPE != fqdn ]]; then
    info "Enumeracion pasiva de subdominios no aplicable a $TARGET_TYPE"
    [[ $TARGET_TYPE == hostname ]] && printf '%s\n' "$TARGET" >"$PASSIVE_DIR/hosts.txt"
    return 0
  fi
  if ((EXTERNAL_OSINT == 0)) || special_use_domain "$SCOPE_DOMAIN"; then
    info "Fuentes pasivas externas omitidas para este dominio/ajuste"
    printf '%s\n' "$SCOPE_DOMAIN" >"$PASSIVE_DIR/hosts.txt"
    return 0
  fi

  local -a pids=()
  if tool_ready subfinder; then
    run_cmd "Subfinder pasivo" "$PASSIVE_DIR/subfinder.txt" "$LOG_DIR/subfinder.err" 600 subfinder -silent -d "$SCOPE_DOMAIN" -all & pids+=("$!")
  fi
  if tool_ready assetfinder; then
    run_cmd "Assetfinder pasivo" "$PASSIVE_DIR/assetfinder.txt" "$LOG_DIR/assetfinder.err" 600 assetfinder --subs-only "$SCOPE_DOMAIN" & pids+=("$!")
  fi
  if tool_ready amass; then
    run_cmd "Amass pasivo" "$PASSIVE_DIR/amass.txt" "$LOG_DIR/amass.err" 900 amass enum -passive -norecursive -d "$SCOPE_DOMAIN" & pids+=("$!")
  fi
  if tool_ready findomain; then
    run_cmd "Findomain pasivo" "$PASSIVE_DIR/findomain.txt" "$LOG_DIR/findomain.err" 600 findomain -q -t "$SCOPE_DOMAIN" & pids+=("$!")
  fi
  local pid
  for pid in "${pids[@]}"; do wait "$pid" || true; done

  if tool_ready curl && tool_ready jq; then
    run_cmd "Certificate Transparency (crt.sh)" "$PASSIVE_DIR/crtsh.json" "$LOG_DIR/crtsh.err" 90 \
      curl -fsS --max-time 80 "https://crt.sh/?q=%25.${SCOPE_DOMAIN}&output=json" || true
    if ((DRY_RUN == 0)) && [[ -s $PASSIVE_DIR/crtsh.json ]]; then
      jq -r '.[].name_value? // empty' "$PASSIVE_DIR/crtsh.json" 2>/dev/null >"$PASSIVE_DIR/crtsh.txt" || true
    else
      : >"$PASSIVE_DIR/crtsh.txt"
    fi
  fi

  printf '%s\n' "$SCOPE_DOMAIN" >>"$candidates"
  local file
  for file in "$PASSIVE_DIR"/subfinder.txt "$PASSIVE_DIR"/assetfinder.txt "$PASSIVE_DIR"/amass.txt "$PASSIVE_DIR"/findomain.txt "$PASSIVE_DIR"/crtsh.txt; do
    [[ -f $file ]] && cat "$file" >>"$candidates"
  done
  normalize_hosts "$candidates" "$PASSIVE_DIR/hosts.txt"
  ok "Hosts pasivos en alcance: $(wc -l <"$PASSIVE_DIR/hosts.txt")"
  return 0
}

module_dns() {
  local candidates="$DNS_DIR/candidates.txt" resolved="$DNS_DIR/resolved-hosts.txt"
  if [[ -s $PASSIVE_DIR/hosts.txt ]]; then cp "$PASSIVE_DIR/hosts.txt" "$candidates"; else printf '%s\n' "$TARGET" >"$candidates"; fi

  if [[ $TARGET_TYPE == fqdn && $ENABLE_ACTIVE -eq 1 && -n $WL_SUBDOMAINS ]]; then
    if ! special_use_domain "$SCOPE_DOMAIN" && tool_ready puredns && tool_ready massdns && [[ -n $WL_RESOLVERS ]]; then
      run_cmd "Resolucion masiva DNS con filtrado wildcard (Puredns)" "$DNS_DIR/bruteforce.txt" "$LOG_DIR/puredns.err" "$STEP_TIMEOUT" \
        puredns bruteforce "$WL_SUBDOMAINS" "$SCOPE_DOMAIN" --quiet --resolvers "$WL_RESOLVERS" --rate-limit "$RATE" || true
    elif tool_ready dnsx; then
      run_cmd "Fuerza de nombres DNS con Dnsx" "$DNS_DIR/bruteforce.txt" "$LOG_DIR/dnsx-brute.err" "$STEP_TIMEOUT" \
        dnsx -silent -d "$SCOPE_DOMAIN" -w "$WL_SUBDOMAINS" -t "$THREADS" -rl "$RATE" || true
    elif tool_ready gobuster; then
      run_cmd "Fuerza de nombres DNS con Gobuster" "$DNS_DIR/bruteforce.txt" "$LOG_DIR/gobuster-dns.err" "$STEP_TIMEOUT" \
        gobuster dns -q --domain "$SCOPE_DOMAIN" -w "$WL_SUBDOMAINS" -t "$THREADS" --timeout 3s || true
    fi
    if [[ -s $DNS_DIR/bruteforce.txt ]]; then
      cat "$DNS_DIR/bruteforce.txt" >>"$candidates"
      normalize_hosts "$candidates" "$DNS_DIR/candidates.normalized.txt"
      mv "$DNS_DIR/candidates.normalized.txt" "$candidates"
    fi
  fi

  if tool_ready dnsx && [[ $TARGET_TYPE != ipv6 ]]; then
    run_cmd "Resolucion y filtrado DNS" "$resolved" "$LOG_DIR/dnsx-resolve.err" 1200 \
      dnsx -silent -l "$candidates" -t "$THREADS" -rl "$RATE" || true
    run_cmd "Detalles DNS" "$DNS_DIR/dns-records.txt" "$LOG_DIR/dnsx-records.err" 1200 \
      dnsx -silent -l "$candidates" -a -aaaa -cname -mx -ns -txt -resp -t "$THREADS" -rl "$RATE" || true
  else
    cp "$candidates" "$resolved"
  fi
  [[ -s $resolved ]] || printf '%s\n' "$TARGET" >"$resolved"
  normalize_hosts "$resolved" "$DNS_DIR/resolved.normalized.txt"
  mv "$DNS_DIR/resolved.normalized.txt" "$resolved"

  if [[ $TARGET_TYPE == fqdn && $ENABLE_ACTIVE -eq 1 ]] && tool_ready dig; then
    run_cmd "Consulta de servidores autoritativos" "$DNS_DIR/nameservers.txt" "$LOG_DIR/nameservers.err" 30 dig +short NS "$SCOPE_DOMAIN" || true
    if ((DRY_RUN)); then printf 'ns1.%s\n' "$SCOPE_DOMAIN" >"$DNS_DIR/nameservers.txt"; fi
    local ns ns_slug
    while IFS= read -r ns; do
      ns=${ns%.}; [[ -n $ns ]] || continue
      ns_slug=$(safe_slug "$ns")
      if in_scope_host "$ns"; then
        run_cmd "Prueba AXFR en $ns" "$DNS_DIR/axfr-$ns_slug.txt" "$LOG_DIR/axfr-$ns_slug.err" 45 \
          dig AXFR "@$ns" "$SCOPE_DOMAIN" || true
      else
        warn "AXFR omitido para nameserver fuera del alcance exacto: $ns"
      fi
    done < <(head -n 10 "$DNS_DIR/nameservers.txt")
  fi

  if [[ $PROFILE == deep && $TARGET_TYPE == fqdn ]] && tool_ready dnsrecon; then
    run_cmd "Enumeracion DNS estandar complementaria" "$DNS_DIR/dnsrecon.txt" "$LOG_DIR/dnsrecon.err" 900 \
      dnsrecon -d "$SCOPE_DOMAIN" -t std --threads "$THREADS" || true
  fi

  head -n "$MAX_HOSTS" "$resolved" >"$SCAN_TARGETS"
  if ! grep -Fxq "$TARGET" "$SCAN_TARGETS"; then
    { printf '%s\n' "$TARGET"; cat "$SCAN_TARGETS"; } | \
      awk -v max="$MAX_HOSTS" '!seen[$0]++ {count++; if (count <= max) print}' >"$SCAN_TARGETS.tmp"
    mv "$SCAN_TARGETS.tmp" "$SCAN_TARGETS"
  fi
  ok "Objetivos activos en alcance: $(wc -l <"$SCAN_TARGETS")"
  return 0
}

extract_nmap_ports() {
  local gnmap=$1 output=$2
  [[ -s $gnmap ]] || { : >"$output"; return; }
  awk -F'Ports: ' '
    /Ports: / {
      host=$1; sub(/^Host: /,"",host); split(host,h," ");
      split($2,ports,", ");
      for (i in ports) {
        split(ports[i],f,"/");
        if (f[2] == "open") print h[1] "\t" f[1] "\t" f[3] "\t" f[5];
      }
    }
  ' "$gnmap" | LC_ALL=C sort -u >"$output"
}

module_ports() {
  if ((ENABLE_ACTIVE == 0)) || [[ $TCP_PORT_SPEC == none && $UDP_PORT_SPEC == none ]]; then
    info "Escaneo de puertos desactivado en perfil passive"
    : >"$PORTS_DIR/open-ports.tsv"
    return 0
  fi
  [[ -s $SCAN_TARGETS ]] || printf '%s\n' "$TARGET" >"$SCAN_TARGETS"
  local scan_type="-sT"; ((PRIVILEGED_SCANS)) && scan_type="-sS"
  local -a family_args=()
  [[ $TARGET_TYPE == ipv6 ]] && family_args=(-6)
  local -a nmap_tcp_ports=() naabu_ports=()
  case "$TCP_PORT_SPEC" in
    top*) nmap_tcp_ports=(--top-ports "${TCP_PORT_SPEC#top}"); naabu_ports=(-top-ports "${TCP_PORT_SPEC#top}") ;;
    all) nmap_tcp_ports=(-p-); naabu_ports=(-p -) ;;
    none) ;;
    *) nmap_tcp_ports=(-p "$TCP_PORT_SPEC"); naabu_ports=(-p "$TCP_PORT_SPEC") ;;
  esac

  if [[ $TCP_PORT_SPEC != none ]]; then
    if tool_ready naabu; then
      run_cmd "Descubrimiento rapido TCP con Naabu" "$PORTS_DIR/naabu.txt" "$LOG_DIR/naabu.err" "$STEP_TIMEOUT" \
        naabu -silent -list "$SCAN_TARGETS" "${naabu_ports[@]}" -rate "$RATE" -c "$THREADS" -retries 1 -timeout 1000 || true
    elif [[ $TCP_PORT_SPEC != top* ]] && tool_ready masscan && ((PRIVILEGED_SCANS)) && [[ $TARGET_TYPE == ipv4 ]]; then
      local masscan_ports=$TCP_PORT_SPEC
      [[ $masscan_ports == all ]] && masscan_ports="1-65535"
      run_cmd "Descubrimiento TCP de respaldo con Masscan" "$PORTS_DIR/masscan.stdout" "$LOG_DIR/masscan.err" "$STEP_TIMEOUT" \
        "${SCAN_PRIV_PREFIX[@]}" masscan -iL "$SCAN_TARGETS" -p"$masscan_ports" --rate "$RATE" --wait 2 --open-only \
        --output-format list --output-filename "$PORTS_DIR/masscan.list" || true
    fi

    if tool_ready nmap; then
      if [[ ! -s $PORTS_DIR/naabu.txt && ! -s $PORTS_DIR/masscan.list || $DRY_RUN -eq 1 ]]; then
        run_cmd "Descubrimiento TCP con Nmap" "$PORTS_DIR/nmap-discovery.stdout" "$LOG_DIR/nmap-discovery.err" "$STEP_TIMEOUT" \
          "${SCAN_PRIV_PREFIX[@]}" nmap "${family_args[@]}" -n -Pn "$scan_type" --open --reason -T4 --max-retries 2 --max-rate "$RATE" \
          "${nmap_tcp_ports[@]}" -iL "$SCAN_TARGETS" -oA "$PORTS_DIR/nmap-discovery" || true
      fi

      local ports=""
      if [[ -s $PORTS_DIR/naabu.txt ]]; then
        ports=$(awk -F: '{print $NF}' "$PORTS_DIR/naabu.txt" | grep -E '^[0-9]+$' | sort -nu | paste -sd, -)
      elif [[ -s $PORTS_DIR/masscan.list ]]; then
        ports=$(awk '$1=="open" && $2=="tcp" && $3 ~ /^[0-9]+$/ {print $3}' "$PORTS_DIR/masscan.list" | sort -nu | paste -sd, -)
      elif [[ -s $PORTS_DIR/nmap-discovery.gnmap ]]; then
        extract_nmap_ports "$PORTS_DIR/nmap-discovery.gnmap" "$PORTS_DIR/discovery-ports.tsv"
        ports=$(awk -F'\t' '$3=="tcp"{print $2}' "$PORTS_DIR/discovery-ports.tsv" | sort -nu | paste -sd, -)
      fi
      if ((DRY_RUN)) && [[ -z $ports ]]; then ports="22,80,443"; fi

      if [[ -n $ports ]]; then
        local -a os_args=()
        ((PRIVILEGED_SCANS)) && os_args=(-O --osscan-limit)
        run_cmd "Validacion TCP y enumeracion detallada con Nmap" "$PORTS_DIR/nmap-services.stdout" "$LOG_DIR/nmap-services.err" "$STEP_TIMEOUT" \
          "${SCAN_PRIV_PREFIX[@]}" nmap "${family_args[@]}" -n -Pn "$scan_type" -sV --version-all --reason -T4 --max-retries 2 --script-timeout 45s \
          --script "safe and not (brute or dos or exploit or intrusive or fuzzer)" \
          "${os_args[@]}" -p "$ports" -iL "$SCAN_TARGETS" -oA "$PORTS_DIR/nmap-services" || true
      else
        warn "No se detectaron puertos TCP abiertos"
      fi
    else
      warn "Nmap no esta instalado; se conservara el descubrimiento TCP disponible"
    fi
  fi

  if [[ $UDP_PORT_SPEC != none ]]; then
    if tool_ready nmap && ((PRIVILEGED_SCANS)); then
      local -a nmap_udp_ports=()
      case "$UDP_PORT_SPEC" in
        top*) nmap_udp_ports=(--top-ports "${UDP_PORT_SPEC#top}") ;;
        all) nmap_udp_ports=(-p-) ;;
        *) nmap_udp_ports=(-p "$UDP_PORT_SPEC") ;;
      esac
      run_cmd "Descubrimiento y enumeracion UDP con Nmap" "$PORTS_DIR/nmap-udp.stdout" "$LOG_DIR/nmap-udp.err" "$STEP_TIMEOUT" \
        "${SCAN_PRIV_PREFIX[@]}" nmap "${family_args[@]}" -n -Pn -sU -sV --version-light --open --reason -T3 \
        --max-retries 1 --max-rate "$RATE" --script-timeout 45s \
        --script "safe and not (brute or dos or exploit or intrusive or fuzzer)" \
        "${nmap_udp_ports[@]}" -iL "$SCAN_TARGETS" -oA "$PORTS_DIR/nmap-udp" || true
    elif ! tool_ready nmap; then
      warn "UDP omitido: Nmap no esta disponible"
    else
      warn "UDP $UDP_PORT_SPEC omitido: autoriza --sudo-scans o ejecuta como root para sockets raw"
    fi
  fi

  : >"$PORTS_DIR/open-ports.tsv"
  local gnmap temp
  for gnmap in "$PORTS_DIR/nmap-services.gnmap" "$PORTS_DIR/nmap-discovery.gnmap" "$PORTS_DIR/nmap-udp.gnmap"; do
    if [[ -s $gnmap ]]; then
      temp="$gnmap.parsed"; extract_nmap_ports "$gnmap" "$temp"; cat "$temp" >>"$PORTS_DIR/open-ports.tsv"; rm -f "$temp"
    fi
  done
  if [[ -s $PORTS_DIR/naabu.txt ]]; then
    awk -F: '{p=$NF; sub(/:[^:]*$/, "", $0); h=$0; sub(/^\[/,"",h); sub(/\]$/,"",h); if (p ~ /^[0-9]+$/) print h "\t" p "\ttcp\tunknown"}' "$PORTS_DIR/naabu.txt" >>"$PORTS_DIR/open-ports.tsv"
  fi
  if [[ -s $PORTS_DIR/masscan.list ]]; then
    awk '$1=="open" && $2=="tcp" {print $4 "\t" $3 "\ttcp\tunknown"}' "$PORTS_DIR/masscan.list" >>"$PORTS_DIR/open-ports.tsv"
  fi
  LC_ALL=C sort -u "$PORTS_DIR/open-ports.tsv" -o "$PORTS_DIR/open-ports.tsv"
  return 0
}

module_services() {
  printf 'host\tport\tprotocol\tservice\n' >"$SERVICES_DIR/service-matrix.tsv"
  [[ -s $PORTS_DIR/open-ports.tsv ]] && cat "$PORTS_DIR/open-ports.tsv" >>"$SERVICES_DIR/service-matrix.tsv"
  local host id ldap_host
  if tool_ready rpcinfo; then
    while IFS= read -r host; do
      [[ -n $host ]] || continue; id=$(safe_slug "$host")
      run_cmd "Enumeracion RPC en $host" "$SERVICES_DIR/$id-rpcinfo.txt" "$LOG_DIR/rpcinfo-$id.err" 60 rpcinfo -p "$host" || true
    done < <(awk -F'\t' '$2==111 || $2==2049 {print $1}' "$PORTS_DIR/open-ports.tsv" 2>/dev/null | sort -u | head -n "$MAX_HOSTS")
  fi
  if tool_ready showmount; then
    while IFS= read -r host; do
      [[ -n $host ]] || continue; id=$(safe_slug "$host")
      run_cmd "Enumeracion NFS exportada en $host" "$SERVICES_DIR/$id-showmount.txt" "$LOG_DIR/showmount-$id.err" 60 showmount -e "$host" || true
    done < <(awk -F'\t' '$2==2049 {print $1}' "$PORTS_DIR/open-ports.tsv" 2>/dev/null | sort -u | head -n "$MAX_HOSTS")
  fi
  if tool_ready ssh-keyscan; then
    while IFS= read -r host; do
      [[ -n $host ]] || continue; id=$(safe_slug "$host")
      run_cmd "Claves publicas SSH en $host" "$SERVICES_DIR/$id-ssh-hostkeys.txt" "$LOG_DIR/ssh-keyscan-$id.err" 45 ssh-keyscan -T 10 "$host" || true
    done < <(awk -F'\t' '$2==22 && $3=="tcp" {print $1}' "$PORTS_DIR/open-ports.tsv" 2>/dev/null | sort -u | head -n "$MAX_HOSTS")
  fi
  if tool_ready smbclient; then
    while IFS= read -r host; do
      [[ -n $host ]] || continue; id=$(safe_slug "$host")
      run_cmd "Listado SMB anonimo en $host" "$SERVICES_DIR/$id-smb-anonymous.txt" "$LOG_DIR/smbclient-$id.err" 90 \
        smbclient -N -g -L "//$host" || true
    done < <(awk -F'\t' '($2==139 || $2==445) && $3=="tcp" {print $1}' "$PORTS_DIR/open-ports.tsv" 2>/dev/null | sort -u | head -n "$MAX_HOSTS")
  fi
  if tool_ready ldapsearch; then
    while IFS=$'\t' read -r host port; do
      [[ -n $host ]] || continue; id=$(safe_slug "$host"); ldap_host=$host
      [[ $host == *:* ]] && ldap_host="[$host]"
      if [[ $port == 636 ]]; then
        run_cmd "LDAPS RootDSE anonimo en $host" "$SERVICES_DIR/$id-ldaps-rootdse.txt" "$LOG_DIR/ldapsearch-$id-636.err" 90 \
          ldapsearch -x -LLL -H "ldaps://$ldap_host:636" -s base -b "" namingContexts defaultNamingContext supportedLDAPVersion || true
      else
        run_cmd "LDAP RootDSE anonimo en $host" "$SERVICES_DIR/$id-ldap-rootdse.txt" "$LOG_DIR/ldapsearch-$id-389.err" 90 \
          ldapsearch -x -LLL -H "ldap://$ldap_host:389" -s base -b "" namingContexts defaultNamingContext supportedLDAPVersion || true
      fi
    done < <(awk -F'\t' '($2==389 || $2==636) && $3=="tcp" {print $1 "\t" $2}' "$PORTS_DIR/open-ports.tsv" 2>/dev/null | sort -u | head -n "$MAX_HOSTS")
  fi
  return 0
}

default_live_urls() {
  printf 'http://%s\nhttps://%s\n' "$URL_TARGET" "$URL_TARGET"
}

module_http() {
  if ((ENABLE_ACTIVE == 0)); then
    info "Sondeo HTTP activo desactivado en perfil passive"
    : >"$LIVE_URLS"
    return 0
  fi
  local common_ports="80,443,3000,4000,5000,7001,8000,8008,8080,8081,8088,8443,8888,9000,9090,9443" ports
  ports=$({ printf '%s' "$common_ports" | tr ',' '\n'; awk -F'\t' '$2 ~ /^[0-9]+$/ && $3=="tcp" {print $2}' "$PORTS_DIR/open-ports.tsv" 2>/dev/null; } | sort -nu | paste -sd, -)
  printf '%s\n' "$ports" >"$HTTP_DIR/probed-ports.txt"
  if pd_httpx_ready; then
    run_cmd "Deteccion HTTP y tecnologias" "$HTTP_DIR/httpx.jsonl" "$LOG_DIR/httpx.err" "$STEP_TIMEOUT" \
      httpx -silent -l "$SCAN_TARGETS" -ports "$ports" -json -status-code -content-length -title \
      -tech-detect -web-server -ip -cname -location \
      -timeout 10 -threads "$THREADS" -rate-limit "$RATE" || true
    if ((DRY_RUN == 0)) && [[ -s $HTTP_DIR/httpx.jsonl ]]; then
      jq -r 'select(.url != null) | .url' "$HTTP_DIR/httpx.jsonl" 2>/dev/null | LC_ALL=C sort -u >"$HTTP_DIR/live-urls.raw.txt" || true
      filter_scope_urls "$HTTP_DIR/live-urls.raw.txt" "$LIVE_URLS"
    fi
  else
    warn "httpx de ProjectDiscovery no disponible; se usara una comprobacion Curl minima"
    if tool_ready curl; then
      local scheme
      : >"$HTTP_DIR/curl-probes.txt"
      for scheme in http https; do
        run_cmd "Sondeo $scheme" "$HTTP_DIR/curl-$scheme.txt" "$LOG_DIR/curl-$scheme.err" 45 \
          curl -k -sS --connect-timeout 5 --max-time 20 -o /dev/null \
          -w '%{url_effective}\t%{http_code}\n' "$scheme://$URL_TARGET" || true
        cat "$HTTP_DIR/curl-$scheme.txt" >>"$HTTP_DIR/curl-probes.txt"
      done
      awk -F'\t' '$2 ~ /^[123][0-9][0-9]$/ {print $1}' "$HTTP_DIR/curl-probes.txt" | sort -u >"$LIVE_URLS"
    fi
  fi
  if ((DRY_RUN)); then default_live_urls >"$LIVE_URLS"; fi
  touch "$LIVE_URLS"

  if tool_ready curl; then
    local url id
    while IFS= read -r url; do
      [[ -n $url ]] || continue
      id=$(printf '%s' "$url" | sha256sum | awk '{print substr($1,1,16)}')
      run_cmd "Cabeceras HTTP $url" "$HTTP_DIR/headers/$id.txt" "$LOG_DIR/headers-$id.err" 45 \
        curl -k -sS -I --connect-timeout 5 --max-time 30 "$url" || true
    done < <(head -n "$MAX_WEB_TARGETS" "$LIVE_URLS")
  fi

  if tool_ready whatweb && [[ -s $LIVE_URLS ]]; then
    run_cmd "Fingerprint web adicional" "$HTTP_DIR/whatweb.txt" "$LOG_DIR/whatweb.err" "$STEP_TIMEOUT" \
      whatweb --no-errors --color=never -i "$LIVE_URLS" || true
  fi
  if tool_ready wafw00f && [[ -s $LIVE_URLS ]]; then
    run_cmd "Deteccion WAF" "$HTTP_DIR/wafw00f.txt" "$LOG_DIR/wafw00f.err" "$STEP_TIMEOUT" \
      wafw00f -i "$LIVE_URLS" -a || true
  fi
  ok "Servicios web vivos: $(wc -l <"$LIVE_URLS")"
  return 0
}

filter_scope_urls() {
  local input=$1 output=$2 url rest authority host
  : >"$output"
  while IFS= read -r url; do
    url=${url//$'\r'/}; url=${url%%#*}
    [[ $url == http://* || $url == https://* ]] || continue
    rest=${url#*://}; authority=${rest%%/*}
    [[ $authority != *@* ]] || continue
    if [[ $authority == \[* ]]; then host=${authority#\[}; host=${host%%\]*}; else host=${authority%%:*}; fi
    in_scope_host "$host" && printf '%s\n' "$url"
  done <"$input" | LC_ALL=C sort -u >"$output"
}

module_crawl() {
  [[ -s $LIVE_URLS ]] || { info "Sin URLs vivas para crawling"; : >"$CRAWL_DIR/endpoints.txt"; return 0; }
  if tool_ready katana; then
    run_cmd "Crawling HTTP/JS con Katana" "$CRAWL_DIR/katana.txt" "$LOG_DIR/katana.err" "$STEP_TIMEOUT" \
      katana -silent -list "$LIVE_URLS" -depth "$CRAWL_DEPTH" -js-crawl -known-files all \
      -field-scope fqdn -disable-update-check -concurrency "$THREADS" -rate-limit "$RATE" -timeout 10 || true
  fi
  if [[ $PROFILE == deep ]] && tool_ready hakrawler; then
    local -a hak_scope=()
    [[ $TARGET_TYPE == fqdn ]] && hak_scope=(-subs)
    run_cmd "Crawling complementario con Hakrawler" "$CRAWL_DIR/hakrawler.txt" "$LOG_DIR/hakrawler.err" "$STEP_TIMEOUT" \
      --stdin "$LIVE_URLS" hakrawler -d "$CRAWL_DEPTH" -insecure -u -t "$THREADS" -timeout 30 "${hak_scope[@]}" || true
  fi
  if [[ $TARGET_TYPE == fqdn && $EXTERNAL_OSINT -eq 1 ]] && ! special_use_domain "$SCOPE_DOMAIN"; then
    if tool_ready gau; then
      run_cmd "URLs historicas con gau" "$CRAWL_DIR/gau.txt" "$LOG_DIR/gau.err" 900 gau --subs "$SCOPE_DOMAIN" || true
    fi
    if tool_ready waybackurls; then
      run_cmd "URLs historicas con Wayback" "$CRAWL_DIR/waybackurls.txt" "$LOG_DIR/waybackurls.err" 900 waybackurls "$SCOPE_DOMAIN" || true
    fi
  fi
  local combined="$CRAWL_DIR/endpoints.raw.txt" file
  : >"$combined"
  for file in "$LIVE_URLS" "$CRAWL_DIR/katana.txt" "$CRAWL_DIR/hakrawler.txt" "$CRAWL_DIR/gau.txt" "$CRAWL_DIR/waybackurls.txt"; do
    [[ -s $file ]] && cat "$file" >>"$combined"
  done
  filter_scope_urls "$combined" "$CRAWL_DIR/endpoints.txt"
  grep -Eai '\.js([?#].*)?$' "$CRAWL_DIR/endpoints.txt" | sort -u >"$CRAWL_DIR/javascript.txt" || true
  grep -Eai '(/api/|/graphql|swagger|openapi|\.json([?#].*)?$)' "$CRAWL_DIR/endpoints.txt" | sort -u >"$CRAWL_DIR/api-candidates.txt" || true
  ok "Endpoints unicos en alcance: $(wc -l <"$CRAWL_DIR/endpoints.txt")"
  return 0
}

url_origin() {
  local url=$1 scheme rest authority
  scheme=${url%%://*}; rest=${url#*://}; authority=${rest%%/*}
  printf '%s://%s' "$scheme" "$authority"
}

ffuf_one() {
  local kind=$1 origin=$2 wordlist=$3 outfile=$4 id=$5
  local -a common=(-s -ac -mc all -fc 404 -t "$THREADS" -rate "$RATE" -timeout 10 -maxtime "$FFUF_MAXTIME" -of json -o "$outfile")
  case "$kind" in
    directories)
      local -a recursion_args=()
      if ((FFUF_RECURSION_DEPTH > 0)); then
        recursion_args=(-recursion -recursion-depth "$FFUF_RECURSION_DEPTH" -maxtime-job "$((FFUF_MAXTIME / 4))")
      fi
      run_cmd "FFUF directorios $origin" "$FUZZ_DIR/$id-directories.stdout" "$LOG_DIR/ffuf-$id-directories.err" "$((FFUF_MAXTIME + 60))" \
        ffuf -w "$wordlist:FUZZ" -u "${origin%/}/FUZZ" "${recursion_args[@]}" "${common[@]}" || true
      ;;
    files)
      run_cmd "FFUF ficheros $origin" "$FUZZ_DIR/$id-files.stdout" "$LOG_DIR/ffuf-$id-files.err" "$((FFUF_MAXTIME + 60))" \
        ffuf -w "$wordlist:FUZZ" -u "${origin%/}/FUZZ" -e .php,.asp,.aspx,.jsp,.json,.xml,.txt,.bak,.old,.zip "${common[@]}" || true
      ;;
    parameters)
      run_cmd "FFUF parametros GET $origin" "$FUZZ_DIR/$id-parameters.stdout" "$LOG_DIR/ffuf-$id-parameters.err" "$((FFUF_MAXTIME + 60))" \
        ffuf -w "$wordlist:FUZZ" -u "${origin%/}/?FUZZ=rekon_probe" "${common[@]}" || true
      ;;
    vhosts)
      run_cmd "FFUF virtual hosts $origin" "$FUZZ_DIR/$id-vhosts.stdout" "$LOG_DIR/ffuf-$id-vhosts.err" "$((FFUF_MAXTIME + 60))" \
        ffuf -w "$wordlist:FUZZ" -u "${origin%/}/" -H "Host: FUZZ.$SCOPE_DOMAIN" "${common[@]}" || true
      ;;
  esac
}

summarize_ffuf() {
  local output="$FUZZ_DIR/results.tsv" file
  printf 'type\turl\tstatus\tlength\twords\tlines\tinput\n' >"$output"
  while IFS= read -r -d '' file; do
    jq -r --arg type "$(basename "$file" .json | sed 's/^[^-]*-//')" '
      .results[]? | [$type, .url, (.status|tostring), (.length|tostring), (.words|tostring), (.lines|tostring), (.input.FUZZ // "")] | @tsv
    ' "$file" 2>/dev/null >>"$output" || true
  done < <(find "$FUZZ_DIR" -maxdepth 1 -type f -name '*.json' -print0)
}

module_fuzz() {
  if ((ENABLE_FUZZ == 0)); then info "Fuzzing desactivado por perfil"; return 0; fi
  [[ -s $LIVE_URLS ]] || { info "Sin servicios web para fuzzing"; return 0; }
  local origins="$FUZZ_DIR/origins.txt" url origin id ran_ferox=0
  : >"$origins"
  while IFS= read -r url; do url_origin "$url"; printf '\n'; done <"$LIVE_URLS" | sort -u | awk -v max="$MAX_WEB_TARGETS" 'NR <= max' >"$origins"

  if tool_ready ffuf; then
    while IFS= read -r origin; do
      [[ -n $origin ]] || continue
      id=$(printf '%s' "$origin" | sha256sum | awk '{print substr($1,1,12)}')
      [[ -n $WL_DIRS ]] && ffuf_one directories "$origin" "$WL_DIRS" "$FUZZ_DIR/$id-directories.json" "$id"
      [[ -n $WL_FILES ]] && ffuf_one files "$origin" "$WL_FILES" "$FUZZ_DIR/$id-files.json" "$id"
      [[ -n $WL_PARAMS ]] && ffuf_one parameters "$origin" "$WL_PARAMS" "$FUZZ_DIR/$id-parameters.json" "$id"
      if [[ $TARGET_TYPE == fqdn && -n $WL_VHOSTS ]]; then
        ffuf_one vhosts "$origin" "$WL_VHOSTS" "$FUZZ_DIR/$id-vhosts.json" "$id"
      fi
    done <"$origins"
    ((DRY_RUN == 0)) && summarize_ffuf
  elif tool_ready feroxbuster && [[ -n $WL_DIRS ]]; then
    while IFS= read -r origin; do
      [[ -n $origin ]] || continue
      id=$(printf '%s' "$origin" | sha256sum | awk '{print substr($1,1,12)}')
      run_cmd "Feroxbuster $origin" "$FUZZ_DIR/$id-ferox.json" "$LOG_DIR/ferox-$id.err" "$STEP_TIMEOUT" \
        feroxbuster --silent --json -u "$origin" -w "$WL_DIRS" -t "$THREADS" --rate-limit "$RATE" \
        --scan-limit 1 --auto-tune --depth 1 --time-limit "${FFUF_MAXTIME}s" || true
    done <"$origins"
    ran_ferox=1
  elif tool_ready gobuster && [[ -n $WL_DIRS ]]; then
    while IFS= read -r origin; do
      [[ -n $origin ]] || continue
      id=$(printf '%s' "$origin" | sha256sum | awk '{print substr($1,1,12)}')
      run_cmd "Gobuster web $origin" "$FUZZ_DIR/$id-gobuster.txt" "$LOG_DIR/gobuster-$id.err" "$STEP_TIMEOUT" \
        gobuster dir -q -u "$origin" -w "$WL_DIRS" -t "$THREADS" --timeout 10s -x php,asp,aspx,jsp,json,xml,txt || true
    done <"$origins"
  else
    warn "No hay ffuf, feroxbuster o gobuster; fuzzing omitido"
  fi

  if [[ $PROFILE == deep && $ran_ferox -eq 0 && -n $WL_DIRS ]] && tool_ready feroxbuster; then
    while IFS= read -r origin; do
      [[ -n $origin ]] || continue
      id=$(printf '%s' "$origin" | sha256sum | awk '{print substr($1,1,12)}')
      run_cmd "Recursion web profunda con Feroxbuster $origin" "$FUZZ_DIR/$id-ferox.json" "$LOG_DIR/ferox-$id.err" "$STEP_TIMEOUT" \
        feroxbuster --silent --json -u "$origin" -w "$WL_DIRS" -t "$THREADS" --rate-limit "$RATE" \
        --scan-limit 1 --auto-tune --depth "$FFUF_RECURSION_DEPTH" --time-limit "${FFUF_MAXTIME}s" || true
    done <"$origins"
  fi

  if [[ $PROFILE == deep && $TARGET_TYPE == fqdn && -n $WL_VHOSTS ]] && tool_ready gobuster; then
    while IFS= read -r origin; do
      [[ -n $origin ]] || continue
      id=$(printf '%s' "$origin" | sha256sum | awk '{print substr($1,1,12)}')
      run_cmd "Contraste de virtual hosts con Gobuster $origin" "$FUZZ_DIR/$id-gobuster-vhost.txt" "$LOG_DIR/gobuster-vhost-$id.err" "$STEP_TIMEOUT" \
        gobuster vhost -q -u "$origin" --append-domain -w "$WL_VHOSTS" -t "$THREADS" --timeout 10s || true
    done <"$origins"
  fi

  if [[ $PROFILE == deep && -n $WL_PARAMS ]] && tool_ready arjun; then
    local arjun_targets="$FUZZ_DIR/arjun-targets.txt" arjun_threads=$THREADS
    ((arjun_threads > 10)) && arjun_threads=10
    if [[ -s $CRAWL_DIR/endpoints.txt ]]; then
      awk 'NR <= 50' "$CRAWL_DIR/endpoints.txt" >"$arjun_targets"
    else
      awk 'NR <= 50' "$origins" >"$arjun_targets"
    fi
    run_cmd "Descubrimiento de parametros GET con Arjun" "$FUZZ_DIR/arjun.stdout" "$LOG_DIR/arjun.err" "$STEP_TIMEOUT" \
      arjun -i "$arjun_targets" -m GET -w "$WL_PARAMS" -t "$arjun_threads" --ratelimit "$RATE" -T 10 -oJ "$FUZZ_DIR/arjun.json" || true
  fi
  return 0
}

tls_authority() {
  local url=$1 rest authority
  rest=${url#*://}; authority=${rest%%/*}
  if [[ $authority == \[*\] ]]; then printf '%s:443' "$authority"; elif [[ $authority == *:* ]]; then printf '%s' "$authority"; else printf '%s:443' "$authority"; fi
}

tls_server_name() {
  local url=$1 rest authority
  rest=${url#*://}; authority=${rest%%/*}
  if [[ $authority == \[* ]]; then
    authority=${authority#\[}; printf '%s' "${authority%%\]*}"
  else
    printf '%s' "${authority%%:*}"
  fi
}

module_tls() {
  [[ -s $LIVE_URLS ]] || return 0
  local url authority server_name id tester=""
  if tool_ready testssl.sh; then tester="testssl.sh"; elif tool_ready testssl; then tester="testssl"; fi
  while IFS= read -r url; do
    [[ $url == https://* ]] || continue
    authority=$(tls_authority "$url")
    server_name=$(tls_server_name "$url")
    id=$(printf '%s' "$authority" | sha256sum | awk '{print substr($1,1,12)}')
    if [[ -n $tester ]]; then
      run_cmd "Analisis TLS $authority" "$TLS_DIR/$id-testssl.txt" "$LOG_DIR/testssl-$id.err" "$STEP_TIMEOUT" \
        "$tester" --quiet --warnings batch --color 0 "$authority" || true
    elif tool_ready sslscan; then
      run_cmd "Analisis TLS $authority" "$TLS_DIR/$id-sslscan.txt" "$LOG_DIR/sslscan-$id.err" 600 \
        sslscan --no-colour "$authority" || true
    elif tool_ready openssl; then
      local -a sni_args=()
      [[ $server_name =~ [A-Za-z] ]] && sni_args=(-servername "$server_name")
      run_cmd "Handshake TLS $authority" "$TLS_DIR/$id-openssl.txt" "$LOG_DIR/openssl-$id.err" 60 \
        --stdin /dev/null openssl s_client -connect "$authority" "${sni_args[@]}" -showcerts || true
    fi
  done < <(head -n "$MAX_WEB_TARGETS" "$LIVE_URLS")
  return 0
}

module_observations() {
  if ((ENABLE_SAFE_NUCLEI == 0)) || [[ ! -s $LIVE_URLS ]]; then return 0; fi
  if tool_ready nuclei; then
    run_cmd "Observaciones Nuclei no intrusivas" "$OBS_DIR/nuclei.stdout" "$LOG_DIR/nuclei.err" "$STEP_TIMEOUT" \
      nuclei -silent -l "$LIVE_URLS" -type http -tags tech,exposure,misconfig \
      -exclude-tags dos,fuzzing,bruteforce,intrusive,exploit,code,headless,oast \
      -no-interactsh -rate-limit "$RATE" -concurrency "$THREADS" -timeout 10 -retries 1 \
      -jsonl -output "$OBS_DIR/nuclei.jsonl" || true
    if ((DRY_RUN == 0)) && [[ -s $OBS_DIR/nuclei.jsonl ]]; then
      jq -r '[.info.severity, .info.name, (."matched-at" // .host // "")] | @tsv' "$OBS_DIR/nuclei.jsonl" 2>/dev/null >"$OBS_DIR/nuclei.tsv" || true
    fi
  fi
  return 0
}

module_screenshots() {
  [[ -s $LIVE_URLS ]] || return 0
  if tool_ready gowitness; then
    mkdir -p "$HTTP_DIR/screenshots"
    if ((DRY_RUN)) || (gowitness --help 2>&1 | grep -qE '(^|[[:space:]])scan([[:space:]]|$)'); then
      run_cmd "Capturas web" "$HTTP_DIR/gowitness.stdout" "$LOG_DIR/gowitness.err" "$STEP_TIMEOUT" \
        gowitness scan file -f "$LIVE_URLS" --screenshot-path "$HTTP_DIR/screenshots" --write-db \
        --db-path "$HTTP_DIR/gowitness.sqlite3" || true
    else
      run_cmd "Capturas web" "$HTTP_DIR/gowitness.stdout" "$LOG_DIR/gowitness.err" "$STEP_TIMEOUT" \
        gowitness file -f "$LIVE_URLS" -P "$HTTP_DIR/screenshots" --disable-db || true
    fi
  fi
  return 0
}

count_lines() { local f=$1; [[ -s $f ]] && wc -l <"$f" || printf '0'; }

module_report() {
  ((DRY_RUN == 0)) && summarize_ffuf || true
  local hosts ports urls endpoints fuzz fuzz_artifacts observations
  hosts=$(count_lines "$SCAN_TARGETS")
  ports=$(count_lines "$PORTS_DIR/open-ports.tsv")
  urls=$(count_lines "$LIVE_URLS")
  endpoints=$(count_lines "$CRAWL_DIR/endpoints.txt")
  fuzz=0; [[ -s $FUZZ_DIR/results.tsv ]] && fuzz=$(( $(wc -l <"$FUZZ_DIR/results.tsv") - 1 )); ((fuzz < 0)) && fuzz=0
  fuzz_artifacts=$(find "$FUZZ_DIR" -maxdepth 1 -type f \( -name '*.json' -o -name '*gobuster*.txt' \) -size +0c 2>/dev/null | wc -l)
  observations=$(count_lines "$OBS_DIR/nuclei.tsv")

  {
    printf '# Informe REKON\n\n'
    printf '> Reconocimiento y enumeracion de laboratorio. Los resultados son observaciones que requieren validacion manual.\n\n'
    printf '## Contexto\n\n'
    printf -- '- Objetivo: `%s`\n' "$TARGET"
    printf -- '- Tipo: `%s`\n' "$TARGET_TYPE"
    printf -- '- Perfil: `%s`\n' "$PROFILE"
    printf -- '- Version REKON: `%s`\n' "$REKON_VERSION"
    printf -- '- Generado (UTC): `%s`\n' "$(now_iso)"
    printf -- '- Limites: `%s` hilos, `%s` req/s, `%s` hosts\n' "$THREADS" "$RATE" "$MAX_HOSTS"
    printf -- '- Puertos: TCP `%s`, UDP `%s`, privilegiado `%s`\n\n' "$TCP_PORT_SPEC" "$UDP_PORT_SPEC" "$PRIVILEGED_SCANS"
    printf '## Resumen\n\n'
    printf '| Metrica | Total |\n|---|---:|\n'
    printf '| Hosts procesados | %s |\n' "$hosts"
    printf '| Puertos abiertos | %s |\n' "$ports"
    printf '| Servicios web vivos | %s |\n' "$urls"
    printf '| Endpoints unicos | %s |\n' "$endpoints"
    printf '| Resultados FFUF normalizados | %s |\n' "$fuzz"
    printf '| Artefactos de fuzzing | %s |\n' "$fuzz_artifacts"
    printf '| Observaciones no intrusivas | %s |\n\n' "$observations"
    printf '## Puertos y servicios\n\n'
    if [[ -s $PORTS_DIR/open-ports.tsv ]]; then
      printf '| Host | Puerto | Protocolo | Servicio |\n|---|---:|---|---|\n'
      awk -F'\t' 'NR<=250 {gsub(/\|/,"\\|",$0); printf "| %s | %s | %s | %s |\n",$1,$2,$3,$4}' "$PORTS_DIR/open-ports.tsv"
    else printf '_No se registraron puertos abiertos._\n'; fi
    printf '\n## Servicios web\n\n'
    if [[ -s $LIVE_URLS ]]; then awk 'NR <= 250 {print "- " $0}' "$LIVE_URLS"; else printf '_No se registraron servicios web vivos._\n'; fi
    printf '\n\n## Observaciones Nuclei acotadas\n\n'
    if [[ -s $OBS_DIR/nuclei.tsv ]]; then
      printf '| Severidad | Observacion | Recurso |\n|---|---|---|\n'
      awk -F'\t' 'NR<=250 {gsub(/\|/,"\\|",$0); printf "| %s | %s | %s |\n",$1,$2,$3}' "$OBS_DIR/nuclei.tsv"
    else printf '_Sin observaciones o modulo no ejecutado._\n'; fi
    printf '\n\n## Trazabilidad\n\n'
    printf -- '- Comandos: `logs/commands.tsv`\n'
    printf -- '- Estado de modulos: `00-meta/modules.tsv`\n'
    printf -- '- Diccionarios elegidos: `00-meta/selected-wordlists.tsv`\n'
    printf -- '- Integridad: `SHA256SUMS`\n\n'
    printf '## Interpretacion\n\n'
    printf 'Este informe no demuestra por si solo una vulnerabilidad. Valida manualmente falsos positivos, alcance, impacto y evidencia antes de emitir conclusiones.\n'
  } >"$REPORT_DIR/REKON-report.md"

  if command -v jq >/dev/null 2>&1; then
    jq -n \
      --arg target "$TARGET" --arg target_type "$TARGET_TYPE" --arg profile "$PROFILE" \
      --arg version "$REKON_VERSION" --arg generated_at "$(now_iso)" \
      --arg tcp_ports "$TCP_PORT_SPEC" --arg udp_ports "$UDP_PORT_SPEC" --argjson privileged_scans "$PRIVILEGED_SCANS" \
      --argjson hosts "$hosts" --argjson ports "$ports" --argjson urls "$urls" \
      --argjson endpoints "$endpoints" --argjson fuzz "$fuzz" --argjson fuzz_artifacts "$fuzz_artifacts" --argjson observations "$observations" \
      '{target:$target,target_type:$target_type,profile:$profile,rekon_version:$version,generated_at:$generated_at,scan:{tcp_ports:$tcp_ports,udp_ports:$udp_ports,privileged:$privileged_scans},counts:{hosts:$hosts,open_ports:$ports,live_urls:$urls,endpoints:$endpoints,ffuf_results:$fuzz,fuzz_artifacts:$fuzz_artifacts,observations:$observations}}' \
      >"$REPORT_DIR/summary.json"
  fi
  if tool_ready pandoc && ((DRY_RUN == 0)); then
    run_cmd "Informe HTML" "$LOG_DIR/pandoc.stdout" "$LOG_DIR/pandoc.err" 120 \
      pandoc -s "$REPORT_DIR/REKON-report.md" -o "$REPORT_DIR/REKON-report.html" || true
  fi

  (cd "$RUN_DIR" && find . -type f ! -name SHA256SUMS -print0 | LC_ALL=C sort -z | xargs -0 sha256sum >SHA256SUMS)
  return 0
}

self_test() {
  local -a good=("127.0.0.1" "192.168.56.10" "example.invalid" "lab-host" "2001:db8::1")
  local -a bad=("10.0.0.0/24" "example.com;id" "https://example.com" "*.example.com" "a.example.com,b.example.com" "999.1.1.1")
  local -a good_ports=("none" "all" "top50" "top1000" "22,80,443" "8000-8100")
  local -a bad_ports=("0" "65536" "100-20" "80,,443" "22;id" "top500")
  local value failures=0
  for value in "${good[@]}"; do
    TARGET_TYPE=""; TARGET=""
    if ! classify_target "$value"; then printf 'FAIL valid: %s\n' "$value"; ((failures+=1)); fi
  done
  for value in "${bad[@]}"; do
    TARGET_TYPE=""; TARGET=""
    if classify_target "$value"; then printf 'FAIL invalid: %s\n' "$value"; ((failures+=1)); fi
  done
  for value in "${good_ports[@]}"; do
    if ! valid_port_spec "$value"; then printf 'FAIL valid port spec: %s\n' "$value"; ((failures+=1)); fi
  done
  for value in "${bad_ports[@]}"; do
    if valid_port_spec "$value"; then printf 'FAIL invalid port spec: %s\n' "$value"; ((failures+=1)); fi
  done
  if ((failures)); then printf 'Self-test: %s fallo(s)\n' "$failures"; return 1; fi
  printf 'Self-test: OK\n'
}

on_interrupt() {
  warn "Interrupcion recibida; los resultados parciales quedan en ${RUN_DIR:-sin-inicializar}"
  jobs -pr | xargs -r kill 2>/dev/null || true
  exit 130
}

main() {
  parse_args "$@"
  configure_colors
  export PATH="$USER_BIN_DIR:$PATH"
  if ((SELF_TEST)); then self_test; exit $?; fi
  if ((DOCTOR_ONLY)); then doctor; exit 0; fi
  interactive_inputs
  configure_profile
  confirm_authorization
  init_run
  trap on_interrupt INT TERM

  printf '%s\n' "$(uname -a)" >"$META_DIR/system.txt"
  [[ -r $SCRIPT_DIR/requirements-tools.tsv ]] && cp -- "$SCRIPT_DIR/requirements-tools.tsv" "$META_DIR/requirements-tools.tsv"
  doctor "$META_DIR/tools-before-install.tsv"
  choose_install_mode
  install_requirements
  doctor "$META_DIR/tools.tsv"
  resolve_wordlist_root
  configure_scan_privileges
  select_wordlists

  info "$REKON_NAME $REKON_VERSION | objetivo=$TARGET | perfil=$PROFILE | salida=$RUN_DIR"
  ((DRY_RUN)) && warn "Modo dry-run: no se emitira trafico de red"

  run_module target module_target
  run_module passive module_passive
  run_module dns module_dns
  run_module ports module_ports
  run_module services module_services
  run_module http module_http
  run_module crawl module_crawl
  run_module fuzz module_fuzz
  run_module tls module_tls
  run_module observations module_observations
  run_module screenshots module_screenshots
  run_module report module_report

  ok "Ejecucion finalizada"
  printf '\nInforme: %s\nResultados: %s\n' "$REPORT_DIR/REKON-report.md" "$RUN_DIR"
}

main "$@"
