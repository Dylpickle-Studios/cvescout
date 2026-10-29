#!/usr/bin/env bash
# CVE Scout installer / uninstaller.
#
#   curl -fsSLO https://github.com/Dylpickle-Studios/cvescout/releases/latest/download/install.sh
#   less install.sh
#   sudo bash install.sh --network 192.168.1.0/24
#
# Install is idempotent: re-running upgrades the code and keeps instance/.
# Uninstall keeps your data unless you ask for --purge: by default it writes a
# backup to /var/backups/cvescout-<timestamp> and then removes the install.
set -euo pipefail

REPO="Dylpickle-Studios/cvescout"
PREFIX="/opt/cvescout"
APP_USER="cvescout"
ENV_FILE="/etc/cvescout.env"
UNIT_DIR="/etc/systemd/system"
BACKUP_ROOT="/var/backups"

VERSION=""
NETWORK=""
SOURCE=""
MODE="install"
DO_APT=1
DO_ADMIN=1
DO_TIMER=0
DRY_RUN=0
PURGE=0
BACKUP_DIR=""
KEEP_DATA=0

usage() {
  cat <<'USAGE'
CVE Scout installer

Usage:
  install.sh [options]              Install or upgrade
  install.sh --uninstall [options]  Remove CVE Scout

Install options:
  --version vX.Y.Z   Install a specific release tag (default: latest release)
  --source PATH      Install from a local checkout or built package instead of GitHub
  --network CIDR     Network CVE Scout may scan (default: detected default route)
  --prefix PATH      Install prefix (default: /opt/cvescout)
  --user NAME        Service account (default: cvescout)
  --no-apt           Do not install python3-venv/nmap with apt
  --no-admin         Skip the interactive administrator prompt
  --with-timer       Enable the nightly port-scan timer
  --dry-run          Print what would happen, change nothing

Uninstall options:
  --uninstall        Stop services and remove the install
  --backup DIR       Write a database + secret backup to DIR before removing
  --keep-data        Keep the instance directory (database, secret) in place
  --purge            Delete data without a backup (destructive, cannot be undone)

Examples:
  sudo bash install.sh --network 192.168.1.0/24 --with-timer
  sudo bash install.sh --uninstall                       # backup, then remove
  sudo bash install.sh --uninstall --purge               # delete everything
  sudo bash install.sh --uninstall --keep-data           # remove code, keep database
USAGE
}

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

run() {
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '  [dry-run] %s\n' "$*"
    return 0
  fi
  "$@"
}

need_root() {
  if [ "$(id -u)" -ne 0 ] && [ "$DRY_RUN" -eq 0 ]; then
    die "run as root: sudo bash $0 $*"
  fi
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --version) VERSION="${2:?--version needs a tag}"; shift 2 ;;
      --network) NETWORK="${2:?--network needs a CIDR}"; shift 2 ;;
      --source) SOURCE="${2:?--source needs a path}"; shift 2 ;;
      --prefix) PREFIX="${2:?--prefix needs a path}"; shift 2 ;;
      --user) APP_USER="${2:?--user needs a name}"; shift 2 ;;
      --backup) BACKUP_DIR="${2:?--backup needs a directory}"; shift 2 ;;
      --no-apt) DO_APT=0; shift ;;
      --no-admin) DO_ADMIN=0; shift ;;
      --with-timer) DO_TIMER=1; shift ;;
      --dry-run) DRY_RUN=1; shift ;;
      --uninstall) MODE="uninstall"; shift ;;
      --keep-data) KEEP_DATA=1; shift ;;
      --purge) PURGE=1; shift ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown option: $1 (try --help)" ;;
    esac
  done
  if [ "$MODE" = "uninstall" ] && [ "$PURGE" -eq 1 ] && [ "$KEEP_DATA" -eq 1 ]; then
    die "--purge and --keep-data contradict each other"
  fi
}

detect_platform() {
  [ "$(uname -s)" = "Linux" ] || die "CVE Scout installs on Linux only"
  command -v systemctl >/dev/null 2>&1 || die "systemd is required"
  ARCH="$(uname -m)"
  MODEL=""
  if [ -r /proc/device-tree/model ]; then
    MODEL="$(tr -d '\0' </proc/device-tree/model)"
  fi
  [ -n "$MODEL" ] || MODEL="$(uname -m) host"
  CORES="$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || echo 1)"
  RAM_MB="$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0)"
  if [ "$CORES" -ge 4 ] && [ "$RAM_MB" -ge 3800 ]; then
    PROFILE="fast"
  elif [ "$CORES" -ge 2 ] && [ "$RAM_MB" -ge 900 ]; then
    PROFILE="balanced"
  else
    PROFILE="minimal"
  fi
  log "Hardware: $MODEL ($ARCH), ${CORES} core(s), ${RAM_MB} MB RAM -> profile $PROFILE"
}

detect_network() {
  if [ -n "$NETWORK" ]; then
    return
  fi
  local iface addr
  iface="$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')"
  addr="$(ip -o -4 addr show dev "${iface:-eth0}" 2>/dev/null | awk '{print $4; exit}')"
  if [ -n "$addr" ]; then
    NETWORK="$(python3 -c 'import ipaddress,sys; print(ipaddress.ip_network(sys.argv[1], strict=False))' "$addr" 2>/dev/null || true)"
  fi
  if [ -n "$NETWORK" ]; then
    log "Detected scan network: $NETWORK"
  else
    warn "could not detect a network; set one later in $ENV_FILE (CVESCOUT_NETWORKS)"
  fi
}

install_packages() {
  if [ "$DO_APT" -eq 0 ]; then
    log "Skipping apt (--no-apt); ensure python3-venv and nmap are present"
    return
  fi
  local missing=()
  for pkg in python3-venv nmap; do
    case "$pkg" in
      python3-venv) [ -d /usr/lib/python3/dist-packages/venv ] || python3 -m venv --help >/dev/null 2>&1 || missing+=("$pkg") ;;
      nmap) command -v nmap >/dev/null 2>&1 || missing+=("$pkg") ;;
    esac
  done
  if [ ${#missing[@]} -eq 0 ]; then
    log "Dependencies already installed"
    return
  fi
  log "Installing: ${missing[*]}"
  run apt-get update -qq
  run apt-get install -y "${missing[@]}"
}

create_user() {
  if id -u "$APP_USER" >/dev/null 2>&1; then
    return
  fi
  log "Creating system account $APP_USER"
  run useradd --system --home-dir "$PREFIX" --shell /usr/sbin/nologin "$APP_USER"
}

fetch_release() {
  local api asset url
  if [ -n "$SOURCE" ]; then
    [ -e "$SOURCE" ] || die "--source path does not exist: $SOURCE"
    PACKAGE="$SOURCE"
    log "Installing from $PACKAGE"
    return
  fi
  command -v curl >/dev/null 2>&1 || die "curl is required"
  if [ -n "$VERSION" ]; then
    api="https://api.github.com/repos/$REPO/releases/tags/$VERSION"
  else
    api="https://api.github.com/repos/$REPO/releases/latest"
  fi
  asset="$(curl -fsSL "$api" | grep -oE '"browser_download_url": *"[^"]+"' | cut -d'"' -f4 | grep -E '\.(whl|tar\.gz)$' | head -1 || true)"
  if [ -z "$asset" ]; then
    die "no release package found (tag: ${VERSION:-latest}); publish a release or use --source"
  fi
  url="$asset"
  PACKAGE="/tmp/$(basename "$url")"
  log "Downloading $(basename "$url")"
  run curl -fsSL -o "$PACKAGE" "$url"
}

install_app() {
  log "Installing into $PREFIX"
  run install -d -m 0755 "$PREFIX"
  run install -d -o "$APP_USER" -g "$APP_USER" -m 0750 "$PREFIX/instance"
  if [ ! -x "$PREFIX/.venv/bin/python" ]; then
    log "Creating virtual environment"
    run python3 -m venv "$PREFIX/.venv"
  fi
  log "Installing package"
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '  [dry-run] %s\n' "$PREFIX/.venv/bin/pip install --upgrade $PACKAGE"
  else
    "$PREFIX/.venv/bin/pip" install --quiet --upgrade pip
    "$PREFIX/.venv/bin/pip" install --quiet --upgrade "$PACKAGE"
  fi
  run chown -R "$APP_USER:$APP_USER" "$PREFIX"
}

write_env() {
  if [ -f "$ENV_FILE" ]; then
    log "Keeping existing $ENV_FILE"
    return
  fi
  log "Writing $ENV_FILE"
  if [ "$DRY_RUN" -eq 0 ]; then
    {
      echo "# CVE Scout configuration. Read by systemd, not by the shell."
      echo "CVESCOUT_NETWORKS=${NETWORK:-192.168.1.0/24}"
      echo "CVESCOUT_PROFILE=$PROFILE"
      echo "CVESCOUT_HTTPS=0"
      echo "# CVESCOUT_NVD_API_KEY="
      echo "# CVESCOUT_CLOUDFLARE_API_TOKEN="
    } >"$ENV_FILE"
    chown "root:$APP_USER" "$ENV_FILE"
    chmod 0640 "$ENV_FILE"
  fi
}

install_units() {
  log "Installing systemd units"
  run "$PREFIX/.venv/bin/flask" --app cvescout install-units --target "$UNIT_DIR" --prefix "$PREFIX" --user "$APP_USER"
  run systemctl daemon-reload
  run systemctl enable --now cvescout
  if [ "$DO_TIMER" -eq 1 ]; then
    run systemctl enable --now cvescout-scan.timer
  fi
}

create_admin() {
  if [ "$DO_ADMIN" -eq 0 ]; then
    log "Skipping administrator creation; run: sudo -u $APP_USER $PREFIX/.venv/bin/flask --app cvescout init-admin"
    return
  fi
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '  [dry-run] %s\n' "sudo -u $APP_USER flask --app cvescout init-admin (interactive)"
    return
  fi
  log "Create the administrator account"
  ( cd "$PREFIX" && sudo -u "$APP_USER" "$PREFIX/.venv/bin/flask" --app cvescout init-admin )
}

summary() {
  local bind="127.0.0.1:5000"
  cat <<SUMMARY

CVE Scout is installed.

  Service   systemctl status cvescout
  Logs      journalctl -u cvescout -f
  Config    $ENV_FILE
  Data      $PREFIX/instance
  Web UI    http://$bind  (put an HTTPS proxy in front before exposing it)
  Network   ${NETWORK:-not set — edit CVESCOUT_NETWORKS}
  Profile   $PROFILE

Next steps
  1. Open $ENV_FILE and set CVESCOUT_NETWORKS if it is wrong.
  2. Add an NVD API key to speed up CVE lookups.
  3. Configure notifications under Settings in the web UI.

SUMMARY
}

backup_data() {
  local target="$1"
  local stamp
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  [ -n "$target" ] || target="$BACKUP_ROOT/cvescout-$stamp"
  run install -d -m 0700 "$target"
  if [ -f "$PREFIX/instance/cvescout.sqlite3" ]; then
    log "Backing up database to $target"
    if command -v sqlite3 >/dev/null 2>&1 && [ "$DRY_RUN" -eq 0 ]; then
      sqlite3 "$PREFIX/instance/cvescout.sqlite3" ".backup '$target/cvescout.sqlite3'"
    else
      run cp -a "$PREFIX/instance/cvescout.sqlite3" "$target/cvescout.sqlite3"
    fi
  else
    warn "no database found in $PREFIX/instance"
  fi
  if [ -f "$PREFIX/instance/secret_key" ]; then
    run cp -a "$PREFIX/instance/secret_key" "$target/secret_key"
    run chmod 0600 "$target/secret_key"
  fi
  log "Backup written to $target"
}

uninstall() {
  need_root "$@"
  log "Uninstalling CVE Scout (mode: uninstall)"
  run systemctl disable --now cvescout-scan.timer 2>/dev/null || true
  run systemctl disable --now cvescout 2>/dev/null || true
  for unit in cvescout.service cvescout-scan.service cvescout-scan.timer; do
    if [ -f "$UNIT_DIR/$unit" ]; then
      run rm -f "$UNIT_DIR/$unit"
    fi
  done
  run systemctl daemon-reload

  if [ "$PURGE" -eq 1 ]; then
    warn "--purge deletes the database, secret, and audit history"
    run rm -rf "$PREFIX"
  elif [ "$KEEP_DATA" -eq 1 ]; then
    log "Keeping data in $PREFIX/instance"
    run rm -rf "$PREFIX/.venv" "$PREFIX/cvescout" "$PREFIX/cvescout.egg-info"
  else
    backup_data "$BACKUP_DIR"
    run rm -rf "$PREFIX"
  fi

  if [ -f "$ENV_FILE" ] && [ "$KEEP_DATA" -eq 0 ]; then
    run rm -f "$ENV_FILE"
  fi
  if id -u "$APP_USER" >/dev/null 2>&1 && [ "$KEEP_DATA" -eq 0 ]; then
    run userdel "$APP_USER" 2>/dev/null || true
  fi
  log "Uninstall complete"
  if [ "$PURGE" -eq 0 ] && [ "$KEEP_DATA" -eq 0 ]; then
    log "Restore later with: sudo bash install.sh, then copy the backup back into $PREFIX/instance"
  fi
}

main() {
  parse_args "$@"
  need_root "$@"
  detect_platform
  if [ "$MODE" = "uninstall" ]; then
    uninstall "$@"
    return
  fi
  detect_network
  install_packages
  create_user
  fetch_release
  install_app
  write_env
  install_units
  create_admin
  summary
}

main "$@"
