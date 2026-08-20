#!/usr/bin/env bash
# deploy.sh — Build a release binary and install a complete Ubuntu relay over SSH as root.
#
# On a fresh host this creates the non-login `nostr` system user, installs the
# runtime layout, nginx, and a Let's Encrypt TLS certificate. Existing relay
# configuration and policy files are preserved.
#
# Build modes (--build, default auto):
#   auto    --binary if given; else local cargo on linux/amd64; else remote
#   local   cargo build --release --locked on this machine (linux/amd64 only)
#   remote  rsync sources to the first --host and cargo -j1 there (default
#           from macOS / other non-linux/amd64 machines)
#
# After a remote build the binary is copied back once, then installed on
# every --host. Extra hosts do not compile.
#
# The SSH key is passed with -i only. Nothing is written to ~/.ssh,
# including id_ed25519.
#
# Usage:
#   ./scripts/deploy.sh \
#       --host relay.example.com \
#       --key ~/.ssh/id_ed25519 \
#       --domain relay.example.com \
#       --email admin@example.com
#
#   ./scripts/deploy.sh \
#       --host relay.example.com \
#       --key ~/.ssh/id_ed25519 \
#       --domain relay.example.com \
#       --email admin@example.com \
#       --port 60022
#
#   ./scripts/deploy.sh \
#       --host relay.example.com \
#       --key ~/.ssh/id_ed25519 \
#       --domain relay.example.com \
#       --email admin@example.com \
#       --binary ./target/release/nostr-rs-relay
#
# Flags (each also falls back to its $ENV unless overridden on the CLI):
#   --host HOST        target host; repeatable for multiple hosts (required)
#   --key PATH         SSH private key (req; fallback SSH_KEY)
#   --ip HOST          explicit IP/host to keyscan (fallback DEPLOY_IP)
#   --port N           ssh port (default 22; fallback DEPLOY_PORT)
#   --domain DOMAIN    public relay domain for nginx/TLS (req; fallback RELAY_DOMAIN)
#   --email EMAIL      Let's Encrypt notification email (req; fallback CERTBOT_EMAIL)
#   --restart          restart service after install (default)
#   --no-restart       do not restart the service
#   --remote-bin PATH  remote binary path (default /usr/local/bin/nostr-rs-relay)
#   --remote-src PATH  remote source dir for rsync (default /opt/nostr-rs-relay-src)
#   --service NAME     systemd unit name (default nostr-rs-relay)
#   --build MODE       auto | local | remote (default auto; fallback DEPLOY_BUILD)
#   --jobs N           cargo -j for a remote build (default 1; fallback CARGO_JOBS)
#   --binary PATH      skip cargo and deploy this file instead
#   -h, --help         show this help

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DEFAULT_BUILD_OUTPUT="${PROJECT_DIR}/target/release/nostr-rs-relay"

# --- Configuration (flags win, env fills in the rest, then defaults) ---
HOSTS=()
DEPLOY_KEY="${SSH_KEY:-}"
SSH_USER="root"
DEPLOY_IP="${DEPLOY_IP:-}"
DEPLOY_PORT="${DEPLOY_PORT:-22}"
DOMAIN="${RELAY_DOMAIN:-}"
CERTBOT_EMAIL="${CERTBOT_EMAIL:-}"
RESTART=true
REMOTE_BIN="${REMOTE_BIN:-/usr/local/bin/nostr-rs-relay}"
REMOTE_SRC="${REMOTE_SRC:-/opt/nostr-rs-relay-src}"
REMOTE_CONFIG="${REMOTE_CONFIG:-/etc/nostr-rs-relay/config.toml}"
REMOTE_KINDS="${REMOTE_KINDS:-/etc/nostr-rs-relay/.config/kinds.json}"
REMOTE_DATA="${REMOTE_DATA:-/var/lib/nostr-rs-relay}"
LISTEN_PORT="${LISTEN_PORT:-8080}"
SERVICE="${SERVICE:-nostr-rs-relay}"
LOCAL_CONFIG="${PROJECT_DIR}/config.toml"
LOCAL_KINDS_EXAMPLE="${PROJECT_DIR}/contrib/kinds.json.example"
BUILD_MODE="${DEPLOY_BUILD:-auto}"
CARGO_JOBS="${CARGO_JOBS:-1}"
BINARY_OVERRIDE=""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'
log() { echo -e "${BLUE}[deploy]${NC} $1"; }
ok() { echo -e "${GREEN}[deploy]${NC} $1"; }
warn() { echo -e "${YELLOW}[deploy]${NC} $1"; }
err() { echo -e "${RED}[deploy]${NC} $1" >&2; }

usage() {
    awk 'NR==1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"
    exit 0
}

require_cmd() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        err "Required command not found: $cmd"
        exit 1
    fi
}

# Return 0 when this machine can natively produce a linux/amd64 binary.
is_linux_amd64() {
    local os arch
    os="$(uname -s)"
    arch="$(uname -m)"
    [[ "$os" == "Linux" && ( "$arch" == "x86_64" || "$arch" == "amd64" ) ]]
}

# Expand ~ and make the key path absolute so rsync -e can find it.
resolve_key_path() {
    local key="$1"
    if [[ "$key" == ~* ]]; then
        key="${key/#\~/$HOME}"
    fi
    if [[ "$key" != /* ]]; then
        key="$(pwd)/$key"
    fi
    printf '%s' "$key"
}

# --- Parse flags ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)
            if [[ $# -lt 2 || -z "${2:-}" ]]; then
                err "--host requires a hostname."
                exit 1
            fi
            HOSTS+=("$2")
            shift 2
            ;;
        --key)
            if [[ $# -lt 2 || -z "${2:-}" ]]; then
                err "--key requires a path."
                exit 1
            fi
            DEPLOY_KEY="$2"
            shift 2
            ;;
        --user)
            err "--user is not accepted. Deploy is root-only."
            exit 1
            ;;
        --ip)
            if [[ $# -lt 2 || -z "${2:-}" ]]; then
                err "--ip requires a host or address."
                exit 1
            fi
            DEPLOY_IP="$2"
            shift 2
            ;;
        --port)
            if [[ $# -lt 2 || -z "${2:-}" ]]; then
                err "--port requires a port number."
                exit 1
            fi
            if ! [[ "$2" =~ ^[0-9]+$ ]] || [[ "$2" -lt 1 || "$2" -gt 65535 ]]; then
                err "Invalid SSH port: $2"
                exit 1
            fi
            DEPLOY_PORT="$2"
            shift 2
            ;;
        --domain)
            if [[ $# -lt 2 || -z "${2:-}" ]]; then
                err "--domain requires a public domain name."
                exit 1
            fi
            DOMAIN="$2"
            shift 2
            ;;
        --email)
            if [[ $# -lt 2 || -z "${2:-}" ]]; then
                err "--email requires a Let's Encrypt notification email."
                exit 1
            fi
            CERTBOT_EMAIL="$2"
            shift 2
            ;;
        --restart)
            RESTART=true
            shift
            ;;
        --no-restart)
            RESTART=false
            shift
            ;;
        --remote-bin)
            if [[ $# -lt 2 || -z "${2:-}" ]]; then
                err "--remote-bin requires a path."
                exit 1
            fi
            REMOTE_BIN="$2"
            shift 2
            ;;
        --remote-src)
            if [[ $# -lt 2 || -z "${2:-}" ]]; then
                err "--remote-src requires a path."
                exit 1
            fi
            REMOTE_SRC="$2"
            shift 2
            ;;
        --service)
            if [[ $# -lt 2 || -z "${2:-}" ]]; then
                err "--service requires a unit name."
                exit 1
            fi
            SERVICE="$2"
            shift 2
            ;;
        --build)
            if [[ $# -lt 2 || -z "${2:-}" ]]; then
                err "--build requires auto, local, or remote."
                exit 1
            fi
            BUILD_MODE="$2"
            shift 2
            ;;
        --jobs)
            if [[ $# -lt 2 || -z "${2:-}" ]]; then
                err "--jobs requires a positive integer."
                exit 1
            fi
            if ! [[ "$2" =~ ^[1-9][0-9]*$ ]]; then
                err "Invalid --jobs value: $2"
                exit 1
            fi
            CARGO_JOBS="$2"
            shift 2
            ;;
        --binary)
            if [[ $# -lt 2 || -z "${2:-}" ]]; then
                err "--binary requires a path."
                exit 1
            fi
            BINARY_OVERRIDE="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            err "Unknown option: $1"
            echo "Try: $0 --help"
            exit 1
            ;;
    esac
done

# --- Hosts: required, from flags only ---
if [[ ${#HOSTS[@]} -eq 0 ]]; then
    err "No target host(s) given. Use --host <host> (repeatable)."
    echo "Try: $0 --help"
    exit 1
fi
if [[ -z "$DOMAIN" || ! "$DOMAIN" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]$ ]]; then
    err "A valid public --domain is required for nginx and TLS."
    exit 1
fi
if [[ -z "$CERTBOT_EMAIL" || ! "$CERTBOT_EMAIL" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$ ]]; then
    err "A valid --email is required for Let's Encrypt notifications."
    exit 1
fi

case "$BUILD_MODE" in
    auto|local|remote) ;;
    *)
        err "Unknown --build mode: $BUILD_MODE (use auto, local, or remote)."
        exit 1
        ;;
esac

# --- Preflight ---
if [[ -z "$DEPLOY_KEY" ]]; then
    err "No SSH key provided. Use --key /path/to/key (deploys as ${SSH_USER})."
    exit 1
fi
DEPLOY_KEY="$(resolve_key_path "$DEPLOY_KEY")"
if [[ ! -f "$DEPLOY_KEY" ]]; then
    err "SSH key not found: $DEPLOY_KEY"
    exit 1
fi
if [[ ! -r "$DEPLOY_KEY" ]]; then
    err "SSH key is not readable: $DEPLOY_KEY"
    exit 1
fi

for cmd in scp ssh ssh-keyscan; do
    require_cmd "$cmd"
done

if [[ -n "$BINARY_OVERRIDE" ]]; then
    if [[ ! -f "$BINARY_OVERRIDE" ]]; then
        err "Binary not found: $BINARY_OVERRIDE"
        exit 1
    fi
    EFFECTIVE_BUILD="binary"
elif [[ "$BUILD_MODE" == "local" ]]; then
    EFFECTIVE_BUILD="local"
elif [[ "$BUILD_MODE" == "remote" ]]; then
    EFFECTIVE_BUILD="remote"
elif is_linux_amd64; then
    EFFECTIVE_BUILD="local"
else
    EFFECTIVE_BUILD="remote"
fi

if [[ "$EFFECTIVE_BUILD" == "local" ]]; then
    if ! is_linux_amd64; then
        err "This machine is $(uname -s)/$(uname -m), not linux/amd64."
        err "Use the default remote build, or pass --binary PATH."
        exit 1
    fi
    require_cmd cargo
    require_cmd rustc
    if ! command -v protoc >/dev/null 2>&1; then
        err "protoc not found. Install protobuf-compiler before building."
        exit 1
    fi
fi

if [[ "$EFFECTIVE_BUILD" == "remote" ]]; then
    require_cmd rsync
fi

if [[ ! -f "$LOCAL_CONFIG" ]]; then
    err "Missing local config template: $LOCAL_CONFIG"
    exit 1
fi
if [[ ! -f "$LOCAL_KINDS_EXAMPLE" ]]; then
    err "Missing kinds example: $LOCAL_KINDS_EXAMPLE"
    exit 1
fi

# --- Prepare SSH ---
# Use the given key in place via -i. Do not copy it, and do not write anything
# into ~/.ssh (orly's CI copies the secret to ~/.ssh/id_ed25519; this script
# must never do that). Host keys go in a throwaway file.
SSH_WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/nostr-rs-relay-deploy.XXXXXX")"
cleanup_ssh_workdir() {
    rm -rf "$SSH_WORKDIR"
}
trap cleanup_ssh_workdir EXIT

KNOWN_HOSTS="${SSH_WORKDIR}/known_hosts"
: > "$KNOWN_HOSTS"
chmod 600 "$KNOWN_HOSTS"

DEFAULT_IDENTITY="${HOME}/.ssh/id_ed25519"
if [[ -e "$DEFAULT_IDENTITY" ]]; then
    DEFAULT_IDENTITY_FINGERPRINT="$(cksum "$DEFAULT_IDENTITY" | awk '{print $1" "$2}')"
else
    DEFAULT_IDENTITY_FINGERPRINT=""
fi

assert_default_identity_untouched() {
    if [[ ! -e "$DEFAULT_IDENTITY" ]]; then
        if [[ -n "$DEFAULT_IDENTITY_FINGERPRINT" ]]; then
            err "Refusing to continue: ${DEFAULT_IDENTITY} was removed during deploy."
            exit 1
        fi
        return 0
    fi
    if [[ -z "$DEFAULT_IDENTITY_FINGERPRINT" ]]; then
        err "Refusing to continue: ${DEFAULT_IDENTITY} was created during deploy."
        exit 1
    fi
    local now
    now="$(cksum "$DEFAULT_IDENTITY" | awk '{print $1" "$2}')"
    if [[ "$now" != "$DEFAULT_IDENTITY_FINGERPRINT" ]]; then
        err "Refusing to continue: ${DEFAULT_IDENTITY} changed during deploy."
        exit 1
    fi
}

for host in "${HOSTS[@]}"; do
    ssh-keyscan -p "$DEPLOY_PORT" -H "${DEPLOY_IP:-$host}" >> "$KNOWN_HOSTS" 2>/dev/null || true
done

SSH_OPTS=(
    -p "$DEPLOY_PORT"
    -i "$DEPLOY_KEY"
    -o IdentitiesOnly=yes
    -o IdentityFile="$DEPLOY_KEY"
    -o UserKnownHostsFile="$KNOWN_HOSTS"
    -o GlobalKnownHostsFile=/dev/null
    -o StrictHostKeyChecking=accept-new
    -o ConnectTimeout=15
)

SCP_OPTS=(
    -P "$DEPLOY_PORT"
    -i "$DEPLOY_KEY"
    -o IdentitiesOnly=yes
    -o IdentityFile="$DEPLOY_KEY"
    -o UserKnownHostsFile="$KNOWN_HOSTS"
    -o GlobalKnownHostsFile=/dev/null
    -o StrictHostKeyChecking=accept-new
)

# rsync -e takes a single shell string; quote the key and known_hosts paths.
RSYNC_RSH="ssh -p ${DEPLOY_PORT} -i '${DEPLOY_KEY}' -o IdentitiesOnly=yes -o IdentityFile='${DEPLOY_KEY}' -o UserKnownHostsFile='${KNOWN_HOSTS}' -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15"

ssh_run() {
    local host="$1"
    shift
    ssh "${SSH_OPTS[@]}" "${SSH_USER}@${host}" "$@"
}

scp_put() {
    local src="$1"
    local dest="$2"
    scp "${SCP_OPTS[@]}" "$src" "$dest"
}

scp_get() {
    local src="$1"
    local dest="$2"
    scp "${SCP_OPTS[@]}" "$src" "$dest"
}

# A 1 GB VPS will OOM rustc without swap (seen on dm2: rustc RSS ~400M, SIGKILL).
ensure_remote_swap() {
    local host="$1"
    log "Ensuring swap on ${host} for the remote compile..."
    ssh_run "$host" "bash -s" <<'REMOTE'
set -euo pipefail
SWAPFILE=/swapfile
if swapon --show | grep -q .; then
    echo "Swap already active:"
    swapon --show
    free -h
    exit 0
fi
if [[ ! -f "$SWAPFILE" ]]; then
    # fallocate is fast; dd if the filesystem rejects it.
    if ! fallocate -l 2G "$SWAPFILE" 2>/dev/null; then
        dd if=/dev/zero of="$SWAPFILE" bs=1M count=2048 status=none
    fi
    chmod 600 "$SWAPFILE"
    mkswap "$SWAPFILE"
fi
swapon "$SWAPFILE"
swapon --show
free -h
REMOTE
    ok "Swap ready."
}

# Install build deps and rustup on the remote if cargo/protoc are missing.
ensure_remote_toolchain() {
    local host="$1"
    log "Ensuring build toolchain on ${host}..."
    ssh_run "$host" "bash -s" <<'REMOTE'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
if [[ -f "${HOME}/.cargo/env" ]]; then
    # shellcheck source=/dev/null
    source "${HOME}/.cargo/env"
fi
need_pkgs=()
command -v cargo >/dev/null 2>&1 || need_pkgs+=(curl)
command -v rsync >/dev/null 2>&1 || need_pkgs+=(rsync)
command -v protoc >/dev/null 2>&1 || need_pkgs+=(protobuf-compiler)
command -v cmake >/dev/null 2>&1 || need_pkgs+=(cmake)
command -v pkg-config >/dev/null 2>&1 || need_pkgs+=(pkg-config)
command -v cc >/dev/null 2>&1 || need_pkgs+=(build-essential)
if [[ ${#need_pkgs[@]} -gt 0 ]]; then
    if ! command -v apt-get >/dev/null 2>&1; then
        echo "Missing packages (${need_pkgs[*]}) and apt-get is not available." >&2
        exit 1
    fi
    apt-get update
    apt-get install -y "${need_pkgs[@]}" libssl-dev
fi
if ! command -v cargo >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    # shellcheck source=/dev/null
    source "${HOME}/.cargo/env"
fi
command -v cargo >/dev/null 2>&1 || { echo "cargo still missing after rustup." >&2; exit 1; }
command -v protoc >/dev/null 2>&1 || { echo "protoc still missing." >&2; exit 1; }
cargo --version
protoc --version
REMOTE
    ok "Remote toolchain ready."
}

# rsync project sources to the build host. Local target/ is excluded so a
# Darwin/ARM tree cannot pollute the Linux incremental cache.
rsync_sources() {
    local host="$1"
    log "Rsyncing sources to ${SSH_USER}@${host}:${REMOTE_SRC} ..."
    ssh_run "$host" "mkdir -p '${REMOTE_SRC}'"
    rsync -az --delete \
        -e "$RSYNC_RSH" \
        --exclude target/ \
        --exclude .git/ \
        --exclude nostr.db \
        --exclude 'nostr.db-*' \
        --exclude result \
        --exclude .config/ \
        "${PROJECT_DIR}/" \
        "${SSH_USER}@${host}:${REMOTE_SRC}/"
    ok "Sources synced."
}

build_remote() {
    local host="$1"
    log "Remote cargo build --release --locked -j${CARGO_JOBS} on ${host}..."
    ssh_run "$host" "REMOTE_SRC='${REMOTE_SRC}' CARGO_JOBS='${CARGO_JOBS}' bash -s" <<'REMOTE'
set -euo pipefail
if [[ -f /root/.cargo/env ]]; then
    # shellcheck source=/dev/null
    source /root/.cargo/env
fi
cd "${REMOTE_SRC}"
export CARGO_INCREMENTAL=0
cargo build --release --locked -j"${CARGO_JOBS}"
test -x "${REMOTE_SRC}/target/release/nostr-rs-relay"
REMOTE
    log "Fetching remote binary..."
    BUILD_OUTPUT="${SSH_WORKDIR}/nostr-rs-relay"
    scp_get "${SSH_USER}@${host}:${REMOTE_SRC}/target/release/nostr-rs-relay" "$BUILD_OUTPUT"
    chmod 755 "$BUILD_OUTPUT"
}

# First-run layout: a non-login service account, relay configuration and policy,
# plus a hardened systemd service. Existing config.toml and kinds.json survive.
ensure_remote_runtime() {
    local host="$1"
    local config_dir kinds_dir unit_path
    config_dir="$(dirname "$REMOTE_CONFIG")"
    kinds_dir="$(dirname "$REMOTE_KINDS")"
    unit_path="/etc/systemd/system/${SERVICE}.service"

    log "  Ensuring non-login nostr user and runtime layout..."
    ssh_run "$host" "bash -s" <<REMOTE
set -euo pipefail
id nostr >/dev/null 2>&1 || useradd --system --home '${REMOTE_DATA}' --shell /usr/sbin/nologin nostr
mkdir -p '${config_dir}' '${kinds_dir}' '${REMOTE_DATA}'
chown -R nostr:nostr '${REMOTE_DATA}'
REMOTE

    if ssh_run "$host" "test -f '${REMOTE_KINDS}'"; then
        ok "  Keeping existing policy file: ${REMOTE_KINDS}"
    else
        log "  Installing policy file from contrib/kinds.json.example..."
        scp_put "$LOCAL_KINDS_EXAMPLE" "${SSH_USER}@${host}:${REMOTE_KINDS}"
        ok "  Installed ${REMOTE_KINDS}"
    fi

    if ssh_run "$host" "test -f '${REMOTE_CONFIG}'"; then
        ok "  Keeping existing config: ${REMOTE_CONFIG}"
    else
        log "  Installing and configuring production config template..."
        scp_put "$LOCAL_CONFIG" "${SSH_USER}@${host}:${REMOTE_CONFIG}"
        ssh_run "$host" "bash -s" <<REMOTE
set -euo pipefail
cfg='${REMOTE_CONFIG}'
sed -i 's|^relay_url = .*|relay_url = "wss://${DOMAIN}/"|' "\$cfg"
sed -i 's|^address = .*|address = "127.0.0.1"|' "\$cfg"
sed -i 's|^port = .*|port = ${LISTEN_PORT}|' "\$cfg"
sed -i 's|^config_file = .*|config_file = "${REMOTE_KINDS}"|' "\$cfg"
grep -q '^remote_ip_header' "\$cfg" || sed -i '/^\[network\]/a remote_ip_header = "x-forwarded-for"' "\$cfg"
chown root:nostr "\$cfg" '${REMOTE_KINDS}'
chmod 640 "\$cfg" '${REMOTE_KINDS}'
REMOTE
        ok "  Installed ${REMOTE_CONFIG}"
    fi

    if ssh_run "$host" "test -f '${unit_path}'"; then
        ok "  Keeping existing systemd unit: ${unit_path}"
        return
    fi

    log "  Installing systemd unit (User=nostr)..."
    ssh_run "$host" "cat > '${unit_path}'" <<UNIT
[Unit]
Description=nostr-rs-relay
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nostr
Group=nostr
WorkingDirectory=${REMOTE_DATA}
Environment=RUST_LOG=warn,nostr_rs_relay=info
ExecStart=${REMOTE_BIN} --config ${REMOTE_CONFIG} --db ${REMOTE_DATA}
TimeoutStopSec=10
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=${REMOTE_DATA}

[Install]
WantedBy=multi-user.target
UNIT
    ssh_run "$host" "systemctl daemon-reload && systemctl enable '${SERVICE}'"
    ok "  systemd unit ${SERVICE} enabled (nostr non-login user)."
}

# Configure each nginx/TLS component only when it is missing. Routine deploys
# therefore do not rewrite a working proxy configuration or invoke certbot.
setup_nginx_tls() {
    local host="$1"
    log "  Checking nginx and Let's Encrypt TLS for ${DOMAIN}..."
    ssh_run "$host" "DOMAIN='${DOMAIN}' SERVICE='${SERVICE}' LISTEN_PORT='${LISTEN_PORT}' CERTBOT_EMAIL='${CERTBOT_EMAIL}' bash -s" <<'REMOTE'
set -euo pipefail
site="/etc/nginx/sites-available/${SERVICE}"
cert="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"

if ! command -v nginx >/dev/null 2>&1 || ! command -v certbot >/dev/null 2>&1; then
    command -v apt-get >/dev/null 2>&1 || { echo 'Ubuntu/Debian apt-get is required.' >&2; exit 1; }
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y nginx certbot python3-certbot-nginx
fi

if [[ ! -f "$site" ]]; then
    cat > "$site" <<NGINX
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};

    location / {
        proxy_pass http://127.0.0.1:${LISTEN_PORT};
        proxy_http_version 1.1;
        proxy_read_timeout 1d;
        proxy_send_timeout 1d;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
NGINX
    rm -f /etc/nginx/sites-enabled/default
    ln -sfn "$site" "/etc/nginx/sites-enabled/${SERVICE}"
    nginx -t
    systemctl enable --now nginx
    systemctl reload nginx
    echo "Created nginx site: $site"
else
    echo "Keeping existing nginx site: $site"
fi

if [[ ! -f "$cert" ]]; then
    certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m "$CERTBOT_EMAIL" --redirect
    systemctl reload nginx
    echo "TLS certificate obtained."
else
    echo "Keeping existing TLS certificate: $cert"
fi
REMOTE
    ok "  nginx/TLS requirements are present."
}

describe_binary() {
    local path="$1"
    local size arch
    size="$(du -h "$path" | cut -f1)"
    arch="unknown"
    if command -v file >/dev/null 2>&1; then
        arch="$(file "$path" | grep -oE 'x86-64|x86_64|aarch64|ARM|arm64' | head -n1 || true)"
        arch="${arch:-unknown}"
    fi
    ok "Binary: $path ($size, $arch)"
    if "$path" --version >/dev/null 2>&1; then
        ok "Local smoke test passed ($("$path" --version 2>/dev/null || echo unknown))"
    else
        warn "Local smoke test failed (binary may be a different OS/arch) — continuing"
    fi
}

# --- Step 1: Obtain a release binary ---
BUILD_OUTPUT=""
case "$EFFECTIVE_BUILD" in
    binary)
        BUILD_OUTPUT="$BINARY_OVERRIDE"
        log "Using prebuilt binary: $BUILD_OUTPUT"
        ;;
    local)
        log "Building release binary locally (cargo build --release --locked)..."
        (
            cd "$PROJECT_DIR"
            cargo build --release --locked
        )
        BUILD_OUTPUT="$DEFAULT_BUILD_OUTPUT"
        if [[ ! -x "$BUILD_OUTPUT" ]]; then
            err "Build finished but binary not found at $BUILD_OUTPUT"
            exit 1
        fi
        ;;
    remote)
        BUILD_HOST="${HOSTS[0]}"
        log "Remote build on ${BUILD_HOST} (this machine is $(uname -s)/$(uname -m))."
        ensure_remote_toolchain "$BUILD_HOST"
        ensure_remote_swap "$BUILD_HOST"
        rsync_sources "$BUILD_HOST"
        build_remote "$BUILD_HOST"
        ;;
esac

if [[ ! -f "$BUILD_OUTPUT" ]]; then
    err "Deploy binary is missing: $BUILD_OUTPUT"
    exit 1
fi
describe_binary "$BUILD_OUTPUT"

# --- Step 2 + 3: Deploy and start/verify on each host ---
for host in "${HOSTS[@]}"; do
    log "==> Deploying to $host"

    log "  Backing up current binary..."
    ssh_run "$host" "cp -f '${REMOTE_BIN}' '${REMOTE_BIN}.prev' 2>/dev/null || true"

    if [[ "$RESTART" == "true" ]]; then
        log "  Stopping service..."
        ssh_run "$host" "systemctl stop '${SERVICE}'" || true
    fi

    log "  Installing new binary..."
    ssh_run "$host" "mkdir -p '$(dirname "$REMOTE_BIN")'"
    scp_put "$BUILD_OUTPUT" "${SSH_USER}@${host}:${REMOTE_BIN}"
    ssh_run "$host" "chmod 755 '${REMOTE_BIN}'"

    # Each setup helper checks its own resources and creates only what is absent.
    ensure_remote_runtime "$host"
    setup_nginx_tls "$host"

    if [[ "$RESTART" == "true" ]]; then
        log "  Starting service..."
        ssh_run "$host" "systemctl start '${SERVICE}'"
        sleep 3
        if ssh_run "$host" "systemctl is-active '${SERVICE}'" | grep -q active; then
            ok "  ✔ ${SERVICE} active on ${host}"
        else
            err "Service failed to start on ${host} — journalctl -u ${SERVICE} -n 50"
            err "Rollback: ssh -p ${DEPLOY_PORT} -i ${DEPLOY_KEY} ${SSH_USER}@${host} 'cp ${REMOTE_BIN}.prev ${REMOTE_BIN} && systemctl restart ${SERVICE}'"
            exit 1
        fi
    else
        warn "  Skipping restart (--no-restart)."
    fi

    REMOTE_VER="$(ssh_run "$host" "'${REMOTE_BIN}' --version" 2>/dev/null || echo unknown)"
    ok "  Remote version: ${REMOTE_VER}"
done

assert_default_identity_untouched

printf '\n'
ok "Deployment complete."
cat <<EOF

Deployment summary
  Relay URL:       wss://${DOMAIN}/
  Hosts:           ${HOSTS[*]}
  Service:         ${SERVICE}.service (runs as non-login user: nostr)
  Executable:      ${REMOTE_BIN}
  Configuration:   ${REMOTE_CONFIG}
  Policy file:     ${REMOTE_KINDS}
  Data / database: ${REMOTE_DATA}
  nginx site:      /etc/nginx/sites-available/${SERVICE}
  TLS certificates:/etc/letsencrypt/live/${DOMAIN}/

Useful commands (run on a server):
  systemctl status ${SERVICE}
  journalctl -fu ${SERVICE}
  systemctl restart ${SERVICE}
  nginx -t && systemctl reload nginx
  certbot renew --dry-run
EOF
