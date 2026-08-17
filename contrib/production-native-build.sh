#!/usr/bin/env bash
#
# Interactive production deployment for nostr-rs-relay on Ubuntu.
# Implements docs/production-native-build.md
#
# Usage:
#   curl -O https://.../production-native-build.sh   # or scp the file
#   chmod +x production-native-build.sh
#   sudo ./production-native-build.sh
#
set -euo pipefail

# ---------------------------------------------------------------------------
# UI helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

step()  { echo -e "\n${BOLD}${BLUE}==> $*${NC}\n"; }
info()  { echo -e "${BLUE}[info]${NC} $*"; }
ok()    { echo -e "${GREEN}[ok]${NC} $*"; }
warn()  { echo -e "${YELLOW}[warn]${NC} $*"; }
fail()  { echo -e "${RED}[error]${NC} $*" >&2; exit 1; }

prompt() {
    local var_name="$1"
    local message="$2"
    local default="${3:-}"
    local input
    if [[ -n "$default" ]]; then
        read -r -p "$message [$default]: " input
        input="${input:-$default}"
    else
        read -r -p "$message: " input
        while [[ -z "$input" ]]; do
            warn "This field is required."
            read -r -p "$message: " input
        done
    fi
    printf -v "$var_name" '%s' "$input"
}

confirm() {
    local message="$1"
    local default="${2:-y}"
    local hint="y/n"
    [[ "$default" == "y" ]] && hint="Y/n"
    [[ "$default" == "n" ]] && hint="y/N"
    local input
    read -r -p "$message ($hint): " input
    input="${input:-$default}"
    [[ "$input" =~ ^[Yy] ]]
}

run() {
    info "Running: $*"
    if "$@"; then
        ok "Done."
    else
        fail "Command failed: $*"
    fi
}

require_root() {
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        fail "This script must be run as root (or with sudo)."
    fi
}

check_ubuntu() {
    if [[ ! -f /etc/os-release ]]; then
        warn "Cannot detect OS; continuing anyway."
        return
    fi
    # shellcheck source=/dev/null
    source /etc/os-release
    if [[ "${ID:-}" != "ubuntu" ]]; then
        warn "This guide targets Ubuntu. Detected: ${PRETTY_NAME:-unknown}."
        if ! confirm "Continue anyway?"; then
            exit 1
        fi
    else
        ok "Detected ${PRETTY_NAME:-Ubuntu}."
    fi
}

# ---------------------------------------------------------------------------
# Collect configuration
# ---------------------------------------------------------------------------
collect_inputs() {
    step "Configuration"

    echo "Answer the prompts below. Press Enter to accept defaults shown in brackets."
    echo

    prompt DOMAIN "Public domain name for the relay (DNS must point to this server)"
    prompt CERTBOT_EMAIL "Email address for Let's Encrypt certificate notifications"
    prompt RELAY_NAME "Relay display name" "My Nostr Relay"
    prompt RELAY_DESCRIPTION "Relay description" "A nostr-rs-relay instance."
    prompt GIT_REPO "Git repository URL" "https://git.nostrdev.com/complex/nostr-rs-relay.git"
    prompt BUILD_DIR "Directory to clone and build the source" "/opt/nostr-rs-relay-src"

    echo
    info "Public relay rate limits reduce abuse on open relays."
    ENABLE_LIMITS=false
    confirm "Enable public relay rate limits (messages_per_sec=5, subscriptions_per_min=10)?" && ENABLE_LIMITS=true

    ENABLE_KIND_FILTERS=false
    confirm "Set up kind filters (.config/kinds.json)?" "n" && ENABLE_KIND_FILTERS=true

    echo
    step "Configuration summary"
    echo "  Domain:           wss://${DOMAIN}/"
    echo "  Certbot email:    ${CERTBOT_EMAIL}"
    echo "  Relay name:       ${RELAY_NAME}"
    echo "  Build directory:  ${BUILD_DIR}"
    echo "  Rate limits:      ${ENABLE_LIMITS}"
    echo "  Kind filters:     ${ENABLE_KIND_FILTERS}"
    echo

    confirm "Proceed with installation?" || fail "Aborted by user."
}

# ---------------------------------------------------------------------------
# Installation steps (docs/production-native-build.md)
# ---------------------------------------------------------------------------
install_system_packages() {
    step "1/8 — Install system packages"
    run apt update
    run apt install -y \
        build-essential cmake protobuf-compiler pkg-config libssl-dev \
        git sqlite3 nginx certbot python3-certbot-nginx curl
    ok "System packages installed."
}

install_rust() {
    step "2/8 — Install Rust toolchain"
    if command -v cargo >/dev/null 2>&1; then
        ok "Rust already installed: $(cargo --version)"
        return
    fi
    info "Installing rustup (this may take a minute)..."
    run bash -c 'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y'
    # shellcheck source=/dev/null
    source "${HOME}/.cargo/env"
    ok "Rust installed: $(cargo --version)"
}

clone_and_build() {
    step "3/8 — Clone repository and build release binary"
    if [[ -d "${BUILD_DIR}/.git" ]]; then
        warn "Build directory already exists: ${BUILD_DIR}"
        if confirm "Pull latest changes and rebuild?"; then
            info "Updating existing clone..."
            run git -C "${BUILD_DIR}" pull
        elif [[ -x "${BUILD_DIR}/target/release/nostr-rs-relay" ]]; then
            ok "Using existing binary at ${BUILD_DIR}/target/release/nostr-rs-relay"
            return
        else
            fail "No release binary found in ${BUILD_DIR}. Remove the directory or choose rebuild."
        fi
    else
        info "Cloning into ${BUILD_DIR}..."
        run git clone "${GIT_REPO}" "${BUILD_DIR}"
    fi

    info "Building release binary (single job to limit memory use; may take several minutes)..."
    # shellcheck source=/dev/null
    [[ -f "${HOME}/.cargo/env" ]] && source "${HOME}/.cargo/env"
    run bash -c "cd '${BUILD_DIR}' && cargo build --release -j1"
    [[ -x "${BUILD_DIR}/target/release/nostr-rs-relay" ]] \
        || fail "Build finished but binary not found at ${BUILD_DIR}/target/release/nostr-rs-relay"
    ok "Binary built: ${BUILD_DIR}/target/release/nostr-rs-relay"
}

setup_user_and_dirs() {
    step "4/8 — Create system user and directories"
    if id nostr &>/dev/null; then
        ok "User 'nostr' already exists."
    else
        run useradd -r -s /usr/sbin/nologin -d /var/lib/nostr-rs-relay nostr
        ok "Created user 'nostr'."
    fi

    run mkdir -p /etc/nostr-rs-relay
    run mkdir -p /var/lib/nostr-rs-relay/.config
    run chown -R nostr:nostr /var/lib/nostr-rs-relay

    info "Installing binary..."
    run cp "${BUILD_DIR}/target/release/nostr-rs-relay" /usr/local/bin/nostr-rs-relay
    run chmod 755 /usr/local/bin/nostr-rs-relay
    ok "Binary installed to /usr/local/bin/nostr-rs-relay"
}

configure_relay() {
    step "5/8 — Configure the relay"
    local config_src="${BUILD_DIR}/config.toml"
    [[ -f "$config_src" ]] || fail "config.toml not found in ${BUILD_DIR}"

    if [[ -f /etc/nostr-rs-relay/config.toml ]]; then
        warn "Existing config at /etc/nostr-rs-relay/config.toml"
        if confirm "Overwrite with freshly generated production config?" "n"; then
            cp "${config_src}" /etc/nostr-rs-relay/config.toml
        else
            info "Keeping existing config.toml (skipping template edits)."
            return
        fi
    else
        run cp "${config_src}" /etc/nostr-rs-relay/config.toml
    fi

    local cfg=/etc/nostr-rs-relay/config.toml

    # [info]
    sed -i "s|^relay_url = .*|relay_url = \"wss://${DOMAIN}/\"|" "$cfg"
    sed -i "s|^name = .*|name = \"${RELAY_NAME}\"|" "$cfg"
    sed -i "s|^description = .*|description = \"${RELAY_DESCRIPTION}\"|" "$cfg"

    # [network] — bind locally, trust nginx for client IPs
    sed -i 's|^address = .*|address = "127.0.0.1"|' "$cfg"
    sed -i 's|^port = .*|port = 8080|' "$cfg"
    if grep -q '^#remote_ip_header = "x-forwarded-for"' "$cfg"; then
        sed -i 's|^#remote_ip_header = "x-forwarded-for"|remote_ip_header = "x-forwarded-for"|' "$cfg"
    elif ! grep -q '^remote_ip_header' "$cfg"; then
        sed -i '/^\[network\]/a remote_ip_header = "x-forwarded-for"' "$cfg"
    fi

    # [limits]
    if [[ "$ENABLE_LIMITS" == true ]]; then
        sed -i 's|^#messages_per_sec = .*|messages_per_sec = 5|' "$cfg"
        sed -i 's|^#subscriptions_per_min = .*|subscriptions_per_min = 10|' "$cfg"
        sed -i 's|^limit_scrapers = .*|limit_scrapers = true|' "$cfg"
    fi

    # [kind_filters_config]
    if [[ "$ENABLE_KIND_FILTERS" == true ]]; then
        run mkdir -p /etc/nostr-rs-relay/.config
        local kinds_example="${BUILD_DIR}/contrib/kinds.json.example"
        [[ -f "$kinds_example" ]] || fail "kinds.json.example not found in ${BUILD_DIR}/contrib/"
        run cp "$kinds_example" /etc/nostr-rs-relay/.config/kinds.json
        run chown root:nostr /etc/nostr-rs-relay/.config/kinds.json
        run chmod 640 /etc/nostr-rs-relay/.config/kinds.json
        sed -i 's|^config_file = .*|config_file = "/etc/nostr-rs-relay/.config/kinds.json"|' "$cfg"
        ok "Kind filters configured at /etc/nostr-rs-relay/.config/kinds.json"
    else
        sed -i 's|^config_file = .*|#config_file = ".config/kinds.json"|' "$cfg"
        info "Kind filters disabled (config_file commented out)."
    fi

    ok "Configuration written to /etc/nostr-rs-relay/config.toml"
}

install_systemd() {
    step "6/8 — Install systemd service"
    local service_src="${BUILD_DIR}/contrib/nostr-rs-relay.service"
    [[ -f "$service_src" ]] || fail "nostr-rs-relay.service not found in ${BUILD_DIR}/contrib/"

    run cp "$service_src" /etc/systemd/system/nostr-rs-relay.service
    run systemctl daemon-reload
    run systemctl enable nostr-rs-relay
    run systemctl restart nostr-rs-relay

    sleep 2
    if systemctl is-active --quiet nostr-rs-relay; then
        ok "nostr-rs-relay service is active."
    else
        warn "Service may not be running. Recent logs:"
        journalctl -u nostr-rs-relay -n 30 --no-pager || true
        if ! confirm "Service is not active. Continue with nginx setup anyway?"; then
            fail "Fix the service first: journalctl -u nostr-rs-relay -n 50"
        fi
    fi

    if [[ "$ENABLE_KIND_FILTERS" == true ]]; then
        info "Checking kind filter load in logs..."
        if journalctl -u nostr-rs-relay -n 20 --no-pager | grep -q '\[Config\].*kind filters'; then
            ok "Kind filters loaded successfully."
        else
            warn "Could not confirm kind filters in logs. Check: journalctl -u nostr-rs-relay -n 20"
        fi
    fi
}

setup_nginx_tls() {
    step "7/8 — Configure nginx and obtain TLS certificate"

    info "Writing /etc/nginx/sites-available/default ..."
    tee /etc/nginx/sites-available/default > /dev/null <<NGINX_EOF
server {
    server_name ${DOMAIN};
    location / {
        proxy_pass http://127.0.0.1:8080;

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
NGINX_EOF

    if [[ -L /etc/nginx/sites-enabled/default ]] || [[ -f /etc/nginx/sites-enabled/default ]]; then
        ok "nginx default site already enabled."
    else
        run ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default
    fi

    run nginx -t
    run systemctl reload nginx

    info "Requesting Let's Encrypt certificate for ${DOMAIN}..."
    if certbot --nginx -d "${DOMAIN}" --non-interactive --agree-tos -m "${CERTBOT_EMAIL}"; then
        ok "TLS certificate obtained."
    else
        warn "certbot failed. Common causes: DNS not pointing here, port 80 blocked, or rate limits."
        warn "You can retry later: certbot --nginx -d ${DOMAIN}"
        if ! confirm "Continue without a valid certificate?"; then
            fail "Fix DNS/firewall and re-run certbot."
        fi
    fi

    run systemctl reload nginx
    ok "nginx reloaded."
}

verify_deployment() {
    step "8/8 — Verify deployment"

    info "Checking local relay info document..."
    if curl -sf --max-time 10 http://127.0.0.1:8080 >/dev/null; then
        ok "Relay responds on http://127.0.0.1:8080"
        echo
        curl -s http://127.0.0.1:8080 | head -c 500
        echo
        echo
    else
        warn "Could not reach relay on http://127.0.0.1:8080"
    fi

    info "Checking HTTPS endpoint..."
    if curl -sf --max-time 15 "https://${DOMAIN}" >/dev/null; then
        ok "Relay responds on https://${DOMAIN}"
        echo
        curl -s "https://${DOMAIN}" | head -c 500
        echo
    else
        warn "HTTPS check failed for https://${DOMAIN} (certificate or DNS may still be propagating)."
    fi

    echo
    info "WebSocket test (optional): install websocat and run:"
    echo "  websocat wss://${DOMAIN}"
}

print_summary() {
    step "Deployment complete"
    cat <<EOF
nostr-rs-relay is installed and configured.

  Relay URL:     wss://${DOMAIN}/
  Binary:        /usr/local/bin/nostr-rs-relay
  Config:        /etc/nostr-rs-relay/config.toml
  Data / DB:     /var/lib/nostr-rs-relay/
  Source clone:  ${BUILD_DIR}

Useful commands:
  sudo systemctl status nostr-rs-relay
  sudo journalctl -f -u nostr-rs-relay
  sudo systemctl restart nostr-rs-relay

To upgrade later (from a linux/amd64 machine with root SSH):
  ./scripts/deploy.sh --host ${DOMAIN} --key ~/.ssh/id_ed25519

Connect a Nostr client to: wss://${DOMAIN}
EOF
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    echo -e "${BOLD}nostr-rs-relay — Production Native Build${NC}"
    echo "Interactive installer for Ubuntu (see docs/production-native-build.md)"
    echo

    require_root
    check_ubuntu
    collect_inputs

    install_system_packages
    install_rust
    clone_and_build
    setup_user_and_dirs
    configure_relay
    install_systemd
    setup_nginx_tls
    verify_deployment
    print_summary
}

main "$@"
