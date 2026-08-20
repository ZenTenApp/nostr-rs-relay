# Production Native Build (Ubuntu)

This guide covers deploying `nostr-rs-relay` on Ubuntu as a native binary managed
by systemd, with TLS termination via nginx. It is intended for long-running
production relays.

## Architecture

```
Internet
   │
   ▼
nginx (443, TLS) ──► nostr-rs-relay (127.0.0.1:8080)
```

Clients connect over `wss://`. The relay binds locally on port `8080` and is
not exposed directly to the internet.

## Requirements

- Ubuntu 20.04, 22.04, or 24.04
- A domain name pointing at the server (for TLS)
- At least 1 CPU core and 1 GB RAM (scale up for busy public relays)
- Root or sudo access

## 1. System packages

Install build dependencies and runtime tools:

```bash
sudo apt update
sudo apt install -y \
  build-essential cmake protobuf-compiler pkg-config libssl-dev \
  git sqlite3 nginx certbot python3-certbot-nginx
```

## 2. Install Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

## 3. Build from source

```bash
git clone https://git.nostrdev.com/complex/nostr-rs-relay.git
cd nostr-rs-relay
cargo build --release -j1
```

The release binary is at `target/release/nostr-rs-relay`.

To install or upgrade over SSH as root, use
[`scripts/deploy.sh`](../scripts/deploy.sh). On a fresh Ubuntu host it creates
an unprivileged, non-login `nostr` system user; installs the relay, config,
and policy file; configures nginx; and obtains a Let's Encrypt certificate.
On later deployments it checks each component individually, creates only missing
resources, and preserves existing configuration and policy files.

On linux/amd64 it builds locally. From macOS (or any other machine) it
rsyncs the tree to the first `--host` and runs `cargo build --release
--locked -j1` there, then installs the binary.

```bash
./scripts/deploy.sh \
  --host relay.example.com \
  --key ~/.ssh/id_ed25519 \
  --domain relay.example.com \
  --email admin@example.com
```

Pass `--binary` to skip cargo and ship a file you already have. Repeat
`--host` to install the same binary on more servers. Use `--no-restart` to
install without bouncing systemd. On failure the previous binary is left at
`/usr/local/bin/nostr-rs-relay.prev`.

## 4. Create system user and directories

Run the relay as a dedicated unprivileged user:

```bash
sudo useradd -r -s /usr/sbin/nologin -d /var/lib/nostr-rs-relay nostr

sudo mkdir -p /etc/nostr-rs-relay
sudo mkdir -p /var/lib/nostr-rs-relay/.config
sudo chown -R nostr:nostr /var/lib/nostr-rs-relay
```

Install the binary and configuration:

```bash
sudo cp target/release/nostr-rs-relay /usr/local/bin/
sudo cp config.toml /etc/nostr-rs-relay/config.toml
```

### Directory layout

| Path                                     | Purpose                                                      |
| ---------------------------------------- | ------------------------------------------------------------ |
| `/usr/local/bin/nostr-rs-relay`          | Relay binary                                                 |
| `/etc/nostr-rs-relay/config.toml`        | Configuration (root-owned, readable by service)              |
| `/etc/nostr-rs-relay/.config/kinds.json` | Optional kind filter config (path relative to `config.toml`) |
| `/var/lib/nostr-rs-relay/`               | Working directory and SQLite database                        |
| `/var/lib/nostr-rs-relay/nostr.db`       | SQLite database (created on first start)                     |

## 5. Configure the relay

Edit `/etc/nostr-rs-relay/config.toml`. At minimum, set your public URL and
relay metadata:

```toml
[info]
relay_url = "wss://relay.example.com/"
name = "My Nostr Relay"
description = "A nostr-rs-relay instance."

[network]
address = "127.0.0.1"
port = 8080
remote_ip_header = "x-forwarded-for"
```

Binding to `127.0.0.1` ensures only nginx (on the same host) can reach the
relay. Set `remote_ip_header` so rate limits and logs reflect real client IPs.

### Public relay limits

For a public relay, enable rate limits to reduce abuse:

```toml
[limits]
messages_per_sec = 5
subscriptions_per_min = 10
limit_scrapers = true
```

See the sample [`config.toml`](../config.toml) for all available options,
including NIP-05 verification, NIP-42 auth, pay-to-relay, and kind filters.

If using kind filters, create the file next to `config.toml`. Relative paths
in `config_file` are resolved from `/etc/nostr-rs-relay/`, not the data
directory:

```bash
sudo mkdir -p /etc/nostr-rs-relay/.config
sudo cp contrib/kinds.json.example /etc/nostr-rs-relay/.config/kinds.json
sudo chown root:nostr /etc/nostr-rs-relay/.config/kinds.json
sudo chmod 640 /etc/nostr-rs-relay/.config/kinds.json
```

Or use an absolute path in `config.toml` to avoid ambiguity:

```toml
[kind_filters_config]
config_file = "/etc/nostr-rs-relay/.config/kinds.json"
```

After creating or editing the file, restart and confirm it loaded:

```bash
sudo systemctl restart nostr-rs-relay
sudo journalctl -u nostr-rs-relay -n 20 --no-pager | grep '\[Config\]'
```

You should see `Loaded kind filters from /etc/nostr-rs-relay/.config/kinds.json`.
If you do not need kind filters yet, comment out `config_file` in `config.toml`
instead of creating the file.

## 6. Install the systemd service

Copy the service unit from the repository:

```bash
sudo cp contrib/nostr-rs-relay.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now nostr-rs-relay
sudo systemctl status nostr-rs-relay
```

The service runs as the `nostr` user, reads config from `/etc/nostr-rs-relay/`,
and stores the database in `/var/lib/nostr-rs-relay/`.

### Logs

```bash
sudo journalctl -f -u nostr-rs-relay
```

### Service management

```bash
sudo systemctl restart nostr-rs-relay   # after config or binary changes
sudo systemctl stop nostr-rs-relay
```

## 7. TLS with nginx

Remove default site configuration

Create an nginx site configuration at
`/etc/nginx/sites-available/default`:

```bash
sudo tee /etc/nginx/sites-available/default > /dev/null << NGINX_EOF
server {
    server_name $Replace_with_your_server_name;
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


        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Host \$host;
    }
}
NGINX_EOF
```

Test nginx config

`sudo nginx -t`

Obtain certificate

`sudo certbot --nginx $Replace_with_your_domain --non-interactive --agree-tos -m "$Replace_with_your_email"`

Reload nginx service and enable the site:

`sudo systemctl reload nginx`

## 8. Firewall

Allow SSH and HTTPS only. Do not expose port 8080 publicly.

```bash
sudo ufw allow OpenSSH
sudo ufw allow 'Nginx Full'
sudo ufw enable
sudo ufw status
```

## 9. Verify deployment

Check the relay info document locally:

```bash
curl -s http://127.0.0.1:8080
```

Check over TLS:

```bash
curl -s https://relay.example.com
```

Test the WebSocket endpoint:

```bash
# install websocat if needed: cargo install websocat
websocat wss://relay.example.com
```

Or connect with any Nostr client using `wss://relay.example.com`.

## 10. Backups

Back up the SQLite database regularly. Online backups can run while the relay
is active. See [Database Maintenance](database-maintenance.md) for full details.

```bash
sudo mkdir -p /var/backups/nostr
BACKUP_FILE=/var/backups/nostr/$(date +%Y%m%d_%H%M).db
sudo -u nostr sqlite3 -readonly /var/lib/nostr-rs-relay/nostr.db ".backup $BACKUP_FILE"
```

Consider scheduling this with a cron job or systemd timer.

## 11. Optional hardening

### Restrict config file permissions

```bash
sudo chown root:nostr /etc/nostr-rs-relay/config.toml
sudo chmod 640 /etc/nostr-rs-relay/config.toml
```

### Automatic security updates

```bash
sudo apt install -y unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades
```

### Access control

For a private relay, use `[authorization] pubkey_whitelist` in `config.toml`.
For authenticated clients, enable `[authorization] nip42_auth`. See
[User Verification (NIP-05)](user-verification-nip05.md) and
[Pay to Relay](pay-to-relay.md) for additional access models.

## Troubleshooting

| Symptom                                  | Check                                                       |
| ---------------------------------------- | ----------------------------------------------------------- |
| Service fails to start                   | `sudo journalctl -u nostr-rs-relay -n 50`                   |
| Permission denied on database            | `sudo chown -R nostr:nostr /var/lib/nostr-rs-relay`         |
| WebSocket connects but immediately drops | nginx `Upgrade` headers and `proxy_read_timeout`            |
| Wrong client IPs in logs                 | `remote_ip_header` in config and `X-Forwarded-For` in nginx |
| `wss://` fails, local `curl` works       | certbot certificate, DNS, firewall on port 443              |

## Related documentation

- [`scripts/deploy.sh`](../scripts/deploy.sh) — upgrade an existing host over SSH
- [Run as a Linux System Process](run-as-linux-system-process.md) — minimal systemd setup
- [Reverse Proxy](reverse-proxy.md) — HAProxy, nginx, and Traefik examples
- [Database Maintenance](database-maintenance.md) — vacuum, pruning, and backups
- [User Verification (NIP-05)](user-verification-nip05.md)
- [Pay to Relay](pay-to-relay.md)
- [gRPC Extensions](grpc-extensions.md)
