#!/usr/bin/env bash
#
# Install DNS Daddy as a systemd service on a Debian, Ubuntu, or RHEL-family
# host. Run as root:
#
#     curl -fsSL https://raw.githubusercontent.com/jameshoulder/dnsdaddy/main/deploy/install.sh | sudo bash
#
# Or, from a clone:
#
#     sudo ./deploy/install.sh
#
# The script is idempotent: running it again upgrades the binary and leaves
# your configuration and database alone.

set -euo pipefail

REPO="jameshoulder/dnsdaddy"
BIN_PATH="/usr/local/bin/dnsdaddy"
CONFIG_DIR="/etc/dnsdaddy"
DATA_DIR="/var/lib/dnsdaddy"
SERVICE_USER="dnsdaddy"
VERSION="${DNSDADDY_VERSION:-latest}"

log()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m==>\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m==>\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "This script must run as root. Try: sudo $0"
command -v systemctl >/dev/null || die "systemd is required. For other init systems, run the binary directly or use Docker."

# --- 1. detect platform ------------------------------------------------------
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  armv7l) ARCH=armv7 ;;
  *) die "Unsupported architecture: $(uname -m)" ;;
esac
log "Platform: linux/${ARCH}"

# --- 2. free up port 53 ------------------------------------------------------
# systemd-resolved binds 127.0.0.53:53 on most Ubuntu installs and will stop
# DNS Daddy from starting. Disabling its stub listener is the standard fix, and
# is worth doing before the install rather than after a confusing failure.
if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
  if ss -lnup 2>/dev/null | grep -q ':53 ' || ss -lntp 2>/dev/null | grep -q ':53 '; then
    warn "systemd-resolved is listening on port 53."
    mkdir -p /etc/systemd/resolved.conf.d
    cat > /etc/systemd/resolved.conf.d/dnsdaddy.conf <<'EOF'
# Installed by DNS Daddy: free port 53 for the resolver, and stop resolved
# from acting as a caching stub in front of it.
[Resolve]
DNSStubListener=no
EOF
    # /etc/resolv.conf usually symlinks to the stub. Point this machine's own
    # lookups somewhere that will still answer once the stub is gone.
    if [[ -L /etc/resolv.conf ]]; then
      ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
    fi
    systemctl restart systemd-resolved
    log "Disabled the systemd-resolved stub listener."
  fi
fi

# --- 3. create the service account ------------------------------------------
if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER" 2>/dev/null \
    || useradd --system --no-create-home --shell /sbin/nologin "$SERVICE_USER"
  log "Created service user ${SERVICE_USER}."
fi

install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0750 "$DATA_DIR"
install -d -m 0755 "$CONFIG_DIR"

# --- 4. install the binary ---------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -f "${SCRIPT_DIR}/../go.mod" ]] && command -v go >/dev/null; then
  log "Building from source…"
  ( cd "${SCRIPT_DIR}/.." && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$BIN_PATH" ./cmd/dnsdaddy )
else
  if [[ "$VERSION" == "latest" ]]; then
    TAG=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
          | grep -m1 '"tag_name"' | cut -d'"' -f4) \
      || die "Could not determine the latest release. Set DNSDADDY_VERSION, or clone the repo and build with Go."
  else
    TAG="$VERSION"
  fi
  URL="https://github.com/${REPO}/releases/download/${TAG}/dnsdaddy_${TAG#v}_linux_${ARCH}.tar.gz"

  log "Downloading ${TAG}…"
  TMP=$(mktemp -d)
  trap 'rm -rf "$TMP"' EXIT
  curl -fsSL "$URL" -o "${TMP}/dnsdaddy.tar.gz" || die "Download failed: $URL"

  # Verify against the release checksums when they are published.
  if curl -fsSL "https://github.com/${REPO}/releases/download/${TAG}/checksums.txt" -o "${TMP}/checksums.txt" 2>/dev/null; then
    ( cd "$TMP" && grep "linux_${ARCH}.tar.gz" checksums.txt | sha256sum -c - ) \
      || die "Checksum mismatch — refusing to install."
    log "Checksum verified."
  else
    warn "No checksums published for ${TAG}; skipping verification."
  fi

  tar -xzf "${TMP}/dnsdaddy.tar.gz" -C "$TMP"
  install -m 0755 "${TMP}/dnsdaddy" "$BIN_PATH"
fi
log "Installed $($BIN_PATH -version)"

# --- 5. configuration --------------------------------------------------------

# The dashboard is authenticated but travels in plaintext, so what matters is
# who can reach the port. This installer runs non-interactively (curl | sudo
# bash), so it cannot ask — and it must therefore fail closed.
#
# Loopback, always, unless the operator says otherwise. A private address on
# the default route is NOT evidence that a machine has no public reachability:
# on AWS, GCP, Azure, and most cloud providers the instance NIC holds an RFC
# 1918 address and the public address is 1:1 NATed onto it. Binding every
# interface there publishes the management API to the internet, which is the
# exact condition this choice exists to prevent, and nothing visible from
# inside the host distinguishes it from a LAN machine.
HTTP_LISTEN="${DNSDADDY_HTTP_LISTEN:-127.0.0.1:8080}"
DASHBOARD_NOTE=""

if [[ ! -f "${CONFIG_DIR}/config.yaml" ]]; then
  if [[ -f "${SCRIPT_DIR}/../dnsdaddy.example.yaml" ]]; then
    install -m 0644 "${SCRIPT_DIR}/../dnsdaddy.example.yaml" "${CONFIG_DIR}/config.yaml"
  else
    cat > "${CONFIG_DIR}/config.yaml" <<EOF
data_dir: ${DATA_DIR}
dns:
  listen_udp: ":53"
  listen_tcp: ":53"
  upstreams:
    - "tls://9.9.9.9:853#dns.quad9.net"
    - "tls://1.1.1.1:853#cloudflare-dns.com"
http:
  listen: "${HTTP_LISTEN}"
EOF
  fi
  # The example config ships with ":8080"; rewrite it to whatever was chosen.
  sed -i -E "s|^(\s*)listen: \"?:?8080\"?|\1listen: \"${HTTP_LISTEN}\"|" "${CONFIG_DIR}/config.yaml" 2>/dev/null || true
  log "Wrote ${CONFIG_DIR}/config.yaml (dashboard: ${HTTP_LISTEN})"
else
  log "Keeping existing ${CONFIG_DIR}/config.yaml"
  # `|| true` is load-bearing: a config that relies on the built-in default
  # has no listen: line at all, grep exits 1, and under `set -e` the bare
  # assignment would kill the installer here — on an upgrade, after the new
  # binary is already in place and before the service is restarted.
  HTTP_LISTEN=$(grep -oP '^\s*listen:\s*"?\K[^"\s]+' "${CONFIG_DIR}/config.yaml" 2>/dev/null | tail -1 || true)
  [[ -n "$HTTP_LISTEN" ]] || HTTP_LISTEN=":8080"
fi

# --- 6. systemd unit ---------------------------------------------------------
if [[ -f "${SCRIPT_DIR}/dnsdaddy.service" ]]; then
  install -m 0644 "${SCRIPT_DIR}/dnsdaddy.service" /etc/systemd/system/dnsdaddy.service
else
  curl -fsSL "https://raw.githubusercontent.com/${REPO}/main/deploy/dnsdaddy.service" \
    -o /etc/systemd/system/dnsdaddy.service || die "Could not fetch the systemd unit."
fi

systemctl daemon-reload
systemctl enable dnsdaddy >/dev/null
systemctl restart dnsdaddy

# --- 7. report ---------------------------------------------------------------
sleep 3
if ! systemctl is-active --quiet dnsdaddy; then
  warn "DNS Daddy did not start. Recent log:"
  journalctl -u dnsdaddy -n 30 --no-pager >&2
  exit 1
fi

IP=$(hostname -I 2>/dev/null | awk '{print $1}')
: "${IP:=<this-server>}"

case "$HTTP_LISTEN" in
  127.*|localhost*)
    DASHBOARD_URL="http://${HTTP_LISTEN}"
    DASHBOARD_NOTE="loopback only. See \"Opening the dashboard\" below."
    ;;
  :8080)
    DASHBOARD_URL="http://${IP}:8080"
    DASHBOARD_NOTE="every interface — make sure this machine has no public address"
    ;;
  *)
    DASHBOARD_URL="http://${HTTP_LISTEN}"
    DASHBOARD_NOTE="as configured"
    ;;
esac

cat <<EOF

  DNS Daddy is running.

  Dashboard   ${DASHBOARD_URL}
              ${DASHBOARD_NOTE}
  Resolver    ${IP}  (set this as your DNS server)

EOF

if [[ -f "${DATA_DIR}/initial-password.txt" ]]; then
  echo "  $(cat "${DATA_DIR}/initial-password.txt" | head -1)"
  echo
  echo "  Sign in, change it under Settings, then delete ${DATA_DIR}/initial-password.txt"
else
  echo "  Sign in with the admin password from your config."
fi

cat <<EOF

  Next steps
    1. Open the dashboard and go to Threat feeds → Refresh now.
    2. Point one test device at ${IP} and confirm queries appear.
    3. Only then change your DHCP scope or firewall for everyone else.

  Logs        journalctl -u dnsdaddy -f
  Restart     systemctl restart dnsdaddy

  Opening the dashboard

    The dashboard is authenticated but travels in plaintext, so it is bound to
    loopback until you say otherwise. Reach it now with an SSH tunnel:

      ssh -L 8080:127.0.0.1:8080 ${USER:-you}@${IP}

    On a LAN machine with no public address, publish it on your network:

      sudo sed -i 's|listen: "127.0.0.1:8080"|listen: ":8080"|' ${CONFIG_DIR}/config.yaml
      sudo systemctl restart dnsdaddy

    Do NOT do that on a cloud VPS. Most providers give the instance a private
    address and NAT a public one onto it, so ":8080" is reachable from the
    internet even though \`ip addr\` shows only 10.x or 172.x. There, put TLS in
    front instead — see docs/deploy.md.

  DNS Daddy reports it if this goes wrong: a management request arriving over
  plain HTTP from a public address is raised on the dashboard and at
  /api/v1/diagnostics.

EOF
