#!/usr/bin/env bash
#
# DNS Daddy — guided Docker Compose install.
#
#     git clone https://github.com/jameshoulder/dnsdaddy.git
#     cd dnsdaddy
#     ./deploy/install-docker.sh
#
# It checks the things that actually go wrong, writes .env, starts the stack,
# and runs `dnsdaddy doctor`. It asks before doing anything that changes the
# machine, and it never disables a system service on your behalf.
#
#   --dry-run    run every check and print the .env that would be written,
#                without touching anything
#   --yes        accept the detected answers without prompting
#
# For a native systemd install instead, use deploy/install.sh.

set -uo pipefail

DRY_RUN=0
ASSUME_YES=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    --yes|-y)  ASSUME_YES=1 ;;
    --help|-h) sed -n '2,20p' "$0" | sed 's/^# \?//'; exit 0 ;;
    *) printf 'Unknown option: %s\n' "$arg" >&2; exit 2 ;;
  esac
done

BOLD=$'\033[1m'; GREEN=$'\033[1;32m'; YELLOW=$'\033[1;33m'; RED=$'\033[1;31m'; OFF=$'\033[0m'
pass() { printf '  %sPASS%s  %s\n' "$GREEN" "$OFF" "$*"; }
warn() { printf '  %sWARN%s  %s\n' "$YELLOW" "$OFF" "$*"; }
fail() { printf '  %sFAIL%s  %s\n' "$RED" "$OFF" "$*"; }
head_() { printf '\n%s%s%s\n' "$BOLD" "$*" "$OFF"; }
die()  { printf '\n%sCannot continue:%s %s\n\n' "$RED" "$OFF" "$*" >&2; exit 1; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || die "Could not enter the repository root."

printf '\n%sDNS Daddy setup%s\n' "$BOLD" "$OFF"
[[ $DRY_RUN -eq 1 ]] && printf '(dry run — nothing will be changed)\n'

# --- 1. the machine ----------------------------------------------------------
head_ "System"

[[ "$(uname -s)" == "Linux" ]] || die "This installer supports Linux. On macOS or Windows, run \`docker compose up -d\` by hand."
pass "Linux $(uname -r)"

if command -v docker >/dev/null 2>&1; then
  pass "docker $(docker --version 2>/dev/null | awk '{print $3}' | tr -d ,)"
else
  die "Docker is not installed. See https://docs.docker.com/engine/install/"
fi

if docker compose version >/dev/null 2>&1; then
  pass "docker compose $(docker compose version --short 2>/dev/null)"
else
  die "The Docker Compose plugin is not installed. See https://docs.docker.com/compose/install/"
fi

if docker info >/dev/null 2>&1; then
  pass "Docker daemon is running"
elif [[ $DRY_RUN -eq 1 ]]; then
  warn "Docker daemon is not reachable (ignored for --dry-run)"
else
  die "The Docker daemon is not reachable. Try: sudo systemctl start docker — or re-run with sudo."
fi

# --- 2. addressing -----------------------------------------------------------
head_ "Network"

# The address on the route to the default gateway is the one clients will use.
HOST_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+' || true)"
[[ -n "$HOST_IP" ]] || HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
IFACE="$(ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'dev \K\S+' || true)"

if [[ -n "$HOST_IP" ]]; then
  pass "Address: ${HOST_IP}${IFACE:+  (interface ${IFACE})}"
else
  warn "Could not detect this machine's address; you will need to supply it."
fi

# The CIDR of the address above, as the kernel records it.
SUBNET=""
if [[ -n "$HOST_IP" && -n "$IFACE" ]]; then
  SUBNET="$(ip -4 -o addr show dev "$IFACE" 2>/dev/null \
            | awk -v ip="$HOST_IP" '$4 ~ "^"ip"/" {print $4}' | head -1)"
fi
[[ -n "$SUBNET" ]] && pass "Network: $SUBNET"

IS_PRIVATE=0
case "$HOST_IP" in
  10.*|192.168.*|127.*) IS_PRIVATE=1 ;;
  172.1[6-9].*|172.2[0-9].*|172.3[01].*) IS_PRIVATE=1 ;;
  100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) IS_PRIVATE=1 ;;
esac

if command -v systemd-detect-virt >/dev/null 2>&1; then
  VIRT="$(systemd-detect-virt 2>/dev/null || true)"
  [[ -n "$VIRT" && "$VIRT" != "none" ]] && pass "Virtualisation: $VIRT"
fi

# --- 3. ports ----------------------------------------------------------------
head_ "Ports"

# ss is not always installed; fall back to /proc, which always is.
port_owner() {
  local proto="$1" port="$2" hexport owners=""
  hexport="$(printf '%04X' "$port")"
  if command -v ss >/dev/null 2>&1; then
    owners="$(ss -lnp "-${proto:0:1}" 2>/dev/null | awk -v p=":$port" '$0 ~ p"$" || $0 ~ p" " {print}' \
              | grep -oP 'users:\(\("\K[^"]+' | sort -u | paste -sd, -)"
  fi
  if [[ -z "$owners" ]]; then
    for f in "/proc/net/$proto" "/proc/net/${proto}6"; do
      [[ -r "$f" ]] || continue
      if awk -v hp=":$hexport" 'NR>1 && $2 ~ hp"$" {found=1} END{exit !found}' "$f"; then
        owners="(in use; run with sudo to name the process)"
      fi
    done
  fi
  printf '%s' "$owners"
}

PORT53_BLOCKED=0
for proto in udp tcp; do
  owner="$(port_owner "$proto" 53)"
  if [[ -n "$owner" ]]; then
    PORT53_BLOCKED=1
    fail "${proto^^} port 53 is already in use by: $owner"
  else
    pass "${proto^^} port 53 is free"
  fi
done

if [[ $PORT53_BLOCKED -eq 1 ]]; then
  if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    cat <<'EOF'

  systemd-resolved is running and is the usual owner of port 53 on Ubuntu.
  DNS Daddy cannot listen on port 53 until its stub listener is switched off.

  This installer will NOT change that for you, because doing so alters how
  this machine resolves names. To do it yourself:

    sudo mkdir -p /etc/systemd/resolved.conf.d
    printf '[Resolve]\nDNSStubListener=no\n' | sudo tee /etc/systemd/resolved.conf.d/dnsdaddy.conf
    sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
    sudo systemctl restart systemd-resolved

  Then run this installer again.
EOF
  else
    printf '\n  Stop whatever owns port 53, or run DNS Daddy on another port, then try again.\n'
  fi
  die "Port 53 is not available."
fi

if [[ -n "$(port_owner tcp 8080)" ]]; then
  warn "TCP port 8080 is in use. The dashboard will not start until it is free."
else
  pass "TCP port 8080 is free"
fi

# --- 4. deployment type ------------------------------------------------------
head_ "Deployment"

if [[ $IS_PRIVATE -eq 1 ]]; then
  DEFAULT_CHOICE=1
  printf '  This looks like a %sprivate network%s (%s).\n' "$BOLD" "$OFF" "${HOST_IP:-unknown}"
else
  DEFAULT_CHOICE=2
  printf '  This looks like a %spublic address%s (%s).\n' "$BOLD" "$OFF" "${HOST_IP:-unknown}"
fi

cat <<EOF

  1. LAN / homelab / VM  — dashboard reachable from your own network
  2. Public VPS          — dashboard stays private; put TLS in front yourself

EOF

CHOICE="$DEFAULT_CHOICE"
if [[ $ASSUME_YES -eq 0 && $DRY_RUN -eq 0 && -t 0 ]]; then
  read -r -p "  Deployment type [${DEFAULT_CHOICE}]: " reply
  [[ -n "${reply:-}" ]] && CHOICE="$reply"
fi
case "$CHOICE" in
  1|2) ;;
  *) die "Expected 1 or 2, got '$CHOICE'." ;;
esac

DASHBOARD_BIND=""
if [[ "$CHOICE" == "1" ]]; then
  [[ -n "$HOST_IP" ]] || die "A LAN install needs this machine's address, which could not be detected."
  if [[ $IS_PRIVATE -eq 0 ]]; then
    warn "$HOST_IP is not a private address. Publishing the dashboard on it exposes an"
    warn "authenticated but PLAINTEXT management API to the internet. Choose 2 instead."
    die "Refusing to publish the dashboard on a public address."
  fi
  DASHBOARD_BIND="$HOST_IP"
  pass "Dashboard will be published on http://${HOST_IP}:8080 (your LAN only)"
else
  pass "Dashboard will stay on 127.0.0.1:8080 — reach it over an SSH tunnel or a TLS proxy"
fi

# --- 5. .env -----------------------------------------------------------------
head_ "Configuration"

ENV_LINES=""
if [[ -n "$DASHBOARD_BIND" ]]; then
  ENV_LINES="DNSDADDY_DASHBOARD_BIND=${DASHBOARD_BIND}"
fi

if [[ "$CHOICE" == "2" ]]; then
  cat <<'EOF'

  On a public VPS the built-in client ACL (loopback and the private ranges)
  does not cover your clients, so every real query is answered REFUSED. Set
  DNSDADDY_ALLOWED_CLIENT_CIDRS in .env to the source addresses your firewall
  allows on port 53, keeping 127.0.0.0/8 and 172.16.0.0/12.
EOF
fi

if [[ $DRY_RUN -eq 1 ]]; then
  printf '\n  Would write to .env:\n'
  if [[ -n "$ENV_LINES" ]]; then
    printf '    %s\n' "$ENV_LINES"
  else
    printf '    (defaults from .env.example only)\n'
  fi
  printf '\n  Dry run complete. Nothing was changed.\n\n'
  exit 0
fi

if [[ -f .env ]]; then
  pass "Keeping your existing .env"
  if [[ -n "$ENV_LINES" ]] && ! grep -q '^DNSDADDY_DASHBOARD_BIND=' .env; then
    printf '\n# Added by install-docker.sh — dashboard on this machine'"'"'s LAN address.\n%s\n' \
      "$ENV_LINES" >> .env
    pass "Appended DNSDADDY_DASHBOARD_BIND"
  fi
else
  cp .env.example .env || die "Could not create .env from .env.example."
  if [[ -n "$ENV_LINES" ]]; then
    printf '\n# Set by install-docker.sh — dashboard on this machine'"'"'s LAN address.\n%s\n' \
      "$ENV_LINES" >> .env
  fi
  pass "Wrote .env"
fi

# --- 6. start ----------------------------------------------------------------
head_ "Starting"

docker compose up -d || die "\`docker compose up -d\` failed. The output above says why."
pass "Containers started"

printf '  Waiting for the resolver to come up'
for _ in $(seq 1 30); do
  if docker compose exec -T dnsdaddy wget -qO- http://127.0.0.1:8080/api/v1/health >/dev/null 2>&1; then
    break
  fi
  printf '.'
  sleep 2
done
printf '\n'

# --- 7. verify ---------------------------------------------------------------
head_ "Readiness"
docker compose exec -T dnsdaddy dnsdaddy doctor
DOCTOR_STATUS=$?

# --- 8. what to do next ------------------------------------------------------
DISPLAY_IP="${HOST_IP:-<this-server>}"
DASHBOARD_URL="http://127.0.0.1:8080 (via SSH tunnel)"
[[ -n "$DASHBOARD_BIND" ]] && DASHBOARD_URL="http://${DASHBOARD_BIND}:8080"

cat <<EOF

${BOLD}DNS Daddy is installed.${OFF}

  DNS server   ${DISPLAY_IP}
  Dashboard    ${DASHBOARD_URL}

  Admin password
    docker compose logs dnsdaddy | grep -i password

  Test it from another machine, before changing anything else:
    nslookup example.com ${DISPLAY_IP}
    dig @${DISPLAY_IP} example.com

  Then, in order:
    1. Sign in and go to Threat feeds → Refresh now.
    2. Point ONE device at ${DISPLAY_IP} and watch the Query log.
    3. Only once that looks right, change your router or DHCP DNS setting.

  Re-check at any time with:
    docker compose exec dnsdaddy dnsdaddy doctor

EOF

if [[ $DOCTOR_STATUS -ne 0 ]]; then
  warn "doctor reported a FAIL above. A fresh install normally shows an empty threat"
  warn "index until the first feed refresh finishes — anything else is worth reading."
fi

exit 0
