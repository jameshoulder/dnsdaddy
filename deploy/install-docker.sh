#!/usr/bin/env bash
#
# DNS Daddy — guided Docker Compose install.
#
#     git clone https://github.com/jameshoulder/dnsdaddy.git
#     cd dnsdaddy
#     ./deploy/install-docker.sh
#
# It checks the things that actually go wrong, writes .env for you, starts the
# stack, waits for it to be ready, runs `dnsdaddy doctor`, and tells you the
# DNS address, the dashboard URL and your admin password. It asks before doing
# anything that changes the machine, and it never disables a system service on
# your behalf.
#
#   --upgrade      rebuild and restart, keeping your data and your .env
#   --uninstall    stop and remove the containers (your data is kept)
#   --dry-run      run every check and print what would change, touching nothing
#   --yes, -y      take the safe default for every question
#   --lan          publish the dashboard on this machine's LAN address.
#                  Say this explicitly; it is never inferred, because a
#                  private address on the NIC does not mean the host has no
#                  public one.
#   --vps          keep the dashboard on loopback (the default)
#   --help, -h     this message
#
# For a native systemd install instead, use deploy/install.sh.

# No -e. A failing command inside a $(...) capture would take the whole script
# with it, and half this script is capturing output from commands that are
# expected to fail on a machine that is not yet set up.
set -uo pipefail

MODE="install"
DRY_RUN=0
ASSUME_YES=0
PURGE_DATA=0
# Empty means "ask, and default to the closed answer". Set only by an explicit
# flag: an unattended run must never end up publishing a management API
# because something about the machine looked private.
DEPLOYMENT=""
# Where the dashboard ends up published, or empty for loopback. Declared here
# so every path — install, upgrade — has a defined value before the closing
# report reads it.
DASHBOARD_BIND=""
# 1 = LAN, 2 = loopback. Defined here because the upgrade path never asks, and
# the closing report reads it. Loopback is the safe assumption when nobody has
# said otherwise.
CHOICE=2

for arg in "$@"; do
  case "$arg" in
    --upgrade)   MODE="upgrade" ;;
    --uninstall) MODE="uninstall" ;;
    --purge)     PURGE_DATA=1 ;;
    --dry-run)   DRY_RUN=1 ;;
    --yes|-y)    ASSUME_YES=1 ;;
    --lan)       DEPLOYMENT="lan" ;;
    --vps)       DEPLOYMENT="vps" ;;
    --help|-h)   sed -n '2,27p' "$0" | sed 's/^# \?//'; exit 0 ;;
    *) printf 'Unknown option: %s\n' "$arg" >&2; exit 2 ;;
  esac
done

# --- output ------------------------------------------------------------------

if [[ -t 1 ]]; then
  BOLD=$'\033[1m'; GREEN=$'\033[1;32m'; YELLOW=$'\033[1;33m'; RED=$'\033[1;31m'; OFF=$'\033[0m'
else
  BOLD=""; GREEN=""; YELLOW=""; RED=""; OFF=""
fi

# Every PASS/WARN/FAIL is printed as it happens *and* kept, so the run ends
# with one summary instead of leaving the important line somewhere in the
# middle of a Compose log.
SUMMARY=()
WARNINGS=0
FAILURES=0

pass()  { printf '  %sPASS%s  %s\n' "$GREEN" "$OFF" "$*"; SUMMARY+=("PASS $*"); }
warn()  { printf '  %sWARN%s  %s\n' "$YELLOW" "$OFF" "$*"; SUMMARY+=("WARN $*"); WARNINGS=$((WARNINGS + 1)); }
fail()  { printf '  %sFAIL%s  %s\n' "$RED" "$OFF" "$*"; SUMMARY+=("FAIL $*"); FAILURES=$((FAILURES + 1)); }
note()  { printf '        %s\n' "$*"; }
head_() { printf '\n%s%s%s\n' "$BOLD" "$*" "$OFF"; }

# die prints the remedy, not just the problem. "Docker failed" is not a
# diagnosis and leaves the reader with nowhere to go.
die() {
  printf '\n%sCannot continue:%s %s\n' "$RED" "$OFF" "$1" >&2
  if [[ $# -gt 1 ]]; then
    printf '\n%s\n' "$2" >&2
  fi
  printf '\n' >&2
  exit 1
}

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || die "Could not enter the repository root."

COMPOSE=(docker compose)

printf '\n%sDNS Daddy setup%s\n' "$BOLD" "$OFF"
case "$MODE" in
  upgrade)   printf 'Mode: upgrade — your data and .env are preserved.\n' ;;
  uninstall) printf 'Mode: uninstall\n' ;;
esac
[[ $DRY_RUN -eq 1 ]] && printf '(dry run — nothing will be changed)\n'

# --- .env helpers ------------------------------------------------------------

ENV_FILE=".env"

# Keys this installer owns. Anything it writes carries the marker below, so an
# upgrade can tell its own past output from a value the operator set by hand
# and reconcile the first without touching the second. Appending blindly is how
# an earlier version left a dashboard published on an address it had just
# reported as closed.
ENV_MARKER="# managed by install-docker.sh"

env_value() { # key -> prints the active value, empty if unset or commented out
  [[ -f "$ENV_FILE" ]] || return 0
  grep -E "^${1}=" "$ENV_FILE" 2>/dev/null | tail -1 | cut -d= -f2- || true
}

env_is_set() { # key
  [[ -f "$ENV_FILE" ]] && grep -qE "^${1}=" "$ENV_FILE" 2>/dev/null
}

# env_is_managed reports whether the ACTIVE line for this key was written by
# this installer, which is what makes it safe to change without asking.
#
# The active line is the last assignment, matching env_value. A grep for the
# marker anywhere near any matching line got that wrong in a way that mattered:
# an older managed assignment followed by a hand-set override made the
# operator's deliberate line look installer-generated, and an upgrade would
# then comment out every active assignment — silently closing a dashboard
# address they had opened on purpose. Only the line immediately above the last
# assignment counts.
env_is_managed() { # key
  [[ -f "$ENV_FILE" ]] || return 1
  awk -v key="$1" -v marker="$ENV_MARKER" '
    $0 ~ "^" key "=" { found = 1; managed = (prev == marker) }
    { prev = $0 }
    END { exit !(found && managed) }
  ' "$ENV_FILE"
}

# env_set writes a key this installer owns, replacing any existing active line.
#
# Delete-then-append rather than edit-in-place, so the marker and the value are
# always adjacent and an upgrade can tell them apart. It also avoids inserting a
# newline through sed, which is not portable across GNU, BSD and BusyBox.
#
# It does overwrite a line the operator set by hand — correctly, because
# env_set is only reached when they have just chosen this value at the prompt
# or with --lan. The upgrade path never calls it, and preserves hand-set lines.
env_set() { # key value
  local key="$1" val="$2"
  if [[ -f "$ENV_FILE" ]] && grep -qE "^${key}=" "$ENV_FILE" 2>/dev/null; then
    sed -i -E "/^${key}=/d" "$ENV_FILE"
  fi
  printf '\n%s\n%s=%s\n' "$ENV_MARKER" "$key" "$val" >> "$ENV_FILE"
}

# env_disable comments a key out. Returns 1 when there was nothing to do, so
# the caller only reports a change it actually made — claiming to have closed
# something that is still open is worse than saying nothing.
env_disable() { # key
  [[ -f "$ENV_FILE" ]] || return 1
  grep -qE "^${1}=" "$ENV_FILE" 2>/dev/null || return 1
  sed -i -E "s|^${1}=|# disabled by install-docker.sh (dashboard kept on loopback): ${1}=|" "$ENV_FILE"
}

ensure_env_file() {
  if [[ -f "$ENV_FILE" ]]; then
    pass "Keeping your existing .env"
    return
  fi
  if [[ -f .env.example ]]; then
    cp .env.example "$ENV_FILE" && pass "Created .env from .env.example" && return
    die "Could not create .env from .env.example." "Check that this directory is writable."
  fi
  # No template to copy: write the minimum a working deployment needs, with
  # the defaults the binary already has. Everything else is left to the
  # binary's own defaults rather than guessed at here.
  cat > "$ENV_FILE" <<'ENVEOF'
# DNS Daddy — Docker Compose environment.
#
# Created by install-docker.sh. Every value here is optional: the binary and
# docker-compose.yml carry working defaults, and this file exists for the
# settings that are specific to your deployment.
#
# Day-to-day administration — which networks may use the resolver, which
# policy each one gets — belongs in the dashboard under Networks, and takes
# effect without a restart. Settings here are bootstrap configuration.
ENVEOF
  [[ -f "$ENV_FILE" ]] || die "Could not create .env." "Check that this directory is writable."
  pass "Created .env"
}

# --- host interrogation ------------------------------------------------------

require_linux() {
  [[ "$(uname -s)" == "Linux" ]] || die \
    "This installer supports Linux." \
    "On macOS or Windows, run these by hand:

    cp .env.example .env
    docker compose up -d
    docker compose exec dnsdaddy dnsdaddy doctor"
  pass "Linux $(uname -r)"
}

check_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    die "Docker is not installed." \
      "Install it, then run this again:

    curl -fsSL https://get.docker.com | sudo sh

  Or follow https://docs.docker.com/engine/install/ for your distribution."
  fi
  pass "docker $(docker --version 2>/dev/null | awk '{print $3}' | tr -d ,)"

  if ! docker compose version >/dev/null 2>&1; then
    die "The Docker Compose plugin is not installed." \
      "On Debian and Ubuntu:

    sudo apt-get install docker-compose-plugin

  Otherwise see https://docs.docker.com/compose/install/linux/"
  fi
  pass "docker compose $(docker compose version --short 2>/dev/null)"

  if docker info >/dev/null 2>&1; then
    pass "Docker daemon is running"
    return
  fi
  if [[ $DRY_RUN -eq 1 ]]; then
    warn "Docker daemon is not reachable (ignored for --dry-run)"
    return
  fi
  # Two different problems with the same symptom, and different remedies.
  if systemctl list-unit-files docker.service >/dev/null 2>&1 && \
     ! systemctl is-active --quiet docker 2>/dev/null; then
    die "The Docker daemon is not running." \
      "Start it with:

    sudo systemctl enable --now docker"
  fi
  die "The Docker daemon is not reachable." \
    "It may be running as root and your user may not be in the docker group:

    sudo usermod -aG docker \$USER    # then log out and back in

  Or run this installer with sudo."
}

# host_addresses prints every global-scope IPv4 address on this machine, one
# per line, most-likely-first: the address on the route to the internet leads.
host_addresses() {
  local primary others
  primary="$(ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+' || true)"
  [[ -n "$primary" ]] && printf '%s\n' "$primary"
  others="$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 || true)"
  if [[ -z "$others" ]]; then
    others="$(hostname -I 2>/dev/null | tr ' ' '\n' || true)"
  fi
  printf '%s\n' "$others" | grep -v '^$' | grep -vxF "${primary:-__none__}" || true
}

is_private_addr() { # address
  case "$1" in
    10.*|192.168.*|127.*) return 0 ;;
    172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 0 ;;
    100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) return 0 ;;
    169.254.*) return 0 ;;
  esac
  return 1
}

# port_owner names what holds a port, or prints nothing when it is free.
#
# Two sources, and the order matters. `ss` sees every listening socket even
# unprivileged; what it cannot do without privilege is name the process behind
# one. So a successful `ss` run is authoritative about whether the port is in
# use, and only the name may be missing — reporting "free" because no name came
# back would be exactly wrong, and would send the operator into a
# `docker compose up` that fails on a port bind.
#
# /proc is the fallback for a machine without iproute2. It always exists, and
# has the same limitation about naming, which it admits to rather than hiding.
port_owner() { # proto port
  local proto="$1" port="$2" hexport lines owners=""

  if command -v ss >/dev/null 2>&1; then
    lines="$(ss -lnp "-${proto:0:1}" 2>/dev/null \
             | awk -v p=":$port" '$0 ~ p"$" || $0 ~ p" " {print}')"
    if [[ -z "$lines" ]]; then
      return 0 # ss ran and saw nothing listening: the port is free
    fi
    owners="$(printf '%s\n' "$lines" | grep -oP 'users:\(\("\K[^"]+' | sort -u | paste -sd, -)"
    [[ -n "$owners" ]] || owners="(in use; run with sudo to name the process)"
    printf '%s' "$owners"
    return 0
  fi

  hexport="$(printf '%04X' "$port")"
  for f in "/proc/net/$proto" "/proc/net/${proto}6"; do
    [[ -r "$f" ]] || continue
    if awk -v hp=":$hexport" 'NR>1 && $2 ~ hp"$" {found=1} END{exit !found}' "$f"; then
      owners="(in use; run with sudo to name the process)"
    fi
  done
  printf '%s' "$owners"
}

# known_dns_server maps an owner string onto the advice for that program. A
# bare "port 53 is in use" tells the reader nothing they did not already know.
dns_owner_advice() { # owners
  case "$1" in
    *systemd-resolved*) printf 'systemd-resolved' ;;
    *dnsmasq*)          printf 'dnsmasq' ;;
    *named*|*bind*)     printf 'BIND' ;;
    *unbound*)          printf 'Unbound' ;;
    *pihole*|*pi-hole*) printf 'Pi-hole' ;;
    *coredns*)          printf 'CoreDNS' ;;
    *dnsdaddy*)         printf 'DNS Daddy' ;;
    *docker-proxy*)     printf 'Docker' ;;
    *)                  printf '' ;;
  esac
}

# stack_is_running reports whether this Compose project's own dnsdaddy service
# is up.
#
# Asking Docker, not the socket's process name. With the userland proxy — the
# default on a great many Docker Engine installs — the published port 53 is
# held by `docker-proxy`, not by anything called dnsdaddy, so matching on the
# name made `--upgrade` refuse to run on its most common deployment. The
# container is the thing that actually knows.
stack_is_running() {
  [[ -n "$("${COMPOSE[@]}" ps -q dnsdaddy 2>/dev/null)" ]]
}

check_ports() {
  local blocked=0 proto owner program ours=0
  # Only an upgrade may treat a busy port as expected. During a fresh install a
  # running stack is a reason to stop and say so, not to carry on into a bind
  # failure.
  if [[ "$MODE" == "upgrade" ]] && stack_is_running; then
    ours=1
  fi

  for proto in udp tcp; do
    owner="$(port_owner "$proto" 53)"
    if [[ -z "$owner" ]]; then
      pass "${proto^^} port 53 is free"
      continue
    fi
    if [[ $ours -eq 1 ]]; then
      pass "${proto^^} port 53 is held by this DNS Daddy deployment (expected during an upgrade)"
      continue
    fi
    program="$(dns_owner_advice "$owner")"
    blocked=1
    fail "${proto^^} port 53 is already in use by: $owner"
  done

  if [[ $blocked -eq 1 ]]; then
    port53_advice
    [[ $DRY_RUN -eq 1 ]] || die "Port 53 is not available."
  fi

  local dash_port="${DASHBOARD_PORT:-8080}"
  owner="$(port_owner tcp "$dash_port")"
  if [[ -n "$owner" ]]; then
    if [[ $ours -eq 1 ]]; then
      pass "TCP port ${dash_port} is held by this DNS Daddy deployment (expected during an upgrade)"
    else
      warn "TCP port ${dash_port} is in use by: $owner — the dashboard will not start until it is free"
    fi
  else
    pass "TCP port ${dash_port} is free"
  fi

  # 853 only matters when DNS-over-TLS is actually configured. Checking a port
  # nothing is going to bind is noise.
  if [[ -n "$(env_value DNSDADDY_DNS_LISTEN_DOT)" ]]; then
    if [[ -n "$(port_owner tcp 853)" ]]; then
      warn "TCP port 853 is in use, and .env configures DNS-over-TLS on it"
    else
      pass "TCP port 853 is free (DNS-over-TLS is configured)"
    fi
  fi
}

port53_advice() {
  local owners
  owners="$(port_owner udp 53)$(port_owner tcp 53)"
  case "$(dns_owner_advice "$owners")" in
    systemd-resolved)
      cat <<'EOF'

  systemd-resolved is running and is the usual owner of port 53 on Ubuntu and
  Debian. DNS Daddy cannot listen on port 53 until its stub listener is off.

  This installer will NOT change that for you: it alters how this machine
  resolves names, and getting it wrong on a remote box costs you the box. To
  do it yourself:

    sudo mkdir -p /etc/systemd/resolved.conf.d
    printf '[Resolve]\nDNSStubListener=no\n' | sudo tee /etc/systemd/resolved.conf.d/dnsdaddy.conf
    sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
    sudo systemctl restart systemd-resolved

  Then run this installer again.
EOF
      ;;
    dnsmasq|BIND|Unbound|Pi-hole|CoreDNS)
      printf '\n  %s already answers DNS on this machine.\n' "$(dns_owner_advice "$owners")"
      printf '  Stop it first, or run DNS Daddy on a different host.\n'
      printf '  Pi-hole and DNS Daddy work well together on separate machines — see docs/pi-hole.md.\n'
      ;;
    "DNS Daddy")
      printf '\n  Another DNS Daddy instance is already running here.\n'
      printf '  Use --upgrade to rebuild and restart it, or `docker compose down` first.\n'
      ;;
    Docker)
      # docker-proxy publishes somebody's container port. Whose, this script
      # cannot say — but `docker ps` can, and that is a better answer than a
      # guess.
      printf '\n  A Docker container already publishes port 53 on this host.\n'
      printf '  If it is DNS Daddy, use --upgrade instead. Otherwise find it with:\n'
      printf '    docker ps --filter publish=53\n'
      ;;
    *)
      printf '\n  Stop whatever owns port 53, then run this again.\n'
      printf '  `sudo ss -lnptu sport = :53` names it.\n'
      ;;
  esac
}

# --- deployment type ---------------------------------------------------------

# choose_deployment asks the one question that cannot be answered from inside
# the machine, and defaults to the closed answer.
#
# A private address on the default route is NOT evidence that a machine has no
# public reachability: on AWS, GCP, Azure and Hetzner Cloud the instance NIC
# holds an RFC 1918 address and the public address is 1:1 NATed onto it, so
# publishing the dashboard on that private address publishes it to the
# internet. Nothing visible from inside the host tells the two apart. That
# assumption caused a real security issue here once; it is not coming back.
choose_deployment() {
  head_ "Deployment"

  printf '  This machine answers on %s%s%s.\n' "$BOLD" "${HOST_IP:-an address that could not be detected}" "$OFF"
  cat <<EOF

  Where is DNS Daddy running?

  1. Home / LAN / homelab   dashboard published on ${HOST_IP:-this machine}:8080.
                            Choose this ONLY if the machine has no public
                            address at all. Most cloud VPSes show a private
                            address here and are still reachable from the
                            internet.
  2. Public VPS, or unsure  dashboard stays on loopback; reach it over an SSH
                            tunnel, or put TLS in front. (default)

EOF

  # --yes and any non-interactive run take the default, which is why the
  # default has to be the safe one: an unattended install must never end up
  # publishing a management API. --lan is the explicit way to ask for the
  # other answer, and being explicit is the whole point of it.
  case "$DEPLOYMENT" in
    lan) CHOICE=1; printf '  (--lan given)\n' ;;
    vps) CHOICE=2; printf '  (--vps given)\n' ;;
    *)
      if [[ $ASSUME_YES -eq 0 && $DRY_RUN -eq 0 && -t 0 ]]; then
        read -r -p "  Deployment type [2]: " reply
        [[ -n "${reply:-}" ]] && CHOICE="$reply"
      fi
      ;;
  esac
  case "$CHOICE" in
    1|2) ;;
    *) die "Expected 1 or 2, got '$CHOICE'." ;;
  esac

  DASHBOARD_BIND=""
  if [[ "$CHOICE" != "1" ]]; then
    pass "Dashboard stays on 127.0.0.1:8080 — reach it over an SSH tunnel or a TLS proxy"
    return
  fi

  [[ -n "$HOST_IP" ]] || die "A LAN install needs this machine's address, which could not be detected." \
    "Set it explicitly and run again:

    DNSDADDY_HOST_IP=192.168.1.75 ./deploy/install-docker.sh"

  if ! is_private_addr "$HOST_IP"; then
    warn "$HOST_IP is not a private address."
    note "Publishing the dashboard on it would expose an authenticated but PLAINTEXT"
    note "management API to the internet."
    die "Refusing to publish the dashboard on a public address." \
      "Choose option 2 and reach the dashboard over an SSH tunnel."
  fi

  # Several addresses and no way to know which LAN the operator means. Confirm
  # rather than taking the first thing `hostname -I` printed.
  if [[ -n "$OTHER_IPS" && $ASSUME_YES -eq 0 && $DRY_RUN -eq 0 && -t 0 ]]; then
    printf '\n  This machine has more than one address:\n'
    printf '    %s  (on the route to the internet)\n' "$HOST_IP"
    printf '%s\n' "$OTHER_IPS" | sed 's/^/    /'
    read -r -p "  Publish the dashboard on [${HOST_IP}]: " reply
    [[ -n "${reply:-}" ]] && HOST_IP="$reply"
    is_private_addr "$HOST_IP" || die "$HOST_IP is not a private address." \
      "Choose option 2 and reach the dashboard over an SSH tunnel."
  fi

  DASHBOARD_BIND="$HOST_IP"
  pass "Dashboard will be published on http://${HOST_IP}:8080 (your LAN only)"
}

# reconcile_env brings the keys this installer owns into line with the choice
# just made — in both directions.
#
# Only ever adding a key meant choosing the closed option left a previously
# published address in place: the script said "the dashboard will stay on
# loopback", Compose republished on the old address, and re-running the fixed
# installer did not close a dashboard an earlier version had opened.
reconcile_env() {
  if [[ -n "$DASHBOARD_BIND" ]]; then
    env_set DNSDADDY_DASHBOARD_BIND "$DASHBOARD_BIND"
    pass "DNSDADDY_DASHBOARD_BIND=${DASHBOARD_BIND}"
    return
  fi
  if env_disable DNSDADDY_DASHBOARD_BIND; then
    warn "Your .env published the dashboard on a specific address; that line is now commented out"
    note "The dashboard returns to loopback. If it was reachable from the internet,"
    note "change the admin password: assume it has been seen."
  fi
}

# --- runtime -----------------------------------------------------------------

compose_up() { # extra args
  "${COMPOSE[@]}" up -d "$@" || die "\`docker compose up -d\` failed." \
    "The output above says why. Common causes: no disk space, a port taken
  between the check above and now, or a build failure."
  pass "Containers started"
}

# wait_for_health polls until the service answers, rather than printing
# "container started" and leaving. A container that starts and then exits is
# indistinguishable from a working one for the first few seconds.
wait_for_health() {
  # Two minutes: a cold start rebuilds the blocklist index from cached feeds
  # on a single vCPU. Overridable so the installer's own tests do not have to
  # wait out the real timeout to assert on the failure path.
  local limit="${DNSDADDY_INSTALL_HEALTH_TIMEOUT:-120}"
  local deadline=$((SECONDS + limit))
  printf '  Waiting for DNS Daddy to come up'
  while (( SECONDS < deadline )); do
    if "${COMPOSE[@]}" exec -T dnsdaddy wget -qO- http://127.0.0.1:8080/api/v1/health >/dev/null 2>&1; then
      printf '\n'
      pass "DNS Daddy is responding"
      return 0
    fi
    printf '.'
    sleep 2
  done
  printf '\n'
  fail "DNS Daddy did not become ready within ${limit}s"
  note "Its own log will say why:  docker compose logs --tail=50 dnsdaddy"
  return 1
}

# admin_password reads the generated first-run credential from the data volume.
#
# It is written there with mode 0600 and, deliberately, is no longer written to
# the log at all — a credential in `docker compose logs` lives for the life of
# the container and in whatever log shipper is pointed at it. Reading the file
# is why `docker compose logs | grep password` is no longer the documented way
# to find it.
admin_password() {
  "${COMPOSE[@]}" exec -T dnsdaddy cat /var/lib/dnsdaddy/initial-password.txt 2>/dev/null \
    | grep -oP 'password: \K\S+' || true
}

run_doctor() {
  head_ "Readiness"
  "${COMPOSE[@]}" exec -T dnsdaddy dnsdaddy doctor
  DOCTOR_STATUS=$?
  if [[ $DOCTOR_STATUS -eq 0 ]]; then
    pass "dnsdaddy doctor reports no failures"
  else
    warn "dnsdaddy doctor reported a failure — see its output above"
  fi
}

# --- the three modes ---------------------------------------------------------

do_uninstall() {
  head_ "Uninstall"

  if [[ $DRY_RUN -eq 1 ]]; then
    printf '  Would run: docker compose down\n'
    [[ $PURGE_DATA -eq 1 ]] && printf '  Would DELETE the dnsdaddy-data volume\n'
    printf '\n  Dry run complete. Nothing was changed.\n\n'
    exit 0
  fi

  "${COMPOSE[@]}" down || die "\`docker compose down\` failed." "The output above says why."
  pass "Containers stopped and removed"

  if [[ $PURGE_DATA -eq 0 ]]; then
    cat <<EOF

  Your data is kept. The named volume still holds the query history, threat
  feed cache, session key and your settings, so re-running this installer
  brings DNS Daddy back exactly as it was.

  To delete it permanently — this cannot be undone:

    ./deploy/install-docker.sh --uninstall --purge

  Your .env is also untouched. Delete it by hand if you want it gone.

EOF
    exit 0
  fi

  # Data deletion is explicit twice: the flag, and then a typed confirmation.
  # A flag alone is one tab-completion away from destroying a year of history.
  printf '\n  %sThis will permanently delete DNS Daddy'"'"'s database, query history,\n' "$RED"
  printf '  feed cache and settings.%s There is no undo and no backup.\n\n' "$OFF"
  if [[ $ASSUME_YES -eq 1 || ! -t 0 ]]; then
    die "Refusing to delete data without an interactive confirmation." \
      "Re-run --uninstall --purge from a terminal, or remove the volume yourself:

    docker volume rm dnsdaddy_dnsdaddy-data"
  fi
  read -r -p "  Type DELETE to confirm: " reply
  [[ "${reply:-}" == "DELETE" ]] || die "Not confirmed. Nothing was deleted."

  "${COMPOSE[@]}" down -v || die "Removing the volume failed." "The output above says why."
  pass "Data volume deleted"
  printf '\n  DNS Daddy is removed.\n\n'
  exit 0
}

do_upgrade() {
  head_ "Current deployment"

  PREVIOUS_IMAGE="$(docker inspect --format '{{.Image}}' dnsdaddy 2>/dev/null || true)"
  if [[ -n "$PREVIOUS_IMAGE" ]]; then
    pass "Running image: ${PREVIOUS_IMAGE:0:19}"
  else
    warn "No running DNS Daddy container found; this will behave as a fresh start"
  fi

  # Reconcile the keys this installer owns, without asking the deployment
  # question again. An upgrade must not silently change where the dashboard is
  # published — but it must also not leave behind a default that an earlier,
  # buggier version of this script generated.
  head_ "Configuration"
  if [[ ! -f "$ENV_FILE" ]]; then
    warn "No .env found; creating one"
    [[ $DRY_RUN -eq 1 ]] || ensure_env_file
  else
    pass "Keeping your existing .env"
  fi

  local bind
  bind="$(env_value DNSDADDY_DASHBOARD_BIND)"
  if [[ -z "$bind" ]]; then
    pass "Dashboard stays on loopback"
    DASHBOARD_BIND=""
  elif env_is_managed DNSDADDY_DASHBOARD_BIND; then
    if is_private_addr "$bind"; then
      pass "Dashboard stays published on ${bind}:8080, as this installer configured"
      DASHBOARD_BIND="$bind"
      CHOICE=1
    else
      # An earlier version of this installer inferred "private NIC means
      # private host" and could write a public address here. That inference
      # was wrong and caused a real exposure; a value it generated is not a
      # choice the operator made, so it is closed rather than preserved.
      warn "${bind} is a public address, and this installer wrote that line, not you"
      note "Publishing an authenticated but plaintext management API on it is not safe."
      if [[ $DRY_RUN -eq 0 ]] && env_disable DNSDADDY_DASHBOARD_BIND; then
        warn "That line is now commented out; the dashboard returns to loopback"
        note "If it was reachable from the internet, change the admin password."
      fi
    fi
  else
    # Set by hand. Report it, and leave it alone: an upgrade is not the moment
    # to overrule a deliberate choice, even one worth questioning.
    if is_private_addr "$bind"; then
      pass "Dashboard published on ${bind}:8080 (set in your .env; left as-is)"
      DASHBOARD_BIND="$bind"
      CHOICE=1
    else
      warn "Dashboard is published on ${bind}:8080, which is a public address"
      note "This line is yours, not this installer's, so it has been left alone."
      note "On a host reachable from the internet, comment it out and use an SSH tunnel."
      DASHBOARD_BIND="$bind"
    fi
  fi

  if [[ $DRY_RUN -eq 1 ]]; then
    printf '\n  Would run: docker compose up -d --build\n'
    printf '  Would wait for health, then run dnsdaddy doctor.\n'
    printf '\n  Dry run complete. Nothing was changed.\n\n'
    exit 0
  fi

  head_ "Starting"
  compose_up --build

  if ! wait_for_health; then
    cat <<EOF

  ${BOLD}The upgrade did not come up healthy.${OFF}

  Your data is untouched — it lives in the named volume, and nothing in this
  script deletes it. To go back to the image you were running:

    docker compose down
    docker run -d --name dnsdaddy-rollback ${PREVIOUS_IMAGE:-<previous image>}

  More usefully, check out the commit you were on and rebuild:

    git log --oneline -5
    git checkout <previous-commit>
    ./deploy/install-docker.sh --upgrade

  What went wrong:
    docker compose logs --tail=50 dnsdaddy

EOF
    print_summary
    exit 1
  fi

  run_doctor
  print_next_steps
  print_summary
  exit 0
}

# --- reporting ---------------------------------------------------------------

# ssh_client_address is the address this SSH session arrived from, as the
# kernel sees it. That is a real measurement of where the operator is, and the
# one thing on this machine that can honestly answer "which public address
# should I allow?" — the local interface addresses cannot, because a NATed
# cloud NIC does not know its own public address.
ssh_client_address() {
  local addr=""
  [[ -n "${SSH_CLIENT:-}" ]] && addr="$(printf '%s' "$SSH_CLIENT" | awk '{print $1}')"
  [[ -z "$addr" && -n "${SSH_CONNECTION:-}" ]] && addr="$(printf '%s' "$SSH_CONNECTION" | awk '{print $1}')"
  printf '%s' "$addr"
}

print_next_steps() {
  local password client dashboard
  password="$(admin_password)"
  client="$(ssh_client_address)"

  dashboard="http://127.0.0.1:8080  (over an SSH tunnel)"
  [[ -n "$DASHBOARD_BIND" ]] && dashboard="http://${DASHBOARD_BIND}:8080"

  printf '\n%sDNS Daddy is ready.%s\n\n' "$BOLD" "$OFF"

  printf '  %sDNS server%s\n' "$BOLD" "$OFF"
  if [[ -n "$HOST_IP" ]]; then
    printf '    %s\n' "$HOST_IP"
    if [[ -n "$OTHER_IPS" ]]; then
      printf '    This machine has other addresses too:\n'
      printf '%s\n' "$OTHER_IPS" | sed 's/^/      /'
      printf '    Use the one your clients can reach. The address above is the one on\n'
      printf '    the route to the internet, which is usually it.\n'
    fi
    if is_private_addr "$HOST_IP"; then
      printf '    On a cloud VPS this private address may have a public one NATed onto\n'
      printf '    it. If so, your clients use the public address your provider shows —\n'
      printf '    this machine cannot see it, so it is not printed here.\n'
    fi
  else
    printf '    (could not be detected — use the address your clients reach this machine on)\n'
  fi

  printf '\n  %sDashboard%s\n' "$BOLD" "$OFF"
  if [[ -n "$DASHBOARD_BIND" ]]; then
    printf '    %s\n' "$dashboard"
  else
    printf '    From your own machine:\n'
    printf '      ssh -L 8080:127.0.0.1:8080 %s@%s\n' "${USER:-root}" "${HOST_IP:-<this-server>}"
    printf '    Then open:\n'
    printf '      http://127.0.0.1:8080\n'
  fi

  printf '\n  %sAdmin password%s\n' "$BOLD" "$OFF"
  if [[ -n "$password" ]]; then
    printf '    %s\n' "$password"
    printf '    Change it from Settings, then delete the file it came from:\n'
    printf '      docker compose exec dnsdaddy rm /var/lib/dnsdaddy/initial-password.txt\n'
  else
    printf '    Already set — this is not a first run, so no password was generated.\n'
    printf '    If you have lost it, see docs/deploy.md for how to reset it.\n'
  fi

  # What to say next follows from the deployment, and is not guessed at.
  #
  # The shipped client ACL serves loopback and every private range, so on a LAN
  # a test from another machine works right now. On a VPS it does not: clients
  # arrive from public addresses, which that ACL does not cover, and printing a
  # `nslookup` there would hand the operator a command guaranteed to answer
  # REFUSED and no idea why. `dnsdaddy doctor` above has already reported which
  # ranges are actually permitted; this section does not restate it as a
  # measurement it has not made.
  printf '\n  %sNext%s\n' "$BOLD" "$OFF"
  if [[ "$CHOICE" == "1" ]]; then
    printf '    Your LAN is already permitted to use the resolver. Test it from\n'
    printf '    another machine on the same network:\n'
    printf '      nslookup example.com %s\n' "${HOST_IP:-<this-server>}"
    printf '      dig @%s example.com\n' "${HOST_IP:-<this-server>}"
  else
    printf '    No external clients are permitted yet. The built-in list covers\n'
    printf '    loopback and the private ranges only, so a test from another\n'
    printf '    machine would be answered REFUSED — that is DNS Daddy working,\n'
    printf '    not failing.\n\n'
    printf '    Open the dashboard, go to Networks, and add the client or network\n'
    printf '    that should use DNS Daddy. Tick:\n\n'
    printf '      [x] Allow this network to use DNS Daddy\n\n'
    printf '    It takes effect immediately — nothing to restart, no file to edit.\n'
    if [[ -n "$client" ]]; then
      printf '\n    You are connected from %s%s%s. That is where this SSH session\n' "$BOLD" "$client" "$OFF"
      printf '    came from, as this machine sees it — if that is the network that\n'
      printf '    should use DNS Daddy, that is the address to add.\n'
    fi
    printf '\n    Then test from it:\n'
    printf '      nslookup example.com %s\n' "${HOST_IP:-<this-server>}"
  fi

  printf '\n    Re-check anything at any time:\n'
  printf '      docker compose exec dnsdaddy dnsdaddy doctor\n\n'
}

print_summary() {
  printf '%sSummary%s\n\n' "$BOLD" "$OFF"
  local line status rest colour
  for line in "${SUMMARY[@]}"; do
    status="${line%% *}"
    rest="${line#* }"
    case "$status" in
      PASS) colour="$GREEN" ;;
      WARN) colour="$YELLOW" ;;
      *)    colour="$RED" ;;
    esac
    printf '  %s%s%s  %s\n' "$colour" "$status" "$OFF" "$rest"
  done
  printf '\n'
  if [[ $FAILURES -gt 0 ]]; then
    printf '%s%d failure(s) and %d warning(s).%s\n\n' "$RED" "$FAILURES" "$WARNINGS" "$OFF"
  elif [[ $WARNINGS -gt 0 ]]; then
    printf '%s%d warning(s), nothing failed.%s\n\n' "$YELLOW" "$WARNINGS" "$OFF"
  else
    printf '%sEverything passed.%s\n\n' "$GREEN" "$OFF"
  fi
}

# --- main --------------------------------------------------------------------

head_ "System"
require_linux
check_docker

[[ "$MODE" == "uninstall" ]] && do_uninstall

head_ "Network"
HOST_IP="${DNSDADDY_HOST_IP:-$(host_addresses | head -1)}"
OTHER_IPS="$(host_addresses | tail -n +2)"
if [[ -n "$HOST_IP" ]]; then
  IFACE="$(ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'dev \K\S+' || true)"
  pass "Address: ${HOST_IP}${IFACE:+  (interface ${IFACE})}"
  [[ -n "$OTHER_IPS" ]] && note "also: $(printf '%s' "$OTHER_IPS" | paste -sd' ' -)"
else
  warn "Could not detect this machine's address; you will need to supply it"
fi

head_ "Ports"
check_ports

[[ "$MODE" == "upgrade" ]] && do_upgrade

# --- install -----------------------------------------------------------------

choose_deployment

head_ "Configuration"
if [[ "$CHOICE" == "2" ]]; then
  cat <<'EOF'

  On a public VPS the built-in client ACL covers loopback and the private
  ranges, which does not include your clients — so nothing outside this
  machine can use the resolver until you say so.

  You do that in the dashboard, under Networks, with no restart and no file to
  edit. Whether you also set DNSDADDY_ALLOWED_CLIENT_CIDRS is up to you: it is
  bootstrap configuration for automated deployments, and the two combine.
EOF
fi

if [[ $DRY_RUN -eq 1 ]]; then
  printf '\n  Would change in .env:\n'
  if [[ -n "$DASHBOARD_BIND" ]]; then
    printf '    DNSDADDY_DASHBOARD_BIND=%s\n' "$DASHBOARD_BIND"
  elif env_is_set DNSDADDY_DASHBOARD_BIND; then
    printf '    comment out DNSDADDY_DASHBOARD_BIND (currently publishing the dashboard)\n'
  elif [[ ! -f "$ENV_FILE" ]]; then
    printf '    create .env from .env.example\n'
  else
    printf '    (nothing — your .env already matches this deployment)\n'
  fi
  printf '\n  Would then start the stack, wait for health and run dnsdaddy doctor.\n'
  printf '\n  Dry run complete. Nothing was changed.\n\n'
  exit 0
fi

ensure_env_file
reconcile_env

head_ "Starting"
compose_up

if ! wait_for_health; then
  printf '\n  DNS Daddy started but did not become ready. Its log will say why:\n'
  printf '    docker compose logs --tail=50 dnsdaddy\n\n'
  print_summary
  exit 1
fi

run_doctor
print_next_steps
print_summary

[[ $FAILURES -gt 0 ]] && exit 1
exit 0
