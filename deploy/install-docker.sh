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
#   --vps          keep the dashboard on loopback, reached over SSH (the default)
#   --https        keep the dashboard on loopback and put Caddy in front of it,
#                  serving https://<hostname> or https://<public-ip>. Set
#                  DNSDADDY_HTTPS_HOSTNAME=dns.example.com, or
#                  DNSDADDY_HTTPS_HOSTNAME=ip to use this machine's detected
#                  public address, when run non-interactively.
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
# What already serves 80/443, discovered in check_ports and reported in the
# summary. Empty means nothing was listening. Never acted on: see check_ports.
WEB_80_OWNER=""
WEB_443_OWNER=""

# HTTPS mode (option 3). HTTPS_STATE is one of "", conflict, failed, pending,
# dry-run or active, and only configure_https sets it — never on the strength
# of having run the commands, only after the URL answers with a certificate
# this machine's own trust store accepts.
#
# HTTPS_TARGET is the name or address Caddy will serve, and HTTPS_TARGET_KIND
# is one of hostname, ipv4 or ipv6. They are kept apart because the two need
# different Caddy configuration and have very different failure modes, and
# because everything that reaches a generated Caddyfile has to have been
# through a validator that knows which shape it was expecting.
HTTPS_TARGET=""
HTTPS_TARGET_KIND=""
# Why an IP attempt failed, when it did. Reported verbatim so the operator is
# told the real reason rather than "something went wrong".
HTTPS_FAIL_REASON=""
# The Caddyfile as it was before this run, so a failed attempt can put it back.
CADDYFILE_BACKUP=""
CADDYFILE_EXISTED=0
HTTPS_STATE=""

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
    --https)     DEPLOYMENT="https" ;;
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
# TOP_PID and the TERM trap are what make die reliable from inside $( ). A bare
# exit there ends only the subshell: the message prints, the caller carries on
# with an empty string, and the run finishes green. That is not hypothetical —
# it is how an unreadable .env produced "Cannot continue: Could not read .env."
# twice and then "Dashboard stays on loopback", exit 0.
TOP_PID=$$
trap 'exit 1' TERM

die() {
  printf '\n%sCannot continue:%s %s\n' "$RED" "$OFF" "$1" >&2
  if [[ $# -gt 1 ]]; then
    printf '\n%s\n' "$2" >&2
  fi
  printf '\n' >&2
  kill -TERM "$TOP_PID" 2>/dev/null
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

# An unreadable .env is not an empty one. A root-owned 0600 file read by an
# unprivileged run answers "" to every question asked of it, and the answers
# decide whether this installer thinks a dashboard is published — so it would
# report the dashboard closed while leaving it open. grep and awk both separate
# "no match" (1) from "could not read" (above 1); these helpers keep that
# distinction rather than flattening it into an empty string.
env_unreadable() {
  die "Could not read $ENV_FILE." \
    "The file exists but this user cannot read it. Re-run with sudo, or fix its permissions. Answering from a file it cannot read would mean guessing whether your dashboard is published."
}

env_value() { # key -> prints the active value, empty if unset or commented out
  [[ -f "$ENV_FILE" ]] || return 0
  local matches status
  matches=$(grep -E "^${1}=" "$ENV_FILE" 2>/dev/null) && status=0 || status=$?
  case $status in
    0) printf '%s\n' "$matches" | tail -1 | cut -d= -f2- ;;
    1) ;; # no such key
    *) env_unreadable ;;
  esac
}

env_is_set() { # key
  [[ -f "$ENV_FILE" ]] || return 1
  grep -qE "^${1}=" "$ENV_FILE" 2>/dev/null && return 0
  (( $? == 1 )) || env_unreadable
  return 1
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
  ' "$ENV_FILE" 2>/dev/null
  local status=$?
  (( status <= 1 )) || env_unreadable
  return $status
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
# Neither step is allowed to fail quietly. If the delete or the append does not
# land — a readable but unwritable .env is the ordinary way — the caller goes on
# to announce the value it asked for while compose reads the old one. For the
# dashboard bind that means reporting a private address over a public one that
# is still live, which is the same false all-clear env_disable used to give.
# Confirmed by reading the value back, because an exit status only says the
# command ran, not that the file now says what it should.
env_set() { # key value
  local key="$1" val="$2"
  if [[ -f "$ENV_FILE" ]] && grep -qE "^${key}=" "$ENV_FILE" 2>/dev/null; then
    sed -i -E "/^${key}=/d" "$ENV_FILE" || env_set_failed "$key"
  fi
  printf '\n%s\n%s=%s\n' "$ENV_MARKER" "$key" "$val" >> "$ENV_FILE" || env_set_failed "$key"
  [[ "$(env_value "$key")" == "$val" ]] || env_set_failed "$key"
}

env_set_failed() { # key
  die "Could not write ${1} to $ENV_FILE." \
    "Continuing would report a setting the file does not carry, and compose would start from the old value. Fix that file's permissions, then run this again."
}

# env_disable comments a key out, three-way on purpose: 0 disabled it, 1 there
# was nothing to disable, 2 could not. Both callers use it to close a dashboard
# published on a public address — do_upgrade for one this installer wrote, and
# reconcile_env for one an existing .env carried into a fresh install — so
# collapsing 2 into 1 reports an exposure as closed while leaving it open. Every
# caller must distinguish them; an earlier version of this comment said "its one
# caller", and the second one went on treating a failed close as a no-op.
#
# grep says which by exit status — 1 is no match, above that is a read failure —
# and the edit is confirmed by re-reading rather than by trusting sed, which
# reports success for a substitution it did not make.
env_disable() { # key
  [[ -f "$ENV_FILE" ]] || return 1
  grep -qE "^${1}=" "$ENV_FILE" 2>/dev/null
  case $? in
    0) ;;
    1) return 1 ;;
    *) return 2 ;;
  esac
  sed -i -E "s|^${1}=|# disabled by install-docker.sh (dashboard kept on loopback): ${1}=|" "$ENV_FILE" || return 2
  grep -qE "^${1}=" "$ENV_FILE" 2>/dev/null && return 2
  return 0
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

  local distro=""
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091  # not present at lint time; guarded above
    distro="$(. /etc/os-release 2>/dev/null && printf '%s' "${PRETTY_NAME:-$NAME $VERSION_ID}")"
  fi
  pass "Linux $(uname -r)${distro:+  ($distro)}"

  # Named rather than gated. Debian and Ubuntu are what this is developed and
  # tested against; everything else is very likely fine, and refusing to run on
  # Fedora because nobody has tried it would be an obstacle rather than a
  # safeguard. Saying so lets the operator weigh a later failure correctly.
  case "$distro" in
    *Debian*|*Ubuntu*|*Raspbian*) ;;
    "") note "Could not identify the distribution; proceeding." ;;
    *)  note "Tested on Debian and Ubuntu. Everything here is standard Docker and systemd," ;
        note "so this should work, but you are the first to find out if it does not." ;;
  esac
}

# preflight reports what the machine is, without changing any of it.
#
# Every check here answers a question that would otherwise be answered by a
# confusing failure later. None of them act: this installer does not open
# firewall ports, does not stop other people's services, and does not edit
# configuration belonging to software it did not install. Reporting is the
# whole job.
preflight() {
  head_ "Preflight"

  # 1. Privilege. Docker, /etc/caddy and systemd all need it, and finding out
  #    three steps in leaves a half-configured machine.
  if [[ "$(id -u)" -eq 0 ]]; then
    pass "Running as root"
  elif command -v sudo >/dev/null 2>&1; then
    warn "Not running as root; Docker and Caddy configuration will need sudo"
    note "Re-run with: sudo ./deploy/install-docker.sh $*"
  else
    warn "Not running as root and sudo is not installed"
    note "Docker commands and any Caddy configuration will fail."
  fi

  # 2. The commands this script actually calls. A missing one is a "command
  #    not found" halfway through otherwise.
  local missing=()
  for c in curl sed grep awk; do
    command -v "$c" >/dev/null 2>&1 || missing+=("$c")
  done
  if [[ ${#missing[@]} -eq 0 ]]; then
    pass "Required commands present"
  else
    fail "Missing: ${missing[*]}"
    note "Install them first:  apt-get install -y ${missing[*]}"
  fi

  # 3. Outbound HTTPS. Feeds download over it, and so does ACME. This says
  #    nothing about whether the internet can reach *in*, which is the other
  #    half of what HTTPS mode needs and is not observable from here.
  if command -v curl >/dev/null 2>&1; then
    if curl -fsS --max-time 8 -o /dev/null https://acme-v02.api.letsencrypt.org/directory 2>/dev/null; then
      pass "Outbound HTTPS works (Let's Encrypt is reachable)"
    else
      warn "Could not reach Let'\''s Encrypt over HTTPS from this machine"
      note "Threat feeds and certificate issuance both need outbound 443."
    fi
  fi

  # 4. Firewall. Reported, never changed — the rules on this box are one of
  #    two firewalls that matter, and the other one is at your cloud provider
  #    where this script cannot see it. Saying "the firewall is fine" from
  #    here would be a claim about something unmeasured.
  if command -v ufw >/dev/null 2>&1; then
    local ufw_state
    ufw_state="$(ufw status 2>/dev/null | head -1 || true)"
    case "$ufw_state" in
      *inactive*) note "ufw is installed but inactive" ;;
      *active*)   note "ufw is active — DNS needs 53/udp and 53/tcp, HTTPS mode needs 80/tcp and 443/tcp" ;;
      *)          ;;
    esac
  fi
  note "Cloud provider firewalls are separate and cannot be seen from this machine."

  # 5. Somewhere to write. /etc/caddy only matters in HTTPS mode, and is
  #    checked there rather than pre-emptively.
  if [[ -w "$REPO_ROOT" ]]; then
    pass "Repository directory is writable (.env goes here)"
  else
    fail "Cannot write to ${REPO_ROOT}"
    note "The .env file is written here. Fix the permissions, or clone somewhere writable."
  fi
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
    # "systemd-resolve", not "systemd-resolved".
    #
    # The kernel truncates a process name to 15 characters (TASK_COMM_LEN), and
    # "systemd-resolved" is 16 — so ss reports "systemd-resolve" and a pattern
    # written with the trailing d never matches. Found by running the installer
    # on a real Ubuntu 24.04 with something named systemd-resolved holding
    # port 53: the operator got the generic "stop whatever owns port 53"
    # instead of the DNSStubListener recipe, on the single most common conflict
    # on the single most common platform for this product.
    #
    # The pattern below matches both spellings, and
    # TestSystemdResolvedIsRecognisedByItsTruncatedName pins it.
    *systemd-resolve*) printf 'systemd-resolved' ;;
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
  local blocked=0 proto owner ours=0
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

  # Ports 80 and 443 belong to whatever the operator already runs, and nothing
  # in this installer will take them. They are inspected because the most
  # confusing thing it can do is leave a VPS whose host IP serves somebody
  # else's default page without ever mentioning it — the user types the IP,
  # gets Apache, and concludes DNS Daddy failed to install.
  #
  # Recorded for the summary rather than reported here, so the connection is
  # made where the reader is looking for a URL.
  WEB_80_OWNER="$(port_owner tcp 80)"
  WEB_443_OWNER="$(port_owner tcp 443)"
  if [[ -n "$WEB_80_OWNER" ]]; then
    pass "TCP port 80 is served by: ${WEB_80_OWNER} (left alone)"
  fi
  if [[ -n "$WEB_443_OWNER" ]]; then
    pass "TCP port 443 is served by: ${WEB_443_OWNER} (left alone)"
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
  2. Public VPS — SSH tunnel  dashboard stays on loopback. Reach it through an
                            encrypted SSH tunnel. Nothing is published to the
                            internet. (default)
  3. Public VPS — HTTPS     dashboard reachable at https://your-hostname, with
                            Caddy terminating TLS in front of it. The dashboard
                            itself still binds loopback only; Caddy is the only
                            thing listening publicly. Needs a hostname whose
                            DNS already points here.

  Modes 2 and 3 both keep the dashboard off the public internet in plaintext.
  There is no option that publishes the management interface unencrypted, and
  that is deliberate.

EOF

  # --yes and any non-interactive run take the default, which is why the
  # default has to be the safe one: an unattended install must never end up
  # publishing a management API. --lan is the explicit way to ask for the
  # other answer, and being explicit is the whole point of it.
  case "$DEPLOYMENT" in
    lan) CHOICE=1; printf '  (--lan given)\n' ;;
    vps) CHOICE=2; printf '  (--vps given)\n' ;;
    https) CHOICE=3; printf '  (--https given)\n' ;;
    *)
      if [[ $ASSUME_YES -eq 0 && $DRY_RUN -eq 0 && -t 0 ]]; then
        read -r -p "  Deployment type [2]: " reply
        [[ -n "${reply:-}" ]] && CHOICE="$reply"
      fi
      ;;
  esac
  case "$CHOICE" in
    1|2|3) ;;
    *) die "Expected 1, 2 or 3, got '$CHOICE'." ;;
  esac

  # Mode 3 keeps the backend on loopback exactly as mode 2 does — the only
  # difference is that Caddy is put in front of it. DASHBOARD_BIND stays empty
  # here for both, and configure_https never sets it: see the compose file,
  # where an empty value means 127.0.0.1.
  if [[ "$CHOICE" == "3" ]]; then
    DASHBOARD_BIND=""
    choose_https_hostname
    return
  fi

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

# --- HTTPS mode ---------------------------------------------------------------
#
# The architecture is the one deploy/Caddyfile.example already documents and
# deploy/production-deploy.sh already builds:
#
#   internet → :443 Caddy (TLS) → 127.0.0.1:8080 DNS Daddy
#
# Nothing new is invented here. What this adds is doing it during a first
# install rather than as a separate manual step, because "install, get a URL,
# open it" is the experience people expect and the reason they otherwise reach
# for a plaintext port.
#
# The dashboard container is not published beyond loopback in this mode. Caddy
# is the only process listening on a public interface, and the management API
# is never available unencrypted.

# valid_hostname rejects what will obviously fail ACME rather than discovering
# it after Caddy has been reconfigured. It is deliberately not a full RFC 1035
# implementation: it catches a URL pasted in place of a name, a bare label with
# no dot, and the empty string, which are the mistakes people actually make.
# Everything below feeds a generated Caddyfile, so every one of these is a
# security boundary and not merely a usability check. A Caddyfile site address
# containing a brace, a newline or whitespace would let a pasted value close
# the site block and open another one with directives of its own choosing.
#
# The validators are whitelists — an explicit set of permitted characters in an
# explicit shape — rather than blacklists of the metacharacters somebody
# thought of. `[[ =~ ]]` with an anchored pattern and no unquoted expansion is
# what enforces that.

valid_hostname() { # name
  local h="$1"
  [[ -n "$h" ]] || return 1
  [[ "$h" != *://* ]] || return 1
  [[ "$h" != */* ]] || return 1
  [[ "$h" != *:* ]] || return 1
  [[ ${#h} -le 253 ]] || return 1
  [[ "$h" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$ ]] || return 1
  # An all-digit final label is a dotted-quad, which has its own path.
  [[ "${h##*.}" =~ ^[0-9]+$ ]] && return 1
  return 0
}

# valid_ipv4 accepts a dotted quad with every octet in range.
#
# The range check is the point. "999.1.1.1" matches any regex loose enough to
# be readable, and a Caddyfile built around it would fail somewhere less
# obvious than here.
valid_ipv4() { # address
  local a="$1" o
  [[ "$a" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
  local IFS=.
  # shellcheck disable=SC2206  # deliberate split on IFS=. after the regex above
  local parts=($a)
  for o in "${parts[@]}"; do
    [[ "$o" =~ ^0[0-9] ]] && return 1   # 010 is not 10 to every parser
    (( o >= 0 && o <= 255 )) || return 1
  done
  return 0
}

# valid_ipv6 accepts the hex-and-colon forms, including a single "::".
#
# Deliberately not a full RFC 4291 parser: it rejects anything that is not
# hex digits and colons, bounds the length and the group count, and refuses
# more than one "::". A zone index (%eth0) is refused outright — a link-local
# address cannot be reached from the internet, so it can only be a mistake
# here, and a percent sign in a Caddyfile site address is not something to
# find out about later.
valid_ipv6() { # address
  local a="$1"
  [[ -n "$a" ]] || return 1
  [[ "$a" != *%* ]] || return 1
  [[ "$a" != *"["* && "$a" != *"]"* ]] || return 1
  [[ ${#a} -le 45 ]] || return 1
  [[ "$a" =~ ^[0-9A-Fa-f:]+$ ]] || return 1
  [[ "$a" == *:* ]] || return 1
  # At most one "::", and never three colons in a row.
  [[ "$a" == *:::* ]] && return 1
  local doubles="${a//[^:]/}"
  [[ ${#doubles} -le 8 ]] || return 1
  case "$(printf '%s' "$a" | grep -o '::' | wc -l)" in
    0|1) ;;
    *) return 1 ;;
  esac
  return 0
}

# is_public_ipv4 reports whether an address could have come from the internet.
# A certificate will not be issued for anything else, and asking ACME to try is
# a slow way to be told so.
is_public_ipv4() { # address
  is_private_addr "$1" && return 1
  case "$1" in
    0.*|255.*)                       return 1 ;;  # unspecified / broadcast
    22[4-9].*|23[0-9].*|24[0-9].*|25[0-5].*) return 1 ;;  # multicast, reserved
    192.0.2.*|198.51.100.*|203.0.113.*)      return 1 ;;  # documentation ranges
    198.1[89].*)                     return 1 ;;  # benchmarking
  esac
  return 0
}

# detect_public_ip prints this machine's own globally routable address, or
# nothing.
#
# Read from the interfaces and from nowhere else. No third-party lookup
# service: this installer should not phone anybody to work out where it is, and
# an answer from outside would be about the NAT in front of the machine rather
# than about the machine — which is exactly the case where binding to it would
# not work anyway.
#
# On a NATed provider (AWS, GCP, some Azure shapes) there is no such address on
# any interface and this correctly prints nothing. That is not a failure to
# detect; it is the true answer to "which of my addresses can Caddy bind and
# prove control of", and the hostname path is the right one there.
detect_public_ip() {
  local addr
  while read -r addr; do
    [[ -n "$addr" ]] || continue
    if valid_ipv4 "$addr" && is_public_ipv4 "$addr"; then
      printf '%s' "$addr"
      return 0
    fi
  done < <( { printf '%s\n' "${HOST_IP:-}"; host_addresses; } )
  return 1
}

choose_https_hostname() {
  local detected
  detected="$(detect_public_ip || true)"

  cat <<'EOF'

  Secure dashboard setup

  Caddy terminates TLS on ports 80 and 443 and forwards to DNS Daddy on
  127.0.0.1:8080. The dashboard itself is never published — Caddy is the only
  process listening on a public interface.

EOF
  if [[ -n "$detected" ]]; then
    printf '  Detected public IP:\n    %s%s%s\n\n' "$BOLD" "$detected" "$OFF"
    printf '    1. Use this public IP     https://%s\n' "$detected"
    printf '    2. Use a hostname         e.g. dns.example.com\n\n'
  else
    printf '  No public address was found on this machine'\''s interfaces.\n'
    printf '  That is normal on AWS, GCP and other providers that NAT a public\n'
    printf '  address onto a private one — a hostname is the way in there.\n\n'
    printf '    2. Use a hostname         e.g. dns.example.com\n\n'
  fi

  # DNSDADDY_HTTPS_HOSTNAME=ip selects the detected address non-interactively,
  # which is what an unattended VPS install needs.
  local answer=""
  if [[ -n "${DNSDADDY_HTTPS_HOSTNAME:-}" ]]; then
    answer="$DNSDADDY_HTTPS_HOSTNAME"
    printf '  (DNSDADDY_HTTPS_HOSTNAME given: %s)\n' "$answer"
  elif [[ $ASSUME_YES -eq 0 && $DRY_RUN -eq 0 && -t 0 ]]; then
    if [[ -n "$detected" ]]; then
      read -r -p "  Choice [1]: " answer
      [[ -z "$answer" ]] && answer="1"
      if [[ "$answer" == "1" ]]; then
        answer="$detected"
      elif [[ "$answer" == "2" ]]; then
        read -r -p "  Hostname (e.g. dns.example.com): " answer
      fi
    else
      read -r -p "  Hostname (e.g. dns.example.com): " answer
    fi
  fi

  if [[ "$answer" == "ip" || "$answer" == "1" ]]; then
    [[ -n "$detected" ]] || die "DNSDADDY_HTTPS_HOSTNAME=ip was given, but no public address was found on this machine." \
      "Set DNSDADDY_HTTPS_HOSTNAME to the address or hostname to serve, or choose option 2 and reach the dashboard over an SSH tunnel."
    answer="$detected"
  fi

  set_https_target "$answer"
}

# set_https_target validates one operator-supplied value and classifies it.
#
# Nothing reaches a Caddyfile that has not been through here. The classification
# is not cosmetic: an IP site needs an explicit ACME issuer and a certificate
# check the hostname path does not, and a value that fits none of the three
# shapes must stop the run rather than be written out and discovered by Caddy.
set_https_target() { # value
  local v="${1:-}"
  v="${v#"${v%%[![:space:]]*}"}"   # trim leading whitespace
  v="${v%"${v##*[![:space:]]}"}"   # trim trailing whitespace
  v="${v#https://}"; v="${v#http://}"; v="${v%%/*}"

  if valid_hostname "$v"; then
    HTTPS_TARGET="$v"; HTTPS_TARGET_KIND="hostname"
    pass "HTTPS hostname: ${v}"
    check_hostname_points_here "$v"
    return 0
  fi
  if valid_ipv4 "$v"; then
    is_public_ipv4 "$v" || die "${v} is not a publicly routable address." \
      "A certificate cannot be issued for a private or reserved address. Use a hostname, or choose option 2 and reach the dashboard over an SSH tunnel."
    HTTPS_TARGET="$v"; HTTPS_TARGET_KIND="ipv4"
    pass "HTTPS address: ${v}"
    return 0
  fi
  if valid_ipv6 "$v"; then
    HTTPS_TARGET="$v"; HTTPS_TARGET_KIND="ipv6"
    pass "HTTPS address: [${v}]"
    return 0
  fi

  die "'${v}' is not a hostname or an IP address." \
    "Give a name like dns.example.com, or a public IP address. Not a URL, not a single label, and not a private address. Set it non-interactively with DNSDADDY_HTTPS_HOSTNAME=dns.example.com (or =ip for this machine'\''s detected public address), or choose option 2 and reach the dashboard over an SSH tunnel."
}

# check_hostname_points_here warns when the name does not resolve to an address
# this machine holds.
#
# A warning and never a refusal: DNS may not have propagated yet, split-horizon
# resolvers exist, and the machine may sit behind a NAT whose public address is
# not on any interface here. But by far the most common reason ACME fails is
# that the record was never created, and finding that out now — before Caddy
# has been reconfigured and 45 seconds have been spent waiting — is the
# difference between a clear message and a mystery.
check_hostname_points_here() { # hostname
  local name="$1" resolved="" mine="" a
  if command -v getent >/dev/null 2>&1; then
    resolved="$(getent ahostsv4 "$name" 2>/dev/null | awk '{print $1}' | sort -u)"
  fi
  if [[ -z "$resolved" ]]; then
    note "Could not resolve ${name} from this machine; ACME will need it to resolve publicly."
    return 0
  fi
  mine="$( { printf '%s\n' "${HOST_IP:-}"; host_addresses; } | grep -v '^$' | sort -u)"
  while read -r a; do
    [[ -n "$a" ]] || continue
    if printf '%s\n' "$mine" | grep -qxF "$a"; then
      pass "${name} resolves to ${a}, which is an address on this machine"
      return 0
    fi
  done <<<"$resolved"
  warn "${name} resolves to $(printf '%s' "$resolved" | paste -sd, -), which is not an address on this machine."
  note "If this host is behind a NAT that forwards 80 and 443, that is expected."
  note "Otherwise the certificate request will fail: the A record must point here."
}

# https_port_conflict names what would stop Caddy binding, or prints nothing.
#
# Caddy's own listener is not a conflict — it is what an upgrade looks like.
https_port_conflict() {
  local conflict=""
  if [[ -n "$WEB_80_OWNER" && "$WEB_80_OWNER" != *caddy* ]]; then
    conflict="${WEB_80_OWNER} on port 80"
  fi
  if [[ -n "$WEB_443_OWNER" && "$WEB_443_OWNER" != *caddy* ]]; then
    [[ -n "$conflict" ]] && conflict="${conflict}, "
    conflict="${conflict}${WEB_443_OWNER} on port 443"
  fi
  printf '%s' "$conflict"
}

# configure_https puts Caddy in front of the loopback dashboard.
#
# It sets HTTPS_STATE to active or failed, and never to active on the strength
# of having run the commands: the last thing it does is ask the URL whether it
# answers. Announcing a working HTTPS dashboard that does not exist is worse
# than saying plainly that the proxy step did not finish, because the operator
# would stop looking.
configure_https() {
  [[ "$CHOICE" == "3" ]] || return 0

  head_ "HTTPS"

  local conflict
  conflict="$(https_port_conflict)"
  if [[ -n "$conflict" ]]; then
    HTTPS_STATE="conflict"
    warn "Cannot configure HTTPS: ${conflict}"
    note "DNS Daddy itself is installed and the resolver is running. Only the"
    note "TLS front end was skipped, and nothing belonging to that service was"
    note "changed — this installer does not stop, reconfigure or take ports"
    note "from software you already run."
    note ""
    note "Either point your existing web server at 127.0.0.1:8080 yourself, or"
    note "free ports 80 and 443 and re-run with --https."
    revert_env_to_tunnel
    return 0
  fi

  if ! command -v caddy >/dev/null 2>&1; then
    printf '  Installing Caddy...\n'
    if ! install_caddy; then
      HTTPS_STATE="failed"
      HTTPS_FAIL_REASON="Caddy could not be installed."
      warn "Caddy could not be installed; the dashboard stays on loopback."
      revert_env_to_tunnel
      return 0
    fi
  fi
  pass "Caddy $(caddy_version)"

  # Overridable so the rollback paths can be exercised by the test suite
  # against a temporary directory. Not a privilege boundary: anyone who can set
  # this already runs the installer as root.
  # An IP-address deployment needs a Caddy whose CertMagic knows that Let's
  # Encrypt issues IP certificates. Checked before the Caddyfile is written, so
  # the operator is told what to do rather than shown a parse error.
  if [[ "$HTTPS_TARGET_KIND" != "hostname" ]] \
     && ! caddy_version_at_least "$CADDY_MIN_IP_MAJOR" "$CADDY_MIN_IP_MINOR"; then
    HTTPS_STATE="failed"
    HTTPS_FAIL_REASON="Caddy $(caddy_version) is too old for IP-address certificates; ${CADDY_MIN_IP_MAJOR}.${CADDY_MIN_IP_MINOR} or newer is required."
    warn "$HTTPS_FAIL_REASON"
    note "Distribution packages lag a long way behind - Debian 13 ships 2.6.2."
    note "Install the current release from the upstream repository:"
    note "  https://caddyserver.com/docs/install#debian-ubuntu-raspbian"
    note "Then re-run with --https. A hostname works on this Caddy; only the"
    note "IP-address path needs the newer one."
    revert_env_to_tunnel
    return 0
  fi

  local caddyfile="${DNSDADDY_CADDYFILE:-/etc/caddy/Caddyfile}"
  if [[ $DRY_RUN -eq 1 ]]; then
    printf '  [dry-run] would write %s for %s (%s) and reload Caddy\n' \
      "$caddyfile" "$HTTPS_TARGET" "$HTTPS_TARGET_KIND"
    if [[ "$HTTPS_TARGET_KIND" != "hostname" ]]; then
      printf '  [dry-run] would then require a publicly trusted certificate for that\n'
      printf '            address, and restore the previous Caddyfile if none arrived\n'
    fi
    HTTPS_STATE="dry-run"
    return 0
  fi

  mkdir -p "$(dirname "$caddyfile")"

  # Remember what was there. Every failure path below puts it back: a
  # half-configured proxy in front of a management interface is worse than no
  # proxy, and an operator who already had Caddy serving something else must
  # not lose it because DNS Daddy's certificate did not arrive.
  if [[ -f "$caddyfile" ]]; then
    CADDYFILE_EXISTED=1
    CADDYFILE_BACKUP="${caddyfile}.dnsdaddy-bak-$(date +%F-%H%M%S)"
    if ! cp -p "$caddyfile" "$CADDYFILE_BACKUP"; then
      HTTPS_STATE="failed"
      HTTPS_FAIL_REASON="Could not back up ${caddyfile}."
      warn "$HTTPS_FAIL_REASON Refusing to overwrite it."
      revert_env_to_tunnel
      return 0
    fi
    chmod 0600 "$CADDYFILE_BACKUP" 2>/dev/null || true
    pass "Existing Caddyfile saved to ${CADDYFILE_BACKUP}"
  fi

  if ! write_caddyfile "$caddyfile"; then
    HTTPS_STATE="failed"
    HTTPS_FAIL_REASON="Could not write ${caddyfile}."
    warn "$HTTPS_FAIL_REASON"
    restore_caddyfile "$caddyfile"
    revert_env_to_tunnel
    return 0
  fi
  # It contains no secret, but it decides what is published; keep it out of
  # world-readable reach and owned by root like the rest of /etc/caddy.
  chown root:root "$caddyfile" 2>/dev/null || true
  chmod 0644 "$caddyfile" 2>/dev/null || true

  # Validate before activating. A Caddyfile that does not parse would take down
  # whatever Caddy was already serving — and for an IP target this is also the
  # version check: a Caddy too old to know the `profile` subdirective fails
  # here, by capability rather than by a version number this script would have
  # to keep guessing at.
  local validate_out
  if ! validate_out="$(caddy validate --config "$caddyfile" 2>&1)"; then
    HTTPS_STATE="failed"
    if [[ "$HTTPS_TARGET_KIND" != "hostname" ]] && printf '%s' "$validate_out" | grep -qi 'profile'; then
      HTTPS_FAIL_REASON="This Caddy does not understand the ACME 'profile' setting, which public IP certificates require."
    else
      HTTPS_FAIL_REASON="The generated Caddyfile did not validate."
    fi
    warn "$HTTPS_FAIL_REASON Caddy was not reloaded."
    note "$(printf '%s' "$validate_out" | head -3)"
    restore_caddyfile "$caddyfile"
    revert_env_to_tunnel
    return 0
  fi
  pass "Caddyfile validated"

  systemctl enable --now caddy >/dev/null 2>&1 || true
  if ! systemctl reload caddy >/dev/null 2>&1 && ! systemctl restart caddy >/dev/null 2>&1; then
    HTTPS_STATE="failed"
    HTTPS_FAIL_REASON="Caddy would not reload with the new configuration."
    warn "$HTTPS_FAIL_REASON"
    restore_caddyfile "$caddyfile"
    systemctl reload caddy >/dev/null 2>&1 || systemctl restart caddy >/dev/null 2>&1 || true
    revert_env_to_tunnel
    return 0
  fi

  if verify_https; then
    HTTPS_STATE="active"
    return 0
  fi

  # Everything below is a failure to obtain a publicly trusted certificate.
  #
  # For a hostname this is usually DNS or a firewall and is worth waiting on,
  # so the previous configuration stays in place and the operator is told what
  # to watch. For an IP it is a hard stop with a known cause, and leaving the
  # site configured would leave Caddy answering :443 for an address it cannot
  # produce a trusted certificate for — a browser warning on the management
  # interface, which is the outcome this whole path exists to avoid.
  if [[ "$HTTPS_TARGET_KIND" == "hostname" ]]; then
    HTTPS_STATE="pending"
    warn "Caddy is configured for ${HTTPS_TARGET}, but the URL did not answer yet."
    note "This is usually DNS or certificate issuance still in progress, or ports"
    note "80/443 not reachable from the internet. DNS Daddy itself is running."
    note "Check with:"
    note "  systemctl status caddy"
    note "  journalctl -u caddy --no-pager -n 30"
    note "  curl -v https://${HTTPS_TARGET}/api/v1/health"
    return 0
  fi

  HTTPS_STATE="failed"
  [[ -n "$HTTPS_FAIL_REASON" ]] || HTTPS_FAIL_REASON="No publicly trusted certificate was issued for ${HTTPS_TARGET}."
  warn "$HTTPS_FAIL_REASON"
  restore_caddyfile "$caddyfile"
  systemctl reload caddy >/dev/null 2>&1 || systemctl restart caddy >/dev/null 2>&1 || true
  revert_env_to_tunnel
  return 0
}

# https_url renders the dashboard URL, bracketing IPv6 as a URL requires.
https_url() {
  if [[ "$HTTPS_TARGET_KIND" == "ipv6" ]]; then
    printf 'https://[%s]' "$HTTPS_TARGET"
  else
    printf 'https://%s' "$HTTPS_TARGET"
  fi
}

# caddy_version prints what `caddy version` says, or a legible stand-in.
#
# A Caddy built without a VCS stamp — `go install`, or some distribution
# builds — prints literally "unknown". Passing that through as "Caddy unknown"
# reads like a bug in this script rather than a property of that binary, so it
# is spelled out. The version gate treats an unparseable version as too old,
# which is the safe direction.
caddy_version() {
  local v
  v="$(caddy version 2>/dev/null | head -1)"
  v="${v%%$'\n'*}"
  case "${v:-}" in
    ""|unknown|"(devel)") printf 'version not reported by this build' ;;
    *) printf '%s' "$v" ;;
  esac
}

# restore_caddyfile puts back whatever was there before this run.
#
# When there was nothing, the generated file is removed rather than left
# behind: an abandoned site block for a management interface is precisely the
# thing nobody would think to look for later.
restore_caddyfile() { # path
  local caddyfile="$1"
  if [[ $CADDYFILE_EXISTED -eq 1 && -n "$CADDYFILE_BACKUP" && -f "$CADDYFILE_BACKUP" ]]; then
    if cp -p "$CADDYFILE_BACKUP" "$caddyfile"; then
      note "Your previous Caddyfile has been restored."
    else
      warn "Could not restore ${caddyfile} from ${CADDYFILE_BACKUP} — do it by hand."
    fi
    return 0
  fi
  rm -f "$caddyfile"
  note "The generated Caddyfile was removed; Caddy is serving nothing for DNS Daddy."
}

# write_caddyfile generates the reverse-proxy configuration.
#
# The site address is the only operator-supplied value in the file, and it has
# already been through valid_hostname, valid_ipv4 or valid_ipv6 — an anchored
# whitelist of characters that cannot express a brace, a newline or whitespace,
# so it cannot close the site block and open one of its own. The heredoc is
# quoted where nothing is substituted and the substitution is a single
# validated word where it is not.
write_caddyfile() { # path
  local out="$1" site tls_block=""

  case "$HTTPS_TARGET_KIND" in
    hostname) site="$HTTPS_TARGET" ;;
    ipv4)     site="$HTTPS_TARGET" ;;
    ipv6)     site="[$HTTPS_TARGET]" ;;
    *)        return 1 ;;
  esac

  # An IP site pins the public ACME issuer explicitly.
  #
  # Two reasons, and the second is the important one. Let's Encrypt issues
  # certificates for IP addresses only through the `shortlived` profile
  # (generally available since 2026-01-15, 160-hour lifetime, renewed
  # automatically by Caddy like any other). And naming the issuer stops Caddy
  # falling back to its own internal CA for an address it decides is not
  # publicly nameable — that fallback would put a certificate no browser
  # trusts in front of the management interface and call the install a
  # success, which is worse than failing.
  if [[ "$HTTPS_TARGET_KIND" != "hostname" ]]; then
    tls_block=$'\n\ttls {\n\t\tissuer acme {\n\t\t\tprofile shortlived\n\t\t}\n\t}\n'
  fi

  {
    cat <<'EOF'
# Generated by deploy/install-docker.sh. Re-running the installer replaces it,
# after backing up whatever was here.
#
#   Internet → :443 (Caddy, TLS) → 127.0.0.1:8080 (DNS Daddy)
#
# DNS itself does not pass through Caddy. Queries reach the resolver directly
# on port 53, restricted by the client ACL to the networks you permit.

EOF
    printf '%s {\n' "$site"
    printf '%s' "$tls_block"
    cat <<'EOF'

	# The container publishes only on loopback, which is why the dashboard is
	# unreachable from outside without this proxy. That is intentional: the
	# management API is never exposed in plaintext.
	reverse_proxy 127.0.0.1:8080 {
		header_up X-Real-IP {remote_host}
		transport http {
			dial_timeout 5s
		}
	}

	encode gzip

	header {
		# The dashboard is HTTPS-only from here on. Safe because this site
		# block is only ever written for a deployment that just proved it can
		# serve a publicly trusted certificate — the installer restores the
		# previous configuration when that fails, rather than leaving an HSTS
		# policy pinned to a name it cannot serve.
		Strict-Transport-Security "max-age=31536000; includeSubDomains"
		X-Content-Type-Options "nosniff"
		Referrer-Policy "no-referrer"
		Cross-Origin-Opener-Policy "same-origin"
		Cross-Origin-Resource-Policy "same-origin"
		Permissions-Policy "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"
		-Server
	}

	log {
		output file /var/log/caddy/dnsdaddy.log {
			roll_size 10MiB
			roll_keep 5
		}
	}
}
EOF
  } > "$out"
}

# verify_https decides whether HTTPS actually works, and is the only thing
# allowed to conclude that it does.
#
# Two probes, and the difference between them is the whole check:
#
#   strict   curl with this machine's trust store. Success means a browser
#            will be happy, which is the only definition of "working" worth
#            printing.
#   lax      curl -k. Success while strict fails means something IS serving
#            TLS on 443 and its certificate is not publicly trusted — Caddy's
#            internal CA, almost always. That is a definite answer, available
#            immediately, and it means waiting longer is pointless.
#
# Without the second probe an IP deployment would sit through the whole
# timeout and then report "still in progress" about a state that was never
# going to improve.
verify_https() {
  local url deadline lax_seen=0
  case "$HTTPS_TARGET_KIND" in
    ipv6) url="https://[${HTTPS_TARGET}]/api/v1/health" ;;
    *)    url="https://${HTTPS_TARGET}/api/v1/health" ;;
  esac

  printf '  Waiting for a publicly trusted certificate for %s...\n' "$HTTPS_TARGET"
  deadline=$((SECONDS + ${DNSDADDY_HTTPS_TIMEOUT:-45}))
  while (( SECONDS < deadline )); do
    if curl -fsS --max-time 5 "$url" >/dev/null 2>&1; then
      pass "${url%/api/v1/health} is serving the dashboard over HTTPS"
      pass "Certificate is trusted by this machine's CA store"
      return 0
    fi
    # -k succeeding means TLS is up and the certificate is not trusted. For a
    # hostname that can still be a transient state during issuance, so it is
    # only recorded; for an IP it is the answer.
    if curl -fsSk --max-time 5 "$url" >/dev/null 2>&1; then
      lax_seen=1
      if [[ "$HTTPS_TARGET_KIND" != "hostname" ]]; then
        HTTPS_FAIL_REASON="Caddy is serving a certificate for ${HTTPS_TARGET} that this machine does not trust — it fell back to its own internal CA rather than obtaining a public one."
        return 1
      fi
    fi
    sleep 3
  done

  if [[ $lax_seen -eq 1 ]]; then
    HTTPS_FAIL_REASON="TLS is answering on ${HTTPS_TARGET}, but the certificate is not publicly trusted."
  elif [[ "$HTTPS_TARGET_KIND" != "hostname" ]]; then
    HTTPS_FAIL_REASON="No certificate was issued for ${HTTPS_TARGET}. For an IP address that usually means ports 80 and 443 are not reachable from the internet at this address - the ACME challenge has to arrive there - or the address does not belong to this machine."
  fi
  return 1
}

# install_caddy adds the upstream Caddy repository and installs from it.
#
# Every step is checked, and the reason is a real one this was caught doing:
# when the Cloudsmith repository cannot be reached — a proxy, a firewall, an
# outage — the `&&` chain used to run on to `apt-get install caddy`, apt found
# the distribution's own package, and the install "succeeded" with **Caddy
# 2.6.2** on Debian 13. That is a 2022 release being put in front of a
# management interface, and nothing said so.
#
# Now: if the repository cannot be added, that is a failure with its own
# message, and the distribution package is only used as a named, reported
# fallback rather than as an accident.
install_caddy() {
  apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https curl gnupg >/dev/null 2>&1

  local keyring=/usr/share/keyrings/caddy-stable-archive-keyring.gpg
  local listfile=/etc/apt/sources.list.d/caddy-stable.list
  local repo_ok=0

  if curl -1sLf --max-time 20 "https://dl.cloudsmith.io/public/caddy/stable/gpg.key" \
       | gpg --dearmor -o "$keyring" 2>/dev/null && [[ -s "$keyring" ]]; then
    if curl -1sLf --max-time 20 "https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt" \
         > "${listfile}.tmp" 2>/dev/null && [[ -s "${listfile}.tmp" ]]; then
      mv "${listfile}.tmp" "$listfile"
      apt-get update -qq >/dev/null 2>&1 && repo_ok=1
    fi
  fi
  rm -f "${listfile}.tmp"

  if [[ $repo_ok -eq 0 ]]; then
    warn "Could not add the upstream Caddy repository (dl.cloudsmith.io unreachable)."
    note "Falling back to the distribution's own Caddy package, which is usually"
    note "much older. The version is checked below and reported either way."
    rm -f "$listfile"
    apt-get update -qq >/dev/null 2>&1
  fi

  apt-get install -y -qq caddy >/dev/null 2>&1 || return 1
  command -v caddy >/dev/null 2>&1
}

# caddy_version_at_least compares the installed Caddy against a minimum.
#
# Version numbers rather than a feature probe, because this runs *before*
# anything is written and its whole job is to say "this will not work, and
# here is why" instead of producing a parse error the operator has to
# interpret. `caddy validate` is still the authority afterwards — this only
# turns one common, fixable situation into a sentence somebody can act on.
caddy_version_at_least() { # major minor
  local want_major="$1" want_minor="$2" v major minor
  v="$(caddy version 2>/dev/null | head -1 | grep -oE 'v?[0-9]+\.[0-9]+' | head -1)"
  v="${v#v}"
  [[ -n "$v" ]] || return 1
  major="${v%%.*}"; minor="${v#*.}"
  [[ "$major" =~ ^[0-9]+$ && "$minor" =~ ^[0-9]+$ ]] || return 1
  (( major > want_major )) && return 0
  (( major < want_major )) && return 1
  (( minor >= want_minor ))
}

# Caddy that can ask a public CA for an IP-address certificate.
#
# 2.11 is the first release whose bundled CertMagic knows that Let's Encrypt
# issues them: certmagic's ACMEIssuer.PreCheck holds a map of public CAs to
# whether they support IP certificates, and before that map gained
# `api.letsencrypt.org: true` the request was refused locally, without an
# order ever being sent. Verified empirically against certmagic v0.25.3 as
# shipped in Caddy v2.11.4 — see docs/deployment-matrix.md.
CADDY_MIN_IP_MAJOR=2
CADDY_MIN_IP_MINOR=11

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
  # HTTPS mode configures the app to know it is behind TLS. The bind is
  # deliberately untouched below: the backend stays on loopback, and Caddy is
  # the only thing listening publicly. See docker-compose.yml, where an empty
  # DNSDADDY_DASHBOARD_BIND means 127.0.0.1.
  if [[ "$CHOICE" == "3" && -n "$HTTPS_TARGET" ]]; then
    local base
    if [[ "$HTTPS_TARGET_KIND" == "ipv6" ]]; then
      base="https://[${HTTPS_TARGET}]"
    else
      base="https://${HTTPS_TARGET}"
    fi
    env_set DNSDADDY_BASE_URL "$base"
    env_set DNSDADDY_SECURE_COOKIES "always"
    # The container sees the Docker bridge gateway, not 127.0.0.1, so this is
    # the narrow range that actually needs trusting — not a wildcard.
    env_set DNSDADDY_TRUSTED_PROXY_CIDRS "$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Subnet}}' 2>/dev/null || echo '172.17.0.0/16')"
    pass "Configured for HTTPS at ${base} (backend stays on loopback)"
  fi

  env_disable DNSDADDY_DASHBOARD_BIND
  case $? in
    0)
      warn "Your .env published the dashboard on a specific address; that line is now commented out"
      note "The dashboard returns to loopback. If it was reachable from the internet,"
      note "change the admin password: assume it has been seen."
      ;;
    1) ;; # nothing was published; there is nothing to close
    *)
      die "Could not close the dashboard address in $ENV_FILE." \
        "Your .env still publishes the dashboard, and starting now would put it back on that address after saying it had returned to loopback. Fix that file's permissions, or comment the line out by hand, then run this again."
      ;;
  esac
}

# revert_env_to_tunnel undoes the HTTPS-mode settings after a failed attempt.
#
# Without this, failing closed also failed shut. reconcile_env runs before
# configure_https — it has to, because the container must be up before there is
# anything for Caddy to proxy — so by the time HTTPS fails, .env already says
# DNSDADDY_SECURE_COOKIES=always. The operator is then told to fall back to the
# SSH tunnel and reach http://127.0.0.1:8080, where the browser accepts the
# Secure cookie and refuses to send it back over plain HTTP. Login is
# impossible, with no error that points at the cause.
#
# The security posture of option 2 is loopback-only plus an SSH tunnel. Getting
# there means putting these three keys back as well as the Caddyfile, and
# restarting so the container reads them.
#
# DNSDADDY_DASHBOARD_BIND is deliberately not touched: HTTPS mode never set it,
# the backend has been on loopback throughout, and that is exactly where it
# should stay.
revert_env_to_tunnel() {
  local changed=0 key
  for key in DNSDADDY_SECURE_COOKIES DNSDADDY_BASE_URL DNSDADDY_TRUSTED_PROXY_CIDRS; do
    env_disable "$key"
    case $? in
      0) changed=1 ;;
      1) ;;
      *) warn "Could not revert ${key} in ${ENV_FILE}; edit it by hand before using the tunnel."
         note "With DNSDADDY_SECURE_COOKIES=always set, the browser will not send the"
         note "session cookie over http://127.0.0.1:8080 and login will fail silently."
         return 1 ;;
    esac
  done

  [[ $changed -eq 1 ]] || return 0

  pass "Reverted the HTTPS settings in .env so the SSH tunnel works"
  if "${COMPOSE[@]}" up -d >/dev/null 2>&1; then
    pass "Restarted DNS Daddy with the tunnel configuration"
  else
    warn "Could not restart DNS Daddy to apply the reverted settings."
    note "Run: docker compose up -d"
  fi
  return 0
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
      if [[ $DRY_RUN -eq 0 ]]; then
        env_disable DNSDADDY_DASHBOARD_BIND
        case $? in
          0)
            warn "That line is now commented out; the dashboard returns to loopback"
            note "If it was reachable from the internet, change the admin password."
            ;;
          1) ;; # already gone; nothing was published to close
          *)
            # Carrying on here would hand compose the unchanged file and
            # republish the address this branch exists to close, after saying
            # it had been closed. Stop instead, having changed nothing.
            die "Could not close the published dashboard in $ENV_FILE." \
              "DNSDADDY_DASHBOARD_BIND=${bind} is still active, so continuing would republish it. Fix that file's permissions, or comment the line out by hand, then run the upgrade again."
            ;;
        esac
      else
        # A dry run that stays silent here shows the operator an unsafe bind
        # and no plan to deal with it, which reads as "this run intends to
        # leave it published". It is the security-relevant edit of the whole
        # upgrade and the one most worth reviewing before it happens.
        printf '\n  Would change in .env:\n'
        printf '    comment out DNSDADDY_DASHBOARD_BIND=%s (dashboard returns to loopback)\n' "$bind"
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
  if [[ "$HTTPS_STATE" == "active" ]]; then
    printf '    Mode:    Secure HTTPS\n'
    printf '    URL:     %s\n' "$(https_url)"
    printf '    Backend: 127.0.0.1:8080 (not reachable from the internet)\n'
    printf '    TLS:     Caddy on this machine, certificate verified as publicly trusted\n'
  elif [[ "$HTTPS_STATE" == "pending" ]]; then
    # Configured, certificate not confirmed. Do not print the URL as though it
    # serves the dashboard.
    printf '    Mode:    HTTPS requested for %s — certificate not confirmed yet\n' "$HTTPS_TARGET"
    printf '    Backend: 127.0.0.1:8080 (not reachable from the internet)\n'
    printf '    Until the URL answers, reach it the same way as tunnel mode:\n'
    printf '      ssh -L 8080:127.0.0.1:8080 %s@%s\n' "${USER:-root}" "${HOST_IP:-<this-server>}"
    printf '      http://127.0.0.1:8080\n'
  elif [[ "$CHOICE" == "3" ]]; then
    # HTTPS was attempted and did not work. The dashboard is where option 2
    # leaves it, which is the whole point: a failed TLS setup falls back to the
    # most conservative access model, never to plaintext on a public address.
    printf '    Mode:    HTTPS setup could not be completed\n'
    [[ -n "$HTTPS_FAIL_REASON" ]] && printf '    Reason:  %s\n' "$HTTPS_FAIL_REASON"
    printf '\n    DNS Daddy remains safely accessible only over loopback.\n'
    printf '    Nothing was published to the internet, and no plaintext management\n'
    printf '    port was opened.\n\n'
    printf '    Connect from your own machine:\n'
    printf '      ssh -L 8080:127.0.0.1:8080 %s@%s\n\n' "${USER:-root}" "${HOST_IP:-<this-server>}"
    printf '    Then open:\n'
    printf '      http://127.0.0.1:8080\n'
    if [[ "$HTTPS_TARGET_KIND" != "hostname" && -n "$HTTPS_TARGET_KIND" ]]; then
      printf '\n    To retry with a hostname once its DNS points here:\n'
      printf '      sudo ./deploy/install-docker.sh --https\n'
    fi
  elif [[ -n "$DASHBOARD_BIND" ]]; then
    printf '    Mode:    Published on this network\n'
    printf '    URL:     %s\n' "$dashboard"
    printf '    Open it from another machine on the same network.\n'
  else
    printf '    Public access: disabled — the dashboard binds 127.0.0.1 only\n'
    printf '    Backend:       127.0.0.1:8080\n\n'
    printf '    Connect from your own machine:\n'
    printf '      ssh -L 8080:127.0.0.1:8080 %s@%s\n\n' "${USER:-root}" "${HOST_IP:-<this-server>}"
    printf '    Then open:\n'
    printf '      http://127.0.0.1:8080\n\n'
    printf '    That URL is plain HTTP, but it never leaves your machine: the SSH\n'
    printf '    tunnel carries it to the server encrypted, and the dashboard is not\n'
    printf '    listening on any public address.\n'
  fi

  # The Apache question. Printed whenever something else holds 80 or 443,
  # because "I installed it and the IP shows someone else's page" is the
  # confusion this whole section exists to prevent.
  if [[ -n "$WEB_80_OWNER" || -n "$WEB_443_OWNER" ]]; then
    printf '\n  %sExisting web server%s\n' "$BOLD" "$OFF"
    [[ -n "$WEB_80_OWNER" ]]  && printf '    Port 80:  %s\n' "$WEB_80_OWNER"
    [[ -n "$WEB_443_OWNER" ]] && printf '    Port 443: %s\n' "$WEB_443_OWNER"
    if [[ "$HTTPS_STATE" != "active" ]]; then
      printf '\n    Visiting http://%s reaches that server, not DNS Daddy.\n' "${HOST_IP:-this-machine}"
      printf '    DNS Daddy has not been published there and has not changed it.\n'
      if [[ "$HTTPS_STATE" == "conflict" ]]; then
        printf '    It also holds the ports HTTPS mode needs, which is why TLS was\n'
        printf '    skipped. Nothing belonging to it was stopped or reconfigured.\n'
      fi
    fi
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
    # "Your LAN is permitted" is only true of the shipped ACL. A deployment
    # that sets DNSDADDY_ALLOWED_CLIENT_CIDRS is permitted whatever that lists,
    # and this installer preserves an existing .env rather than overwriting it
    # — so on an upgrade, or a fresh install onto an existing file, the
    # deployment choice says nothing about what is actually admitted. doctor
    # has just printed the real list; point at it rather than assert over it.
    if env_is_set DNSDADDY_ALLOWED_CLIENT_CIDRS; then
      printf '    This deployment sets DNSDADDY_ALLOWED_CLIENT_CIDRS, so what may resolve\n'
      printf '    is whatever that lists — CLIENT ACCESS above shows it. If your LAN is\n'
      printf '    in there, test from another machine on the same network:\n'
    else
      printf '    Your LAN is already permitted to use the resolver. Test it from\n'
      printf '    another machine on the same network:\n'
    fi
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
preflight "$@"
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
  edit.

  DNSDADDY_ALLOWED_CLIENT_CIDRS is the other way in, and it is for automated
  deployments: Ansible, a Compose file, an image build. The two combine as a
  union, so know which one you are using and why — a range listed there is
  permitted no matter what the dashboard says about it, and unticking "Allow
  this network to use DNS Daddy" cannot withdraw it. To keep a permission you
  can revoke from the dashboard, add it as a Network and leave it out of .env.
EOF
fi

if [[ $DRY_RUN -eq 1 ]]; then
  printf '\n  Would change in .env:\n'
  if [[ "$CHOICE" == "3" ]]; then
    # The point of previewing HTTPS mode is that the reader can see the
    # dashboard bind is NOT among the changes: the backend stays on loopback
    # and Caddy is the only public listener.
    printf '    DNSDADDY_BASE_URL=%s\n' "$(https_url)"
    printf '    DNSDADDY_SECURE_COOKIES=always\n'
    printf '    DNSDADDY_TRUSTED_PROXY_CIDRS=<docker bridge subnet>\n'
    printf '    (backend stays on loopback — DNSDADDY_DASHBOARD_BIND is not set)\n'
    printf '\n  Would then configure Caddy for %s (%s), validate the config,\n' "$HTTPS_TARGET" "$HTTPS_TARGET_KIND"
    printf '  reload it, and require a publicly trusted certificate before reporting\n'
    printf '  HTTPS as working. A certificate this machine does not trust counts as\n'
    printf '  a failure, not as success.\n'
    if [[ "$HTTPS_TARGET_KIND" != "hostname" ]]; then
      printf '\n  This is an IP-address deployment. Let'\''s Encrypt issues IP certificates\n'
      printf '  only through the short-lived ACME profile (160-hour lifetime, renewed\n'
      printf '  automatically), so the generated Caddyfile pins that issuer explicitly\n'
      printf '  rather than letting Caddy fall back to its own internal CA. A certificate\n'
      printf '  no browser trusts, in front of the management interface, is not an\n'
      printf '  acceptable outcome.\n'
      printf '\n  Needs Caddy %s.%s or newer; distribution packages are usually older.\n' "$CADDY_MIN_IP_MAJOR" "$CADDY_MIN_IP_MINOR"
      printf '  Ports 80 and 443 must be reachable from the internet at this address.\n'
      printf '  If issuance fails the previous Caddyfile is restored, the HTTPS settings\n'
      printf '  in .env are reverted, and the dashboard is left exactly where SSH-tunnel\n'
      printf '  mode leaves it: loopback only.\n'
    fi
  elif [[ -n "$DASHBOARD_BIND" ]]; then
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

configure_https
run_doctor
print_next_steps
print_summary

[[ $FAILURES -gt 0 ]] && exit 1
exit 0
