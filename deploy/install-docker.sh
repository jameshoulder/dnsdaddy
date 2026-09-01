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
# Why an HTTPS attempt failed, when it did. Reported verbatim so the operator
# is told the real reason rather than "something went wrong".
#
# REASON is one sentence naming the cause. HINT is the specific thing to do
# about it, which is usually not on this machine — a cloud firewall, a DNS
# record. DETAIL is the CA's own words, kept separate because quoting the
# upstream error verbatim is what makes the diagnosis checkable rather than
# something the operator has to take on trust.
HTTPS_FAIL_REASON=""
HTTPS_FAIL_HINT=""
HTTPS_FAIL_DETAIL=""
# Whether caddy_acme_diagnosis actually recognised a cause, as opposed to
# verify_https writing a fallback sentence. These are different facts and
# conflating them cost the pending path its reachability: every timeout sets a
# reason, so a gate on "is the reason empty" was never true for a hostname and
# the branch it guarded could not run.
HTTPS_FAIL_DIAGNOSED=0
# Timestamp taken just before Caddy is reloaded, so the log reader can ignore
# everything an earlier attempt wrote.
CADDY_LOG_SINCE=""
# The slice of Caddy's log the diagnosis is reasoning about, and the line
# number within it of the last "the certificate arrived". Held as state rather
# than passed around because every diagnosis arm needs both, and because an
# arm that forgot the second one is exactly the bug this pair exists to stop.
ACME_LOG_WINDOW=""
ACME_SUCCESS_LINE=0
# The account the Caddy systemd unit runs as, resolved once and reported in
# failure messages so the operator knows whose permissions to fix.
CADDY_SERVICE_USER=""
# The HTTPS-mode env keys exactly as they were when this run started, so a
# failed attempt can put back what was there rather than assuming there was
# nothing. On a fresh install these are empty and restoring them means
# disabling, which is the same thing the old code did. On a re-run over a
# working HTTPS deployment they carry the working values, and blanket-disabling
# them would have left Caddy still terminating TLS and proxying to an app that
# no longer knew it was behind TLS: no Secure cookie, and every client
# appearing to come from the proxy.
HTTPS_ENV_SNAPSHOT_TAKEN=0
HTTPS_ENV_BASE_URL_WAS=""
HTTPS_ENV_SECURE_COOKIES_WAS=""
HTTPS_ENV_TRUSTED_PROXY_WAS=""
# What public DNS says about a hostname target: match, mismatch, unresolved,
# aaaa-orphan, or empty when no hostname was chosen. Recorded rather than only
# printed, so the pre-ACME summary can restate it without resolving twice.
HOSTNAME_DNS_STATE=""
# The Caddyfile as it was before this run, so a failed attempt can put it back.
#
# The mode and owner are recorded separately from the backup file because the
# backup is hardened to 0600 the moment it is made, and restoring its
# permissions along with its contents is what once left a rolled-back
# /etc/caddy/Caddyfile that Caddy could not read.
CADDYFILE_BACKUP=""
CADDYFILE_ORIG_MODE=""
CADDYFILE_ORIG_OWNER=""
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

# Whether the operator named a deployment mode on the command line.
#
# `--https` over an already-running deployment is a reconfiguration, not a
# fresh install: the ports it finds busy are its own. Without this the
# installer refused, told the operator to use --upgrade, and left them with no
# supported way to move an existing tunnel deployment to HTTPS short of taking
# the resolver down.
DEPLOYMENT_REQUESTED=0

for arg in "$@"; do
  case "$arg" in
    --upgrade)   MODE="upgrade" ;;
    --uninstall) MODE="uninstall" ;;
    --purge)     PURGE_DATA=1 ;;
    --dry-run)   DRY_RUN=1 ;;
    --yes|-y)    ASSUME_YES=1 ;;
    --lan)       DEPLOYMENT="lan"; DEPLOYMENT_REQUESTED=1 ;;
    --vps)       DEPLOYMENT="vps"; DEPLOYMENT_REQUESTED=1 ;;
    --https)     DEPLOYMENT="https"; DEPLOYMENT_REQUESTED=1 ;;
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
      warn "Could not reach Let's Encrypt over HTTPS from this machine"
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

# project_publishes_port proves that THIS Compose project's dnsdaddy container
# is the thing publishing a given HOST port.
#
# The distinction matters because `ss` names the holder of a published port as
# `docker-proxy`, which says only that some container has it — not whose. A
# stranger's DNS container and our own are indistinguishable from the socket.
# The container id comes from `docker compose ps -q dnsdaddy`, which is scoped
# to this project, so its port map is an answer that cannot be confused.
#
# Reads the whole map rather than asking about one port, because the argument
# form of `docker port` takes the CONTAINER port and the caller here knows the
# HOST one. Those differ: the container runs unprivileged and cannot bind 53,
# so docker-compose.yml publishes "53:5353". Asking `docker port <cid> 53/udp`
# would have been asking whether the container listens on 53 internally, which
# it never does — a check that always says no is the same as no check at all.
#
#   $ docker port <cid>
#   5353/tcp -> 0.0.0.0:53
#   5353/udp -> 0.0.0.0:53
#   8080/tcp -> 127.0.0.1:8080
project_publishes_port() { # proto host_port
  local proto="$1" port="$2" cid
  cid="$("${COMPOSE[@]}" ps -q dnsdaddy 2>/dev/null | head -1)"
  [[ -n "$cid" ]] || return 1
  docker port "$cid" 2>/dev/null \
    | grep -qE "^[0-9]+/${proto}[[:space:]]+->[[:space:]].*:${port}\$"
}

check_ports() {
  local blocked=0 proto owner ours=0
  # A busy port may be treated as expected only when this project's own
  # deployment is what is holding it, and only for an operation that is
  # legitimately performed over a running deployment:
  #
  #   --upgrade    rebuild and restart in place
  #   --https etc. change the deployment mode of what is already running
  #
  # `--https` used to fall outside this, so an operator moving an existing
  # tunnel deployment to HTTPS was told their own resolver was in the way and
  # advised to run --upgrade, which is not the operation they asked for. A
  # fresh install with no mode requested still stops: there, a running stack is
  # genuinely unexpected.
  if [[ "$MODE" == "upgrade" || $DEPLOYMENT_REQUESTED -eq 1 ]] && stack_is_running; then
    ours=1
  fi

  for proto in udp tcp; do
    owner="$(port_owner "$proto" 53)"
    if [[ -z "$owner" ]]; then
      pass "${proto^^} port 53 is free"
      continue
    fi
    # "Our deployment is running" is not on its own a reason to accept a busy
    # port: something else may hold it while our container publishes nothing.
    # Both halves have to be true.
    if [[ $ours -eq 1 ]] && project_publishes_port "$proto" 53; then
      pass "${proto^^} port 53 is published by this DNS Daddy deployment (expected)"
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
    if [[ $ours -eq 1 ]] && project_publishes_port tcp "$dash_port"; then
      pass "TCP port ${dash_port} is published by this DNS Daddy deployment (expected)"
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
      printf '  To rebuild and restart it:            --upgrade\n'
      printf '  To move it to HTTPS or another mode:  --https, --lan or --vps\n'
      printf '  Neither takes the resolver down or touches your data.\n'
      printf '  If it is not this project, `docker compose down` in its own directory first.\n'
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

  1. LAN / Homelab
     Dashboard available on your trusted LAN, at ${HOST_IP:-this machine}:8080.
     Choose this ONLY if the machine has no public address at all. Most cloud
     VPSes show a private address here and are still reachable from the
     internet.

  2. Public VPS — SSH tunnel                              (recommended, default)
     Dashboard stays private on this server. You reach it through an encrypted
     SSH tunnel. Nothing is published to the internet.

  3. Public VPS — HTTPS dashboard
     Dashboard is available in a browser through Caddy over HTTPS. DNS Daddy
     itself still stays private on 127.0.0.1:8080 — Caddy is the only thing
     listening publicly, and it proxies to the loopback backend.
       Preferred: a hostname whose DNS points at this machine.
       Advanced:  this machine's public IP address, which Let's Encrypt can now
                  certify directly. Needs inbound 80 and 443 from the internet.

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
# host_addresses6 lists this machine's global IPv6 addresses, if it has any.
#
# Separate from host_addresses because a host with no IPv6 stack is normal and
# must not be reported as a mismatch: an AAAA record that resolves to something
# this machine cannot confirm is a different statement from one that resolves
# to the wrong place.
host_addresses6() {
  ip -6 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | grep -v '^$' || true
}

# check_hostname_points_here compares public DNS against this machine.
#
# It reports and never changes anything: editing somebody's DNS is not this
# installer's business, and it could not do it correctly anyway. What it can do
# is tell the operator, before ACME runs, whether the record they think they
# set is the record the CA will see — which is the single most common reason a
# hostname deployment fails.
#
# Both families are checked. The old version looked at A records only, so a
# host reached over IPv6 with a stale or missing AAAA got a clean PASS and then
# an unexplained challenge failure.
check_hostname_points_here() { # hostname
  local name="$1" a4="" a6="" mine4 mine6 addr matched=0 mismatched=""

  if command -v getent >/dev/null 2>&1; then
    a4="$(getent ahostsv4 "$name" 2>/dev/null | awk '{print $1}' | sort -u)"
    a6="$(getent ahostsv6 "$name" 2>/dev/null | awk '{print $1}' | sort -u)"
  fi

  if [[ -z "$a4" && -z "$a6" ]]; then
    warn "${name} does not resolve from this machine."
    note "Let's Encrypt has to resolve it publicly before it will issue a"
    note "certificate. Create the record, then check with: dig +short ${name}"
    note "A new record can take minutes to hours to propagate; this installer"
    note "cannot tell you when it has."
    HOSTNAME_DNS_STATE="unresolved"
    return 0
  fi

  mine4="$( { printf '%s\n' "${HOST_IP:-}"; host_addresses; } | grep -v '^$' | sort -u)"
  mine6="$(host_addresses6 | sort -u)"

  while read -r addr; do
    [[ -n "$addr" ]] || continue
    if printf '%s\n' "$mine4" | grep -qxF "$addr"; then
      pass "${name} resolves to ${addr}, which is an address on this machine"
      matched=1
    else
      mismatched="${mismatched}${mismatched:+, }${addr}"
    fi
  done <<<"$a4"

  while read -r addr; do
    [[ -n "$addr" ]] || continue
    if printf '%s\n' "$mine6" | grep -qxF "$addr"; then
      pass "${name} resolves to ${addr} (IPv6), which is an address on this machine"
      matched=1
    elif [[ -n "$mine6" ]]; then
      mismatched="${mismatched}${mismatched:+, }${addr}"
    else
      # An AAAA record on a host with no IPv6 stack. Worth saying, because the
      # CA may prefer IPv6 and fail against an address this machine never had.
      warn "${name} has an AAAA record (${addr}) but this machine has no global IPv6 address."
      note "Let's Encrypt prefers IPv6 when a AAAA exists. If that record is stale,"
      note "remove it, or the challenge will be sent somewhere this host is not."
      HOSTNAME_DNS_STATE="aaaa-orphan"
    fi
  done <<<"$a6"

  if [[ $matched -eq 1 ]]; then
    [[ -n "$mismatched" ]] && note "It also resolves to ${mismatched}, which is not this machine."
    [[ -n "$HOSTNAME_DNS_STATE" ]] || HOSTNAME_DNS_STATE="match"
    return 0
  fi

  warn "${name} currently resolves to ${mismatched}."
  note "This machine appears to be $(printf '%s' "${HOST_IP:-unknown}")."
  note "If this host is behind NAT that forwards 80 and 443, that is expected"
  note "and the certificate can still be issued. Otherwise the record has to"
  note "point here before Let's Encrypt will issue one — change it at your DNS"
  note "provider, then re-run. This installer does not change DNS records."
  HOSTNAME_DNS_STATE="mismatch"
  return 0
}

# report_reachability separates what this host can measure from what it cannot.
#
# The installer knows whether it can bind a port. It cannot know whether a
# packet from the internet arrives at it — a cloud firewall sits somewhere this
# script cannot see, and on the VPS this was first tested against that is
# exactly what stopped issuance. Presenting both as one list of checks would
# imply a confidence that does not exist, so they are printed as two.
report_reachability() {
  printf '\n  %sLocal%s — measured on this machine\n' "$BOLD" "$OFF"
  # "Port 80 is free" and "the internet can reach port 80" are different facts,
  # and the first wording was routinely read as the second — printed, as it is,
  # directly above a line admitting the second is unknown. What this host can
  # actually establish is whether Caddy will be able to bind, so that is what
  # it now says.
  local p
  for p in 80 443; do
    local owner
    [[ "$p" == "80" ]] && owner="$WEB_80_OWNER" || owner="$WEB_443_OWNER"
    if [[ -z "$owner" ]]; then
      pass "Port ${p} available for Caddy"
    elif printf '%s' "$owner" | grep -qi 'caddy'; then
      # Re-running --https over a working deployment: Caddy holding its own
      # ports is the expected state, not a conflict.
      pass "Port ${p} already held by Caddy (expected)"
    else
      warn "Port ${p} is held by ${owner}, which will stop Caddy binding it"
    fi
  done

  printf '\n  %sExternal%s — cannot be confirmed from here\n' "$BOLD" "$OFF"
  note "UNKNOWN  whether inbound TCP 80 and 443 reach this machine"
  note ""
  note "Let's Encrypt validates by connecting to this address from the"
  note "internet. If your provider has a firewall in front of the host —"
  note "Linode Cloud Firewall, an AWS security group, an Azure NSG, a GCP"
  note "firewall rule — both ports must allow inbound traffic there as well."
  note "This installer does not change firewall rules, on this host or at"
  note "your provider."
  note ""
  note "DNS itself needs UDP 53 and TCP 53. Opening those does not make this"
  note "an open resolver: which clients may query is decided by the client"
  note "ACL under Networks, not by the firewall."
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
    unwind_https_env
    return 0
  fi

  if ! command -v caddy >/dev/null 2>&1; then
    printf '  Installing Caddy...\n'
    if ! install_caddy; then
      HTTPS_STATE="failed"
      HTTPS_FAIL_REASON="Caddy could not be installed."
      warn "Caddy could not be installed; the dashboard stays on loopback."
      unwind_https_env
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
    unwind_https_env
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

    # The live file's own mode and ownership, captured BEFORE the backup is
    # hardened.
    #
    # The backup is deliberately 0600 — it is a copy of a file that decides
    # what this machine publishes, and it sits in a directory the operator may
    # not have thought about. But rollback used `cp -p`, which copies mode as
    # well as content, so restoring handed the live Caddyfile the backup's
    # 0600. On a real VPS that produced "open /etc/caddy/Caddyfile: permission
    # denied" *after* a rollback that reported success: the configuration was
    # correct and unreadable by the service meant to read it. Content and
    # permissions come from different places now, and this is the second one.
    CADDYFILE_ORIG_MODE="$(stat -c '%a' "$caddyfile" 2>/dev/null || printf '644')"
    CADDYFILE_ORIG_OWNER="$(stat -c '%U:%G' "$caddyfile" 2>/dev/null || printf 'root:root')"

    if ! cp -p "$caddyfile" "$CADDYFILE_BACKUP"; then
      HTTPS_STATE="failed"
      HTTPS_FAIL_REASON="Could not back up ${caddyfile}."
      warn "$HTTPS_FAIL_REASON Refusing to overwrite it."
      unwind_https_env
      return 0
    fi
    if ! chmod 0600 "$CADDYFILE_BACKUP"; then
      # Not fatal — the backup exists and rollback will still work — but the
      # operator should know a copy of their configuration is more readable
      # than intended.
      warn "Could not restrict permissions on ${CADDYFILE_BACKUP}."
    fi
    pass "Existing Caddyfile saved to ${CADDYFILE_BACKUP} (mode ${CADDYFILE_ORIG_MODE}, owner ${CADDYFILE_ORIG_OWNER} recorded for rollback)"
  fi

  report_reachability

  printf '\n  %sWhat happens next%s\n' "$BOLD" "$OFF"
  if [[ "$HTTPS_TARGET_KIND" == "hostname" ]]; then
    note "Caddy will ask Let's Encrypt for a certificate for ${HTTPS_TARGET}."
    note "Let's Encrypt will connect back to that name on port 443, then 80, to"
    note "check you control it. Nothing is published until that succeeds."
  else
    note "Caddy will ask Let's Encrypt for a certificate for the IP address"
    note "${HTTPS_TARGET}, using the 'shortlived' profile — the only one Let's"
    note "Encrypt issues IP certificates under. It is valid for about six days"
    note "and Caddy renews it automatically, like any other certificate."
    note "Let's Encrypt will connect back to ${HTTPS_TARGET} on port 443, then"
    note "80, to check you control it. Nothing is published until that succeeds."
  fi
  note ""
  note "If it does not succeed, the dashboard stays private on 127.0.0.1:8080"
  note "and you reach it over an SSH tunnel. It is never published in plaintext."

  if ! write_caddyfile "$caddyfile"; then
    HTTPS_STATE="failed"
    HTTPS_FAIL_REASON="Could not write ${caddyfile}."
    warn "$HTTPS_FAIL_REASON"
    restore_caddyfile "$caddyfile"
    unwind_https_env
    return 0
  fi
  # It contains no secret, but it decides what is published; keep it owned by
  # root like the rest of /etc/caddy, and readable — Caddy runs as an
  # unprivileged service account and has to read it.
  #
  # These used to end in `|| true`. A chmod that silently fails here is how a
  # configuration ends up correct and unreadable, and the failure only surfaces
  # minutes later as a service that will not start.
  if ! chown root:root "$caddyfile"; then
    warn "Could not set ownership on ${caddyfile}."
  fi
  if ! chmod 0644 "$caddyfile"; then
    HTTPS_STATE="failed"
    HTTPS_FAIL_REASON="Could not set permissions on ${caddyfile}."
    warn "$HTTPS_FAIL_REASON Caddy would not be able to read it."
    restore_caddyfile "$caddyfile"
    unwind_https_env
    return 0
  fi

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
    unwind_https_env
    return 0
  fi
  pass "Caddyfile syntax validated"

  # Syntax valid and "the service can actually read it" are different claims,
  # and the first was being reported as though it covered the second.
  #
  # `caddy validate` above ran as root. The Caddy systemd unit does not: it
  # runs as its own service account, and root being able to parse a file is no
  # evidence at all that an unprivileged user can open it. On a real VPS this
  # produced "PASS Caddyfile validated" followed immediately by
  # "Error: reading config from file: open /etc/caddy/Caddyfile: permission
  # denied". Two checks, reported separately, because they fail separately.
  if ! caddy_service_can_read "$caddyfile"; then
    HTTPS_STATE="failed"
    HTTPS_FAIL_REASON="The Caddy service account (${CADDY_SERVICE_USER:-unknown}) cannot read ${caddyfile}."
    warn "$HTTPS_FAIL_REASON Caddy was not reloaded."
    note "Fix the permissions on ${caddyfile} and every directory above it, then re-run with --https."
    restore_caddyfile "$caddyfile"
    unwind_https_env
    return 0
  fi

  # Stamp the log window before the reload, so verify_https reads only what
  # this attempt produces. A second earlier than the reload rather than the
  # exact instant: journald and this clock need not agree to the millisecond,
  # and losing the first line of the attempt would be worse than including one
  # line before it.
  CADDY_LOG_SINCE="$(date -d '-1 second' '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date '+%Y-%m-%d %H:%M:%S')"

  # `|| true` used to swallow this. Enabling the unit is the step that makes
  # Caddy survive a reboot, and a machine whose management interface quietly
  # stops being reachable after a restart is a bad way to find that out.
  if ! systemctl enable --now caddy >/dev/null 2>&1; then
    warn "Could not enable the Caddy service to start at boot."
    note "Check it by hand: systemctl status caddy"
  fi

  if ! systemctl reload caddy >/dev/null 2>&1 && ! systemctl restart caddy >/dev/null 2>&1; then
    HTTPS_STATE="failed"
    HTTPS_FAIL_REASON="Caddy would not reload with the new configuration."
    warn "$HTTPS_FAIL_REASON"
    report_caddy_service_error
    restore_caddyfile "$caddyfile"
    restart_caddy_after_rollback
    unwind_https_env
    return 0
  fi

  # A reload that returned zero is not the same as a service that is running.
  #
  # systemd reports success for the reload request; Caddy can still exit
  # milliseconds later while parsing its new configuration or opening a log
  # writer it has no permission for. That is exactly what happened on the real
  # VPS, and the installer then spent three minutes waiting for a certificate
  # from a process that was not there. There is no certificate coming from a
  # dead Caddy, so this is checked before any waiting starts.
  if ! caddy_is_active; then
    HTTPS_STATE="failed"
    HTTPS_FAIL_REASON="Caddy accepted the configuration but is not running."
    warn "$HTTPS_FAIL_REASON"
    report_caddy_service_error
    restore_caddyfile "$caddyfile"
    restart_caddy_after_rollback
    unwind_https_env
    return 0
  fi
  pass "Caddy service is active"

  # Active and listening are still not the same thing, and the operator is
  # about to wait minutes on the difference. Five separate states get five
  # separate lines, because a PASS for one must not be read as the next:
  #
  #   1. the port was available for Caddy      report_reachability, above
  #   2. the Caddy service is active           the check above
  #   3. Caddy is listening on it              here
  #   4. ACME validation is happening          the wait below
  #   5. a publicly trusted certificate exists verify_https
  if [[ -n "$(port_owner tcp 443)" ]]; then
    pass "Caddy is listening on TCP 443"
  else
    # Not fatal on its own — `ss` may be absent, and a race between systemd
    # reporting active and the socket appearing is possible — so this informs
    # rather than aborts. A genuinely dead Caddy was already caught above.
    note "Nothing is listening on TCP 443 yet; the certificate wait may not succeed."
  fi

  if verify_https; then
    # The certificate is real and trusted, so the HSTS policy can go out now.
    # Written on a second pass rather than up front: a one-year policy is not
    # something to publish on the strength of an attempt that might fail.
    if write_caddyfile "$caddyfile" 1 && caddy validate --config "$caddyfile" >/dev/null 2>&1; then
      if { systemctl reload caddy >/dev/null 2>&1 || systemctl restart caddy >/dev/null 2>&1; } \
         && caddy_is_active; then
        pass "HSTS enabled now that the certificate is proven"
      else
        # The reload is the one place a working deployment can still be taken
        # down by this script, so "did it come back" is asked here too rather
        # than assumed from a zero exit status.
        warn "Caddy did not come back after the HSTS reload."
        restore_caddyfile "$caddyfile"
        restart_caddy_after_rollback
        HTTPS_STATE="failed"
        HTTPS_FAIL_REASON="A certificate was issued, but Caddy stopped when HSTS was applied."
        unwind_https_env
        return 0
      fi
    else
      warn "Could not enable HSTS; the dashboard is serving without it."
      # Put the file back to the configuration Caddy is currently running, so a
      # reboot does not start it on a half-written one. Caddy was never
      # reloaded onto the HSTS version, so no reload is needed here — but a
      # failure to rewrite it leaves exactly that mismatch, and is said.
      if ! write_caddyfile "$caddyfile" 0; then
        warn "${caddyfile} may not match the configuration Caddy is running."
        note "Check it before rebooting: caddy validate --config ${caddyfile}"
      fi
    fi
    verify_https_posture
    HTTPS_STATE="active"
    return 0
  fi

  # Everything below is a failure to obtain a publicly trusted certificate.
  #
  # What separates the two outcomes is whether the cause is known, not whether
  # the target is a hostname. Caddy told us or it did not:
  #
  #   known    a refused challenge, a rate limit, an NXDOMAIN. None of these
  #            resolve by waiting, so the whole attempt is rolled back and the
  #            operator is told the one thing to change.
  #   unknown  issuance may genuinely still be in flight — DNS propagation is
  #            not instant and CertMagic retries for up to 30 days. The site
  #            stays configured so that retrying continues.
  #
  # Either way .env goes back to the tunnel configuration. That is not
  # optional: reconcile_env has already set DNSDADDY_SECURE_COOKIES=always, and
  # leaving it set means the browser will not return the session cookie over
  # http://127.0.0.1:8080 — the operator is handed a tunnel they cannot log in
  # through, with no error naming the cause. Failing closed has to leave a way
  # back in.
  if [[ $HTTPS_FAIL_DIAGNOSED -eq 0 ]] && [[ "$HTTPS_TARGET_KIND" == "hostname" ]]; then
    HTTPS_STATE="pending"
    warn "Caddy is configured for ${HTTPS_TARGET}, but no certificate has arrived yet."
    note "Caddy keeps trying in the background, so this can still complete on its"
    note "own — DNS propagation is not instant. Nothing here says it will."
    note "Watch it:      journalctl -u caddy -f"
    note "Test it:       curl -v https://${HTTPS_TARGET}/api/v1/health"
    note "When it answers, re-run with --https to switch the dashboard over."
    note "Until then the dashboard is reachable through the SSH tunnel below."
    unwind_https_env
    return 0
  fi

  # A known cause, or an IP that did not come up. Leaving the site configured
  # for an address Caddy cannot produce a trusted certificate for would put a
  # browser warning on the management interface, which is the outcome this
  # whole path exists to avoid.
  HTTPS_STATE="failed"
  [[ -n "$HTTPS_FAIL_REASON" ]] || HTTPS_FAIL_REASON="No publicly trusted certificate was issued for ${HTTPS_TARGET}."
  report_https_failure
  restore_caddyfile "$caddyfile"
  restart_caddy_after_rollback
  unwind_https_env
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

# caddy_is_active reports whether the Caddy service is running right now.
#
# Overridable for the test suite, which has no systemd. Not a privilege
# boundary: anyone who can set it already runs this script as root.
caddy_is_active() {
  if [[ -n "${DNSDADDY_CADDY_ACTIVE_CMD:-}" ]]; then
    eval "${DNSDADDY_CADDY_ACTIVE_CMD}" >/dev/null 2>&1
    return $?
  fi
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl is-active --quiet caddy 2>/dev/null
}

# report_caddy_service_error shows what the service actually said.
#
# Reached only when Caddy failed to reload or exited after being told to start,
# which is precisely when the operator needs Caddy's own words rather than this
# script's summary of them. Restricted to this attempt's window for the same
# reason the ACME diagnosis is: a previous run's error is not this one's.
report_caddy_service_error() {
  local log
  log="$(caddy_recent_log)" || return 0
  [[ -n "$log" ]] || return 0
  note "Caddy said:"
  printf '%s\n' "$log" | grep -iE 'error|fatal|denied|cannot|failed' | tail -5 | while IFS= read -r line; do
    note "  ${line}"
  done
}

# restart_caddy_after_rollback puts Caddy back on the restored configuration
# and says plainly whether that worked.
#
# The old code ended in `|| true`, so a rollback that left Caddy dead printed
# "Your previous Caddyfile has been restored" and nothing else — which reads as
# though the machine is back to how it started. It may not be: whatever Caddy
# was serving before this run is down until somebody notices.
restart_caddy_after_rollback() {
  if systemctl reload caddy >/dev/null 2>&1 || systemctl restart caddy >/dev/null 2>&1; then
    if caddy_is_active; then
      pass "Caddy restarted on the restored configuration"
      return 0
    fi
  fi
  warn "ROLLBACK INCOMPLETE: the previous Caddyfile is back, but Caddy is not running."
  note "Anything else this machine was serving through Caddy is down until you fix it."
  note "  systemctl status caddy"
  note "  journalctl -u caddy -n 50"
  report_caddy_service_error
  return 1
}

# caddy_service_user names the account the Caddy systemd unit actually runs as.
#
# Not guessed. `systemctl show` reports the unit's resolved User=, which is
# what matters; the Debian and upstream packages both use "caddy", but an
# operator may have changed it and a guess that is wrong would either pass a
# check that should fail or fail one that should pass.
#
# Prints nothing when it cannot be determined, which the caller treats as
# "cannot prove either way" rather than as a failure.
caddy_service_user() {
  if [[ -n "${DNSDADDY_CADDY_USER:-}" ]]; then
    printf '%s' "$DNSDADDY_CADDY_USER"
    return 0
  fi
  command -v systemctl >/dev/null 2>&1 || return 0
  local u
  u="$(systemctl show -p User --value caddy 2>/dev/null)"
  # An empty User= means the unit runs as root, which can read anything.
  [[ -n "$u" ]] || return 0
  printf '%s' "$u"
}

# caddy_service_can_read proves the Caddy service account can open the live
# configuration, including traversing every directory above it.
#
# `sudo -u <user> test -r` is the check, because it is the same syscall path
# Caddy itself will take: a mode-0644 file inside a mode-0700 directory is
# readable by root and unreadable by everyone else, and only an attempt from
# the right account discovers that.
#
# Returns 0 when the account can read it, or when there is no unprivileged
# account to test (root unit, no systemd, no sudo). Fails closed only on a
# proven negative: refusing to proceed because a check could not run would
# block deployments that are actually fine.
caddy_service_can_read() { # path
  local path="$1" user
  user="$(caddy_service_user)"
  CADDY_SERVICE_USER="$user"

  if [[ -z "$user" || "$user" == "root" ]]; then
    pass "Caddy runs as root; configuration readability is not in question"
    return 0
  fi
  if ! id -u "$user" >/dev/null 2>&1; then
    note "Caddy's service user (${user}) does not exist yet; readability will be decided at start."
    return 0
  fi
  if ! command -v sudo >/dev/null 2>&1 && ! command -v runuser >/dev/null 2>&1; then
    note "No sudo or runuser here, so ${user}'s access to ${path} could not be tested."
    return 0
  fi

  local as=(sudo -n -u "$user")
  command -v sudo >/dev/null 2>&1 || as=(runuser -u "$user" --)

  if "${as[@]}" test -r "$path" 2>/dev/null; then
    pass "Caddy service account (${user}) can read ${path}"
    return 0
  fi

  # Distinguish "the file" from "the path to it": both produce the same error
  # from Caddy and need different fixes.
  local dir
  dir="$(dirname "$path")"
  if ! "${as[@]}" test -x "$dir" 2>/dev/null; then
    warn "${user} cannot traverse ${dir}."
  fi
  return 1
}

# restore_caddyfile puts back whatever was there before this run.
#
# When there was nothing, the generated file is removed rather than left
# behind: an abandoned site block for a management interface is precisely the
# thing nobody would think to look for later.
restore_caddyfile() { # path
  local caddyfile="$1"
  if [[ $CADDYFILE_EXISTED -eq 1 && -n "$CADDYFILE_BACKUP" && -f "$CADDYFILE_BACKUP" ]]; then
    # Content from the backup; permissions from what the live file had.
    #
    # `cp -p` did both from the backup, and the backup is deliberately 0600,
    # so a rollback silently made the restored configuration unreadable by the
    # Caddy service account. The operator was told "Your previous Caddyfile has
    # been restored" while Caddy refused to start on it. Note the missing -p.
    if ! cp "$CADDYFILE_BACKUP" "$caddyfile"; then
      warn "Could not restore ${caddyfile} from ${CADDYFILE_BACKUP} — do it by hand."
      return 0
    fi
    if ! chown "${CADDYFILE_ORIG_OWNER:-root:root}" "$caddyfile"; then
      warn "Restored ${caddyfile}, but could not put its ownership back to ${CADDYFILE_ORIG_OWNER:-root:root}."
    fi
    if ! chmod "${CADDYFILE_ORIG_MODE:-644}" "$caddyfile"; then
      warn "Restored ${caddyfile}, but could not put its mode back to ${CADDYFILE_ORIG_MODE:-644}."
      note "Check it is readable by Caddy before relying on this machine's other sites."
    fi
    note "Your previous Caddyfile has been restored (mode ${CADDYFILE_ORIG_MODE:-644}, owner ${CADDYFILE_ORIG_OWNER:-root:root})."
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
write_caddyfile() { # path [with_hsts]
  local out="$1" with_hsts="${2:-0}" site tls_block="" hsts_line=""

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

  # HSTS is written only on the second pass, after a publicly trusted
  # certificate has actually been served.
  #
  # The comment that used to sit on this header claimed exactly that and was
  # wrong: write_caddyfile runs before verify_https, so the header went out
  # with the first reload regardless of whether a certificate ever arrived.
  # A browser ignores HSTS over an untrusted connection, so nothing was
  # broken — but a one-year policy is not something to publish on the strength
  # of an attempt, and the ordering now matches what the comment says.
  if [[ "$with_hsts" == "1" ]]; then
    hsts_line=$'\t\tStrict-Transport-Security "max-age=31536000; includeSubDomains"\n'
  fi

  # Access logging goes to stderr, which systemd collects into the journal —
  # the same place caddy_recent_log already reads Caddy's diagnostics from.
  #
  # It used to be `output file /var/log/caddy/dnsdaddy.log`. On a real Debian 13
  # VPS the Caddy service account could not write that path, so Caddy exited at
  # startup with "opening log writer ... permission denied"; and because
  # `caddy validate` had passed as root, the installer went on to wait three
  # minutes for a certificate from a process that was no longer running. An
  # optional access log is not worth a failure mode that can stop the
  # management interface coming up at all, and journald already rotates, already
  # has the right permissions, and is already where anyone debugging this looks.
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
EOF
    printf '%s' "$hsts_line"
    cat <<'EOF'
		X-Content-Type-Options "nosniff"
		Referrer-Policy "no-referrer"
		Cross-Origin-Opener-Policy "same-origin"
		Cross-Origin-Resource-Policy "same-origin"
		Permissions-Policy "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"
		-Server
	}

	# Access logs go to the journal:  journalctl -u caddy -f
	log {
		output stderr
	}
}
EOF
  } > "$out"
}

# caddy_recent_log prints what Caddy has said recently.
#
# Overridable so the test suite can feed it a captured log rather than needing
# a journal. Not a privilege boundary: anyone who can set it already runs this
# script as root.
caddy_recent_log() {
  if [[ -n "${DNSDADDY_CADDY_LOG_CMD:-}" ]]; then
    eval "${DNSDADDY_CADDY_LOG_CMD}" 2>/dev/null
    return 0
  fi
  command -v journalctl >/dev/null 2>&1 || return 1
  # Only this attempt. A fixed ten-minute window swept in the previous run's
  # errors, so re-running the installer — which is a supported and expected
  # thing to do after opening a firewall — could diagnose a stale refusal and
  # roll back an attempt that was progressing normally. CADDY_LOG_SINCE is
  # stamped immediately before the reload that starts this attempt.
  journalctl -u caddy --no-pager -n 400 --since "${CADDY_LOG_SINCE:--10 min}" 2>/dev/null
}

# caddy_acme_diagnosis names why the certificate did not arrive.
#
# The old code guessed. It printed "usually means ports 80 and 443 are not
# reachable" whatever had happened, because the only evidence it gathered was
# whether curl worked. Caddy knows the answer exactly — it logs the ACME
# problem document the CA returned — and that log was never read.
#
# Sets HTTPS_FAIL_REASON to a sentence naming the cause and HTTPS_FAIL_HINT to
# the specific thing to do about it. Returns 0 only when the log actually said
# something; a silent log means the caller falls back to its own wording rather
# than inventing a cause from nothing.
caddy_acme_diagnosis() {
  # Wrapper so every recognised cause records that it was recognised, rather
  # than each arm having to remember to.
  if caddy_acme_diagnose_inner; then
    HTTPS_FAIL_DIAGNOSED=1
    return 0
  fi
  return 1
}

# log_last_line prints the 1-based number of the last line matching a pattern,
# or 0. The whole point is ordering: which of two things Caddy said happened
# last.
log_last_line() { # pattern text
  local n
  n="$(printf '%s\n' "$2" | grep -n -iE "$1" 2>/dev/null | tail -1 | cut -d: -f1)"
  printf '%s' "${n:-0}"
}

# acme_evidence is true when a pattern matched AND nothing since then said the
# certificate arrived.
#
# On the real VPS an attempt that ultimately succeeded logged a transient error
# on its way there, and the installer diagnosed the attempt from that line
# while Caddy was still working. Seconds later the same attempt logged
# "certificate obtained successfully". A log line is evidence of what was true
# when it was written, not of what is true now, and the only thing that makes
# an error line current is that nothing has superseded it.
acme_evidence() { # pattern
  local hit
  hit="$(log_last_line "$1" "$ACME_LOG_WINDOW")"
  [[ "$hit" != "0" ]] || return 1
  (( hit > ACME_SUCCESS_LINE ))
}

caddy_acme_diagnose_inner() {
  local log
  log="$(caddy_recent_log)" || return 1
  [[ -n "$log" ]] || return 1

  # Newest evidence first: a retry that has since succeeded must not be
  # diagnosed from the attempt before it.
  ACME_LOG_WINDOW="$(printf '%s\n' "$log" | tail -120)"

  # Where the last "it worked" sits, so every arm below can ask whether its
  # own evidence is older than that. Both phrases are Caddy's, logged by
  # CertMagic when an order finalises.
  ACME_SUCCESS_LINE="$(log_last_line \
    'certificate obtained successfully|successfully downloaded available certificate chains' \
    "$ACME_LOG_WINDOW")"

  # Ordered most specific first. Each arm names a cause the operator can act
  # on, rather than a category they still have to interpret.
  #
  # Every arm goes through acme_evidence, which additionally requires the match
  # to be more recent than the last success. An arm that matched a line Caddy
  # has since superseded is describing a moment that has passed.
  if acme_evidence 'cannot have public IP certificate'; then
    HTTPS_FAIL_REASON="This Caddy's certificate library refuses public IP certificates; it predates Let's Encrypt's IP support."
    HTTPS_FAIL_HINT="Install the current Caddy from https://caddyserver.com/docs/install and re-run with --https."
    return 0
  fi

  # Only the CA's own structured rate-limit error counts.
  #
  # This used to also match the bare words "rate limit", and Caddy says them
  # constantly during a perfectly healthy issuance: CertMagic paces its own
  # requests and logs "waiting on internal rate limiter" / "done waiting on
  # internal rate limiter" while doing so. On a real VPS the installer read one
  # of those lines, announced "Let's Encrypt rate-limited this request", and
  # began rolling HTTPS back — seconds before the same attempt logged
  # "certificate obtained successfully". The substring was never evidence of
  # anything; it was Caddy narrating its own politeness.
  #
  # urn:ietf:params:acme:error:rateLimited is unambiguous: it appears only in a
  # problem document the CA sent. The phrase form is kept alongside it because
  # Let's Encrypt's own detail text is distinctive enough to be safe, and it
  # tells the operator which limit they hit.
  if acme_evidence 'acme:error:rateLimited|too many certificates.*already issued|too many (new orders|failed authorizations)'; then
    HTTPS_FAIL_REASON="Let's Encrypt rate-limited this request."
    HTTPS_FAIL_HINT="Wait before retrying — repeating now makes it worse. https://letsencrypt.org/docs/rate-limits/"
    return 0
  fi
  if acme_evidence 'acme:error:invalidContact|forbidden domain'; then
    HTTPS_FAIL_REASON="Let's Encrypt rejected the ACME account contact address."
    HTTPS_FAIL_HINT="Remove or correct the email in the tls block of ${DNSDADDY_CADDYFILE:-/etc/caddy/Caddyfile}."
    return 0
  fi
  if acme_evidence 'profile.*(unknown|not supported|malformed)|(unknown|unsupported).*profile'; then
    HTTPS_FAIL_REASON="Let's Encrypt did not accept the certificate profile this deployment asked for."
    HTTPS_FAIL_HINT="Your Caddy may be older than the profile it is being asked to use. https://caddyserver.com/docs/install"
    return 0
  fi

  # The connection family is the common one, and the detail distinguishes two
  # very different situations: nothing listening at all, versus a packet that
  # never arrived. Both are outside this host, which is exactly the point.
  if acme_evidence 'acme:error:connection'; then
    local detail
    detail="$(printf '%s' "$ACME_LOG_WINDOW" | grep -oiE '"detail":"[^"]*"' | tail -1 | cut -d'"' -f4)"
    if printf '%s' "$detail" | grep -qi 'timeout\|timed out'; then
      HTTPS_FAIL_REASON="Let's Encrypt could not reach ${HTTPS_TARGET} — the challenge timed out."
      HTTPS_FAIL_HINT="A firewall is dropping inbound 80/443. Open both to the internet in your cloud provider's firewall, then re-run with --https."
    else
      HTTPS_FAIL_REASON="Let's Encrypt could not reach ${HTTPS_TARGET} — the connection was refused."
      HTTPS_FAIL_HINT="Inbound TCP 80 and 443 are not reaching this machine. Check your cloud firewall (Linode Cloud Firewall, AWS security group, Azure NSG, GCP firewall) allows both, then re-run with --https."
    fi
    [[ -n "$detail" ]] && HTTPS_FAIL_DETAIL="$detail"
    return 0
  fi
  if acme_evidence 'acme:error:dns|no such host'; then
    HTTPS_FAIL_REASON="Let's Encrypt could not resolve ${HTTPS_TARGET}."
    HTTPS_FAIL_HINT="The public DNS record does not exist yet, or has not propagated. Check with: dig +short ${HTTPS_TARGET}"
    return 0
  fi
  if acme_evidence 'acme:error:unauthorized'; then
    HTTPS_FAIL_REASON="The ACME challenge reached something at ${HTTPS_TARGET}, but not this Caddy."
    HTTPS_FAIL_HINT="Another host or proxy is answering for that address on port 80/443. Confirm the address really points at this machine."
    return 0
  fi
  if acme_evidence 'dial tcp 127\.0\.0\.1:8080|connect: connection refused.*8080'; then
    HTTPS_FAIL_REASON="Caddy is running, but it cannot reach DNS Daddy on 127.0.0.1:8080."
    HTTPS_FAIL_HINT="Check the container is up: docker compose ps"
    return 0
  fi

  return 1
}

# verify_https decides whether HTTPS actually works, and is the only thing
# allowed to conclude that it does.
#
# Three sources of evidence, in decreasing order of how much they prove:
#
#   strict   curl with this machine's trust store. Success means a browser
#            will be happy, which is the only definition of "working" worth
#            printing.
#   log      what Caddy says. A definite ACME failure is available here in
#            seconds and means waiting out the timeout is pointless — and it
#            names the cause, which curl never can.
#   lax      curl -k. Success while strict fails means something IS serving
#            TLS and its certificate is not publicly trusted.
#
# The lax probe used to carry the IP path on its own, on the theory that Caddy
# would fall back to its internal CA. It does not: write_caddyfile pins
# `issuer acme`, so when ACME fails there is no certificate at all and the
# handshake fails too. Both probes then fail identically and the old code fell
# through to a guess. The log is what actually distinguishes the cases.
verify_https() {
  local url deadline lax_seen=0
  case "$HTTPS_TARGET_KIND" in
    ipv6) url="https://[${HTTPS_TARGET}]/api/v1/health" ;;
    *)    url="https://${HTTPS_TARGET}/api/v1/health" ;;
  esac

  printf '  Waiting for a publicly trusted certificate for %s...\n' "$HTTPS_TARGET"
  printf '    Let'"'"'s Encrypt must reach this machine on TCP 80 and 443 to issue it.\n'

  # Long enough to outlast CertMagic's own retry cadence. It backs off 60s
  # after a failed attempt, so the old 45s default declared failure before the
  # second attempt had started — a transient first failure was reported as a
  # dead deployment. Three minutes covers a retry and the issuance after it.
  deadline=$((SECONDS + ${DNSDADDY_HTTPS_TIMEOUT:-180}))
  while (( SECONDS < deadline )); do
    if curl -fsS --max-time 5 "$url" >/dev/null 2>&1; then
      pass "${url%/api/v1/health} is serving the dashboard over HTTPS"
      pass "Certificate is trusted by this machine's CA store"
      return 0
    fi

    # Ask Caddy before waiting again. A refused challenge or a rate limit is
    # not going to resolve itself inside this loop, and the operator is better
    # served by the real reason now than by a spinner and a guess later.
    if caddy_acme_diagnosis; then
      return 1
    fi

    if curl -fsSk --max-time 5 "$url" >/dev/null 2>&1; then
      lax_seen=1
    fi
    sleep 3
  done

  if [[ $lax_seen -eq 1 ]]; then
    HTTPS_FAIL_REASON="TLS is answering on ${HTTPS_TARGET}, but the certificate is not publicly trusted."
    HTTPS_FAIL_HINT="Something other than this deployment's Caddy may be serving that address."
  elif [[ "$HTTPS_TARGET_KIND" == "hostname" ]]; then
    HTTPS_FAIL_REASON="No certificate has arrived for ${HTTPS_TARGET} yet, and Caddy has not reported why."
    HTTPS_FAIL_HINT="Issuance can outlast this installer. Watch it with: journalctl -u caddy -f"
  else
    HTTPS_FAIL_REASON="No certificate was issued for ${HTTPS_TARGET}, and Caddy has not reported why."
    HTTPS_FAIL_HINT="Check that inbound TCP 80 and 443 reach this machine from the internet, then re-run with --https."
  fi
  return 1
}

# verify_https_posture proves the parts of the deployment that can be proved.
#
# "HTTPS works" is a claim with several independent halves, and a deployment
# can get most of them right while failing the one that matters. Each line
# below is a separate measurement rather than an inference from the one above:
# a certificate that verifies says nothing about whether 8080 is private, and
# a redirect that works says nothing about the certificate.
verify_https_posture() {
  local url host_hdr
  case "$HTTPS_TARGET_KIND" in
    ipv6) url="https://[${HTTPS_TARGET}]" ;;
    *)    url="https://${HTTPS_TARGET}" ;;
  esac

  # The certificate covers the name or address actually being used. curl
  # already refuses a mismatch, so reaching here having used the strict probe
  # is the check; this states it rather than leaving it implied.
  pass "Certificate matches ${HTTPS_TARGET} and verifies against the public trust store"

  # The proxy really is reaching the backend, rather than serving an error page
  # of its own that happens to be over TLS.
  if curl -fsS --max-time 8 "${url}/api/v1/health" 2>/dev/null | grep -q '"status"'; then
    pass "Caddy is reaching DNS Daddy on 127.0.0.1:8080"
  else
    warn "TLS is up, but the dashboard API did not answer through Caddy."
    note "Check the container: docker compose ps"
  fi

  # HTTP must not serve the dashboard. Caddy's automatic redirect is expected;
  # a 200 here would mean the management interface is answering in plaintext.
  host_hdr="$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 "http://${HTTPS_TARGET}/" 2>/dev/null || echo "000")"
  case "$host_hdr" in
    30*) pass "Plain HTTP redirects to HTTPS (${host_hdr})" ;;
    000) note "Port 80 did not answer from here; the redirect could not be checked." ;;
    200) warn "http://${HTTPS_TARGET}/ answered 200 rather than redirecting."
         note "Something is serving the dashboard in plaintext. Investigate before use." ;;
    *)   note "Plain HTTP answered ${host_hdr}; not a redirect, but not the dashboard either." ;;
  esac

  # The whole point of the architecture: the backend is not published.
  if curl -fsS --max-time 5 "http://${HTTPS_TARGET}:8080/api/v1/health" >/dev/null 2>&1; then
    fail "The dashboard backend is reachable at http://${HTTPS_TARGET}:8080 — it must not be."
    note "Check DNSDADDY_DASHBOARD_BIND in ${ENV_FILE} and the ports: block in docker-compose.yml."
  else
    pass "Port 8080 is not reachable from outside; the backend stays on loopback"
  fi
}

# report_https_failure prints the diagnosis, then the evidence for it.
#
# Kept separate from the wording above so every failure path prints the same
# shape: what went wrong, what to do, and the CA's own words when there are
# any — rather than each call site inventing its own layout.
report_https_failure() {
  warn "${HTTPS_FAIL_REASON:-HTTPS could not be configured.}"
  [[ -n "$HTTPS_FAIL_HINT" ]]   && note "$HTTPS_FAIL_HINT"
  [[ -n "$HTTPS_FAIL_DETAIL" ]] && note "Caddy reported: ${HTTPS_FAIL_DETAIL}"
  note "Full detail: journalctl -u caddy --no-pager -n 50"
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
  snapshot_https_env
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
# snapshot_https_env records the three keys before this run changes them.
snapshot_https_env() {
  [[ $HTTPS_ENV_SNAPSHOT_TAKEN -eq 0 ]] || return 0
  HTTPS_ENV_BASE_URL_WAS="$(env_value DNSDADDY_BASE_URL)"
  HTTPS_ENV_SECURE_COOKIES_WAS="$(env_value DNSDADDY_SECURE_COOKIES)"
  HTTPS_ENV_TRUSTED_PROXY_WAS="$(env_value DNSDADDY_TRUSTED_PROXY_CIDRS)"
  HTTPS_ENV_SNAPSHOT_TAKEN=1
}

# https_env_was_working reports whether this .env already described a working
# HTTPS deployment when the run began.
#
# The base URL is the discriminator: reconcile_env writes it only for mode 3,
# so its presence at snapshot time means a previous successful HTTPS install
# left it there.
https_env_was_working() {
  [[ -n "$HTTPS_ENV_BASE_URL_WAS" ]]
}

# restore_https_env puts the snapshot back after a failed re-run.
#
# Used instead of revert_env_to_tunnel when the Caddyfile that was restored is
# a working HTTPS configuration: the proxy is still terminating TLS and still
# forwarding to this app, so telling the app it is on plain HTTP would strip
# the Secure flag from session cookies on a live public site and collapse every
# client to the proxy's own address.
restore_https_env() {
  env_set DNSDADDY_BASE_URL "$HTTPS_ENV_BASE_URL_WAS"
  [[ -n "$HTTPS_ENV_SECURE_COOKIES_WAS" ]] && env_set DNSDADDY_SECURE_COOKIES "$HTTPS_ENV_SECURE_COOKIES_WAS"
  [[ -n "$HTTPS_ENV_TRUSTED_PROXY_WAS" ]] && env_set DNSDADDY_TRUSTED_PROXY_CIDRS "$HTTPS_ENV_TRUSTED_PROXY_WAS"
  pass "Restored the previous HTTPS settings; the working deployment is unchanged"
  if "${COMPOSE[@]}" up -d >/dev/null 2>&1; then
    pass "Restarted DNS Daddy with the settings it had before this run"
    wait_for_rollback_health || return 1
  else
    warn "Could not restart DNS Daddy to apply the restored settings."
    note "Run: docker compose up -d"
    return 1
  fi
  return 0
}

# unwind_https_env picks the right rollback for what was actually restored.
unwind_https_env() {
  if https_env_was_working; then
    restore_https_env
    return $?
  fi
  revert_env_to_tunnel
}

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
    wait_for_rollback_health || return 1
  else
    warn "Could not restart DNS Daddy to apply the reverted settings."
    note "Run: docker compose up -d"
    return 1
  fi
  return 0
}

# wait_for_rollback_health blocks until the container the rollback just
# recreated is answering again.
#
# Without this the installer went straight from `compose up -d` into `dnsdaddy
# doctor`, and on a real VPS doctor reported "Nothing is listening on :5353"
# and "dashboard connection refused" about a container that was two seconds
# into its start-up and became healthy immediately afterwards. The diagnosis
# was not wrong about the instant it ran; it was asked at the wrong instant.
#
# Deliberately the same wait_for_health the install path uses, rather than a
# sleep: a cold start rebuilding the blocklist index takes as long as it takes,
# and any fixed number is either too short on a small VPS or wasted on a big
# one. A rollback that cannot get back to health is reported as incomplete,
# with the container's own log, rather than being hidden.
wait_for_rollback_health() {
  if wait_for_health; then
    return 0
  fi
  warn "ROLLBACK INCOMPLETE: DNS Daddy did not come back up after the settings were reverted."
  note "Its own log will say why:"
  "${COMPOSE[@]}" logs --tail=30 dnsdaddy 2>&1 | sed 's/^/    /' || true
  return 1
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
      printf '\n  This is an IP-address deployment. Let'"'"'s Encrypt issues IP certificates\n'
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
