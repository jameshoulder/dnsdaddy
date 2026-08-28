#!/usr/bin/env bash
#
# DNS Daddy — one-command production deployment.
#
#   cd /root/dnsdaddy && sudo ./deploy/production-deploy.sh
#   sudo ./deploy/production-deploy.sh --dry-run     # decide nothing, change nothing
#
# A dry run changes nothing, so it does not need root to write. It still needs
# to read the database, and a named volume lives under Docker's root-owned
# store — so keep the sudo unless the data volume is one your own user can read.
#
# Does the whole job: investigate, back up, derive the client ACL from the
# database, build, deploy onto the EXISTING volume, install Caddy, wire up boot
# persistence, and verify the live service.
#
# Safety rules it enforces on itself:
#   - never `docker compose down -v`, never `docker volume rm`
#   - the data volume is discovered from the running container, never guessed
#   - it aborts before touching the container if the backup is missing
#   - it never invents client CIDRs or a hostname; if it cannot establish them
#     it FAILS CLOSED rather than opening the resolver to the internet
#   - the old container keeps serving until the new image has built
#
# Fail-closed public-resolver policy:
#   If no client CIDRs can be derived from the database, this script will NOT
#   deploy an open recursive resolver. It aborts and tells you what to
#   configure. Running an open resolver is a real, common way to get your
#   server conscripted into DNS amplification DDoS attacks within days.
#
#   If you have deliberately decided to run a public resolver (rare — most
#   deployments should not do this), you must opt in explicitly and
#   knowingly:
#
#     sudo ./deploy/production-deploy.sh --allow-public-resolver
#
set -euo pipefail

DRY_RUN=0
ALLOW_PUBLIC_RESOLVER=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    --allow-public-resolver) ALLOW_PUBLIC_RESOLVER=1 ;;
    *) ;;
  esac
done

REPO="${REPO:-/root/dnsdaddy}"
CONTAINER="${CONTAINER:-dnsdaddy}"
DATA_DEST="/var/lib/dnsdaddy"
STAMP="$(date +%F-%H%M%S)"
BACKUP_DIR="${BACKUP_DIR:-/root}"

RED=$'\e[31m'; GRN=$'\e[32m'; YLW=$'\e[33m'; BLD=$'\e[1m'; RST=$'\e[0m'
step() { printf '\n%s══ %s%s\n' "$BLD" "$1" "$RST"; }
ok()   { printf '  %sok%s   %s\n' "$GRN" "$RST" "$1"; }
warn() { printf '  %swarn%s %s\n' "$YLW" "$RST" "$1"; }
die()  { printf '\n  %sABORT%s %s\n\n' "$RED" "$RST" "$1"; exit 1; }
act()  { if [[ $DRY_RUN -eq 1 ]]; then printf '  %s[dry-run]%s would: %s\n' "$YLW" "$RST" "$*"; else "$@"; fi; }

cd "$REPO" || die "repository not found at $REPO"
[[ $DRY_RUN -eq 1 ]] && printf '%s*** DRY RUN — nothing will be changed ***%s\n' "$YLW" "$RST"

# ---------------------------------------------------------------------------
step "1. Preflight"
# ---------------------------------------------------------------------------
# A real deploy needs root. A dry run does not: it changes nothing, every
# mutating step goes through act(), and being able to ask what a deploy would
# do without sudo is worth more than the uniformity. It is also what makes this
# script testable, which is why the check is written this way and not inlined.
if [[ $EUID -ne 0 ]]; then
  [[ $DRY_RUN -eq 1 ]] || die "run with sudo"
  warn "not running as root — fine for a dry run, if the data volume is readable by this user"
fi
command -v docker >/dev/null || die "docker is not installed"
docker compose version >/dev/null 2>&1 || die "docker compose v2 is not available"
systemctl is-active --quiet docker || die "the docker daemon is not running"
ok "docker present and running"

[[ -f docker-compose.yml ]] || die "no docker-compose.yml in $REPO"
git -C "$REPO" rev-parse --short HEAD >/dev/null 2>&1 && ok "repo at $(git -C "$REPO" rev-parse --short HEAD)"

RUNNING=0
if docker inspect "$CONTAINER" >/dev/null 2>&1; then
  STATE=$(docker inspect "$CONTAINER" --format '{{.State.Status}}')
  ok "existing container found (state=$STATE)"
  [[ "$STATE" == "running" ]] && RUNNING=1
else
  warn "no existing container named $CONTAINER"
fi

# ---------------------------------------------------------------------------
step "2. Discover the data volume (never guessed)"
# ---------------------------------------------------------------------------
VOL_TYPE=""; VOL_NAME=""; VOL_SRC=""
if [[ $RUNNING -eq 1 || -n "${STATE:-}" ]]; then
  read -r VOL_TYPE VOL_NAME VOL_SRC <<<"$(docker inspect "$CONTAINER" \
    --format "{{range .Mounts}}{{if eq .Destination \"$DATA_DEST\"}}{{.Type}} {{if .Name}}{{.Name}}{{else}}-{{end}} {{.Source}}{{end}}{{end}}")"
fi
[[ -n "$VOL_SRC" ]] || die "could not resolve the $DATA_DEST mount from the container — refusing to continue blind"
ok "type=$VOL_TYPE  name=$VOL_NAME"
ok "host path=$VOL_SRC"

DB="$VOL_SRC/dnsdaddy.db"
# Tell "not allowed" apart from "not there" before reporting either, and test
# the two independently: the directory may be listable while the database is
# root-owned 0600. Neither -f nor stat needs read access, so an unreadable
# database otherwise sails through this step as "database present", and step 4
# suppresses sqlite3's errors — leaving the script to blame the operator's
# network configuration for a file it was never able to open.
if [[ $EUID -ne 0 ]]; then
  [[ -r "$VOL_SRC" && -x "$VOL_SRC" ]] ||
    die "cannot list $VOL_SRC as an unprivileged user — it is Docker's own volume directory, so even a dry run over it needs sudo"
  [[ ! -e "$DB" || -r "$DB" ]] ||
    die "cannot read $DB as an unprivileged user — the database is there, but not readable by this user, so even a dry run over it needs sudo"
fi
[[ -f "$DB" ]] || die "no database at $DB — this is not the data volume"
DB_BYTES=$(stat -c %s "$DB")
(( DB_BYTES > 65536 )) || die "database is only $DB_BYTES bytes — refusing to proceed"
ok "database present ($(numfmt --to=iec "$DB_BYTES"))"

# ---------------------------------------------------------------------------
step "3. Backup"
# ---------------------------------------------------------------------------
PRIOR=$(ls -1 "$BACKUP_DIR"/dnsdaddy-backup-*.db 2>/dev/null | tail -1 || true)
[[ -n "$PRIOR" ]] && ok "prior backup: $PRIOR ($(du -h "$PRIOR" | cut -f1))" || warn "no prior backup found"

command -v sqlite3 >/dev/null || act apt-get install -y -qq sqlite3
NEW_BACKUP="$BACKUP_DIR/dnsdaddy-backup-$STAMP.db"
if [[ $DRY_RUN -eq 0 ]]; then
  # .backup is consistent against a live WAL database; cp is not.
  sqlite3 "$DB" ".backup '$NEW_BACKUP'" || die "backup failed — not touching the container"
  [[ -s "$NEW_BACKUP" ]] || die "backup file is empty"
  ok "fresh backup: $NEW_BACKUP ($(du -h "$NEW_BACKUP" | cut -f1))"
else
  act sqlite3 "$DB" ".backup '$NEW_BACKUP'"
fi

# ---------------------------------------------------------------------------
step "4. Derive the client ACL from configured networks"
# ---------------------------------------------------------------------------
# The administrator's intended client ranges live in network_cidrs. Query-log
# source addresses are NOT used: the resolver is currently open, so that log is
# full of scanners and copying it would whitelist the abuse.
#
# Only networks carrying the "allow this network to use DNS Daddy" permission
# count. A network exists to attribute a policy as well as to grant access, and
# writing every configured range into the ACL would overrule an operator who
# deliberately left that box unticked — the opposite of what this script is for.
CFG_CIDRS=""
CFG_LEGACY=0
if command -v sqlite3 >/dev/null; then
  PERMITTED_Q="SELECT DISTINCT c.cidr FROM network_cidrs c
       JOIN networks n ON n.id = c.network_id
      WHERE n.enabled = 1 AND n.allow_resolver = 1 AND c.cidr <> '';"
  ALL_Q="SELECT DISTINCT c.cidr FROM network_cidrs c
       JOIN networks n ON n.id = c.network_id
      WHERE n.enabled = 1 AND c.cidr <> '';"

  # The read is authoritative, and only one failure means "old database": the
  # allow_resolver column is not there. Everything else — SQLITE_BUSY, a
  # corrupt page, an unreadable -wal sidecar, any other schema error — used to
  # land in the same branch, because the query's output was discarded and an
  # empty result was taken as proof. That is not a cosmetic misdiagnosis: a
  # transient failure on this query followed by a working fallback promotes
  # every enabled range into the bootstrap list, where the dashboard can no
  # longer withdraw it. So anything unrecognised stops the deployment and
  # quotes what SQLite actually said.
  #
  # The message is fetched by asking again rather than by capturing stderr to a
  # temporary file. A temp file would be a real write, and a dry run here
  # promises not to make any; the cost is one extra query on a path that has
  # already failed.
  if CFG_CIDRS=$(sqlite3 -readonly "$DB" "$PERMITTED_Q" 2>/dev/null); then
    CFG_CIDRS=$(printf '%s' "$CFG_CIDRS" | tr '\n' ',' | sed 's/,$//')
  else
    SQL_ERR=$(sqlite3 -readonly "$DB" "$PERMITTED_Q" 2>&1 >/dev/null || true)
    if [[ "$SQL_ERR" == *"no such column"* && "$SQL_ERR" == *allow_resolver* ]]; then
      warn "this database predates per-network resolver access; using every enabled network"
      # These ranges have to go into the bootstrap list, unlike the managed
      # ones. The upgrade migrates every legacy network with allow_resolver = 0,
      # so the database will grant none of them back — dropping them here would
      # answer REFUSED to every client this deployment was already serving.
      CFG_LEGACY=1
      CFG_CIDRS=$(sqlite3 -readonly "$DB" "$ALL_Q" 2>/dev/null) ||
        die "could not read the networks from $DB: $(sqlite3 -readonly "$DB" "$ALL_Q" 2>&1 >/dev/null | tr '\n' ' ' || true)"
      CFG_CIDRS=$(printf '%s' "$CFG_CIDRS" | tr '\n' ',' | sed 's/,$//')
    else
      die "could not read the client networks from $DB: $(printf '%s' "${SQL_ERR:-sqlite3 exited non-zero without a message}" | tr '\n' ' ')"
    fi
  fi
fi

# The derived ranges decide whether it is safe to deploy. They are deliberately
# NOT copied into the bootstrap list.
#
# The bootstrap list and the dashboard's permissions are combined by union, and
# a union has no deny rules — so a range promoted here would go on admitting
# its clients after the operator unticked "Allow this network to use DNS
# Daddy", disabled the network or deleted it. That makes the dashboard's
# revocation control ineffective on exactly the deployments this script
# creates, and a revocation control that does not revoke is worse than none:
# the operator believes the client is cut off.
#
# The managed ranges stay where they can be withdrawn. BASE keeps the config
# valid and the container closed on the way up, and the first read of the
# database — immediately after start — adds the permitted networks back. The
# window between the two refuses clients rather than admitting them, which is
# the right way round for a gap this brief.
BASE="127.0.0.0/8,172.16.0.0/12"
if [[ -n "$CFG_CIDRS" ]] && [[ $CFG_LEGACY -eq 1 ]]; then
  # The legacy path is the exception to everything above. Nothing in this
  # database carries the permission, so nothing will grant these ranges after
  # the upgrade; they stay in the bootstrap list or the deployment goes dark.
  # The trade is deliberate and stated: keeping the clients served costs the
  # ability to revoke them from the dashboard until they are re-added as
  # permitted Networks.
  ok "configured client networks found: $CFG_CIDRS"
  warn "kept in .env because this database predates per-network access — after"
  warn "upgrading, re-add them under Networks with the box ticked and remove"
  warn "them from DNSDADDY_ALLOWED_CLIENT_CIDRS to make them revocable again"
  ACL="$BASE,$CFG_CIDRS"
  ACL_KNOWN=1
elif [[ -n "$CFG_CIDRS" ]]; then
  ok "configured client networks found: $CFG_CIDRS"
  ok "left in the database, where unticking the box can still withdraw them"
  ACL="$BASE"
  ACL_KNOWN=1
elif [[ $ALLOW_PUBLIC_RESOLVER -eq 1 ]]; then
  warn "no client CIDRs configured in the database"
  warn "--allow-public-resolver was passed: proceeding to deploy an OPEN"
  warn "recursive resolver, reachable by anyone on the internet, as explicitly"
  warn "requested. This is a genuine abuse risk (DNS amplification DDoS)."
  ACL=""
  ACL_KNOWN=0
else
  echo
  die "no client CIDRs configured — refusing to deploy an open resolver.

  This script FAILS CLOSED by default: it will not deploy a DNS Daddy
  instance that answers queries from the whole internet. Nothing has been
  changed; the existing container (if any) keeps running as-is.

  To fix this properly:
    1. Open the dashboard and add your sites/ranges as Networks, ticking
       "Allow this network to use DNS Daddy" on each one.
    2. Re-run this script — it will derive the ACL from them automatically.

  On a running deployment that tick-box is enough on its own: it takes effect
  on the next query. This script checks that you have set at least one, so it
  never deploys a resolver nobody has decided the audience for.

  Or set DNSDADDY_ALLOWED_CLIENT_CIDRS in .env yourself and run
  'docker compose up -d' directly.

  Only if you deliberately intend to run a public resolver (rare, and a
  common source of DDoS-amplification abuse complaints), re-run with:
    sudo ./deploy/production-deploy.sh --allow-public-resolver"
fi

# ---------------------------------------------------------------------------
step "5. Discover the dashboard hostname"
# ---------------------------------------------------------------------------
# base_url is NOT stored in the database — the settings table holds only the
# admin password hash. It comes from config or the environment, so those are
# the only places worth looking.
HOSTNAME_FOUND=""
# 1. The running container's environment (where the old deployment set it).
if [[ -n "${STATE:-}" ]]; then
  HOSTNAME_FOUND=$(docker inspect "$CONTAINER" \
    --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null \
    | sed -n 's/^DNSDADDY_BASE_URL=//p' | head -1 || true)
fi
# A source that exists but cannot be read is recorded, not treated as absent.
# Concluding "no hostname configured" from a file this run never opened puts
# Caddy inactive and the dashboard on loopback for a deployment that may have a
# hostname, and reports it as though it had been measured.
UNREADABLE_SOURCE=""
readable_or_note() { # path -> true when it can be read; records it when it cannot
  [[ -f "$1" ]] || return 1
  [[ -r "$1" ]] && return 0
  UNREADABLE_SOURCE="${UNREADABLE_SOURCE:-$1}"
  return 1
}
# 2. .env in the repo.
[[ -z "$HOSTNAME_FOUND" ]] && readable_or_note .env && \
  HOSTNAME_FOUND=$(sed -n 's/^DNSDADDY_BASE_URL=//p' .env | head -1 || true)
# 3. A mounted config file, if this deployment uses one.
if [[ -z "$HOSTNAME_FOUND" ]]; then
  for c in /etc/dnsdaddy/config.yaml "$VOL_SRC/config.yaml"; do
    readable_or_note "$c" && HOSTNAME_FOUND=$(sed -n 's/^[[:space:]]*base_url:[[:space:]]*//p' "$c" | tr -d '"'"'" | head -1) && \
      [[ -n "$HOSTNAME_FOUND" ]] && break
  done
fi
# 4. An existing Caddyfile from a previous attempt.
if [[ -z "$HOSTNAME_FOUND" ]] && readable_or_note /etc/caddy/Caddyfile; then
  HOSTNAME_FOUND=$(grep -oE '^[a-z0-9.-]+\.[a-z]{2,}' /etc/caddy/Caddyfile | grep -v example | head -1 || true)
fi
HOSTNAME_FOUND="${HOSTNAME_FOUND#https://}"; HOSTNAME_FOUND="${HOSTNAME_FOUND#http://}"; HOSTNAME_FOUND="${HOSTNAME_FOUND%%/*}"

if [[ -z "$HOSTNAME_FOUND" && -n "$UNREADABLE_SOURCE" ]]; then
  warn "$UNREADABLE_SOURCE exists but could not be read by this user, so no hostname could be discovered"
  note "  A real deploy runs as root and would read it. Re-run this preview with sudo"
  note "  to see the plan it would actually follow."
elif [[ -n "$HOSTNAME_FOUND" ]]; then
  ok "hostname: $HOSTNAME_FOUND"
else
  warn "no hostname configured — Caddy will be installed but left inactive"
  warn "the dashboard will be loopback-only; reach it with an SSH tunnel:"
  warn "  ssh -L 8080:127.0.0.1:8080 root@\$(hostname -I | awk '{print \$1}')"
fi

# ---------------------------------------------------------------------------
step "6. Write .env (secrets preserved, never overwritten with examples)"
# ---------------------------------------------------------------------------
# A dry run must not create or restamp .env. The banner above promises nothing
# changes, and on a host that has none yet, touch leaves an empty one behind.
act touch .env
set_env() {
  local k="$1" v="$2"
  if grep -qE "^${k}=" .env 2>/dev/null; then
    act sed -i "s|^${k}=.*|${k}=${v}|" .env
  else
    [[ $DRY_RUN -eq 0 ]] && printf '%s=%s\n' "$k" "$v" >> .env || act append "$k=$v"
  fi
}
if [[ $ACL_KNOWN -eq 1 ]]; then
  set_env DNSDADDY_ALLOWED_CLIENT_CIDRS "$ACL"; ok "bootstrap ACL set to: $ACL"
  if [[ -n "$CFG_CIDRS" ]]; then
    ok "permitted networks stay in the database: $CFG_CIDRS"
    # An earlier version of this script copied them here. Say so, because a
    # previous run's promoted ranges are exactly what this narrowing removes,
    # and an operator watching the diff deserves the reason rather than a
    # silent change to who their resolver admits.
    ok "(a previous run may have copied these into .env; they are withdrawn from"
    ok " the bootstrap list so that unticking the box in the dashboard works)"
  fi
else
  # Reaching this branch requires --allow-public-resolver: step 4 already
  # aborted the deployment otherwise. This is the explicit, deliberate opt-in
  # path — never a silent default.
  set_env DNSDADDY_ALLOWED_CLIENT_CIDRS ""
  set_env DNSDADDY_ALLOW_PUBLIC_RESOLVER "true"
  warn "PUBLIC RESOLVER MODE — deploying open to the internet, as explicitly requested"
  warn "SEE THE REPORT AT THE END"
fi
BRIDGE=$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Subnet}}' 2>/dev/null || echo "172.17.0.0/16")
set_env DNSDADDY_TRUSTED_PROXY_CIDRS "$BRIDGE"
if [[ -n "$HOSTNAME_FOUND" ]]; then
  set_env DNSDADDY_BASE_URL "https://$HOSTNAME_FOUND"
  set_env DNSDADDY_SECURE_COOKIES "always"
else
  set_env DNSDADDY_SECURE_COOKIES "auto"
fi
[[ $DRY_RUN -eq 1 ]] || chmod 600 .env 2>/dev/null || true
grep -q '^\.env$' .gitignore 2>/dev/null || warn ".env is not gitignored"

# ---------------------------------------------------------------------------
step "7. Validate and build (old container keeps serving)"
# ---------------------------------------------------------------------------
docker compose config >/dev/null || die "docker compose config is invalid"
ok "compose config valid"
if command -v go >/dev/null 2>&1; then
  # Read-only against the deployment, but not against the disk: go writes a
  # build cache under $HOME, and this run has promised to change nothing. It is
  # also minutes of work nobody asked a dry run to do.
  if [[ $DRY_RUN -eq 1 ]]; then
    act go vet ./...
    act go test ./...
  else
    go vet ./... >/dev/null 2>&1 && ok "go vet clean" || warn "go vet reported issues"
    go test ./... >/dev/null 2>&1 && ok "go test passed" || warn "go test failed — review before relying on this build"
  fi
else
  warn "Go not installed on the host; relying on the Docker build"
fi
act docker compose build
ok "image built"

# ---------------------------------------------------------------------------
step "8. Deploy onto the existing volume"
# ---------------------------------------------------------------------------
# `up -d` recreates the container and REUSES the named volume. No -v anywhere.
act docker compose up -d --remove-orphans
if [[ $DRY_RUN -eq 0 ]]; then
  for i in $(seq 1 60); do
    s=$(docker inspect "$CONTAINER" --format '{{.State.Status}}' 2>/dev/null || echo none)
    h=$(docker inspect "$CONTAINER" --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' 2>/dev/null || echo none)
    [[ "$s" == "running" && ( "$h" == "healthy" || "$h" == "none" ) ]] && break
    sleep 2
  done
  [[ "$(docker inspect "$CONTAINER" --format '{{.State.Status}}')" == "running" ]] \
    || { docker logs --tail=50 "$CONTAINER"; die "container is not running after deploy"; }
  ok "container running (health=$h)"

  NEW_SRC=$(docker inspect "$CONTAINER" --format "{{range .Mounts}}{{if eq .Destination \"$DATA_DEST\"}}{{.Source}}{{end}}{{end}}")
  [[ "$NEW_SRC" == "$VOL_SRC" ]] && ok "same volume reattached: $NEW_SRC" \
    || die "VOLUME CHANGED ($VOL_SRC -> $NEW_SRC) — stop and investigate"
fi

# ---------------------------------------------------------------------------
step "9. Verify the live service"
# ---------------------------------------------------------------------------
if [[ $DRY_RUN -eq 0 ]]; then
  BODY=$(curl -fsS --max-time 10 http://127.0.0.1:8080/api/v1/health || true)
  [[ -n "$BODY" ]] || die "health endpoint did not respond"
  echo "  $BODY"
  SIZE=$(sed -n 's/.*"blocklistSize":\([0-9]*\).*/\1/p' <<<"$BODY")
  (( SIZE > 2000000 )) && ok "blocklist intact ($SIZE)" || warn "blocklist is $SIZE — expected ~2.87M; investigate before trusting this"

  RC=$(dig @127.0.0.1 example.com +timeout=4 +tries=1 2>/dev/null | sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1)
  [[ "$RC" == "NOERROR" ]] && ok "dig @127.0.0.1 example.com -> NOERROR" || die "local DNS returned $RC"
fi

# ---------------------------------------------------------------------------
step "10. Caddy"
# ---------------------------------------------------------------------------
if ! command -v caddy >/dev/null 2>&1; then
  act bash -c 'apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https curl gnupg &&
    curl -1sLf "https://dl.cloudsmith.io/public/caddy/stable/gpg.key" | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg &&
    curl -1sLf "https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt" > /etc/apt/sources.list.d/caddy-stable.list &&
    apt-get update -qq && apt-get install -y -qq caddy'
  ok "caddy installed"
else
  ok "caddy already installed"
fi
if [[ -n "$HOSTNAME_FOUND" ]]; then
  if [[ $DRY_RUN -eq 0 ]]; then
    [[ -f /etc/caddy/Caddyfile ]] && cp /etc/caddy/Caddyfile "/etc/caddy/Caddyfile.bak-$STAMP"
    sed "s/dns\.example\.co\.uk/$HOSTNAME_FOUND/" deploy/Caddyfile.example > /etc/caddy/Caddyfile
    caddy validate --config /etc/caddy/Caddyfile >/dev/null 2>&1 || die "generated Caddyfile is invalid"
  fi
  act systemctl enable --now caddy
  act systemctl reload caddy
  ok "caddy serving $HOSTNAME_FOUND"
else
  act systemctl enable caddy
  warn "caddy enabled at boot but NOT configured — no hostname available"
fi

# ---------------------------------------------------------------------------
step "11. Boot persistence"
# ---------------------------------------------------------------------------
act systemctl enable docker
if systemctl list-unit-files 2>/dev/null | grep -q '^dnsdaddy\.service'; then
  act systemctl disable --now dnsdaddy
  ok "native dnsdaddy.service disabled (Docker is authoritative)"
else
  ok "native dnsdaddy.service not installed — no conflict"
fi
if [[ $DRY_RUN -eq 0 ]]; then
  sed "s|^WorkingDirectory=.*|WorkingDirectory=$REPO|" deploy/dnsdaddy-compose.service \
    > /etc/systemd/system/dnsdaddy-compose.service
  systemctl daemon-reload
fi
act systemctl enable dnsdaddy-compose
ok "dnsdaddy-compose enabled (WorkingDirectory=$REPO)"

# ---------------------------------------------------------------------------
step "12. Lifecycle test"
# ---------------------------------------------------------------------------
if [[ $DRY_RUN -eq 0 ]]; then
  docker restart "$CONTAINER" >/dev/null && sleep 12
  [[ "$(docker inspect "$CONTAINER" --format '{{.State.Status}}')" == "running" ]] \
    && ok "container returns after restart" || die "container did not come back"
  RC=$(dig @127.0.0.1 example.com +timeout=4 +tries=1 2>/dev/null | sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1)
  [[ "$RC" == "NOERROR" ]] && ok "DNS still answering after restart" || warn "DNS returned $RC after restart"
fi

step "Summary"
printf '  volume        : %s (%s)\n' "$VOL_NAME" "$VOL_SRC"
printf '  backup        : %s\n' "$NEW_BACKUP"
printf '  ACL           : %s\n' "${ACL:-NONE — RESOLVER STILL OPEN}"
printf '  hostname      : %s\n' "${HOSTNAME_FOUND:-NOT CONFIGURED}"
printf '  docker boot   : %s\n' "$(systemctl is-enabled docker 2>/dev/null)"
printf '  compose boot  : %s\n' "$(systemctl is-enabled dnsdaddy-compose 2>/dev/null || echo n/a)"
printf '  caddy boot    : %s\n' "$(systemctl is-enabled caddy 2>/dev/null || echo n/a)"
echo
if [[ $ACL_KNOWN -eq 0 ]]; then
  printf '%s  THIS SERVER IS AN OPEN RECURSIVE RESOLVER (--allow-public-resolver).%s\n' "$RED" "$RST"
  printf '  Anyone on the internet can use it for DNS amplification attacks. This\n'
  printf '  was deployed only because you explicitly requested it.\n'
  printf '  To narrow it down instead: add your sites public IPs as Networks in\n'
  printf '  the dashboard, then re-run this script WITHOUT --allow-public-resolver\n'
  printf '  — it will derive the ACL from them automatically and close the resolver.\n\n'
fi
./deploy/healthcheck.sh || true
