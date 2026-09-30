#!/usr/bin/env bash
#
# DNS Daddy production health check.
#
# HTTP 200 from /api/v1/health is only process liveness. A working dashboard
# does not establish that DNS answers, the client's network is allowed, or a
# blocklist is loaded. Missing evidence is reported as an incomplete check.
#
# This checks four things independently:
#
#   1. the container is running and Docker considers it healthy
#   2. /api/v1/health reports status=ok with a non-empty blocklist
#   3. DNS actually answers a known-good query over UDP and TCP
#   4. the public HTTPS dashboard responds, if one is configured
#
# A non-empty blocklist does not prove that every policy enforces filtering.
# These checks establish local readiness; repeat from a client to check its
# network/firewall path and verify its policy with the dashboard's policy test.
#
# Exit codes:  0 ready   1 degraded or incomplete checks   2 failed
#
# Usage:
#   ./deploy/healthcheck.sh
#   DNSDADDY_PUBLIC_URL=https://dns.example.co.uk ./deploy/healthcheck.sh
#   ./deploy/healthcheck.sh --quiet     # for cron: output only on failure
set -uo pipefail

CONTAINER="${DNSDADDY_CONTAINER:-dnsdaddy}"
API="${DNSDADDY_API:-http://127.0.0.1:8080}"
DNS_ADDR="${DNSDADDY_DNS_ADDR:-127.0.0.1}"
DNS_PORT="${DNSDADDY_DNS_PORT:-53}"
PUBLIC_URL="${DNSDADDY_PUBLIC_URL:-}"
# A domain that must resolve. The timeout permits a cold Daddybound validation
# (the binary's default is 5s) instead of declaring a 3s wait to be a failure.
PROBE_GOOD="${DNSDADDY_PROBE_GOOD:-example.com}"
PROBE_TIMEOUT="${DNSDADDY_PROBE_TIMEOUT:-8}"

QUIET=0
[[ "${1:-}" == "--quiet" ]] && QUIET=1

OUT=""
STATUS=0   # 0 ok, 1 degraded, 2 down

say()  { OUT+="$1"$'\n'; }
fail() { say "FAIL  $1"; STATUS=2; }
warn() { say "WARN  $1"; [[ $STATUS -lt 1 ]] && STATUS=1; return 0; }
ok()   { say "ok    $1"; }

# --- 1. container ----------------------------------------------------------
if command -v docker >/dev/null 2>&1; then
  state=$(docker inspect "$CONTAINER" --format '{{.State.Status}}' 2>/dev/null) || state=""
  if [[ -z "$state" ]]; then
    fail "container '$CONTAINER' does not exist"
  elif [[ "$state" != "running" ]]; then
    fail "container '$CONTAINER' is '$state', not running"
    say "      docker logs --tail=50 $CONTAINER"
  else
    health=$(docker inspect "$CONTAINER" --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' 2>/dev/null)
    restarts=$(docker inspect "$CONTAINER" --format '{{.RestartCount}}' 2>/dev/null)
    case "$health" in
      healthy) ok "container running (health=healthy, restarts=$restarts)" ;;
      none)    ok "container running (no healthcheck defined, restarts=$restarts)" ;;
      *)       warn "container running but health=$health (restarts=$restarts)" ;;
    esac
    # A climbing restart count means it is crash-looping, which "running" hides.
    if [[ "${restarts:-0}" -gt 5 ]]; then
      warn "container has restarted $restarts times — check for a crash loop"
    fi
  fi
else
  say "note  docker not present; skipping container check (native install?)"
fi

# --- 2. application health -------------------------------------------------
#
# /api/v1/health answers in two tiers. Every caller gets {"status":"ok"} —
# liveness and nothing else, because in the HTTPS deployment that endpoint is
# published to the internet. The protection state comes back only for a caller
# the server considers entitled: an authenticated one, or one whose peer
# address is loopback.
#
# Run from the host against a published Docker port, this script is NOT a
# loopback peer — Docker translates the source address to the bridge gateway —
# so it sees liveness only. That is why the depth check below runs inside the
# container when it can, and says plainly what it could not verify when it
# cannot. Announcing "protected" without having looked is the failure this
# whole script exists to avoid.
body=$(curl -fsS --max-time 5 "$API/api/v1/health" 2>/dev/null) || body=""
if [[ -z "$body" ]]; then
  fail "no response from $API/api/v1/health"
else
  app_status=$(printf '%s' "$body" | sed -n 's/.*"status"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
  if [[ "$app_status" != "ok" ]]; then
    fail "api returned an unexpected status: $body"
  else
    ok "api responding (status=ok)"

    # Depth. Ask from inside the container, where the peer really is loopback.
    detail=""
    if command -v docker >/dev/null 2>&1; then
      detail=$(docker exec "$CONTAINER" wget -qO- http://127.0.0.1:8080/api/v1/health 2>/dev/null || true)
    fi
    if [[ -z "$detail" ]]; then
      detail=$(curl -fsS --max-time 5 "$API/api/v1/health" 2>/dev/null || true)
    fi

    protecting=$(printf '%s' "$detail" | sed -n 's/.*"protecting"[[:space:]]*:[[:space:]]*\(true\|false\).*/\1/p')
    blocklist=$(printf '%s' "$detail" | sed -n 's/.*"blocklistSize"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p')
    case "$protecting" in
      true)  if [[ -n "$blocklist" && "$blocklist" -gt 0 ]]; then
               ok "blocklist loaded ($blocklist domains); per-client enforcement depends on policy"
             else
               warn "health reported a loaded blocklist without a positive domain count"
             fi ;;
      false) warn "the blocklist is empty — feed-based filtering is not ready"
             say "      feeds may still be downloading; if this persists, refresh them" ;;
      *)     warn "could not read the blocklist state; readiness is not fully verified"
             say "      this check has to run where the"
             say "      health endpoint sees a loopback peer, or with an API token."
             say "      Try: docker exec $CONTAINER dnsdaddy doctor" ;;
    esac
  fi
fi

# --- 3. DNS actually answering --------------------------------------------
dns_probe() { # udp | tcp
  # One query, parsed from the full response. Never use `dig +short` for this:
  # on timeout it prints ";; communications error ..." to stdout, which a
  # naive non-empty check reads as a successful answer.
  local protocol="$1" transport=+notcp reply rcode addr
  [[ "$protocol" == "tcp" ]] && transport=+tcp
  reply=$(dig "$transport" +noall +comments +answer "+timeout=$PROBE_TIMEOUT" +tries=1 \
              "@$DNS_ADDR" -p "$DNS_PORT" "$PROBE_GOOD" A 2>/dev/null)
  rcode=$(printf '%s' "$reply" | sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1)
  # An actual A record, not dig's diagnostics.
  addr=$(printf '%s' "$reply" | awk '$4=="A" {print $5; exit}')

  case "$rcode" in
    "")
      fail "no $protocol DNS response from $DNS_ADDR:$DNS_PORT (timeout or nothing listening)"
      ;;
    REFUSED)
      # The single most likely cause of "DNS is down" after an upgrade.
      fail "$protocol DNS returned REFUSED — this client is not permitted to use the resolver"
      say "      add it under Networks and tick \"Allow this network to use DNS Daddy\","
      say "      with the Network enabled. Non-loopback bootstrap CIDRs apply only when"
      say "      ad-hoc access is enabled; a host-to-Docker probe may arrive from its gateway."
      ;;
    SERVFAIL)
      fail "$protocol DNS returned SERVFAIL for $PROBE_GOOD — resolution or validation is failing"
      say "      run dnsdaddy doctor for the active transport, endpoint and DNSSEC diagnosis"
      say "      native Live needs outbound UDP/TCP 53; encrypted DNS needs its configured"
      say "      TCP 443 (DoH2), UDP 443 (DoH3), UDP 853 (DoQ), or TCP 853 (DoT)"
      ;;
    NOERROR)
      if [[ "$addr" == "0.0.0.0" || "$addr" == 127.* ]]; then
        warn "$protocol DNS returned a sinkhole address for $PROBE_GOOD ($addr); check its policy"
      elif [[ -n "$addr" ]]; then
        ok "$protocol dns answering ($PROBE_GOOD -> $addr)"
      else
        warn "$protocol dns returned NOERROR but no A record for $PROBE_GOOD"
      fi
      ;;
    NXDOMAIN)
      # The probe is meant to resolve; NXDOMAIN means it is being blocked or
      # the upstream is broken. Either way it is not a healthy probe.
      warn "$protocol dns returned NXDOMAIN for $PROBE_GOOD — is the probe domain blocked?"
      ;;
    *)
      warn "$protocol dns returned $rcode for $PROBE_GOOD"
      ;;
  esac
}

if command -v dig >/dev/null 2>&1; then
  dns_probe udp
  dns_probe tcp
else
  warn "dig not installed; DNS readiness was not checked (apt install dnsutils)"
fi

# --- 4. public HTTPS dashboard --------------------------------------------
if [[ -n "$PUBLIC_URL" ]]; then
  code=$(curl -fsS -o /dev/null -w '%{http_code}' --max-time 10 "$PUBLIC_URL/api/v1/health" 2>/dev/null) || code="000"
  if [[ "$code" == "200" ]]; then
    ok "public dashboard reachable over HTTPS ($PUBLIC_URL)"
  else
    fail "public dashboard $PUBLIC_URL returned HTTP $code"
    say "      check the reverse proxy: systemctl status caddy"
  fi
else
  say "note  DNSDADDY_PUBLIC_URL unset; skipping HTTPS check"
fi

case $STATUS in
  0) say ""; say "RESULT: ready — UDP/TCP DNS answering and blocklist loaded" ;;
  1) say ""; say "RESULT: DEGRADED — one or more readiness checks failed or could not be verified" ;;
  2) say ""; say "RESULT: FAILED — service or DNS checks failed; review the evidence above" ;;
esac

# In --quiet mode (cron), stay silent unless something is wrong.
if [[ $QUIET -eq 0 || $STATUS -ne 0 ]]; then
  printf '%s' "$OUT"
fi
exit $STATUS
