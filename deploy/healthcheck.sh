#!/usr/bin/env bash
#
# DNS Daddy production health check.
#
# HTTP 200 from /api/v1/health is NOT proof that the network is protected. The
# resolver reports "degraded" when it is answering queries but has no blocklist
# loaded — every lookup succeeds, nothing is filtered, and a naive check that
# only looks at the status code sees a perfectly green service while the whole
# point of running it has quietly stopped.
#
# This checks four things independently:
#
#   1. the container is running and Docker considers it healthy
#   2. /api/v1/health reports status=ok with a non-empty blocklist
#   3. DNS actually answers, and a known-bad domain is actually blocked
#   4. the public HTTPS dashboard responds, if one is configured
#
# Exit codes:  0 healthy   1 degraded (serving, not protecting)   2 down
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
# A domain that must resolve, and one that must be blocked once feeds load.
PROBE_GOOD="${DNSDADDY_PROBE_GOOD:-example.com}"

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
body=$(curl -fsS --max-time 5 "$API/api/v1/health" 2>/dev/null) || body=""
if [[ -z "$body" ]]; then
  fail "no response from $API/api/v1/health"
else
  app_status=$(printf '%s' "$body" | sed -n 's/.*"status":"\([^"]*\)".*/\1/p')
  blocklist=$(printf '%s' "$body" | sed -n 's/.*"blocklistSize":\([0-9]*\).*/\1/p')
  case "$app_status" in
    ok)
      if [[ "${blocklist:-0}" -gt 0 ]]; then
        ok "api healthy (status=ok, blocklist=$blocklist domains)"
      else
        warn "api reports ok but the blocklist is empty — nothing is being filtered"
      fi
      ;;
    degraded)
      warn "api reports degraded (blocklist=$blocklist) — resolving but not protecting"
      say "      feeds may still be downloading; if this persists, refresh them"
      ;;
    *)
      fail "api returned an unexpected status: $body"
      ;;
  esac
fi

# --- 3. DNS actually answering --------------------------------------------
if command -v dig >/dev/null 2>&1; then
  # One query, parsed from the full response. Never use `dig +short` for this:
  # on timeout it prints ";; communications error ..." to stdout, which a
  # naive non-empty check reads as a successful answer.
  reply=$(dig +noall +comments +answer +timeout=3 +tries=1 \
              "@$DNS_ADDR" -p "$DNS_PORT" "$PROBE_GOOD" A 2>/dev/null)
  rcode=$(printf '%s' "$reply" | sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1)
  # An actual A record, not dig's diagnostics.
  addr=$(printf '%s' "$reply" | awk '$4=="A" {print $5; exit}')

  case "$rcode" in
    "")
      fail "no DNS response from $DNS_ADDR:$DNS_PORT (timeout or nothing listening)"
      ;;
    REFUSED)
      # The single most likely cause of "DNS is down" after an upgrade.
      fail "DNS returned REFUSED — this client is not in dns.allowed_client_cidrs"
      say "      check DNSDADDY_ALLOWED_CLIENT_CIDRS includes 127.0.0.0/8 and your clients"
      ;;
    SERVFAIL)
      fail "DNS returned SERVFAIL for $PROBE_GOOD — upstream resolution is failing"
      say "      check outbound 853/tcp to the configured DoT upstreams"
      ;;
    NOERROR)
      if [[ -n "$addr" ]]; then
        ok "dns answering ($PROBE_GOOD -> $addr)"
      else
        warn "dns returned NOERROR but no A record for $PROBE_GOOD"
      fi
      ;;
    NXDOMAIN)
      # The probe is meant to resolve; NXDOMAIN means it is being blocked or
      # the upstream is broken. Either way it is not a healthy probe.
      warn "dns returned NXDOMAIN for $PROBE_GOOD — is the probe domain blocked?"
      ;;
    *)
      warn "dns returned $rcode for $PROBE_GOOD"
      ;;
  esac
else
  say "note  dig not installed; skipping DNS check (apt install dnsutils)"
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
  0) say ""; say "RESULT: healthy — resolving and filtering" ;;
  1) say ""; say "RESULT: DEGRADED — answering queries but not fully protecting" ;;
  2) say ""; say "RESULT: DOWN — service is not working" ;;
esac

# In --quiet mode (cron), stay silent unless something is wrong.
if [[ $QUIET -eq 0 || $STATUS -ne 0 ]]; then
  printf '%s' "$OUT"
fi
exit $STATUS
