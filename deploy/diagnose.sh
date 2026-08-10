#!/usr/bin/env bash
#
# DNS Daddy production diagnostic — read-only.
#
# Changes nothing. Run it on the server and read the SUMMARY at the end, or
# send the whole output somewhere it can be read.
#
#   sudo ./deploy/diagnose.sh          # sudo gives fuller systemd/ss output
#   sudo ./deploy/diagnose.sh > diag.txt 2>&1
#
# It answers, in order: is anything running, how is it deployed, are the two
# deployment methods fighting, is the data still there, and what is actually
# listening.
#
# ⚠️  WARNING — this output is sensitive. It includes your server's hostname,
# public and private IP addresses, firewall rules, the Caddyfile (which
# contains your real domain name), container logs, and DNS query samples.
# Review it yourself and redact anything identifying before pasting it into a
# GitHub issue, a chat room, or anywhere else outside your control.
set -uo pipefail

h()   { printf '\n===== %s =====\n' "$1"; }
run() { printf '\n$ %s\n' "$*"; "$@" 2>&1 | head -60 || true; }

cat <<'EOF'
################################################################################
#  WARNING: this diagnostic output contains SENSITIVE information —          #
#  hostnames, public/private IP addresses, firewall rules, your Caddyfile    #
#  (real domain name), container logs, and live DNS query samples.          #
#                                                                             #
#  Do NOT post this output publicly (GitHub issues, forums, chat) without    #
#  reading it first and redacting anything you don't want disclosed.         #
################################################################################
EOF

echo "DNS Daddy diagnostic — $(date -Is) on $(hostname)"

h "1. Host"
run uname -a
run df -h /
run free -h
printf '\n$ uptime\n'; uptime

h "2. Docker daemon"
if command -v docker >/dev/null 2>&1; then
  run systemctl is-enabled docker
  run systemctl is-active docker
  systemctl status docker --no-pager 2>&1 | head -12
else
  echo "docker is not installed"
fi

h "3. Containers"
if command -v docker >/dev/null 2>&1; then
  run docker ps -a
  echo
  echo '$ docker inspect dnsdaddy (key fields)'
  docker inspect dnsdaddy --format '  status       : {{.State.Status}}
  running      : {{.State.Running}}
  exit code    : {{.State.ExitCode}}
  error        : {{.State.Error}}
  started      : {{.State.StartedAt}}
  finished     : {{.State.FinishedAt}}
  restarts     : {{.RestartCount}}
  restart plcy : {{.HostConfig.RestartPolicy.Name}}
  health       : {{if .State.Health}}{{.State.Health.Status}}{{else}}(none){{end}}
  image        : {{.Config.Image}}
  mounts       : {{range .Mounts}}{{.Name}}->{{.Destination}} {{end}}' 2>&1 | head -20
  echo
  echo '$ docker logs --tail=80 dnsdaddy   # THE most important output here'
  docker logs --tail=80 dnsdaddy 2>&1 | tail -80
fi

h "4. Compose project"
if command -v docker >/dev/null 2>&1; then
  for d in /opt/dnsdaddy /root/dnsdaddy /home/*/dnsdaddy .; do
    if [[ -f "$d/docker-compose.yml" ]]; then
      echo "compose file found at: $d"
      ( cd "$d" && docker compose ps 2>&1 | head -20 )
      break
    fi
  done
fi

h "5. Native systemd service (must NOT run alongside Docker)"
run systemctl is-enabled dnsdaddy
run systemctl is-active dnsdaddy
systemctl status dnsdaddy --no-pager 2>&1 | head -12
run systemctl is-enabled dnsdaddy-compose
run systemctl is-active dnsdaddy-compose

h "6. Reverse proxy"
run systemctl is-enabled caddy
run systemctl is-active caddy
systemctl status caddy --no-pager 2>&1 | head -12
if [[ -f /etc/caddy/Caddyfile ]]; then
  echo; echo '$ cat /etc/caddy/Caddyfile'; cat /etc/caddy/Caddyfile
else
  echo "no /etc/caddy/Caddyfile"
fi
echo; echo '$ journalctl -u caddy --no-pager -n 30'
journalctl -u caddy --no-pager -n 30 2>&1 | tail -30

h "7. Listening sockets (expect :53 udp+tcp and 127.0.0.1:8080)"
run ss -lntup

h "8. Application health"
echo '$ curl -v http://127.0.0.1:8080/api/v1/health'
curl -sv --max-time 5 http://127.0.0.1:8080/api/v1/health 2>&1 | tail -20

h "9. DNS"
if command -v dig >/dev/null 2>&1; then
  echo '$ dig @127.0.0.1 example.com'
  dig @127.0.0.1 example.com +timeout=3 +tries=1 2>&1 | head -25
else
  echo "dig not installed (apt install dnsutils)"
fi

h "10. Data volume — must be preserved"
#
# Never assume the volume is called "dnsdaddy-data". Compose prefixes named
# volumes with the project name, so the real name is normally
# "<project>_dnsdaddy-data" — and the project name defaults to the directory
# the stack was brought up from, which nobody remembers. Guessing wrong here is
# how somebody ends up "restoring" an empty volume over live data.
#
# Ask the container what it is actually using instead.
if command -v docker >/dev/null 2>&1; then
  run docker volume ls

  VOL_NAME=""; VOL_TYPE=""; VOL_SRC=""
  if docker inspect dnsdaddy >/dev/null 2>&1; then
    # Find the mount whose Destination is the data directory, whatever it is
    # named and whether it is a named volume or a bind mount.
    read -r VOL_TYPE VOL_NAME VOL_SRC <<<"$(docker inspect dnsdaddy \
      --format '{{range .Mounts}}{{if eq .Destination "/var/lib/dnsdaddy"}}{{.Type}} {{if .Name}}{{.Name}}{{else}}-{{end}} {{.Source}}{{end}}{{end}}' 2>/dev/null)"
  fi

  if [[ -n "${VOL_TYPE:-}" ]]; then
    echo
    echo "resolved from the running container (authoritative):"
    echo "  mount type : $VOL_TYPE"
    echo "  volume name: $VOL_NAME"
    echo "  host path  : $VOL_SRC"
    if [[ "$VOL_TYPE" == "volume" && "$VOL_NAME" != "-" ]]; then
      echo; echo "\$ docker volume inspect $VOL_NAME"
      docker volume inspect "$VOL_NAME" 2>&1 | head -20
    fi
  else
    echo
    echo "could not resolve the mount from a container (is 'dnsdaddy' present?)."
    echo "candidate volumes by name — confirm before touching any of them:"
    docker volume ls --format '{{.Name}}' 2>/dev/null | grep -i dnsdaddy | sed 's/^/  /' || echo "  none found"
    # Fall back to the first candidate purely for the read-only listing below.
    VOL_NAME=$(docker volume ls --format '{{.Name}}' 2>/dev/null | grep -i dnsdaddy | head -1)
    [[ -n "$VOL_NAME" ]] && VOL_SRC=$(docker volume inspect "$VOL_NAME" --format '{{.Mountpoint}}' 2>/dev/null)
  fi

  if [[ -n "${VOL_SRC:-}" && -d "$VOL_SRC" ]]; then
    echo; echo "contents of $VOL_SRC:"; ls -la "$VOL_SRC" 2>&1 | head -15
    echo; echo "database:"
    if [[ -f "$VOL_SRC/dnsdaddy.db" ]]; then
      du -h "$VOL_SRC/dnsdaddy.db"
      # A file that exists but is empty is not a surviving database.
      sz=$(stat -c %s "$VOL_SRC/dnsdaddy.db" 2>/dev/null || echo 0)
      [[ "$sz" -lt 4096 ]] && echo "  WARNING: dnsdaddy.db is only ${sz} bytes — suspiciously small"
    else
      echo "  no dnsdaddy.db at $VOL_SRC — THIS IS NOT THE DATA VOLUME"
    fi
  fi
fi
if [[ -d /var/lib/dnsdaddy ]]; then
  echo; echo "native data dir /var/lib/dnsdaddy (used by the non-Docker install):"
  ls -la /var/lib/dnsdaddy | head -15
fi

h "11. Firewall"
run ufw status verbose

h "SUMMARY"

# val <fallback> <command...> — print the command's output, or the fallback if
# it produced nothing. Commands like `systemctl is-enabled` print a value AND
# exit non-zero, so `cmd || echo fallback` would print both.
val() {
  local fallback="$1"; shift
  local out
  out=$("$@" 2>/dev/null | head -1)
  [[ -n "$out" ]] && printf '%s' "$out" || printf '%s' "$fallback"
}

mount_tpl='{{range .Mounts}}{{if eq .Destination "/var/lib/dnsdaddy"}}{{if .Name}}{{.Name}}{{else}}{{.Source}}{{end}}{{end}}{{end}}'
src_tpl='{{range .Mounts}}{{if eq .Destination "/var/lib/dnsdaddy"}}{{.Source}}{{end}}{{end}}'

printf 'docker enabled at boot : %s\n' "$(val 'n/a'          systemctl is-enabled docker)"
printf 'docker active          : %s\n' "$(val 'n/a'          systemctl is-active docker)"
printf 'container state        : %s\n' "$(val 'no container' docker inspect dnsdaddy --format '{{.State.Status}}')"
printf 'container health       : %s\n' "$(val 'n/a'          docker inspect dnsdaddy --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}')"
printf 'restart policy         : %s\n' "$(val 'n/a'          docker inspect dnsdaddy --format '{{.HostConfig.RestartPolicy.Name}}')"
printf 'restart count          : %s\n' "$(val 'n/a'          docker inspect dnsdaddy --format '{{.RestartCount}}')"
printf 'native dnsdaddy.service: %s / %s\n' \
   "$(val 'not installed' systemctl is-enabled dnsdaddy)" \
   "$(val 'inactive'      systemctl is-active dnsdaddy)"
printf 'dnsdaddy-compose.service: %s / %s\n' \
   "$(val 'not installed' systemctl is-enabled dnsdaddy-compose)" \
   "$(val 'inactive'      systemctl is-active dnsdaddy-compose)"
printf 'caddy                  : %s / %s\n' \
   "$(val 'not installed' systemctl is-enabled caddy)" \
   "$(val 'inactive'      systemctl is-active caddy)"
printf 'api health             : %s\n' \
   "$(val 'NO RESPONSE' curl -fsS --max-time 3 http://127.0.0.1:8080/api/v1/health)"
printf 'data volume            : %s\n' "$(val 'unresolved' docker inspect dnsdaddy --format "$mount_tpl")"
printf 'data host path         : %s\n' "$(val 'unresolved' docker inspect dnsdaddy --format "$src_tpl")"

echo
echo "Both dnsdaddy.service and a Docker container active at once means they are"
echo "fighting for port 53 — that is a fault, not a redundancy."

cat <<'EOF'

################################################################################
#  Reminder: the output above may contain sensitive IP addresses, hostnames, #
#  and log/query data. Review and redact before sharing it outside your      #
#  organisation.                                                             #
################################################################################
EOF
