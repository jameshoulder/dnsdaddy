#!/usr/bin/env bash
# Secure host-aware entry point. The established installer still owns Docker,
# HTTPS, upgrades and rollback. This layer only hands over a DNS address and
# verifies the running deployment; it never grants a client or edits a firewall.
set -uo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)" || exit 1
cd -- "$ROOT" || exit 1
profile=vps
server_ip=""
dry_run=0
no_prompt=0
uninstall=0
args=()
while (($#)); do
  case "$1" in
    --server-ip)
      [[ $# -ge 2 ]] || { echo '--server-ip needs one IP address.' >&2; exit 2; }
      server_ip="$2"; shift 2 ;;
    --lan) profile=lan; args+=("$1"); shift ;;
    --vps|--https) profile=vps; args+=("$1"); shift ;;
    --dry-run) dry_run=1; args+=("$1"); shift ;;
    --yes|-y) no_prompt=1; args+=("$1"); shift ;;
    --uninstall) uninstall=1; args+=("$1"); shift ;;
    --upgrade|--purge) args+=("$1"); shift ;;
    --help|-h)
      printf '%s\n' 'DNS Daddy host-aware installation' '' \
        '  ./install.sh                         Cloud/VPS, dashboard over SSH' \
        '  ./install.sh --lan                   Trusted LAN installation' \
        '  ./install.sh --https                 HTTPS using the existing TLS installer' \
        '  ./install.sh --upgrade               Upgrade, preserving settings and data' \
        '  ./install.sh --server-ip IP          Explicit LAN/public NAT destination' \
        '  ./install.sh --dry-run               Preview without changing files' '' \
        'Requires Linux, Python 3 and local Docker Engine 28+. No external IP lookup.' \
        'The low-level installer options --yes, --uninstall and --purge are retained.'
      exit 0 ;;
    *) printf 'Unknown option: %s\n' "$1" >&2; exit 2 ;;
  esac
done
if ((uninstall)); then
  exec bash "$ROOT/deploy/install-docker.sh" "${args[@]}"
fi
command -v python3 >/dev/null 2>&1 || { echo 'Python 3 is required for host checks. Install it with your Linux package manager.' >&2; exit 1; }
prep=(prepare --profile "$profile")
[[ -n "$server_ip" ]] && prep+=(--server-ip "$server_ip")
((dry_run)) && prep+=(--dry-run)
((no_prompt)) && prep+=(--non-interactive)
python3 "$ROOT/deploy/docker_network.py" "${prep[@]}" || exit 1
# Choose the same safe VPS default for the legacy installer, without asking a
# second deployment question. Explicit --lan/--https still win by argument order.
bash "$ROOT/deploy/install-docker.sh" --vps "${args[@]}"
status=$?
((status == 0)) || exit "$status"
((dry_run)) && exit 0
python3 "$ROOT/deploy/docker_network.py" verify --profile "$profile"
