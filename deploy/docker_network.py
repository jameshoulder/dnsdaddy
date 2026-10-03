#!/usr/bin/env python3
"""Host-side Docker address handoff. No Internet discovery or permission grants.

Only the installer uses Docker's control socket. The resolver receives one
validated display hint, below explicit configuration and saved dashboard state.
"""
from __future__ import annotations

import argparse
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

KEY = "DNSDADDY_DEPLOYMENT_DNS"
MARKER = "# managed by DNS Daddy host network preflight"
MAX_FILE = 1 << 20
PRIVATE = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "100.64.0.0/10"))


class SetupError(Exception):
    pass


def command(*args: str):
    # No shell, redirects, eval, environment dumps or unbounded command time.
    try:
        with tempfile.TemporaryFile() as output:
            p = subprocess.run(args, stdout=output, stderr=subprocess.DEVNULL, timeout=20, check=False)
            if p.returncode:
                raise SetupError(f"{args[0]} {args[1] if len(args) > 1 else ''} failed; inspect that tool on the host.")
            output.seek(0)
            raw = output.read(MAX_FILE + 1)
        if len(raw) > MAX_FILE:
            raise SetupError("Host inspection exceeded its output limit.")
        return json.loads(raw)
    except (OSError, subprocess.TimeoutExpired, ValueError) as e:
        raise SetupError(f"Could not read {args[0]} host information; no address was guessed.") from e


def address(raw: str):
    if not isinstance(raw, str) or len(raw) > 64 or "%" in raw or raw != raw.strip():
        raise SetupError("Enter one IPv4 or IPv6 address, without a URL, zone, subnet or port.")
    try:
        ip = ipaddress.ip_address(raw)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
    except ValueError as e:
        raise SetupError("Enter one IPv4 or IPv6 address, without a URL, zone, subnet or port.") from e
    if ip.is_unspecified or ip.is_multicast or ip.is_link_local or ip.is_loopback or ip.is_reserved:
        raise SetupError("Use a reachable server address, not loopback, a wildcard or a special-use address.")
    return ip


def endpoint(raw: str):
    if not isinstance(raw, str) or len(raw) > 80:
        raise SetupError("Invalid DNS endpoint.")
    match = re.fullmatch(r"(?:\[([^\]]+)\]|([^:\[\]]+)):(\d{1,5})", raw)
    if not match:
        raise SetupError("Use IP:port, with brackets around IPv6.")
    ip = address(match[1] or match[2])
    port = int(match[3])
    if not 1 <= port <= 65535:
        raise SetupError("DNS port must be between 1 and 65535.")
    return ip, port


def format_endpoint(ip, port: int) -> str:
    return f"[{ip}]:{port}" if ip.version == 6 else f"{ip}:{port}"


def private(ip) -> bool:
    return any(ip.version == n.version and ip in n for n in PRIVATE)


def local_daemon() -> list[str]:
    host = os.environ.get("DOCKER_HOST", "")
    # An explicitly selected context wins over DOCKER_HOST.
    if os.environ.get("DOCKER_CONTEXT") or not host:
        context = command("docker", "context", "inspect")
        if not isinstance(context, list) or len(context) != 1:
            raise SetupError("Cannot identify the active Docker context.")
        host = context[0].get("Endpoints", {}).get("docker", {}).get("Host", "")
    if not host.startswith("unix:///"):
        raise SetupError("This installer needs Docker on this Linux host. A remote Docker context cannot use this machine's IP addresses.")
    info = command("docker", "info", "--format", "{{json .}}")
    if info.get("OSType") != "linux" or "docker desktop" in info.get("OperatingSystem", "").lower():
        raise SetupError("Automatic host detection supports native Linux Docker, not Docker Desktop's virtual machine.")
    match = re.match(r"^(\d+)\.", info.get("ServerVersion", ""))
    if not match or int(match[1]) < 28:
        raise SetupError("Use Docker Engine 28 or newer; older releases have a localhost port-publication exposure. No Docker settings were changed.")
    warnings = []
    if any("rootless" in str(s) for s in info.get("SecurityOptions", [])):
        warnings.append("Rootless Docker: verify original client source addresses before relying on IP permissions; forwarding behavior depends on the RootlessKit driver/version.")
    return warnings


def candidates(interfaces, routes, profile: str) -> list[str]:
    defaults = {r.get("dev") for r in routes if r.get("dst") == "default" and r.get("type", "unicast") == "unicast"}
    found = []
    for interface in interfaces:
        name = interface.get("ifname", "")
        if "UP" not in interface.get("flags", []) or re.match(r"^(lo$|docker\d|br-[0-9a-f]{12}$|veth|virbr|cni|flannel|podman)", name):
            continue
        for item in interface.get("addr_info", []):
            if item.get("scope") != "global" or item.get("preferred_life_time") == 0:
                continue
            flags = set(item.get("flags", []))
            if flags & {"temporary", "tentative", "deprecated", "dadfailed"} or any(item.get(f) for f in ("temporary", "tentative", "deprecated", "dadfailed")):
                continue
            try:
                ip = address(item.get("local", ""))
            except SetupError:
                continue
            if profile == "lan" and not private(ip):
                continue
            if profile != "lan" and not ip.is_global:
                continue
            found.append((name in defaults, ip.version == 4, str(ip)))
    # Prefer a unique stable IPv4 address on a default-route interface. If
    # several remain equally plausible, ask instead of silently picking one.
    if not found or not any(default for default, _, _ in found):
        return []
    rank = max((default, v4) for default, v4, _ in found)
    return sorted({ip for default, v4, ip in found if (default, v4) == rank})


def check_service(service, profile: str) -> None:
    if service.get("network_mode") in ("host", "none") or str(service.get("network_mode", "")).startswith(("container:", "service:")):
        raise SetupError("The automatic installer expects bridge networking with published ports. Keep custom networking on the advanced path.")
    if service.get("privileged") or service.get("cap_add") or service.get("pid") == "host":
        raise SetupError("Refusing a privileged or host-PID resolver deployment.")
    if "ALL" not in service.get("cap_drop", []) or not any(str(s) in ("no-new-privileges:true", "no-new-privileges=true", "no-new-privileges") for s in service.get("security_opt", [])):
        raise SetupError("Keep cap_drop ALL and no-new-privileges on the DNS Daddy service.")
    for mount in service.get("volumes", []):
        if not isinstance(mount, dict):
            raise SetupError("Cannot validate a non-normalized volume mapping.")
        source = str(mount.get("source", ""))
        if source == "/" or "docker.sock" in source or "docker.sock" in str(mount.get("target", "")):
            raise SetupError("Never mount the Docker control socket or host root into the resolver.")
    management = [p for p in service.get("ports", []) if p.get("target") == 8080]
    if not management:
        raise SetupError("No published management port was found; review the Compose configuration.")
    for p in management:
        try:
            ip = ipaddress.ip_address(p.get("host_ip", "0.0.0.0"))
        except ValueError as e:
            raise SetupError("Invalid management bind address.") from e
        if not ip.is_loopback and not (profile == "lan" and private(ip)):
            raise SetupError("Management port 8080 would be published beyond loopback. Use HTTPS/SSH, or deliberately select LAN mode for a trusted LAN host.")


def published_port(ports, ip, preferred=None) -> int:
    matches = {"udp": set(), "tcp": set()}
    for p in ports:
        if p.get("target") != 5353 or p.get("protocol", "tcp") not in matches:
            continue
        host = p.get("host_ip", "")
        if host:
            try:
                bind = ipaddress.ip_address(host)
            except ValueError:
                continue
            if bind != ip and not (bind.is_unspecified and bind.version == ip.version):
                continue
        value = str(p.get("published", ""))
        if re.fullmatch(r"\d{1,5}", value) and 1 <= int(value) <= 65535:
            matches[p.get("protocol", "tcp")].add(int(value))
    common = matches["udp"] & matches["tcp"]
    if preferred is not None and preferred in common:
        return preferred
    if preferred is None and len(common) == 1:
        return next(iter(common))
    raise SetupError("No unambiguous matching UDP and TCP DNS port publication exists for this address. Review Docker's port mappings; no port was guessed.")


def read_env(path: Path) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return b""
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_mode & 0o022:
            raise SetupError(".env must be a regular, non-shared file that other users cannot modify.")
        with os.fdopen(fd, "rb", closefd=False) as f:
            raw = f.read(MAX_FILE + 1)
        if len(raw) > MAX_FILE:
            raise SetupError(".env exceeds the supported size.")
        raw.decode("utf-8")
        return raw
    finally:
        os.close(fd)


def save_hint(path: Path, value: str) -> None:
    if value:
        endpoint(value)
    # Lock only this small handoff, not the lifetime of the running resolver.
    fd = os.open(path.parent / ".dnsdaddy-network.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise SetupError("Invalid network setup lock file.")
        fcntl.flock(fd, fcntl.LOCK_EX)
        before = read_env(path)
        lines = before.decode("utf-8").splitlines(keepends=True)
        active = [i for i, line in enumerate(lines) if re.match(rf"^\s*(?:export\s+)?{KEY}\s*=", line)]
        if active and (active[-1] == 0 or lines[active[-1]-1].strip() != MARKER):
            raise SetupError(f"{KEY} was set by hand; it has not been overwritten. Remove it to use automatic detection.")
        remove = set(active)
        for i in active:
            if i and lines[i-1].strip() == MARKER:
                remove.add(i-1)
        updated = "".join(line for i, line in enumerate(lines) if i not in remove)
        updated = updated.rstrip("\n") + f"\n\n{MARKER}\n{KEY}={value}\n"
        original = path.stat() if path.exists() else None
        temporary, name = tempfile.mkstemp(prefix=".dnsdaddy-env-", dir=path.parent)
        try:
            with os.fdopen(temporary, "wb") as f:
                if original and os.geteuid() == 0:
                    os.fchown(f.fileno(), original.st_uid, original.st_gid)
                os.fchmod(f.fileno(), 0o600)
                f.write(updated.encode("utf-8")); f.flush(); os.fsync(f.fileno())
            if read_env(path) != before:
                raise SetupError(".env changed during setup. Nothing was replaced; retry after the other edit finishes.")
            os.replace(name, path)
            directory = os.open(path.parent, os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(name):
                os.unlink(name)
    finally:
        os.close(fd)


def prepare(profile: str, supplied: str, dry_run: bool, interactive: bool):
    warnings = local_daemon()
    for warning in warnings:
        print("WARNING: " + warning)
    print("WARNING: Docker-published ports may bypass UFW. Keep resolver client permissions and a Docker-aware or provider firewall; no firewall rules were changed.")
    cfg = command("docker", "compose", "config", "--format", "json")
    service = cfg.get("services", {}).get("dnsdaddy", {})
    check_service(service, profile)
    # Compose, not a home-made .env parser, resolves the operator's explicit
    # override. Never print the full service/environment: it may hold secrets.
    explicit = service.get("environment", {}).get("DNSDADDY_ADVERTISED_DNS")
    if explicit:
        ip, port = endpoint(explicit)
        published_port(service.get("ports", []), ip, port)
        print(f"DNS address kept from explicit configuration: {format_endpoint(ip, port)}")
        return
    chosen = supplied
    if not chosen:
        interfaces = command("ip", "-j", "address", "show")
        routes = command("ip", "-j", "-4", "route", "show", "default") + command("ip", "-j", "-6", "route", "show", "default")
        choices = candidates(interfaces, routes, profile)
        if len(choices) == 1:
            chosen = choices[0]
        elif interactive and not dry_run:
            print("Which IP do your devices use to reach this server?" + (" Use the public IP shown by your VPS provider." if profile != "lan" else " Use this host's LAN IP."))
            chosen = input("DNS server IP: ").strip()
        else:
            raise SetupError("The server address is ambiguous or hidden by NAT. Supply --server-ip with the address devices use; no external IP-discovery service was contacted.")
    ip = address(chosen)
    if profile == "lan" and not private(ip):
        raise SetupError("LAN mode requires an assigned private/shared host address. Use VPS mode for a public server.")
    if profile != "lan" and not ip.is_global:
        raise SetupError("A public VPS needs its public destination IP. Use LAN mode for a private routed/VPN deployment.")
    port = published_port(service.get("ports", []), ip)
    value = format_endpoint(ip, port)
    if dry_run:
        print("Would supply client-facing DNS address: " + value + " (not a connectivity test)")
    else:
        if KEY in os.environ:
            raise SetupError(f"Remove the shell {KEY} override before automatically saving the host address.")
        save_hint(Path(".env"), value)
        print("Client-facing DNS address supplied to Docker: " + value)
        print("Saved dashboard addresses and explicit configuration still take precedence. No clients were allowed automatically.")


def verify(profile: str):
    local_daemon()
    ids = command("docker", "compose", "ps", "--format", "json", "dnsdaddy")
    # Compose versions can encode this as one object or a list for one service.
    ids = ids if isinstance(ids, list) else [ids]
    if len(ids) != 1 or not re.fullmatch(r"[0-9a-f]{12,64}", str(ids[0].get("ID", ""))):
        raise SetupError("Could not identify exactly one running DNS Daddy container.")
    inspected = command("docker", "inspect", ids[0]["ID"])
    if not isinstance(inspected, list) or len(inspected) != 1:
        raise SetupError("Unexpected container inspection result.")
    live = inspected[0]
    if not live.get("State", {}).get("Running"):
        raise SetupError("The DNS Daddy container is not running.")
    if str(live.get("Config", {}).get("User", "")).split(":")[0] in ("", "0", "root"):
        raise SetupError("The resolver must run as a non-root user.")
    host = live.get("HostConfig", {})
    ports = []
    for target, bindings in (live.get("NetworkSettings", {}).get("Ports") or {}).items():
        number, protocol = target.split("/")
        for b in bindings or []:
            ports.append({"target": int(number), "protocol": protocol, "host_ip": b["HostIp"], "published": b["HostPort"]})
    check_service({"ports": ports, "network_mode": host.get("NetworkMode"), "privileged": host.get("Privileged"), "pid": host.get("PidMode"), "cap_add": host.get("CapAdd"), "cap_drop": host.get("CapDrop") or [], "security_opt": host.get("SecurityOpt") or [], "volumes": [{"source": m.get("Source", ""), "target": m.get("Destination", "")} for m in live.get("Mounts", [])]}, profile)
    env = dict(v.split("=", 1) for v in live.get("Config", {}).get("Env", []) if "=" in v)
    value = env.get("DNSDADDY_ADVERTISED_DNS") or env.get(KEY)
    if not value:
        raise SetupError("Docker did not pass a DNS address to the running app. Check the Compose environment declaration; no container IP was substituted.")
    ip, port = endpoint(value)
    published_port(ports, ip, port)
    desired = command("docker", "compose", "config", "--format", "json").get("services", {}).get("dnsdaddy", {}).get("environment", {})
    if value != (desired.get("DNSDADDY_ADVERTISED_DNS") or desired.get(KEY)):
        raise SetupError("The running container has a different DNS address from the current configuration. Recreate it before using the displayed address.")
    print("PASS: the running non-root container received the address and publishes matching UDP/TCP DNS ports.")
    print("DNS address: " + str(ip) + (f" (port {port})" if port != 53 else ""))
    print("Next: Connect one intended client in the dashboard and test a real lookup. Remote reachability, original source IP and provider firewall are not verified by these host checks.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "verify"))
    parser.add_argument("--profile", choices=("lan", "vps"), default="vps")
    parser.add_argument("--server-ip", default="")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--non-interactive", action="store_true")
    args = parser.parse_args()
    try:
        if sys.platform != "linux":
            raise SetupError("This host installer supports Linux. No address was guessed for another platform.")
        # Refuse unsafe indirection before reading deployment files as root.
        if Path(".env").exists() or Path(".env").is_symlink():
            read_env(Path(".env"))
        if args.action == "prepare":
            prepare(args.profile, args.server_ip, args.dry_run, sys.stdin.isatty() and not args.non_interactive)
        else:
            if args.dry_run:
                raise SetupError("Use prepare --dry-run; verify inspects a running deployment.")
            verify(args.profile)
    except (SetupError, OSError, EOFError) as e:
        print("Network setup needs attention: " + str(e), file=sys.stderr)
        return 1
    except (TypeError, KeyError, ValueError, AttributeError):
        print("Network setup needs attention: unexpected host data; no address was guessed. Check Docker and iproute2.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
