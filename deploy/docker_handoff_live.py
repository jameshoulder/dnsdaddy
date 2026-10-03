"""Disposable CI test: real Docker, real application, no mocked API responses.

The image is built locally by CI. The test owns a random Compose project and
volume, never the operator's stack. Feeds are off and the only upstream is a
loopback failure target. No public DNS destination is contacted.
"""
import http.cookiejar
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import struct
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid

import docker_network as n


def run(*args):
    p = subprocess.run(args, capture_output=True, text=True, timeout=120)
    if p.returncode:
        raise RuntimeError(f"{args[0]} {args[1]} failed with exit {p.returncode}")
    return p.stdout


def port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def refused(server, number, tcp):
    query = struct.pack("!6H", 700, 0x100, 1, 0, 0, 0) + b"\x07example\x07invalid\0\0\x01\0\x01"
    family = socket.AF_INET6 if ipaddress.ip_address(server).version == 6 else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as s:
        s.settimeout(8)
        s.connect((server, number))
        if tcp:
            s.sendall(struct.pack("!H", len(query)) + query)
            def exact(count):
                data = b""
                while len(data) < count:
                    block = s.recv(count - len(data))
                    assert block, "DNS TCP connection ended early"
                    data += block
                return data
            answer = exact(struct.unpack("!H", exact(2))[0])
        else:
            s.send(query)
            answer = s.recv(4096)
    assert len(answer) >= 12 and struct.unpack("!H", answer[:2])[0] == 700
    assert answer[3] & 15 == 5, "Detecting a destination must not grant the probing client access"


def main():
    helper = Path(__file__).resolve().with_name("docker_network.py")
    interfaces = n.command("ip", "-j", "address", "show")
    routes = n.command("ip", "-j", "-4", "route", "show", "default") + n.command("ip", "-j", "-6", "route", "show", "default")
    profile = "lan"
    choices = n.candidates(interfaces, routes, profile)
    if len(choices) != 1:
        profile = "vps"
        choices = n.candidates(interfaces, routes, profile)
    assert len(choices) == 1, "CI runner needs one unambiguous assigned host address"
    server, dns_port, http_port = choices[0], port(), port()
    while http_port == dns_port:
        http_port = port()
    password = secrets.token_urlsafe(32)
    name = "dnsdaddy-handoff-" + uuid.uuid4().hex[:12]
    service = {
        "image": "dnsdaddy-handoff-ci:local", "pull_policy": "never",
        "environment": {
            n.KEY: "${DNSDADDY_DEPLOYMENT_DNS:-}", "DNSDADDY_ADMIN_PASSWORD": password,
            "DNSDADDY_UPSTREAMS": "udp://127.0.0.1:9",
            "DNSDADDY_ALLOWED_CLIENT_CIDRS": "127.0.0.0/8,::1/128",
            "DNSDADDY_FEED_REFRESH_ON_START": "false", "DNSDADDY_FEED_REFRESH_INTERVAL": "8760h",
            "DNSDADDY_DETECTION_ENABLED": "false", "DNSDADDY_QUERY_LOG": "false",
        },
        "ports": [{"target": 5353, "published": str(dns_port), "host_ip": server, "protocol": p} for p in ("udp", "tcp")] + [{"target": 8080, "published": str(http_port), "host_ip": "127.0.0.1", "protocol": "tcp"}],
        "volumes": ["handoff-data:/var/lib/dnsdaddy"],
        "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"],
    }
    previous = Path.cwd()
    with tempfile.TemporaryDirectory(prefix="dnsdaddy-handoff-") as work:
        os.chdir(work)
        try:
            Path("compose.yaml").write_text(json.dumps({"name": name, "services": {"dnsdaddy": service}, "volumes": {"handoff-data": {}}}))
            Path("compose.yaml").chmod(0o600)
            run("python3", str(helper), "prepare", "--profile", profile, "--non-interactive")
            expected = n.format_endpoint(ipaddress.ip_address(server), dns_port)
            assert n.KEY + "=" + expected in Path(".env").read_text()
            try:
                run("docker", "compose", "up", "-d")
                run("python3", str(helper), "verify", "--profile", profile)
                base = f"http://127.0.0.1:{http_port}"
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
                def api(path, method="GET", body=None):
                    request = urllib.request.Request(base + path, method=method, data=None if body is None else json.dumps(body).encode(), headers={"Content-Type": "application/json", "Origin": base})
                    with opener.open(request, timeout=4) as response:
                        return json.load(response)
                def wait():
                    for attempt in range(60):
                        try:
                            api("/api/v1/health")
                            return
                        except (urllib.error.URLError, TimeoutError, ConnectionError):
                            # Docker can reset a connection while the process
                            # restarts. Retry only this bounded readiness read;
                            # all subsequent state and DNS assertions still run.
                            if attempt == 59:
                                raise
                            time.sleep(0.5)
                wait()
                api("/api/v1/auth/login", "POST", {"password": password})
                setup = api("/api/v1/setup")
                assert setup["endpoint"] == expected and setup["addressSource"] == "installation_hint" and not setup["addressLocked"]
                shown = api("/api/v1/server-addresses")["advertised"]
                assert shown["address"] == server and not shown["verified"]
                before = api("/api/v1/networks")["networks"]
                assert len(before) == 1 and before[0]["id"] == "n_default" and not before[0]["cidrs"]
                refused(server, dns_port, False)
                refused(server, dns_port, True)
                print("PASS: real host address reached Setup/Overview; unpermitted UDP and TCP queries received REFUSED.", flush=True)
                api("/api/v1/setup/address", "PUT", {"serverIp": "203.0.113.53", "dnsPort": 53, "previous": expected})
                run("python3", str(helper), "prepare", "--profile", profile, "--non-interactive")
                run("docker", "compose", "restart")
                wait()
                api("/api/v1/auth/login", "POST", {"password": password})
                after = api("/api/v1/setup")
                assert after["addressSource"] == "dashboard" and after["endpoint"] == "203.0.113.53:53"
                networks = api("/api/v1/networks")["networks"]
                assert len(networks) == 1 and networks[0]["allowResolver"] == before[0]["allowResolver"]
                print("PASS: saved address and permissions survive another installer handoff and restart.", flush=True)
            finally:
                # Only this disposable test project's containers and volume.
                run("docker", "compose", "down", "--volumes")
        finally:
            os.chdir(previous)


if __name__ == "__main__":
    if os.environ.get("CI") != "true":
        raise SystemExit("This integration requires disposable CI and its prebuilt test image.")
    if any(os.environ.get(k) for k in ("COMPOSE_FILE", "COMPOSE_PROJECT_NAME", "COMPOSE_PROFILES", "COMPOSE_ENV_FILES", "DNSDADDY_DEPLOYMENT_DNS")):
        raise SystemExit("Refusing inherited Compose/project/address overrides in this isolated test.")
    main()
