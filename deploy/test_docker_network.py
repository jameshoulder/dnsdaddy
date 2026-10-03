import contextlib
import copy
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import docker_network as n


def iface(name, ip, **kw):
    return {"ifname": name, "flags": ["UP"], "addr_info": [{"scope": "global", "local": ip, **kw}]}


def service():
    return {"cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"], "environment": {}, "volumes": [], "ports": [
        {"target": 5353, "published": "53", "protocol": "udp"},
        {"target": 5353, "published": "53", "protocol": "tcp"},
        {"target": 8080, "published": "8080", "protocol": "tcp", "host_ip": "127.0.0.1"}]}


class HandoffTests(unittest.TestCase):
    def test_lan_uses_host_not_docker_or_unrelated_interfaces(self):
        rows = [iface("docker0", "172.17.0.1"), iface("br-abcdef123456", "172.18.0.1"), iface("eth0", "192.168.1.20"), iface("eth1", "10.2.0.1")]
        self.assertEqual(n.candidates(rows, [{"dst": "default", "dev": "eth0"}], "lan"), ["192.168.1.20"])

    def test_private_cloud_nic_is_not_a_public_destination(self):
        self.assertEqual(n.candidates([iface("eth0", "10.0.0.2")], [{"dst": "default", "dev": "eth0"}], "vps"), [])

    def test_direct_public_host_address_needs_no_external_lookup(self):
        self.assertEqual(n.candidates([iface("eth0", "93.184.216.34")], [{"dst": "default", "dev": "eth0"}], "vps"), ["93.184.216.34"])

    def test_ipv6_temporary_and_deprecated_addresses_are_not_advertised(self):
        rows = [iface("eth0", "2606:4700::1111", temporary=True), iface("eth0", "2606:4700::2222", flags=["deprecated"]), iface("eth0", "2606:4700::3333")]
        self.assertEqual(n.candidates(rows, [{"dst": "default", "dev": "eth0"}], "vps"), ["2606:4700::3333"])

    def test_ambiguous_and_unrouted_hosts_are_not_silently_chosen(self):
        rows = [iface("eth0", "192.168.1.20"), iface("eth0", "192.168.1.21")]
        self.assertEqual(len(n.candidates(rows, [{"dst": "default", "dev": "eth0"}], "lan")), 2)
        self.assertEqual(n.candidates(rows, [], "lan"), [])

    def test_strict_input_never_reaches_a_shell(self):
        for value in ["0.0.0.0", "::", "127.0.0.1", "fe80::1%eth0", "224.0.0.1", "https://host", "192.168.1.2/24", "192.168.1.2:53", "1.2.3.4\nEVIL=x", "$(touch /tmp/bad)"]:
            with self.subTest(value=value), self.assertRaises(n.SetupError):
                n.address(value)
        self.assertEqual(str(n.address("::ffff:192.168.1.20")), "192.168.1.20")

    def test_both_protocols_and_the_correct_bound_address_are_required(self):
        ip = n.address("192.168.1.20")
        self.assertEqual(n.published_port(service()["ports"], ip), 53)
        with self.assertRaises(n.SetupError):
            n.published_port(service()["ports"][1:], ip)
        ports = service()["ports"]
        ports[0]["published"] = "5354"
        with self.assertRaises(n.SetupError):
            n.published_port(ports, ip)
        ports = service()["ports"]
        ports[0]["host_ip"] = "127.0.0.1"
        with self.assertRaises(n.SetupError):
            n.published_port(ports, ip)

    def test_ipv6_and_custom_dns_ports_are_not_guessed_as_53(self):
        ports = [{"target": 5353, "published": "5300", "protocol": p, "host_ip": "::"} for p in ("udp", "tcp")]
        ip = n.address("fd00::20")
        self.assertEqual(n.published_port(ports, ip), 5300)
        self.assertEqual(n.format_endpoint(ip, 5300), "[fd00::20]:5300")
        with self.assertRaises(n.SetupError):
            n.published_port(ports, ip, 53)

    def test_no_privileged_socket_host_network_or_public_management_shortcut(self):
        for bad in [{"privileged": True}, {"network_mode": "host"}, {"pid": "host"}, {"cap_add": ["NET_ADMIN"]}, {"cap_drop": []}, {"security_opt": []}, {"volumes": [{"source": "/var/run/docker.sock"}]}, {"volumes": [{"source": "/"}]}]:
            with self.subTest(bad=bad), self.assertRaises(n.SetupError):
                n.check_service({**service(), **bad}, "vps")
        bad = service(); bad["ports"][-1]["host_ip"] = "0.0.0.0"
        with self.assertRaises(n.SetupError):
            n.check_service(bad, "vps")
        bad["ports"][-1]["host_ip"] = "192.168.1.20"
        n.check_service(bad, "lan")
        with self.assertRaises(n.SetupError):
            n.check_service(bad, "vps")

    def test_remote_docker_context_is_rejected_before_using_host_interfaces(self):
        with patch.dict(os.environ, {"DOCKER_HOST": "ssh://other-host", "DOCKER_CONTEXT": ""}), self.assertRaises(n.SetupError):
            n.local_daemon()

    def test_old_docker_and_desktop_cannot_claim_safe_loopback_publication(self):
        for info in [{"OSType": "linux", "OperatingSystem": "Docker Desktop", "ServerVersion": "29.0.0"}, {"OSType": "linux", "ServerVersion": "27.5.0"}]:
            with patch.dict(os.environ, {"DOCKER_HOST": "unix:///var/run/docker.sock", "DOCKER_CONTEXT": ""}), patch.object(n, "command", return_value=info), self.assertRaises(n.SetupError):
                n.local_daemon()

    def test_env_write_preserves_credentials_modes_acl_and_permissions(self):
        with tempfile.TemporaryDirectory() as d:
            file = Path(d)/".env"
            original = "DNSDADDY_ADMIN_PASSWORD=secret\nDNSDADDY_LOCAL_DNSSEC_VALIDATION=enforce\nDNSDADDY_ALLOWED_CLIENT_CIDRS=10.2.0.0/24\n"
            file.write_text(original)
            n.save_hint(file, "192.168.1.20:53")
            self.assertIn(original, file.read_text())
            self.assertEqual(file.stat().st_mode & 0o777, 0o600)
            n.save_hint(file, "192.168.1.21:53")
            self.assertEqual(file.read_text().count(n.KEY+"="), 1)
            self.assertIn("192.168.1.21:53", file.read_text())
            self.assertIn(original, file.read_text())

    def test_symlink_and_hand_set_hint_are_not_overwritten(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d)/"secret"; target.write_text("untouched")
            file = Path(d)/".env"; file.symlink_to(target)
            with self.assertRaises((n.SetupError, OSError)):
                n.save_hint(file, "192.168.1.20:53")
            self.assertEqual(target.read_text(), "untouched")
            file.unlink(); file.write_text(n.KEY+"=192.168.1.21:53\n")
            with self.assertRaises(n.SetupError):
                n.save_hint(file, "192.168.1.20:53")
            self.assertEqual(file.read_text(), n.KEY+"=192.168.1.21:53\n")

    def test_world_writable_env_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            file=Path(d)/".env"; file.write_text("secret=x\n"); file.chmod(0o666)
            with self.assertRaises(n.SetupError):
                n.save_hint(file, "192.168.1.20:53")
            self.assertEqual(file.read_text(), "secret=x\n")

    def test_dry_run_and_explicit_overrides_do_not_write(self):
        cfg={"services": {"dnsdaddy": service()}}
        with patch.object(n, "local_daemon", return_value=[]), patch.object(n, "command", return_value=cfg), patch.object(n, "save_hint") as save, contextlib.redirect_stdout(io.StringIO()):
            n.prepare("lan", "192.168.1.20", True, False)
            save.assert_not_called()
            cfg["services"]["dnsdaddy"]["environment"]["DNSDADDY_ADVERTISED_DNS"]="192.168.1.21:53"
            n.prepare("lan", "192.168.1.20", False, False)
            save.assert_not_called()

    def test_running_container_must_receive_the_handoff_and_actual_ports(self):
        value="192.168.1.20:53"
        live={"State": {"Running": True}, "Config": {"User": "65532:65532", "Env": [n.KEY+"="+value, "SECRET=never-print"]}, "HostConfig": {"NetworkMode": "project_default", "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges:true"]}, "Mounts": [], "NetworkSettings": {"Ports": {f"5353/{p}": [{"HostIp": "0.0.0.0", "HostPort": "53"}] for p in ("udp", "tcp")}}}
        live["NetworkSettings"]["Ports"]["8080/tcp"]=[{"HostIp": "127.0.0.1", "HostPort": "8080"}]
        cfg={"services": {"dnsdaddy": {"environment": {n.KEY: value}}}}
        for change in (None, "missing", "stale", "root", "no-tcp"):
            data=copy.deepcopy(live)
            if change=="missing": data["Config"]["Env"]=[]
            if change=="stale": data["Config"]["Env"]=[n.KEY+"=192.168.1.21:53"]
            if change=="root": data["Config"]["User"]="0:65532"
            if change=="no-tcp": del data["NetworkSettings"]["Ports"]["5353/tcp"]
            out=io.StringIO()
            with patch.object(n, "local_daemon", return_value=[]), patch.object(n, "command", side_effect=[{"ID": "a"*64}, [data], cfg]), contextlib.redirect_stdout(out):
                if change:
                    with self.assertRaises(n.SetupError): n.verify("lan")
                else:
                    n.verify("lan")
                    self.assertIn("not verified", out.getvalue())
                self.assertNotIn("never-print", out.getvalue())


if __name__ == "__main__":
    unittest.main()
