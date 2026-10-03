// Package setupguide builds bounded, offline deployment and client-access plans.
// Plans never open listeners, discover public IPs, contact providers or grant access.
package setupguide

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

type Preset struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	ServerHelp string `json:"serverHelp"`
	ClientHelp string `json:"clientHelp"`
	Example    string `json:"example"`
}

func Presets() []Preset {
	return []Preset{
		{"lan", "Home / office LAN", "The LAN IP of the machine running DNS Daddy, not its Docker IP.", "The private subnet whose devices will query DNS Daddy directly. A router forwarding queries may appear as just one router IP.", "192.168.1.0/24"},
		{"device", "One device", "The reachable LAN or VPN IP of your DNS Daddy server.", "One device's source IP. A bare IPv4 becomes /32; a bare IPv6 becomes /128. Reserve its address in DHCP.", "192.168.1.50"},
		{"vps", "Public VPS / fixed-site clients", "The VPS's public client-facing IP. It may be NATed and absent from the server's interfaces.", "Your home/office's public egress IP, NOT its private LAN range and NOT the VPS IP. IPv6 clients may have their own public addresses.", "203.0.113.25"},
		{"vpn", "Private VPN", "The server's VPN address reachable by your clients. Install and route the VPN separately.", "The VPN source IP or assigned VPN subnet. CGNAT space is shared address space, not proof that Tailscale is installed.", "100.64.10.20"},
		{"roaming", "Roaming / tokenised encrypted DNS", "The client-facing server IP. HTTPS additionally needs your certificate-matching hostname.", "No public-IP grant is needed for tokenised DoH. Create a dedicated enabled network, then use its token URL from Setup. Do not grant every coffee-shop IP.", ""},
		{"local", "Local development / SSH-only", "127.0.0.1 on the server. It is not an address another device can use.", "Only loopback clients. Remote dashboard access uses an SSH tunnel; ordinary SSH -L does not forward UDP DNS.", "127.0.0.1"},
	}
}

type Input struct {
	Preset   string `json:"preset"`
	ServerIP string `json:"serverIp"`
	DNSPort  int    `json:"dnsPort"`
	Clients  string `json:"clients"`
	Mode     string `json:"mode"`
}

type Address struct {
	CIDR   string `json:"cidr"`
	Scope  string `json:"scope"`
	Single bool   `json:"single"`
}

type Plan struct {
	Preset            string    `json:"preset"`
	Endpoint          string    `json:"endpoint"`
	Addresses         []Address `json:"addresses"`
	CIDRs             []string  `json:"cidrs"`
	PublicAckRequired bool      `json:"publicAckRequired"`
	GrantSourceAccess bool      `json:"grantSourceAccess"`
	Warnings          []string  `json:"warnings"`
	Environment       string    `json:"environment"`
	NativeYAML        string    `json:"nativeYaml"`
	ComposeOverride   string    `json:"composeOverride"`
	UDPTest           string    `json:"udpTest"`
	TCPTest           string    `json:"tcpTest"`
}

// Endpoint accepts an IP and a separate port, never a URL, CIDR or guessed hostname.
func Endpoint(raw string, port int) (string, error) {
	ip, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil || ip.Zone() != "" {
		return "", fmt.Errorf("enter a single server IPv4 or IPv6 address, without http://, a slash, brackets or a port")
	}
	ip = ip.Unmap()
	if (!ip.IsGlobalUnicast() && !ip.IsLoopback()) || ip.IsLinkLocalUnicast() {
		return "", fmt.Errorf("use a reachable host IP, not a wildcard, multicast or link-local address")
	}
	if port < 1 || port > 65535 {
		return "", fmt.Errorf("DNS port must be 1–65535; normal device settings use 53")
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(port)), nil
}

// ParseClient normalises host bits and mapped IPv4 while preserving host/prefix intent.
func ParseClient(raw string) (netip.Prefix, error) {
	var p netip.Prefix
	var err error
	if strings.Contains(raw, "/") {
		p, err = netip.ParsePrefix(raw)
	} else {
		var ip netip.Addr
		ip, err = netip.ParseAddr(raw)
		if err == nil && ip.Zone() == "" {
			p = netip.PrefixFrom(ip, ip.BitLen())
		} else {
			err = fmt.Errorf("invalid address")
		}
	}
	if err != nil || !p.IsValid() {
		return netip.Prefix{}, fmt.Errorf("%q is not an IP or CIDR: use 192.168.1.50, 192.168.1.0/24, or an IPv6 address/prefix; URLs, ports, hostnames and dash ranges are not accepted", raw)
	}
	if p.Addr().Is4In6() {
		if p.Bits() < 96 {
			return netip.Prefix{}, fmt.Errorf("mapped IPv4 prefixes must use /96 or longer")
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	p = p.Masked()
	if p.Bits() == 0 || p.Addr().IsUnspecified() || p.Addr().IsMulticast() || p.Addr().IsLinkLocalUnicast() {
		return netip.Prefix{}, fmt.Errorf("%q is not a supported client grant; never use a wildcard/default route to repair access", raw)
	}
	// The wizard deliberately excludes enormous grants. The existing advanced
	// network editor retains the application's full validation and aggregate guard.
	if (p.Addr().Is4() && p.Bits() < 8) || (p.Addr().Is6() && p.Bits() < 16) {
		return netip.Prefix{}, fmt.Errorf("%q is too broad for guided setup; use your actual assigned subnet", raw)
	}
	return p, nil
}

var localRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("100.64.0.0/10"),
}

func scope(p netip.Prefix) string {
	if (p.Addr().Is4() && p.Bits() >= 8 && netip.MustParsePrefix("127.0.0.0/8").Contains(p.Addr())) || (p.Addr().Is6() && p.Bits() == 128 && p.Addr().IsLoopback()) {
		return "loopback"
	}
	for _, r := range localRanges {
		if r.Bits() <= p.Bits() && r.Contains(p.Addr()) {
			if r.String() == "100.64.0.0/10" {
				return "shared"
			}
			return "private"
		}
	}
	return "public"
}

func Build(in Input) (Plan, error) {
	var out Plan
	valid := false
	for _, p := range Presets() {
		if p.ID == in.Preset {
			valid = true
		}
	}
	if !valid {
		return out, fmt.Errorf("choose a deployment preset")
	}
	if in.DNSPort == 0 {
		in.DNSPort = 53
		if in.Preset == "local" {
			in.DNSPort = 5353
		}
	}
	if in.Mode == "" {
		in.Mode = "off"
	}
	if in.Mode != "off" && in.Mode != "observe" && in.Mode != "enforce" {
		return out, fmt.Errorf("mode must be off, observe or enforce")
	}
	endpoint, err := Endpoint(in.ServerIP, in.DNSPort)
	if err != nil {
		return out, err
	}
	ep := netip.MustParseAddrPort(endpoint)
	server := ep.Addr()
	if in.Preset == "local" && !server.IsLoopback() {
		return out, fmt.Errorf("local development requires a loopback server IP")
	}
	if in.Preset != "local" && server.IsLoopback() {
		return out, fmt.Errorf("other devices cannot use your server's loopback address; enter its LAN, VPN or public IP")
	}
	out = Plan{Preset: in.Preset, Endpoint: endpoint, Addresses: []Address{}, CIDRs: []string{}, Warnings: []string{}, GrantSourceAccess: in.Preset != "roaming"}
	if len(in.Clients) > 4096 {
		return out, fmt.Errorf("client input is limited to 4096 characters")
	}
	parts := strings.FieldsFunc(in.Clients, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\t' || r == '\r'
	})
	if in.Preset == "roaming" && len(parts) != 0 {
		return out, fmt.Errorf("roaming uses an enabled network token, not source-IP grants; leave client addresses empty")
	}
	if len(parts) == 0 && in.Preset != "roaming" {
		return out, fmt.Errorf("enter at least one client IP or network")
	}
	if len(parts) > 32 {
		return out, fmt.Errorf("guided setup accepts at most 32 addresses or prefixes")
	}
	seen := map[string]bool{}
	for _, raw := range parts {
		p, err := ParseClient(raw)
		if err != nil {
			return out, err
		}
		s := scope(p)
		if in.Preset == "local" && s != "loopback" {
			return out, fmt.Errorf("local development permits only loopback clients")
		}
		if in.Preset == "vps" && s != "public" {
			return out, fmt.Errorf("a public VPS normally sees the site's public egress IP, not %s; use the VPN preset for a routed private connection", p)
		}
		if (in.Preset == "lan" || in.Preset == "vpn") && s == "public" {
			out.Warnings = append(out.Warnings, "This prefix is not wholly private/shared. Use it only when it is your assigned source prefix; public-address confirmation is required.")
		}
		if in.Preset == "device" && p.Bits() != p.Addr().BitLen() {
			return out, fmt.Errorf("One device requires an IPv4 /32 or IPv6 /128; choose LAN or VPN for a subnet")
		}
		if seen[p.String()] {
			continue
		}
		seen[p.String()] = true
		out.CIDRs = append(out.CIDRs, p.String())
		out.Addresses = append(out.Addresses, Address{p.String(), s, p.Bits() == p.Addr().BitLen()})
		out.PublicAckRequired = out.PublicAckRequired || s == "public"
	}
	if in.Preset == "vps" {
		out.Warnings = append(out.Warnings, "A public egress /32 permits every device behind that NAT address, not one named device. A changing ISP IP will need updating; use VPN or tokenised DoH for roaming.")
	}
	if in.Preset == "roaming" {
		out.Warnings = append(out.Warnings, "HTTPS must already be configured with a valid certificate. Network tokens are credentials: do not publish screenshots or URLs containing them. No incoming DoQ listener is implied.")
	}
	if in.DNSPort != 53 {
		out.Warnings = append(out.Warnings, "Many operating-system DNS settings accept an IP only and require port 53. Use the displayed port with dig or a client that supports custom ports.")
	}
	if in.Mode != "off" {
		out.Warnings = append(out.Warnings, "Learn/Live on native transport require outbound UDP/TCP 53. Live is experimental and fails closed on bogus or inconclusive DNSSEC; this plan never adds a fallback.")
	}
	out.Warnings = append(out.Warnings, "Saving an advertised address does not create a listener, firewall rule, NAT mapping, VPN or certificate. Test from a permitted device.", "Generated files are starter configurations for a new installation, not an automatic replacement for an existing custom configuration. Source access is granted separately with Apply network in the dashboard.")
	host := server.String()
	out.UDPTest = fmt.Sprintf("dig @%s -p %d example.com A +time=3 +tries=1", host, in.DNSPort)
	out.TCPTest = out.UDPTest + " +tcp"
	// Loopback-only bootstrap makes the explicit managed-network grant the
	// authority on both old and new first-run defaults. No dependence on #84.
	out.Environment = fmt.Sprintf("# Generated starter: %s\n# Keep your existing .env and data when upgrading.\nDNSDADDY_ADVERTISED_DNS=%s\nDNSDADDY_ALLOWED_CLIENT_CIDRS=127.0.0.0/8,::1/128\nDNSDADDY_ALLOW_PUBLIC_RESOLVER=false\nDNSDADDY_UPSTREAMS=https://1.1.1.1/dns-query,https://1.0.0.1/dns-query\nDNSDADDY_UPSTREAM_MODE=failover\nDNSDADDY_LOCAL_DNSSEC_VALIDATION=%s\nDNSDADDY_DASHBOARD_BIND=127.0.0.1\n", in.Preset, endpoint, in.Mode)
	listen := endpoint
	if in.Preset == "vps" {
		// A public NAT address may not exist on this host.
		listen = ":" + strconv.Itoa(in.DNSPort)
	}
	if in.Preset == "roaming" {
		// Roaming clients use tokenised HTTPS, not public plaintext DNS.
		listen = "127.0.0.1:5353"
	}
	out.NativeYAML = fmt.Sprintf("# Generated native starter. Keep management behind SSH or HTTPS.\n# Add the reviewed client Network in the dashboard after installation.\ndata_dir: /var/lib/dnsdaddy\ndns:\n  advertised_endpoint: %q\n  listen_udp: %q\n  listen_tcp: %q\n  allowed_client_cidrs: [\"127.0.0.0/8\", \"::1/128\"]\n  allow_public_resolver: false\n  upstreams: [\"https://1.1.1.1/dns-query\", \"https://1.0.0.1/dns-query\"]\n  upstream_mode: failover\n  local_dnssec_validation: %q\nhttp:\n  listen: \"127.0.0.1:8080\"\n  allow_untokenized_doh: false\n", endpoint, listen, listen, in.Mode)
	bind := server.String()
	if in.Preset == "vps" {
		bind = "0.0.0.0"
		if server.Is6() {
			bind = "::"
		}
	}
	// Do not bind an advertised public NAT IP that may not exist on the host.
	// The source ACL remains closed until the reviewed managed grant is applied.
	ports := fmt.Sprintf("    - %q\n    - %q\n", net.JoinHostPort(bind, strconv.Itoa(in.DNSPort))+":5353/udp", net.JoinHostPort(bind, strconv.Itoa(in.DNSPort))+":5353/tcp")
	if in.Preset == "roaming" {
		ports = ""
	}
	out.ComposeOverride = "# Requires Docker Compose 2.24.4+ (!override).\n# Use with the repository's docker-compose.yml; do not remove volumes.\nservices:\n  dnsdaddy:\n    ports: !override\n" + strings.ReplaceAll(ports, "    -", "      -") + "      - \"127.0.0.1:8080:8080\"\n"
	return out, nil
}
