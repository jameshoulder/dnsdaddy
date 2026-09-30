package api

import (
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/jameshoulder/dnsdaddy/internal/config"
)

const (
	serverAddressLimit          = 32
	serverInterfaceLimit        = 256
	serverInterfaceAddressLimit = 128
)

// ServerAddressesResponse reports local interface or accepted socket evidence,
// not the browser's Host header or an assumed public address. Containers and
// NAT make those very different things, so the response keeps configured
// listeners and candidate client endpoints separate and never calls an external
// discovery service.
type ServerAddressesResponse struct {
	Source           string              `json:"source"`
	PreferredAddress *string             `json:"preferredAddress"`
	Addresses        []ServerAddress     `json:"addresses"`
	Listeners        []ServerDNSListener `json:"listeners"`
	Limit            int                 `json:"limit"`
	Truncated        bool                `json:"truncated"`
	Partial          bool                `json:"partial"`
	Notes            []string            `json:"notes"`
}

type ServerAddress struct {
	Address   string              `json:"address"`
	Family    string              `json:"family"`
	Type      string              `json:"type"`
	Interface string              `json:"interface"`
	DNS       []ServerDNSEndpoint `json:"dns"`
	addr      netip.Addr
	loopback  bool
}

type ServerDNSEndpoint struct {
	Transport string `json:"transport"`
	Port      int    `json:"port"`
	Endpoint  string `json:"endpoint"`
}

type ServerDNSListener struct {
	Transport string `json:"transport"`
	Listen    string `json:"listen"`
	Enabled   bool   `json:"enabled"`
	Port      *int   `json:"port"`
	Binding   string `json:"binding"`
	addr      netip.Addr
}

type serverInterface struct {
	info      net.Interface
	addresses []string
}

type serverInterfaceSnapshot struct {
	interfaces []serverInterface
	truncated  bool
	partial    bool
}

func (a *API) handleServerAddresses(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	read := a.serverInterfaces
	if read == nil {
		read = localServerInterfaces
	}
	snapshot, err := read()
	if err != nil {
		if a.Log != nil {
			a.Log.Warn("read local server interfaces", "error", err)
		}
		if fallback, ok := serverConnectionAddress(a.Config.DNS, r); ok {
			writeJSON(w, http.StatusOK, fallback)
			return
		}
		writeError(w, http.StatusServiceUnavailable, "Server interface addresses could not be read. Check host network permissions and configure clients using the deployment's DNS address.")
		return
	}
	writeJSON(w, http.StatusOK, serverAddresses(a.Config.DNS, snapshot))
}

// net/http supplies LocalAddrContextKey from the accepted server connection.
// It is independent of Host, forwarding headers and the peer address. This
// permits a truthful, explicitly incomplete answer when host hardening denies
// interface enumeration, without relaxing service permissions or making an
// external request. The management connection's port is never a DNS port.
func serverConnectionAddress(cfg config.DNS, r *http.Request) (ServerAddressesResponse, bool) {
	local, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if !ok || local == nil {
		return ServerAddressesResponse{}, false
	}
	socket, err := netip.ParseAddrPort(local.String())
	if err != nil || socket.Port() == 0 {
		return ServerAddressesResponse{}, false
	}
	address := socket.Addr().Unmap().WithZone("")
	if serverAddressType(address) == "" {
		return ServerAddressesResponse{}, false
	}
	out := serverAddresses(cfg, serverInterfaceSnapshot{partial: true, interfaces: []serverInterface{{
		info: net.Interface{Flags: net.FlagUp}, addresses: []string{address.String()},
	}}})
	out.Source = "connection_local_address"
	out.Notes = append([]string{
		"Interface enumeration is unavailable. This is only the server-side local IP of the accepted dashboard connection; the interface name and other interface addresses are unknown. It is not taken from request headers or the client address.",
		"A reverse proxy, tunnel or container may make this connection address loopback or private. It does not reveal an external/NAT address or guarantee that another device can reach a DNS listener.",
	}, out.Notes...)
	return out, true
}

func localServerInterfaces() (serverInterfaceSnapshot, error) {
	return readServerInterfaces(net.Interfaces, func(iface net.Interface) ([]net.Addr, error) {
		return iface.Addrs()
	})
}

// Bounds apply before reading each interface's addresses; down interfaces are
// neither queried nor suggested. The OS APIs return a complete local slice,
// but the response and subsequent processing remain bounded.
func readServerInterfaces(list func() ([]net.Interface, error), addresses func(net.Interface) ([]net.Addr, error)) (serverInterfaceSnapshot, error) {
	var out serverInterfaceSnapshot
	interfaces, err := list()
	if err != nil {
		return out, err
	}
	interfaces = slices.DeleteFunc(interfaces, func(iface net.Interface) bool { return iface.Flags&net.FlagUp == 0 })
	slices.SortFunc(interfaces, func(a, b net.Interface) int {
		if n := strings.Compare(a.Name, b.Name); n != 0 {
			return n
		}
		return a.Index - b.Index
	})
	if len(interfaces) > serverInterfaceLimit {
		interfaces = interfaces[:serverInterfaceLimit]
		out.truncated = true
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Name == "" || len(iface.Name) > 128 {
			out.partial = true
			continue
		}
		values, err := addresses(iface)
		if err != nil {
			out.partial = true
			continue
		}
		entry := serverInterface{info: iface, addresses: make([]string, 0, min(len(values), serverInterfaceAddressLimit))}
		// Keep the smallest bounded prefix even if OS address order changes.
		for _, value := range values {
			if value == nil {
				continue
			}
			raw := value.String()
			if len(raw) > 256 {
				out.partial = true
				continue
			}
			index, found := slices.BinarySearch(entry.addresses, raw)
			if found {
				continue
			}
			if len(entry.addresses) == serverInterfaceAddressLimit {
				out.truncated = true
				if index == len(entry.addresses) {
					continue
				}
				entry.addresses = entry.addresses[:len(entry.addresses)-1]
			}
			entry.addresses = slices.Insert(entry.addresses, index, raw)
		}
		out.interfaces = append(out.interfaces, entry)
	}
	return out, nil
}

func serverAddresses(cfg config.DNS, snapshot serverInterfaceSnapshot) ServerAddressesResponse {
	out := ServerAddressesResponse{
		Source: "local_interfaces", Addresses: []ServerAddress{}, Limit: serverAddressLimit,
		Truncated: snapshot.truncated, Partial: snapshot.partial,
		Listeners: []ServerDNSListener{
			serverListener("udp", cfg.ListenUDP),
			serverListener("tcp", cfg.ListenTCP),
			serverListener("dot", cfg.ListenDoT),
		},
		Notes: []string{
			"These are local addresses visible to this DNS Daddy process. Containers and NAT may expose a different host/public IP or mapped port; no external IP discovery is performed.",
			"DNS endpoints reflect configured listeners, not a reachability test. Client access rules, firewall, routing and operating-system IPv6 behavior still apply.",
		},
	}
	for _, iface := range snapshot.interfaces {
		if iface.info.Flags&net.FlagUp == 0 {
			continue
		}
		for _, raw := range iface.addresses {
			address, ok := serverInterfaceIP(raw)
			if !ok {
				continue
			}
			kind := serverAddressType(address)
			if kind == "" {
				continue
			}
			item := ServerAddress{
				Address: address.String(), Family: "ipv6", Type: kind, Interface: iface.info.Name,
				DNS: []ServerDNSEndpoint{}, addr: address, loopback: iface.info.Flags&net.FlagLoopback != 0,
			}
			if address.Is4() {
				item.Family = "ipv4"
			}
			// A link-local IPv6 scope is the client's interface, not the
			// server's interface name. Do not manufacture a portable endpoint
			// containing a zone that would refer to a different device.
			if kind != "link_local" {
				for _, listener := range out.Listeners {
					if listener.matches(address, iface.info.Name) {
						item.DNS = append(item.DNS, ServerDNSEndpoint{
							Transport: listener.Transport, Port: *listener.Port,
							Endpoint: net.JoinHostPort(item.Address, strconv.Itoa(*listener.Port)),
						})
					}
				}
			}
			index, found := slices.BinarySearchFunc(out.Addresses, item, compareServerAddresses)
			if found {
				continue
			}
			if len(out.Addresses) == serverAddressLimit {
				out.Truncated = true
				if index == len(out.Addresses) {
					continue
				}
				out.Addresses = out.Addresses[:len(out.Addresses)-1]
			}
			out.Addresses = slices.Insert(out.Addresses, index, item)
		}
	}
	for _, address := range out.Addresses {
		if address.preferredCandidate() {
			preferred := address.Address
			out.PreferredAddress = &preferred
			break
		}
	}
	if out.PreferredAddress == nil {
		out.Notes = append(out.Notes, "No non-loopback, non-link-local interface address matches a configured DNS listener. Check listen addresses and deployment port mappings before configuring another device.")
	}
	if out.Partial {
		out.Notes = append(out.Notes, "Some local interface addresses could not be read; this list is incomplete.")
	}
	if out.Truncated {
		out.Notes = append(out.Notes, "The local interface/address limit was reached; this list is truncated.")
	}
	for _, listener := range out.Listeners {
		if listener.Binding == "hostname" || listener.Binding == "invalid" {
			out.Notes = append(out.Notes, "A configured listener could not be mapped to an IP and fixed numeric port without name resolution. It has no inferred client endpoints in this response.")
			break
		}
	}
	if cfg.ListenDoT != "" {
		out.Notes = append(out.Notes, "DNS-over-TLS clients also need the certificate-matching server name and any required network-token hostname; an IP and port alone do not establish TLS identity.")
	}
	if slices.ContainsFunc(out.Addresses, func(a ServerAddress) bool { return a.Type == "link_local" }) {
		out.Notes = append(out.Notes, "Link-local addresses require the same network link; IPv6 also needs the client's interface scope. They are not suggested as portable DNS endpoints.")
	}
	return out
}

func (a ServerAddress) preferredCandidate() bool {
	return !a.loopback && (a.Type == "private" || a.Type == "public") && len(a.DNS) > 0
}

func compareServerAddresses(a, b ServerAddress) int {
	if a.preferredCandidate() != b.preferredCandidate() {
		if a.preferredCandidate() {
			return -1
		}
		return 1
	}
	order := func(address ServerAddress) int {
		switch address.Type {
		case "private":
			if serverSharedIPv4.Contains(address.addr) {
				return 1
			}
			return 0
		case "public":
			return 2
		case "loopback":
			return 3
		default:
			return 4
		}
	}
	if n := order(a) - order(b); n != 0 {
		return n
	}
	if a.addr.Is4() != b.addr.Is4() {
		if a.addr.Is4() {
			return -1
		}
		return 1
	}
	if n := a.addr.Compare(b.addr); n != 0 {
		return n
	}
	return strings.Compare(a.Interface, b.Interface)
}

func serverListener(transport, raw string) ServerDNSListener {
	l := ServerDNSListener{Transport: transport, Listen: raw, Binding: "disabled", Enabled: raw != ""}
	if !l.Enabled {
		return l
	}
	l.Binding = "invalid"
	host, port, err := net.SplitHostPort(raw)
	if err != nil {
		return l
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return l
	}
	l.Port = &n
	if host == "" {
		l.Binding = "all"
		return l
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		l.Binding = "hostname"
		return l
	}
	l.addr = address.Unmap()
	l.Binding = "address"
	if l.addr.IsUnspecified() {
		l.Binding = "ipv6"
		if l.addr.Is4() {
			l.Binding = "ipv4"
		}
	}
	return l
}

func (l ServerDNSListener) matches(address netip.Addr, iface string) bool {
	if l.Port == nil {
		return false
	}
	switch l.Binding {
	case "all":
		return true
	case "ipv4":
		return address.Is4()
	case "ipv6":
		// An IPv6 socket may also receive IPv4 on some hosts. Without the
		// actual socket state, promising that would invent reachability.
		return address.Is6()
	case "address":
		return address == l.addr.WithZone("") && (l.addr.Zone() == "" || l.addr.Zone() == iface)
	default:
		return false
	}
}

func serverInterfaceIP(raw string) (netip.Addr, bool) {
	var address netip.Addr
	bits := -1
	if prefix, err := netip.ParsePrefix(raw); err == nil {
		address, bits = prefix.Addr(), prefix.Bits()
	} else {
		var err error
		address, err = netip.ParseAddr(raw)
		if err != nil {
			return netip.Addr{}, false
		}
	}
	if address.Is4In6() && bits >= 0 {
		if bits < 96 {
			return netip.Addr{}, false
		}
		bits -= 96
	}
	address = address.Unmap().WithZone("")
	if address.Is4() && bits >= 0 && bits < 31 {
		// Directed broadcast/network addresses are not host targets. /31
		// point-to-point addresses and /32 host routes remain legitimate.
		b := address.As4()
		value := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		hostMask := ^uint32(0) >> uint(bits)
		if value&hostMask == 0 || value&hostMask == hostMask {
			return netip.Addr{}, false
		}
	}
	return address, true
}

var serverSharedIPv4 = netip.MustParsePrefix("100.64.0.0/10")

// These are unsuitable host suggestions even though IsGlobalUnicast can
// accept them. Classification is address scope, never an internet probe.
var serverUnusableRanges = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("100::/64"), netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("3fff::/20"), netip.MustParsePrefix("fec0::/10"),
}

func serverAddressType(address netip.Addr) string {
	switch {
	case !address.IsValid() || address.IsUnspecified() || address.IsMulticast():
		return ""
	case address.IsLoopback():
		return "loopback"
	case address.IsLinkLocalUnicast():
		return "link_local"
	case address.IsPrivate() || serverSharedIPv4.Contains(address):
		// Shared CGNAT space also supports private overlay networks. Calling
		// a Tailscale address publicly reachable would misdirect setup.
		return "private"
	case !address.IsGlobalUnicast():
		return ""
	}
	for _, prefix := range serverUnusableRanges {
		if prefix.Contains(address) {
			return ""
		}
	}
	return "public"
}
