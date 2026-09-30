package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/config"
)

func addressFixture(name string, flags net.Flags, values ...string) serverInterface {
	return serverInterface{info: net.Interface{Name: name, Flags: flags}, addresses: values}
}

func TestServerAddressesPreferUsableLANAndRespectListenerFamilies(t *testing.T) {
	input := serverInterfaceSnapshot{interfaces: []serverInterface{
		addressFixture("eth0", net.FlagUp, "192.168.40.12/24", "::ffff:192.168.40.12/120", "fd42::5/64", "fe80::1/64", "169.254.4.9/16"),
		addressFixture("wan0", net.FlagUp, "8.8.4.4/24", "2606:4700:4700::1111/64"),
		addressFixture("overlay0", net.FlagUp|net.FlagPointToPoint, "100.64.25.1/32"),
		addressFixture("lo", net.FlagUp|net.FlagLoopback, "127.0.0.1/8", "::1/128"),
		addressFixture("down", 0, "10.0.0.2/24"),
		addressFixture("invalid", net.FlagUp, "0.0.0.0/0", "::/0", "224.0.0.1/4", "ff02::1/64", "192.168.40.255/24", "192.168.40.0/24", "192.0.2.1/24", "2001:db8::1/64", "not an IP"),
	}}
	cfg := config.DNS{ListenUDP: "0.0.0.0:5353", ListenTCP: "[::]:5354", ListenDoT: "192.168.40.12:8853"}
	out := serverAddresses(cfg, input)
	if out.PreferredAddress == nil || *out.PreferredAddress != "192.168.40.12" {
		t.Fatalf("did not prefer compatible LAN IPv4: %+v", out)
	}
	if len(out.Addresses) != 9 || out.Partial || out.Truncated {
		t.Fatalf("invalid, duplicate or down address survived: %+v", out.Addresses)
	}
	want := map[string]struct {
		kind, family string
		targets      []ServerDNSEndpoint
	}{
		"192.168.40.12":        {"private", "ipv4", []ServerDNSEndpoint{{"udp", 5353, "192.168.40.12:5353"}, {"dot", 8853, "192.168.40.12:8853"}}},
		"fd42::5":              {"private", "ipv6", []ServerDNSEndpoint{{"tcp", 5354, "[fd42::5]:5354"}}},
		"100.64.25.1":          {"private", "ipv4", []ServerDNSEndpoint{{"udp", 5353, "100.64.25.1:5353"}}},
		"8.8.4.4":              {"public", "ipv4", []ServerDNSEndpoint{{"udp", 5353, "8.8.4.4:5353"}}},
		"2606:4700:4700::1111": {"public", "ipv6", []ServerDNSEndpoint{{"tcp", 5354, "[2606:4700:4700::1111]:5354"}}},
		"127.0.0.1":            {"loopback", "ipv4", []ServerDNSEndpoint{{"udp", 5353, "127.0.0.1:5353"}}},
		"::1":                  {"loopback", "ipv6", []ServerDNSEndpoint{{"tcp", 5354, "[::1]:5354"}}},
		"fe80::1":              {"link_local", "ipv6", []ServerDNSEndpoint{}},
		"169.254.4.9":          {"link_local", "ipv4", []ServerDNSEndpoint{}},
	}
	for _, address := range out.Addresses {
		expected, ok := want[address.Address]
		if !ok || address.Type != expected.kind || address.Family != expected.family || !reflect.DeepEqual(address.DNS, expected.targets) || address.Interface == "" {
			t.Errorf("unexpected candidate %+v", address)
		}
	}
	if out.Listeners[0].Binding != "ipv4" || out.Listeners[1].Binding != "ipv6" || out.Listeners[2].Binding != "address" {
		t.Fatalf("wildcard family was lost: %+v", out.Listeners)
	}
}

func TestServerAddressesNeverSuggestAnUnboundOrScopedAddress(t *testing.T) {
	input := serverInterfaceSnapshot{interfaces: []serverInterface{
		addressFixture("eth0", net.FlagUp, "192.168.1.2/24", "192.168.1.3/24", "fd42::1/64", "fe80::2%eth0"),
		addressFixture("lo", net.FlagUp|net.FlagLoopback, "127.0.0.1/8", "::1/128"),
	}}
	for _, cfg := range []config.DNS{
		{ListenUDP: "127.0.0.1:53", ListenTCP: "[::1]:53"},
		{ListenUDP: "[fe80::2%eth0]:53"},
		{ListenUDP: "resolver.example.invalid:53"},
		{ListenUDP: ":0", ListenTCP: ":70000", ListenDoT: "missing-port"},
		{},
	} {
		out := serverAddresses(cfg, input)
		if out.PreferredAddress != nil {
			t.Errorf("invented portable DNS target for %+v: %+v", cfg, out)
		}
		for _, a := range out.Addresses {
			if a.Type != "loopback" && len(a.DNS) != 0 {
				t.Errorf("unbound/scoped address acquired a target: %+v", a)
			}
		}
	}
	out := serverAddresses(config.DNS{ListenUDP: "192.168.1.3:1053", ListenDoT: "[fd42::1]:853"}, input)
	if out.PreferredAddress == nil || *out.PreferredAddress != "192.168.1.3" {
		t.Fatalf("selected unbound smaller address instead of exact listener: %+v", out)
	}
	for _, a := range out.Addresses {
		if a.Address == "192.168.1.2" && len(a.DNS) != 0 {
			t.Fatalf("exact binding was treated as wildcard: %+v", a)
		}
	}
}

func TestServerAddressesRemainDeterministicAndBoundedWithManyInterfaces(t *testing.T) {
	var input serverInterfaceSnapshot
	for i := 1; i <= 100; i++ {
		input.interfaces = append(input.interfaces, addressFixture(fmt.Sprintf("lan%03d", i), net.FlagUp, fmt.Sprintf("10.0.0.%d/24", i)))
	}
	input.interfaces = append(input.interfaces, addressFixture("wan", net.FlagUp, "8.8.8.8/32"))
	cfg := config.DNS{ListenUDP: "8.8.8.8:53"}
	out := serverAddresses(cfg, input)
	if !out.Truncated || len(out.Addresses) != serverAddressLimit || out.PreferredAddress == nil || *out.PreferredAddress != "8.8.8.8" {
		t.Fatalf("bounded list hid the actual configured target: %+v", out)
	}
	slices.Reverse(input.interfaces)
	again := serverAddresses(cfg, input)
	if !reflect.DeepEqual(out, again) {
		t.Fatal("OS enumeration order changed the selected/listed addresses")
	}
}

func TestServerInterfaceDiscoverySkipsDownInterfacesAndReportsIncompleteReads(t *testing.T) {
	called := []string{}
	snapshot, err := readServerInterfaces(func() ([]net.Interface, error) {
		return []net.Interface{
			{Name: "down", Flags: 0}, {Name: "unreadable", Flags: net.FlagUp}, {Name: "eth0", Flags: net.FlagUp},
		}, nil
	}, func(iface net.Interface) ([]net.Addr, error) {
		called = append(called, iface.Name)
		if iface.Name == "unreadable" {
			return nil, errors.New("fixture interface read failed")
		}
		return []net.Addr{&net.IPNet{IP: net.ParseIP("192.168.1.10"), Mask: net.CIDRMask(24, 32)}}, nil
	})
	if err != nil || !snapshot.partial || snapshot.truncated || len(snapshot.interfaces) != 1 || !reflect.DeepEqual(called, []string{"eth0", "unreadable"}) {
		t.Fatalf("interface failure/down state was hidden: %+v calls=%v err=%v", snapshot, called, err)
	}
	if _, err := readServerInterfaces(func() ([]net.Interface, error) { return nil, errors.New("fixture failure") }, nil); err == nil {
		t.Fatal("failed enumeration was presented as an empty successful list")
	}
}

func TestServerInterfaceDiscoveryBoundsInterfacesAndAddresses(t *testing.T) {
	interfaces := make([]net.Interface, serverInterfaceLimit+1)
	for i := range interfaces {
		interfaces[i] = net.Interface{Name: fmt.Sprintf("net%04d", i), Flags: net.FlagUp}
	}
	calls := 0
	snapshot, err := readServerInterfaces(func() ([]net.Interface, error) { return interfaces, nil }, func(iface net.Interface) ([]net.Addr, error) {
		calls++
		addresses := make([]net.Addr, serverInterfaceAddressLimit+1)
		for i := range addresses {
			addresses[i] = &net.IPAddr{IP: net.ParseIP(fmt.Sprintf("10.0.%d.%d", iface.Index, i+1))}
		}
		return addresses, nil
	})
	if err != nil || !snapshot.truncated || calls != serverInterfaceLimit || len(snapshot.interfaces) != serverInterfaceLimit {
		t.Fatalf("interface scan not bounded: calls=%d len=%d truncated=%v err=%v", calls, len(snapshot.interfaces), snapshot.truncated, err)
	}
	for _, iface := range snapshot.interfaces {
		if len(iface.addresses) != serverInterfaceAddressLimit {
			t.Fatalf("address list not bounded: %d", len(iface.addresses))
		}
	}
}

func TestServerAddressFilteringKeepsPointToPointAndHostRoutes(t *testing.T) {
	for _, value := range []string{"192.168.1.0/31", "192.168.1.1/31", "192.168.1.0/32", "192.168.1.255/32"} {
		if _, ok := serverInterfaceIP(value); !ok {
			t.Errorf("valid point-to-point/host address was excluded: %s", value)
		}
	}
}

func TestServerAddressesAreAuthenticatedAndNeverReflectRequestHeaders(t *testing.T) {
	h := newHarness(t)
	reads := 0
	h.api.serverInterfaces = func() (serverInterfaceSnapshot, error) {
		reads++
		return serverInterfaceSnapshot{interfaces: []serverInterface{
			addressFixture("test-lan", net.FlagUp, "192.168.40.12/24", "fd42::5/64"),
		}}, nil
	}
	resp, raw := h.do(http.MethodGet, "/api/v1/server-addresses", nil)
	if resp.StatusCode != http.StatusUnauthorized || strings.Contains(string(raw), "addresses") || reads != 0 {
		t.Fatalf("addresses exposed without authentication: status=%d body=%s", resp.StatusCode, raw)
	}
	// The feature must not piggyback on loopback/public health tiers.
	_, raw = h.do(http.MethodGet, "/api/v1/health", nil)
	if strings.Contains(string(raw), "preferredAddress") || strings.Contains(string(raw), "local_interfaces") {
		t.Fatalf("health exposed the address inventory: %s", raw)
	}
	h.login()
	req, err := http.NewRequest(http.MethodGet, h.server.URL+"/api/v1/server-addresses", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "attacker.example.invalid:60000"
	req.Header.Set("X-Forwarded-Host", "forged.example.invalid")
	req.Header.Set("X-Forwarded-For", "198.51.100.99")
	req.Header.Set("X-Real-IP", "203.0.113.77")
	req.Header.Set("Forwarded", `for="198.51.100.99";host="forged.example.invalid"`)
	resp, err = h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err = io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("authenticated inventory failed: %d %s", resp.StatusCode, raw)
	}
	for _, forged := range []string{"attacker.example.invalid", "forged.example.invalid", "198.51.100.99", "203.0.113.77", "60000"} {
		if strings.Contains(string(raw), forged) {
			t.Errorf("reflected a request-supplied address %q: %s", forged, raw)
		}
	}
	var out ServerAddressesResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.Source != "local_interfaces" || len(out.Addresses) != 2 || len(out.Listeners) != 3 || reads != 1 {
		t.Fatalf("unexpected inventory shape: %+v", out)
	}
	if out.PreferredAddress != nil && !slices.ContainsFunc(out.Addresses, func(a ServerAddress) bool {
		return a.Address == *out.PreferredAddress && len(a.DNS) > 0 && (a.Type == "private" || a.Type == "public")
	}) {
		t.Fatalf("preferred IP is not an eligible returned target: %+v", out)
	}
}

func TestServerAddressesDiscoveryFailureUsesOnlyTheAcceptedSocketLocalAddress(t *testing.T) {
	h := newHarness(t)
	h.api.serverInterfaces = func() (serverInterfaceSnapshot, error) {
		return serverInterfaceSnapshot{}, errors.New("fixture netlink failure with private implementation detail")
	}
	resp, raw := h.do(http.MethodGet, "/api/v1/server-addresses", nil)
	if resp.StatusCode != http.StatusUnauthorized || strings.Contains(string(raw), "connection_local_address") {
		t.Fatalf("socket address exposed without authentication: %d %s", resp.StatusCode, raw)
	}
	h.login()
	req, err := http.NewRequest(http.MethodGet, h.server.URL+"/api/v1/server-addresses", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "attacker.example.invalid:60000"
	for key, value := range map[string]string{
		"X-Forwarded-Host": "forged.example.invalid",
		"X-Forwarded-For":  "192.168.50.50", "X-Real-IP": "192.168.60.60",
		"Forwarded": `for="192.168.70.70";host="forged.example.invalid"`,
	} {
		req.Header.Set(key, value)
	}
	resp, err = h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err = io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("accepted connection fallback failed: %d %s", resp.StatusCode, raw)
	}
	var out ServerAddressesResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.Source != "connection_local_address" || !out.Partial || out.Truncated || len(out.Addresses) != 1 || out.PreferredAddress != nil {
		t.Fatalf("fallback claimed a complete inventory or portable loopback target: %+v", out)
	}
	address := out.Addresses[0]
	if address.Address != "127.0.0.1" || address.Type != "loopback" || address.Family != "ipv4" || address.Interface != "" {
		t.Fatalf("did not report the actual accepted local socket with unknown interface: %+v", address)
	}
	for _, endpoint := range address.DNS {
		if endpoint.Port != 53 || endpoint.Endpoint != "127.0.0.1:53" {
			t.Fatalf("management connection port became a DNS endpoint: %+v", endpoint)
		}
	}
	for _, forbidden := range []string{"attacker.example.invalid", "forged.example.invalid", "192.168.50.50", "192.168.60.60", "192.168.70.70", "netlink", "implementation detail"} {
		if strings.Contains(string(raw), forbidden) {
			t.Errorf("fallback reflected private error details or headers %q: %s", forbidden, raw)
		}
	}
}

func TestServerAddressSocketFallbackUsesOnlyCompatibleDNSListeners(t *testing.T) {
	for _, test := range []struct {
		local                     string
		cfg                       config.DNS
		wantAddress, wantEndpoint string
		preferred                 bool
	}{
		{"192.168.40.12:8080", config.DNS{ListenUDP: ":1053"}, "192.168.40.12", "192.168.40.12:1053", true},
		{"[fd42::5]:8443", config.DNS{ListenTCP: "[::]:5353"}, "fd42::5", "[fd42::5]:5353", true},
		{"[fd42::5]:8443", config.DNS{ListenUDP: "0.0.0.0:53"}, "fd42::5", "", false},
		{"192.168.40.12:8080", config.DNS{ListenUDP: "192.168.40.13:53"}, "192.168.40.12", "", false},
		{"[fe80::5%eth0]:8080", config.DNS{ListenUDP: "[::]:53"}, "fe80::5", "", false},
	} {
		t.Run(test.local+test.cfg.ListenUDP+test.cfg.ListenTCP, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/api/v1/server-addresses", nil)
			r.RemoteAddr = "192.168.99.99:5000"
			r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, socketAddressFixture(test.local)))
			out, ok := serverConnectionAddress(test.cfg, r)
			if !ok || out.Source != "connection_local_address" || !out.Partial || len(out.Addresses) != 1 || out.Addresses[0].Address != test.wantAddress || (out.PreferredAddress != nil) != test.preferred {
				t.Fatalf("invalid socket fallback: %+v ok=%v", out, ok)
			}
			if test.wantEndpoint == "" {
				if len(out.Addresses[0].DNS) != 0 {
					t.Fatalf("invented matching listener: %+v", out.Addresses[0])
				}
			} else if len(out.Addresses[0].DNS) != 1 || out.Addresses[0].DNS[0].Endpoint != test.wantEndpoint {
				t.Fatalf("wrong DNS endpoint: %+v", out.Addresses[0])
			}
		})
	}
}

type socketAddressFixture string

func (a socketAddressFixture) Network() string { return "tcp" }
func (a socketAddressFixture) String() string  { return string(a) }

func TestServerAddressesDiscoveryFailureWithUnusableSocketContextRemainsUnavailable(t *testing.T) {
	a := &API{serverInterfaces: func() (serverInterfaceSnapshot, error) {
		return serverInterfaceSnapshot{}, errors.New("fixture netlink failure with private implementation detail")
	}}
	for _, local := range []any{nil, "192.168.1.10:8080", socketAddressFixture("resolver.example:8080"), socketAddressFixture("0.0.0.0:8080"), socketAddressFixture("[::]:8080"), socketAddressFixture("224.0.0.1:8080"), socketAddressFixture("192.168.1.10:0"), socketAddressFixture("not an address")} {
		r := httptest.NewRequest(http.MethodGet, "http://192.168.70.70:8080/api/v1/server-addresses", nil)
		r.RemoteAddr = "192.168.99.99:5000"
		r.Header.Set("X-Forwarded-For", "192.168.80.80")
		if local != nil {
			r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, local))
		}
		w := httptest.NewRecorder()
		a.handleServerAddresses(w, r)
		raw := w.Body.String()
		if w.Code != http.StatusServiceUnavailable || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("unavailable discovery was not explicit for %v: %d %s", local, w.Code, raw)
		}
		for _, forbidden := range []string{"preferredAddress", "192.168.", "netlink", "implementation detail"} {
			if strings.Contains(raw, forbidden) {
				t.Errorf("invented fallback or internal error for %v: %s", local, raw)
			}
		}
	}
}
