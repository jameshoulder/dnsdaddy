package resolver

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestEncryptedConfigurationRejectsImplicitDNSAndInvalidDestinations(t *testing.T) {
	valid := EncryptedEndpoint{Protocol: "doh3", Address: "https://dns.test/dns-query", BootstrapIPs: []string{"127.0.0.1"}}
	for _, test := range []struct {
		name string
		edit func(*EncryptedEndpoint)
	}{
		{"plain-dns", func(e *EncryptedEndpoint) { e.Protocol = "udp" }},
		{"doq-port-53", func(e *EncryptedEndpoint) { e.Protocol = "doq"; e.Address = "dns.test:53" }},
		{"http-url", func(e *EncryptedEndpoint) { e.Address = "http://dns.test/dns-query" }},
		{"userinfo", func(e *EncryptedEndpoint) { e.Address = "https://secret:password@dns.test/dns-query" }},
		{"query", func(e *EncryptedEndpoint) { e.Address += "?token=secret" }},
		{"empty-query", func(e *EncryptedEndpoint) { e.Address += "?" }},
		{"fragment", func(e *EncryptedEndpoint) { e.Address += "#fragment" }},
		{"empty-fragment", func(e *EncryptedEndpoint) { e.Address += "#" }},
		{"missing-path", func(e *EncryptedEndpoint) { e.Address = "https://dns.test" }},
		{"implicit-bootstrap", func(e *EncryptedEndpoint) { e.BootstrapIPs = nil }},
		{"bootstrap-hostname", func(e *EncryptedEndpoint) { e.BootstrapIPs = []string{"bootstrap.test"} }},
		{"bootstrap-with-port", func(e *EncryptedEndpoint) { e.BootstrapIPs = []string{"127.0.0.1:443"} }},
		{"unspecified-v4", func(e *EncryptedEndpoint) { e.BootstrapIPs = []string{"0.0.0.0"} }},
		{"unspecified-v6", func(e *EncryptedEndpoint) { e.BootstrapIPs = []string{"::"} }},
		{"mapped-unspecified", func(e *EncryptedEndpoint) { e.BootstrapIPs = []string{"::ffff:0.0.0.0"} }},
		{"multicast-v4", func(e *EncryptedEndpoint) { e.BootstrapIPs = []string{"224.0.0.1"} }},
		{"multicast-v6", func(e *EncryptedEndpoint) { e.BootstrapIPs = []string{"ff02::1"} }},
		{"mapped-multicast", func(e *EncryptedEndpoint) { e.BootstrapIPs = []string{"::ffff:224.0.0.1"} }},
		{"broadcast", func(e *EncryptedEndpoint) { e.BootstrapIPs = []string{"255.255.255.255"} }},
		{"mapped-broadcast", func(e *EncryptedEndpoint) { e.BootstrapIPs = []string{"::ffff:255.255.255.255"} }},
		{"zone", func(e *EncryptedEndpoint) { e.BootstrapIPs = []string{"fe80::1%eth0"} }},
		{"different-certificate-name", func(e *EncryptedEndpoint) { e.ServerName = "other.test" }},
		{"wildcard-certificate-name", func(e *EncryptedEndpoint) { e.ServerName = "*.test" }},
		{"invalid-port", func(e *EncryptedEndpoint) { e.Address = "https://dns.test:65536/dns-query" }},
		{"oversized-url", func(e *EncryptedEndpoint) { e.Address += strings.Repeat("x", 2048) }},
		{"too-many-IPs", func(e *EncryptedEndpoint) { e.BootstrapIPs = make([]string, 9) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			endpoint := valid
			test.edit(&endpoint)
			if err := ValidateEncryptedEndpoints([]EncryptedEndpoint{endpoint}); err == nil {
				t.Fatal("unsafe or ambiguous encrypted endpoint accepted")
			}
		})
	}
	if err := ValidateEncryptedEndpoints(nil); err == nil {
		t.Fatal("empty endpoint set accepted")
	}
	if err := ValidateEncryptedEndpoints(make([]EncryptedEndpoint, MaxEncryptedEndpoints+1)); err == nil {
		t.Fatal("unbounded endpoint set accepted")
	}
}

func TestEncryptedConfigurationCopiesApprovedLiteralTargets(t *testing.T) {
	input := EncryptedEndpoint{Protocol: "DOH3", Address: "https://DNS.TEST/dns-query", BootstrapIPs: []string{"::ffff:127.0.0.1", "127.0.0.1", "::1"}}
	client, err := NewEncryptedUpstreams([]EncryptedEndpoint{input}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	input.BootstrapIPs[0] = "192.0.2.33"
	ep := client.endpoints[0]
	if ep.config.Protocol != "doh3" || ep.config.ServerName != "dns.test" || ep.config.Address != "https://dns.test:443/dns-query" {
		t.Fatalf("unexpected normalized endpoint: %+v", ep.config)
	}
	if !reflect.DeepEqual(ep.targets, []string{"127.0.0.1:443", "[::1]:443"}) {
		t.Fatalf("approved targets were not fixed literal addresses: %v", ep.targets)
	}
	for _, input := range []EncryptedEndpoint{
		{Protocol: "doq", Address: "127.0.0.1", ServerName: "dns.test"},
		{Protocol: "doq", Address: "[::1]", ServerName: "dns.test"},
		{Protocol: "doh2", Address: "https://127.0.0.1/dns-query", ServerName: "dns.test"},
		{Protocol: "doq", Address: "10.0.0.1:8853", ServerName: "internal.test"},
	} {
		if err := ValidateEncryptedEndpoints([]EncryptedEndpoint{input}); err != nil {
			t.Fatalf("explicit operator-owned encrypted resolver rejected: %v", err)
		}
	}
}

func TestEncryptedQueryDropsClientIdentifiersAndPreservesDNSSECRequest(t *testing.T) {
	query := encryptedFixtureQuery()
	query.AuthenticatedData = true
	query.IsEdns0().Option = []dns.EDNS0{
		&dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: net.IPv4(192, 0, 2, 1)},
		&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "0123456789abcdef"},
		&dns.EDNS0_LOCAL{Code: 65001, Data: []byte("client-private-id")},
		&dns.EDNS0_TCP_KEEPALIVE{Code: dns.EDNS0TCPKEEPALIVE, Timeout: 20},
	}
	before, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	clean, wire, err := prepareEncryptedQuery(query)
	if err != nil {
		t.Fatal(err)
	}
	if clean.Id != 0 || !clean.AuthenticatedData || !clean.CheckingDisabled || !clean.RecursionDesired || clean.IsEdns0() == nil || !clean.IsEdns0().Do() {
		t.Fatalf("DNSSEC request flags were not preserved: %v", clean)
	}
	if len(clean.IsEdns0().Option) != 0 || bytes.Contains(wire, []byte("client-private-id")) {
		t.Fatal("client identifiers escaped the privacy boundary")
	}
	after, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("transport changed caller-owned query")
	}
}

func TestEncryptedQueryRejectsSignedAndNonQueryOperations(t *testing.T) {
	for _, kind := range []string{"nil", "response", "update", "transfer", "incremental-transfer", "TSIG", "multiple-questions", "duplicate-OPT"} {
		t.Run(kind, func(t *testing.T) {
			query := encryptedFixtureQuery()
			switch kind {
			case "nil":
				query = nil
			case "response":
				query.Response = true
			case "update":
				query.Opcode = dns.OpcodeUpdate
			case "transfer":
				query.Question[0].Qtype = dns.TypeAXFR
			case "incremental-transfer":
				query.Question[0].Qtype = dns.TypeIXFR
			case "TSIG":
				query.SetTsig("secret.test.", dns.HmacSHA256, 300, time.Now().Unix())
			case "multiple-questions":
				query.Question = append(query.Question, query.Question[0])
			case "duplicate-OPT":
				query.Extra = append(query.Extra, query.Extra[0])
			}
			if _, _, err := prepareEncryptedQuery(query); err == nil {
				t.Fatal("unsupported query semantics accepted")
			}
		})
	}
}

func TestEncryptedResponseRejectsAmbiguousCountsAndFlags(t *testing.T) {
	query, _, err := prepareEncryptedQuery(encryptedFixtureQuery())
	if err != nil {
		t.Fatal(err)
	}
	valid := encryptedFixtureReply(t, query)
	for _, test := range []struct {
		name string
		edit func([]byte)
	}{
		{"extra-resource-count", func(w []byte) { binary.BigEndian.PutUint16(w[6:8], 2) }},
		{"omitted-resource-count", func(w []byte) { binary.BigEndian.PutUint16(w[6:8], 0) }},
		{"wrong-opcode", func(w []byte) { w[2] |= 0x08 }},
		{"reserved-flag", func(w []byte) { w[3] |= 0x40 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			wire := append([]byte(nil), valid...)
			test.edit(wire)
			if _, err := validateEncryptedReply(wire, query); !errors.Is(err, ErrEncryptedResponse) {
				t.Fatalf("ambiguous DNS message accepted: %v", err)
			}
		})
	}
}

func TestEncryptedGlobalCapacityRejectsExcessWithoutUnboundedWaiters(t *testing.T) {
	ca := newEncryptedFixtureCA(t)
	started := make(chan struct{}, maxEncryptedConcurrent)
	release := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	endpoint := encryptedFixtureServer(t, "doh2", ca.issue(t, "dns.test", false), func(ctx context.Context, query *dns.Msg) []byte {
		started <- struct{}{}
		select {
		case <-release:
			return encryptedFixtureReply(t, query)
		case <-ctx.Done():
			return nil
		}
	})
	// Four separately pooled approved entries let all global slots be used;
	// each endpoint still has its independent 32-request admission bound.
	client, err := newEncryptedUpstreamsWithRoots([]EncryptedEndpoint{endpoint, endpoint, endpoint, endpoint}, 20*time.Second, ca.roots)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	results := make(chan error, maxEncryptedConcurrent)
	for range maxEncryptedConcurrent {
		go func() { _, err := client.Exchange(context.Background(), encryptedFixtureQuery()); results <- err }()
	}
	for range maxEncryptedConcurrent {
		select {
		case <-started:
		case err := <-results:
			t.Fatalf("admitted exchange returned before saturation: %v", err)
		case <-time.After(4 * time.Second):
			t.Fatalf("did not reach bounded capacity: %+v", client.Stats())
		}
	}
	before := time.Now()
	if _, err := client.Exchange(context.Background(), encryptedFixtureQuery()); !errors.Is(err, ErrEncryptedCapacity) {
		t.Fatalf("expected prompt overload refusal, got %v", err)
	}
	if time.Since(before) > time.Second {
		t.Fatal("overload created an unbounded waiter")
	}
	stats := client.Stats()
	if stats.InFlight != maxEncryptedConcurrent || stats.Rejected != 1 {
		t.Fatalf("incorrect capacity metrics: %+v", stats)
	}
	for _, ep := range stats.Endpoints {
		if ep.InFlight > maxEncryptedPerEndpoint {
			t.Fatalf("endpoint exceeded its limit: %+v", ep)
		}
		if ep.ConnectionsOpened != 1 {
			t.Fatalf("cold query burst opened redundant HTTP/2 connections: %+v", ep)
		}
	}
	once.Do(func() { close(release) })
	for range maxEncryptedConcurrent {
		select {
		case err := <-results:
			if err != nil {
				t.Errorf("admitted exchange failed: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("exchanges failed to drain")
		}
	}
	if stats := client.Stats(); stats.InFlight != 0 || stats.Successes != maxEncryptedConcurrent {
		t.Fatalf("active-work accounting did not drain: %+v", stats)
	}
}

func FuzzEncryptedResponseFraming(f *testing.F) {
	query := new(dns.Msg)
	query.SetQuestion("fuzz.test.", dns.TypeA)
	query.Id = 0
	response := new(dns.Msg)
	response.SetReply(query)
	wire, err := response.Pack()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(wire)
	f.Add(append(append([]byte(nil), wire...), 0))
	f.Add([]byte{0, 0, 128, 0, 0, 1, 255, 255, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, wire []byte) {
		response, err := validateEncryptedReply(wire, query)
		if err == nil && (response == nil || !response.Response || response.Id != 0 || len(response.Question) != 1 || !strings.EqualFold(response.Question[0].Name, query.Question[0].Name) || response.Question[0].Qclass != query.Question[0].Qclass || response.Question[0].Qtype != query.Question[0].Qtype) {
			t.Fatalf("accepted mismatched message: %v", response)
		}
	})
}
