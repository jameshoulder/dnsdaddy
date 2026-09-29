package protection

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func controller(t *testing.T, cfg Config) *Controller {
	t.Helper()
	c, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRateClientAttributionAndRefill(t *testing.T) {
	cfg := Default()
	cfg.RateLimit.QPS = 2
	cfg.RateLimit.Burst = 2
	c := controller(t, cfg)
	now := time.Unix(1000, 0)
	a := netip.MustParseAddr("192.0.2.1")
	for i := 0; i < 2; i++ {
		if !c.Allow(a, "site-a", now) {
			t.Fatalf("initial burst request %d was refused", i+1)
		}
	}
	if c.Allow(a, "site-a", now) {
		t.Fatal("exhausted burst was replenished without elapsed time")
	}
	if c.Allow(netip.MustParseAddr("::ffff:192.0.2.1"), "site-a", now) {
		t.Fatal("mapped address obtained a fresh bucket")
	}
	if !c.Allow(a, "site-b", now) {
		t.Fatal("independently authenticated network inherited another network's bucket")
	}
	if !c.Allow(netip.MustParseAddr("192.0.2.2"), "site-a", now) {
		t.Fatal("another client was throttled")
	}
	if c.Allow(a, "site-a", now.Add(499*time.Millisecond)) || !c.Allow(a, "site-a", now.Add(500*time.Millisecond)) {
		t.Fatal("refill is not elapsed-time based")
	}
	if c.Allow(a, "site-a", now.Add(-time.Minute)) || c.Allow(a, "site-a", now.Add(500*time.Millisecond)) {
		t.Fatal("clock rollback minted tokens")
	}
}

func TestCapacityUsesSharedOverflowInsteadOfEvictingActiveClients(t *testing.T) {
	cfg := Default()
	cfg.RateLimit.MaxClients = 2
	cfg.RateLimit.Burst = 1
	cfg.RateLimit.QPS = 1
	cfg.RateLimit.IdleSeconds = 5
	c := controller(t, cfg)
	now := time.Unix(1000, 0)
	for _, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		if !c.Allow(netip.MustParseAddr(ip), "n", now) {
			t.Fatal(ip)
		}
	}
	if c.Allow(netip.MustParseAddr("192.0.2.4"), "n", now) {
		t.Fatal("new identity bypassed shared overflow bucket")
	}
	if c.Allow(netip.MustParseAddr("192.0.2.1"), "n", now) {
		t.Fatal("active entry was evicted and refilled")
	}
	s := c.Counters()
	if s.TrackedClients != 2 || s.RateOverflow != 2 || s.RateLimited != 2 {
		t.Fatalf("bad bounded-state counters: %+v", s)
	}
	if !c.Allow(netip.MustParseAddr("192.0.2.4"), "n", now.Add(6*time.Second)) {
		t.Fatal("idle expiry did not reclaim capacity")
	}
	if c.Counters().TrackedClients > 2 {
		t.Fatal("capacity exceeded")
	}
}

func TestConcurrentClientsStayBounded(t *testing.T) {
	cfg := Default()
	cfg.RateLimit.MaxClients = 8
	cfg.RateLimit.Burst = 10
	c := controller(t, cfg)
	now := time.Unix(1000, 0)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				c.Allow(netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}), "n", now)
			}
		}(i)
	}
	wg.Wait()
	if c.Counters().TrackedClients != 8 {
		t.Fatalf("unbounded client state: %+v", c.Counters())
	}
}

func answer(t *testing.T, text string) *dns.Msg {
	t.Helper()
	rr, err := dns.NewRR(text)
	if err != nil {
		t.Fatal(err)
	}
	return &dns.Msg{Answer: []dns.RR{rr}}
}

func TestRebindingAddressFamiliesAndTransitions(t *testing.T) {
	c := controller(t, Default())
	for _, tc := range []struct {
		address string
		blocked bool
	}{
		{"10.2.3.4", true}, {"172.16.0.1", true}, {"192.168.1.1", true}, {"127.0.0.1", true},
		{"169.254.169.254", true}, {"100.64.0.1", true}, {"0.1.2.3", true}, {"224.0.0.1", true},
		{"198.18.0.1", true}, {"192.0.2.1", true}, {"203.0.113.1", true}, {"255.255.255.255", true},
		{"192.0.0.100", true}, {"192.0.0.170", true},
		{"192.0.0.9", false}, {"192.0.0.10", false}, {"8.8.8.8", false}, {"9.9.9.9", false},
		{"::", true}, {"::1", true}, {"fe80::1", true}, {"fd12::1", true}, {"ff02::1", true},
		{"::ffff:127.0.0.1", true}, {"::ffff:10.0.0.1", true}, {"::ffff:8.8.8.8", false},
		{"2001:db8::1", true}, {"fec0::1", true}, {"64:ff9b::a00:1", true},
		{"64:ff9b::808:808", false}, {"2002:a00:1::1", true}, {"2002:808:808::1", false},
		{"2001:4860:4860::8888", false},
		{"3fff::1", true}, {"5f00::1", true}, {"100:0:0:1::1", true}, {"2001:100::1", true},
		{"2001:1::1", false}, {"2001:1::2", false}, {"2001:1::3", false},
		{"2001:3::1", false}, {"2001:4:112::1", false}, {"2001:20::1", false}, {"2001:30::1", false},
	} {
		t.Run(tc.address, func(t *testing.T) {
			qtype := "A"
			if netip.MustParseAddr(tc.address).Is6() {
				qtype = "AAAA"
			}
			msg := answer(t, "attack.example. 60 IN "+qtype+" "+tc.address)
			if got := c.CheckResponse("attack.example", msg) != ""; got != tc.blocked {
				t.Fatalf("blocked=%v want=%v", got, tc.blocked)
			}
		})
	}
}

func TestAliasesAndAdditionalRecordsCannotObtainDomainException(t *testing.T) {
	cfg := Default()
	cfg.Rebinding.AllowDomains = []string{"corp.example"}
	c := controller(t, cfg)
	m := answer(t, "attack.example. 60 IN CNAME host.corp.example.")
	rr, _ := dns.NewRR("host.corp.example. 60 IN A 192.168.1.5")
	m.Answer = append(m.Answer, rr)
	if c.CheckResponse("attack.example", m) == "" {
		t.Fatal("alias target obtained a trusted-domain exception")
	}
	if c.CheckResponse("host.corp.example", m) != "" {
		t.Fatal("explicit split-DNS original-question exception ignored")
	}
	if c.CheckResponse("notcorp.example", m) == "" {
		t.Fatal("suffix exception crossed label boundary")
	}
	for _, section := range []string{"answer", "authority", "additional"} {
		n := new(dns.Msg)
		switch section {
		case "answer":
			n.Answer = []dns.RR{rr}
		case "authority":
			n.Ns = []dns.RR{rr}
		default:
			n.Extra = []dns.RR{rr}
		}
		if c.CheckResponse("attack.example", n) == "" {
			t.Fatalf("private address hidden in %s", section)
		}
	}
	m = answer(t, "attack.example. 60 IN DNAME corp.example.")
	m.Answer = append(m.Answer, rr)
	if c.CheckResponse("attack.example", m) == "" {
		t.Fatal("DNAME chain bypassed guard")
	}
}

func TestSVCBAndHTTPSHintsAreChecked(t *testing.T) {
	c := controller(t, Default())
	for _, wire := range []string{"attack.example. 60 IN HTTPS 1 . ipv4hint=192.168.1.1", "attack.example. 60 IN SVCB 1 . ipv6hint=fd00::1"} {
		if c.CheckResponse("attack.example", answer(t, wire)) == "" {
			t.Fatalf("private hint passed: %s", wire)
		}
	}
	if c.CheckResponse("safe.example", answer(t, "safe.example. 60 IN HTTPS 1 . ipv4hint=8.8.8.8")) != "" {
		t.Fatal("public hint rejected")
	}
}

func TestExplicitCIDRExceptionAndInvalidConfiguration(t *testing.T) {
	cfg := Default()
	cfg.Rebinding.AllowCIDRs = []string{"192.168.1.0/24"}
	c := controller(t, cfg)
	if c.CheckResponse("split.example", answer(t, "split.example. 60 IN A 192.168.1.4")) != "" {
		t.Fatal("explicit range not allowed")
	}
	if c.CheckResponse("split.example", answer(t, "split.example. 60 IN A 192.168.2.4")) == "" {
		t.Fatal("exception escaped its range")
	}
	for _, f := range []func(*Config){
		func(c *Config) { c.Rebinding.AllowCIDRs = []string{"0.0.0.0/0"} },
		func(c *Config) { c.Rebinding.AllowCIDRs = []string{"::/0"} },
		func(c *Config) { c.Rebinding.AllowDomains = []string{"com"} },
		func(c *Config) { c.Rebinding.AllowDomains = []string{"*.example.com"} },
		func(c *Config) { c.RateLimit.MaxClients = 65537 },
		func(c *Config) { c.RateLimit.QPS = 0 },
	} {
		bad := Default()
		f(&bad)
		if _, err := New(bad, nil); err == nil {
			t.Fatal("unsafe configuration accepted")
		}
	}
}

func TestConfigurationIsDurableVersionedAndDoesNotRefillForExceptionEdit(t *testing.T) {
	cfg := Default()
	cfg.RateLimit.Burst = 1
	fail := true
	var saved Config
	c, err := New(cfg, func(_ context.Context, cfg Config) error {
		if fail {
			return errors.New("disk unavailable")
		}
		saved = cfg
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	addr := netip.MustParseAddr("192.0.2.1")
	now := time.Unix(1000, 0)
	c.Allow(addr, "n", now)
	next := c.Config()
	next.Rebinding.AllowDomains = []string{"corp.example"}
	if _, err := c.Update(context.Background(), next); err == nil {
		t.Fatal("persistence failure ignored")
	}
	if c.Config().Version != 1 || len(c.Config().Rebinding.AllowDomains) != 0 {
		t.Fatal("failed update became effective")
	}
	fail = false
	got, err := c.Update(context.Background(), next)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 2 || saved.Version != 2 {
		t.Fatal("revision not persisted")
	}
	if c.Allow(addr, "n", now) {
		t.Fatal("exception-only edit minted new burst")
	}
	if _, err := c.Update(context.Background(), next); !errors.Is(err, ErrVersionConflict) {
		t.Fatal("stale version accepted")
	}
	got.Rebinding.AllowDomains[0] = "attacker.example"
	if c.Config().Rebinding.AllowDomains[0] != "corp.example" {
		t.Fatal("caller mutated live settings")
	}
}
