package dnsserver

import (
	"encoding/json"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAccessEvidenceTracksRefusalAndRecoveryWithoutQueryContent(t *testing.T) {
	var a accessTracker
	now := time.Now()
	ip := netip.MustParseAddr("203.0.113.9")
	a.record(now, ip, "udp", "answered")
	if len(a.snapshot(now, true).Entries) != 0 {
		t.Fatal("ordinary answers created a source inventory")
	}
	a.record(now, ip, "udp", "refused")
	a.record(now.Add(time.Second), netip.MustParseAddr("::ffff:203.0.113.9"), "tcp", "refused")
	a.record(now.Add(2*time.Second), ip, "doh", "answered")
	s := a.snapshot(now.Add(3*time.Second), true)
	if len(s.Entries) != 1 {
		t.Fatal(s)
	}
	e := s.Entries[0]
	if e.CIDR != "203.0.113.9/32" || e.Refused != 2 || e.Answered != 1 || e.LastOutcome != "answered" || len(e.Protocols) != 3 {
		t.Fatal(e)
	}
	b, _ := json.Marshal(s)
	for _, forbidden := range []string{"domain", "token", "qname"} {
		if strings.Contains(string(b), forbidden) {
			t.Fatal(string(b))
		}
	}
}
func TestAccessEvidenceExpiresEvenWhenRecoveredTrafficContinues(t *testing.T) {
	var a accessTracker
	now := time.Now()
	ip := netip.MustParseAddr("fd00::50")
	a.record(now, ip, "udp", "refused")
	a.record(now.Add(accessWindow-time.Second), ip, "udp", "answered")
	if len(a.snapshot(now.Add(accessWindow), true).Entries) != 0 {
		t.Fatal("retained expired source")
	}
	a.record(now.Add(accessWindow), ip, "tcp", "answered")
	if len(a.snapshot(now.Add(accessWindow), true).Entries) != 0 {
		t.Fatal("successful traffic extended a refusal record")
	}
}
func TestAccessEvidenceHasAHardMemoryBound(t *testing.T) {
	var a accessTracker
	now := time.Now()
	for i := 0; i < accessCapacity*4; i++ {
		a.record(now.Add(time.Duration(i)*time.Millisecond), netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}), "udp", "refused")
	}
	s := a.snapshot(now.Add(time.Second), true)
	if len(s.Entries) != accessCapacity || s.Evicted != accessCapacity*3 {
		t.Fatal(s)
	}
}
func TestAccessEvidenceNeverWaitsForTheReportingLock(t *testing.T) {
	var a accessTracker
	a.mu.Lock()
	done := make(chan struct{})
	go func() { a.record(time.Now(), netip.MustParseAddr("203.0.113.9"), "udp", "refused"); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		a.mu.Unlock()
		t.Fatal("DNS path blocked on reporting")
	}
	a.mu.Unlock()
	if a.dropped.Load() != 1 {
		t.Fatal("loss was hidden")
	}
}
func TestAccessEvidencePrivacyAndInvalidSources(t *testing.T) {
	var a accessTracker
	now := time.Now()
	for _, raw := range []string{"0.0.0.0", "::", "224.0.0.1", "ff02::1"} {
		a.record(now, netip.MustParseAddr(raw), "udp", "refused")
	}
	a.record(now, netip.Addr{}, "udp", "refused")
	if len(a.snapshot(now, true).Entries) != 0 {
		t.Fatal("invalid source retained")
	}
	a.record(now, netip.MustParseAddr("203.0.113.9"), "udp", "refused")
	if len(a.snapshot(now, false).Entries) != 0 || len(a.snapshot(now, true).Entries) != 0 {
		t.Fatal("privacy clearing retained addresses")
	}
}
func TestAccessEvidenceConcurrentQueriesAndReads(t *testing.T) {
	var a accessTracker
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				a.record(time.Now(), netip.AddrFrom4([4]byte{192, 0, 2, byte(n)}), "udp", "refused")
				if i%10 == 0 {
					a.snapshot(time.Now(), true)
				}
			}
		}(g)
	}
	wg.Wait()
	if len(a.snapshot(time.Now(), true).Entries) > accessCapacity {
		t.Fatal("memory bound exceeded")
	}
}
