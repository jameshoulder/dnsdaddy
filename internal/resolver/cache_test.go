package resolver

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func testCache(maxEntries int) *Cache {
	return NewCache(CacheOptions{
		Enabled:     true,
		MaxEntries:  maxEntries,
		MinTTL:      1,
		MaxTTL:      3600,
		NegativeTTL: 60,
	})
}

func answer(name string, ttl uint32) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m.Response = true
	m.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   []byte{93, 184, 216, 34},
	}}
	return m
}

func TestCacheRoundTrip(t *testing.T) {
	c := testCache(100)
	key := Key(dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, false)

	if got := c.Get(key, 1); got != nil {
		t.Fatal("a fresh cache returned a hit")
	}

	c.Put(key, answer("example.com", 300), 1)

	got := c.Get(key, 1)
	if got == nil {
		t.Fatal("stored answer was not returned")
	}
	if len(got.Answer) != 1 {
		t.Fatalf("cached answer has %d records, want 1", len(got.Answer))
	}
}

func TestCacheGenerationInvalidatesEntries(t *testing.T) {
	// A feed refresh bumps the generation. Answers cached before it must not be
	// served, or a newly blocked domain would keep resolving until its TTL ran out.
	c := testCache(100)
	key := Key(dns.Question{Name: "evil.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, false)

	c.Put(key, answer("evil.com", 3600), 1)
	if c.Get(key, 1) == nil {
		t.Fatal("precondition failed: entry should be cached under generation 1")
	}
	if c.Get(key, 2) != nil {
		t.Error("an entry from a previous blocklist generation was served")
	}
}

func TestCacheDNSSECKeysAreDistinct(t *testing.T) {
	// An answer stripped of RRSIGs must not be handed to a validating client.
	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	if Key(q, true) == Key(q, false) {
		t.Error("DNSSEC-OK and plain queries share a cache key")
	}
}

func TestCacheDecrementsTTL(t *testing.T) {
	c := testCache(100)
	key := Key(dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, false)

	c.Put(key, answer("example.com", 300), 1)
	got := c.Get(key, 1)
	if got == nil {
		t.Fatal("no cache hit")
	}
	if ttl := got.Answer[0].Header().Ttl; ttl > 300 {
		t.Errorf("returned TTL %d exceeds the stored TTL; clients would cache too long", ttl)
	}
}

func TestCacheRespectsTTLBounds(t *testing.T) {
	c := NewCache(CacheOptions{Enabled: true, MaxEntries: 100, MinTTL: 30, MaxTTL: 60, NegativeTTL: 60})
	key := Key(dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, false)

	// An upstream TTL of 86400 must be clamped to MaxTTL.
	c.Put(key, answer("example.com", 86400), 1)
	got := c.Get(key, 1)
	if got == nil {
		t.Fatal("no cache hit")
	}
	if ttl := got.Answer[0].Header().Ttl; ttl > 60 {
		t.Errorf("TTL %d was not clamped to max_ttl=60", ttl)
	}
}

func TestCacheDoesNotStoreServfail(t *testing.T) {
	// Caching SERVFAIL would turn a transient upstream blip into a multi-minute
	// outage for that name.
	c := testCache(100)
	key := Key(dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, false)

	m := answer("example.com", 300)
	m.Rcode = dns.RcodeServerFailure
	c.Put(key, m, 1)

	if c.Get(key, 1) != nil {
		t.Error("a SERVFAIL response was cached")
	}
}

func TestCacheStoresNXDOMAIN(t *testing.T) {
	c := testCache(100)
	key := Key(dns.Question{Name: "nope.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, false)

	m := new(dns.Msg)
	m.SetQuestion("nope.example.", dns.TypeA)
	m.Response = true
	m.Rcode = dns.RcodeNameError
	c.Put(key, m, 1)

	got := c.Get(key, 1)
	if got == nil {
		t.Fatal("NXDOMAIN was not negatively cached")
	}
	if got.Rcode != dns.RcodeNameError {
		t.Errorf("cached rcode = %d, want NXDOMAIN — a cached NXDOMAIN must not become NOERROR", got.Rcode)
	}
}

func TestCacheDoesNotStoreTruncated(t *testing.T) {
	c := testCache(100)
	key := Key(dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, false)

	m := answer("example.com", 300)
	m.Truncated = true
	c.Put(key, m, 1)

	if c.Get(key, 1) != nil {
		t.Error("a truncated response was cached")
	}
}

func TestCacheExpires(t *testing.T) {
	c := NewCache(CacheOptions{Enabled: true, MaxEntries: 100, MinTTL: 0, MaxTTL: 3600, NegativeTTL: 1})
	key := Key(dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, false)

	c.Put(key, answer("example.com", 1), 1)
	time.Sleep(1100 * time.Millisecond)

	if c.Get(key, 1) != nil {
		t.Error("an expired entry was served")
	}
}

func TestCacheStaysBounded(t *testing.T) {
	// A cache that grows without limit would eventually take a 1 GB box down.
	c := testCache(64)
	for i := 0; i < 5000; i++ {
		name := randomName(i)
		key := Key(dns.Question{Name: dns.Fqdn(name), Qtype: dns.TypeA, Qclass: dns.ClassINET}, false)
		c.Put(key, answer(name, 3600), 1)
	}

	size, _, _ := c.Stats()
	if size > 64 {
		t.Errorf("cache holds %d entries, past its 64-entry bound", size)
	}
}

func TestCachePurge(t *testing.T) {
	c := testCache(100)
	key := Key(dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, false)

	c.Put(key, answer("example.com", 3600), 1)
	c.Purge()

	if c.Get(key, 1) != nil {
		t.Error("Purge did not clear the cache; a policy change would not take effect until TTL expiry")
	}
}

func TestCacheDisabled(t *testing.T) {
	c := NewCache(CacheOptions{Enabled: false, MaxEntries: 100})
	key := Key(dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, false)

	c.Put(key, answer("example.com", 300), 1)
	if c.Get(key, 1) != nil {
		t.Error("a disabled cache returned a hit")
	}
}

func TestCacheConcurrentAccess(t *testing.T) {
	c := testCache(500)
	done := make(chan struct{})

	for w := 0; w < 8; w++ {
		go func(w int) {
			defer func() { done <- struct{}{} }()
			for i := 0; i < 500; i++ {
				name := randomName((w * 500) + i)
				key := Key(dns.Question{Name: dns.Fqdn(name), Qtype: dns.TypeA, Qclass: dns.ClassINET}, false)
				c.Put(key, answer(name, 300), 1)
				c.Get(key, 1)
			}
		}(w)
	}
	for w := 0; w < 8; w++ {
		<-done
	}
}

func randomName(i int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	buf := make([]byte, 0, 12)
	n := i
	for j := 0; j < 6; j++ {
		buf = append(buf, letters[n%26])
		n /= 26
	}
	return string(buf) + ".example"
}
