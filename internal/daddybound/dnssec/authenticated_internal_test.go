package dnssec

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

// RFC 4035 section 5.3.3 takes the minimum of four independent TTL limits.
// RFC 1982 serial time must still work across the 2106 DNSSEC clock wrap.
func TestReceiptTTLUsesEveryDNSSECLifetimeBound(t *testing.T) {
	for _, tc := range []struct {
		name                                      string
		dataTTL, sigTTL, origTTL, remaining, want uint32
	}{
		{"data", 2, 200, 200, 200, 2},
		{"signature", 200, 3, 200, 200, 3},
		{"original", 200, 200, 4, 200, 4},
		{"expiration", 200, 200, 200, 5, 5},
		{"uncacheable", 0, 200, 200, 200, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, seconds := range []int64{1800000000, 1<<32 - 2} {
				now := time.Unix(seconds, 0)
				sig := testSig("www.example.test.", dns.TypeA, 3, tc.origTTL)
				sig.Hdr.Ttl = tc.sigTTL
				sig.Inception = DNSSECTime(now) - 20
				sig.Expiration = DNSSECTime(now) + tc.remaining
				set, reason := NewRRset([]dns.RR{aRecord(sig.Hdr.Name, tc.dataTTL, "192.0.2.1")})
				if reason != ReasonNone {
					t.Fatal(reason)
				}
				receipt, ok := authenticatedRRset(set, sig, now)
				if !ok || receipt.TTL() != tc.want {
					t.Fatalf("at %d, TTL=%d, want %d", seconds, receipt.TTL(), tc.want)
				}
			}
		})
	}
}
