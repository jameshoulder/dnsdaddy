package dnssec

import (
	"crypto/sha256"
	"time"

	"github.com/miekg/dns"
)

// AuthenticatedRRset is a receipt for the exact data covered by a successful
// signature verification. Its private fields cannot be fabricated by a
// transport adapter. It is intentionally absent from JSON traces: it binds a
// live response to verification, rather than creating another evidence log.
type AuthenticatedRRset struct {
	sig    *dns.RRSIG
	digest [sha256.Size]byte
	ttl    uint32
}

// Covers reports whether records are precisely the authenticated RRset. The
// comparison uses the same canonical signed bytes as signature verification,
// so record order, case and decremented TTLs do not alter its meaning.
func (a AuthenticatedRRset) Covers(records []dns.RR) bool {
	if a.sig == nil || len(records) == 0 {
		return false
	}
	set, reason := NewRRset(records)
	if reason != ReasonNone || set.Name != dns.CanonicalName(a.sig.Hdr.Name) ||
		set.Class != a.sig.Hdr.Class || set.RRType != a.sig.TypeCovered {
		return false
	}
	data, err := canonicalSignedData(a.sig, records)
	return err == nil && sha256.Sum256(data) == a.digest
}

// TTL is the maximum remaining lifetime permitted by the accepted signature
// at the validation instant (RFC 4035 section 5.3.3).
func (a AuthenticatedRRset) TTL() uint32 { return a.ttl }

func authenticatedRRset(set RRset, sig *dns.RRSIG, now time.Time) (AuthenticatedRRset, bool) {
	data, err := canonicalSignedData(sig, set.Records)
	if err != nil {
		return AuthenticatedRRset{}, false
	}
	ttl := sig.OrigTtl
	if sig.Hdr.Ttl < ttl {
		ttl = sig.Hdr.Ttl
	}
	for _, rr := range set.Records {
		if rr.Header().Ttl < ttl {
			ttl = rr.Header().Ttl
		}
	}
	// uint32 subtraction is the DNSSEC/RFC 1982 serial clock. A valid
	// signature cannot lie more than half the serial space ahead.
	remaining := sig.Expiration - DNSSECTime(now)
	if remaining >= 1<<31 {
		remaining = 0
	}
	if remaining < ttl {
		ttl = remaining
	}
	copySig := *sig
	return AuthenticatedRRset{sig: &copySig, digest: sha256.Sum256(data), ttl: ttl}, true
}
