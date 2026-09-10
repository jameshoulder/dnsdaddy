package native

import (
	"context"
	"fmt"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/recursive"
)

// KeySource fetches a zone's apex DNSKEY RRset through the native resolver,
// satisfying trustanchors.KeySource.
//
// Through the resolver rather than through anything else, and that is the
// point. The keys that decide what this resolver will trust for the next
// thirty days are fetched from the authoritative servers by the same code that
// fetches everything else — not from a forwarder, and emphatically not over
// HTTPS from a URL. Nothing here downloads a trust anchor: a key arriving from
// the network is evidence to be checked against a key already trusted, and
// RFC 5011's hold-down is what turns "arrived" into "trusted".
type KeySource struct{ r *recursive.Resolver }

// NewKeySource wraps a resolver.
func NewKeySource(r *recursive.Resolver) *KeySource { return &KeySource{r: r} }

// DNSKEY resolves the zone's apex DNSKEY RRset with its signatures.
func (s *KeySource) DNSKEY(ctx context.Context, zone string) ([]dns.RR, error) {
	res, err := s.r.Resolve(ctx, zone, dns.TypeDNSKEY)
	if err != nil {
		return nil, err
	}
	if res.Msg.Rcode != dns.RcodeSuccess {
		// Any other rcode is the servers saying they could not answer, which
		// is a failure to fetch rather than a statement about the keys. It
		// must not reach the state machine, where an empty answer would read
		// as "every key has gone".
		return nil, fmt.Errorf("native: %s DNSKEY returned %s",
			zone, dns.RcodeToString[res.Msg.Rcode])
	}
	return res.Msg.Answer, nil
}
