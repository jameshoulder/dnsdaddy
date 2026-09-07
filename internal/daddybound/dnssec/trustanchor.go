package dnssec

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// TrustAnchor is a configured starting point for a chain of trust.
//
// It holds the same fields as a DS record because that is the form the root
// anchor is published in and the form an operator can check against IANA's
// published value by eye. Holding a DNSKEY instead would mean the anchor
// changes on every key rollover; holding the digest means it changes only
// when the key it points at does.
type TrustAnchor struct {
	// Name is the zone the anchor applies to, in canonical form.
	Name string
	// KeyTag, Algorithm and DigestType select and check a DNSKEY exactly as
	// the corresponding DS fields do.
	KeyTag     uint16
	Algorithm  Algorithm
	DigestType DigestType
	// Digest is the raw digest octets.
	Digest []byte
}

// TrustAnchors is a set of configured anchors.
//
// The zero value is a validator with no anchors, which can reach no verdict
// but Indeterminate. That is the correct behaviour and the correct default:
// RFC 4033 §5 describes having no anchor as "the default operation mode", and
// a validator that invents one is not a validator.
type TrustAnchors struct {
	anchors []TrustAnchor
}

// NewTrustAnchors builds an anchor set.
//
// Anchors are supplied as values, from configuration or from a test. Nothing
// in this package acquires an anchor by any other route: there is no code
// path that observes a DNSKEY in a response and decides to trust it. That is
// the single rule the whole design rests on, because a validator that can
// promote an observed key into an anchor validates only that an attacker is
// self-consistent.
func NewTrustAnchors(anchors ...TrustAnchor) (TrustAnchors, error) {
	out := make([]TrustAnchor, 0, len(anchors))
	for i, a := range anchors {
		if a.Name == "" {
			return TrustAnchors{}, fmt.Errorf("dnssec: trust anchor %d has no name", i)
		}
		if len(a.Digest) == 0 {
			return TrustAnchors{}, fmt.Errorf("dnssec: trust anchor %d for %s has no digest", i, a.Name)
		}
		a.Name = dns.CanonicalName(a.Name)
		out = append(out, a)
	}
	return TrustAnchors{anchors: out}, nil
}

// ParseTrustAnchorDS builds an anchor from the DS presentation form an
// operator would copy from IANA or from a registry, for example:
//
//	. 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
//
// Parsing the published spelling rather than asking for five separate
// configuration fields removes a transcription step, and transcription is
// where anchors get broken.
func ParseTrustAnchorDS(s string) (TrustAnchor, error) {
	fields := strings.Fields(s)
	if len(fields) < 5 {
		return TrustAnchor{}, errors.New("dnssec: trust anchor needs name, key tag, algorithm, digest type and digest")
	}

	var (
		anchor TrustAnchor
		keyTag uint16
		alg    uint8
		digest uint8
	)
	if _, err := fmt.Sscanf(fields[1], "%d", &keyTag); err != nil {
		return TrustAnchor{}, fmt.Errorf("dnssec: trust anchor key tag: %w", err)
	}
	if _, err := fmt.Sscanf(fields[2], "%d", &alg); err != nil {
		return TrustAnchor{}, fmt.Errorf("dnssec: trust anchor algorithm: %w", err)
	}
	if _, err := fmt.Sscanf(fields[3], "%d", &digest); err != nil {
		return TrustAnchor{}, fmt.Errorf("dnssec: trust anchor digest type: %w", err)
	}

	// The digest may be split across fields in the published form, so the
	// remainder is joined before decoding rather than taking fields[4] alone.
	raw, err := hex.DecodeString(strings.Join(fields[4:], ""))
	if err != nil {
		return TrustAnchor{}, fmt.Errorf("dnssec: trust anchor digest: %w", err)
	}
	if len(raw) == 0 {
		return TrustAnchor{}, errors.New("dnssec: trust anchor digest is empty")
	}

	anchor = TrustAnchor{
		Name:       dns.CanonicalName(fields[0]),
		KeyTag:     keyTag,
		Algorithm:  Algorithm(alg),
		DigestType: DigestType(digest),
		Digest:     raw,
	}
	return anchor, nil
}

// deepestFor returns the anchors at the most specific configured name that
// covers qname, and that name.
//
// Most specific wins. An operator who configures both the root and an anchor
// for one internal zone means the internal anchor to govern that zone, and
// starting the walk at the root instead would fail at the first delegation
// the public DNS knows nothing about.
func (t TrustAnchors) deepestFor(qname string) (string, []TrustAnchor) {
	qname = dns.CanonicalName(qname)

	best := ""
	for _, a := range t.anchors {
		if !dns.IsSubDomain(a.Name, qname) {
			continue
		}
		if dns.CountLabel(a.Name) > dns.CountLabel(best) || best == "" {
			best = a.Name
		}
	}
	if best == "" {
		return "", nil
	}

	var out []TrustAnchor
	for _, a := range t.anchors {
		if a.Name == best {
			out = append(out, a)
		}
	}
	// Sorted so a trace is reproducible regardless of configuration order.
	sort.Slice(out, func(i, j int) bool {
		if out[i].KeyTag != out[j].KeyTag {
			return out[i].KeyTag < out[j].KeyTag
		}
		return out[i].Algorithm < out[j].Algorithm
	})
	return best, out
}

// Empty reports whether no anchors are configured.
func (t TrustAnchors) Empty() bool { return len(t.anchors) == 0 }

// matchesKey reports whether the anchor authenticates k, and why not if it
// does not.
//
// The logic is deliberately identical to dsMatchesKey, because an anchor is a
// DS that was configured instead of being looked up. Implementing it twice
// would let the configured path and the looked-up path drift, and the
// configured path is the one nobody re-checks.
func (a TrustAnchor) matchesKey(policy Policy, k *dns.DNSKEY) Reason {
	ds := &dns.DS{
		Hdr:        dns.RR_Header{Name: a.Name, Rrtype: dns.TypeDS, Class: dns.ClassINET},
		KeyTag:     a.KeyTag,
		Algorithm:  uint8(a.Algorithm),
		DigestType: uint8(a.DigestType),
		Digest:     hex.EncodeToString(a.Digest),
	}
	return dsMatchesKey(policy, ds, k)
}
