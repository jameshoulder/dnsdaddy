package lab

import (
	"context"
	"crypto"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
)

// ZoneSpec describes one zone to build.
type ZoneSpec struct {
	// Name is the zone apex, for example "example.dnsdaddylab.".
	Name string
	// Algorithm signs this zone. Ed25519 is the default because it signs
	// deterministically, so a scenario produces byte-identical signatures on
	// every run and can be kept in a regression corpus.
	Algorithm dnssec.Algorithm
	// DigestType is used for the DS this zone's parent publishes.
	DigestType dnssec.DigestType
	// Records is the zone's unsigned data, excluding DNSKEY and DS, which
	// are generated. Owner names must be at or below Name.
	Records []dns.RR
}

// Spec describes a whole hierarchy.
type Spec struct {
	// Zones are listed parent first. The first is the trust anchor's zone.
	Zones []ZoneSpec
	// Inception and Expiration bound every signature. Both are fixed values
	// rather than offsets from now, so that a stored trace stays meaningful
	// and a test can sit exactly on either boundary.
	Inception  time.Time
	Expiration time.Time
	// Seed makes key derivation reproducible. Two hierarchies built from the
	// same Spec have the same keys.
	Seed string
}

// Zone is one built and signed zone.
type Zone struct {
	Name       string
	Key        *dns.DNSKEY
	Signer     crypto.Signer
	Algorithm  dnssec.Algorithm
	DigestType dnssec.DigestType

	// DS is the delegation record the parent publishes for this zone. Nil
	// for the top zone, which is vouched for by a trust anchor instead.
	DS *dns.DS

	sets map[setKey][]dns.RR
}

type setKey struct {
	name   string
	rrtype uint16
}

// Hierarchy is a complete signed tree held in memory.
//
// It is both a dnssec.Source, so Daddybound can validate against it directly,
// and a set of records an authoritative DNS server can serve, so a reference
// validator can be pointed at the same data. Serving one hierarchy to both is
// the whole point: a differential comparison is only evidence if both sides
// saw the same bytes.
type Hierarchy struct {
	Zones  []*Zone
	Anchor dnssec.TrustAnchor

	byName map[string]*Zone
	sets   map[setKey][]dns.RR
	spec   Spec
}

// Build constructs and signs a hierarchy.
func Build(spec Spec) (*Hierarchy, error) {
	if len(spec.Zones) == 0 {
		return nil, fmt.Errorf("lab: a hierarchy needs at least one zone")
	}
	if !spec.Expiration.After(spec.Inception) {
		return nil, fmt.Errorf("lab: expiration %s is not after inception %s", spec.Expiration, spec.Inception)
	}

	h := &Hierarchy{
		byName: make(map[string]*Zone),
		sets:   make(map[setKey][]dns.RR),
		spec:   spec,
	}

	for i := range spec.Zones {
		zone, err := buildZone(spec, i)
		if err != nil {
			return nil, err
		}
		h.Zones = append(h.Zones, zone)
		h.byName[zone.Name] = zone
	}

	// The parent publishes each child's DS and signs it, which is the link
	// the chain walk crosses. Built after all zones exist because a DS is a
	// statement about a key that is created with the child.
	for i := 1; i < len(h.Zones); i++ {
		parent, child := h.Zones[i-1], h.Zones[i]
		ds, err := makeDS(child)
		if err != nil {
			return nil, err
		}
		child.DS = ds
		if err := parent.addSigned(spec, []dns.RR{ds}); err != nil {
			return nil, err
		}
	}

	top := h.Zones[0]
	digest, err := hex.DecodeString(mustDS(top).Digest)
	if err != nil {
		return nil, err
	}
	h.Anchor = dnssec.TrustAnchor{
		Name:       top.Name,
		KeyTag:     top.Key.KeyTag(),
		Algorithm:  top.Algorithm,
		DigestType: top.DigestType,
		Digest:     digest,
	}

	h.reindex()
	return h, nil
}

// buildZone creates one zone's key and signs its records.
func buildZone(spec Spec, i int) (*Zone, error) {
	zs := spec.Zones[i]
	name := dns.CanonicalName(zs.Name)

	alg := zs.Algorithm
	if alg == 0 {
		alg = dnssec.AlgED25519
	}
	digest := zs.DigestType
	if digest == 0 {
		digest = dnssec.DigestSHA256
	}

	signer, err := deriveKey(alg, spec.Seed+"|"+name)
	if err != nil {
		return nil, err
	}

	key := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name: name, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600,
		},
		// Both the zone bit and the SEP bit are set because this lab signs
		// each zone with a single key. That is a legal configuration and a
		// deliberate choice: a validator that quietly assumes the KSK/ZSK
		// split — signing the DNSKEY RRset with a SEP key and everything
		// else with a non-SEP key — passes against a two-key lab and fails
		// against real single-key zones. This setup catches that assumption
		// on the first run.
		Flags:     257,
		Protocol:  3,
		Algorithm: uint8(alg),
	}
	if err := setPublicKey(key, signer); err != nil {
		return nil, err
	}

	zone := &Zone{
		Name: name, Key: key, Signer: signer,
		Algorithm: alg, DigestType: digest,
		sets: make(map[setKey][]dns.RR),
	}

	// The apex DNSKEY RRset signs itself, which is what a DS or trust anchor
	// then authenticates.
	if err := zone.addSigned(spec, []dns.RR{key}); err != nil {
		return nil, err
	}

	for _, group := range groupRRsets(zs.Records) {
		if err := zone.addSigned(spec, group); err != nil {
			return nil, err
		}
	}
	return zone, nil
}

// addSigned signs one RRset with the zone's key and stores it alongside its
// signature.
//
// Signing goes through github.com/miekg/dns rather than through Daddybound's
// own canonicalisation, deliberately. Signing with the code under test would
// make every signature verify by construction: a canonicalisation bug would
// cancel out and the tests would pass while producing signatures no other
// implementation accepts. Using an independent implementation to sign means
// Daddybound's verifier is checked against someone else's reading of
// RFC 4034 §6 on every run.
func (z *Zone) addSigned(spec Spec, rrset []dns.RR) error {
	if len(rrset) == 0 {
		return nil
	}
	h := rrset[0].Header()
	sig := &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name: dns.CanonicalName(h.Name), Rrtype: dns.TypeRRSIG,
			Class: h.Class, Ttl: h.Ttl,
		},
		TypeCovered: h.Rrtype,
		Algorithm:   uint8(z.Algorithm),
		Labels:      uint8(dns.CountLabel(h.Name)),
		OrigTtl:     h.Ttl,
		Inception:   uint32(spec.Inception.Unix()),
		Expiration:  uint32(spec.Expiration.Unix()),
		KeyTag:      z.Key.KeyTag(),
		SignerName:  z.Name,
	}
	if err := sig.Sign(z.Signer, rrset); err != nil {
		return fmt.Errorf("lab: signing %s %s: %w", h.Name, dns.TypeToString[h.Rrtype], err)
	}

	k := setKey{name: dns.CanonicalName(h.Name), rrtype: h.Rrtype}
	z.sets[k] = append(append([]dns.RR{}, rrset...), sig)
	return nil
}

// makeDS builds the delegation record a parent publishes for a child.
//
// The digest is computed by github.com/miekg/dns for the same reason
// signatures are: Daddybound recomputes it in dsDigest, and a lab that used
// Daddybound's own computation could not tell a correct implementation from
// a consistently wrong one.
func makeDS(child *Zone) (*dns.DS, error) {
	ds := child.Key.ToDS(uint8(child.DigestType))
	if ds == nil {
		return nil, fmt.Errorf("lab: cannot build a DS for %s with digest type %d", child.Name, child.DigestType)
	}
	ds.Hdr.Name = child.Name
	ds.Hdr.Ttl = 3600
	ds.Hdr.Class = dns.ClassINET
	return ds, nil
}

func mustDS(z *Zone) *dns.DS {
	if z.DS != nil {
		return z.DS
	}
	ds, err := makeDS(z)
	if err != nil {
		// Only reachable with a digest type the library cannot compute,
		// which Build has already rejected for every other zone.
		panic(err)
	}
	return ds
}

// groupRRsets partitions records into RRsets by owner name, class and type,
// in a deterministic order so that two builds produce the same hierarchy.
func groupRRsets(records []dns.RR) [][]dns.RR {
	index := make(map[setKey][]dns.RR)
	var order []setKey
	for _, rr := range records {
		h := rr.Header()
		k := setKey{name: dns.CanonicalName(h.Name), rrtype: h.Rrtype}
		if _, seen := index[k]; !seen {
			order = append(order, k)
		}
		index[k] = append(index[k], rr)
	}
	sort.Slice(order, func(i, j int) bool {
		if order[i].name != order[j].name {
			return order[i].name < order[j].name
		}
		return order[i].rrtype < order[j].rrtype
	})

	out := make([][]dns.RR, 0, len(order))
	for _, k := range order {
		out = append(out, index[k])
	}
	return out
}

// reindex rebuilds the flat lookup table from the zones. Called after any
// mutation so that a scenario's changes are visible to both the Source and
// the authoritative server.
func (h *Hierarchy) reindex() {
	h.sets = make(map[setKey][]dns.RR)
	for _, z := range h.Zones {
		for k, v := range z.sets {
			h.sets[k] = v
		}
	}
}

// Zone returns a zone by name, or nil.
func (h *Hierarchy) Zone(name string) *Zone { return h.byName[dns.CanonicalName(name)] }

// Lookup implements dnssec.Source.
//
// It answers from memory and never blocks, so a validation against the lab
// exercises only the validation logic. The context is honoured anyway: code
// that ignores cancellation in the easy case tends to ignore it in the hard
// one too.
func (h *Hierarchy) Lookup(ctx context.Context, name string, rrtype uint16) ([]dns.RR, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	records := h.sets[setKey{name: dns.CanonicalName(name), rrtype: rrtype}]
	// Copied so a caller — or a mutation applied later — cannot reach into
	// the hierarchy's own slices.
	return append([]dns.RR{}, records...), nil
}

// Records returns every record in the hierarchy, for an authoritative server
// to serve. Sorted, so the server's behaviour does not depend on map order.
func (h *Hierarchy) Records() []dns.RR {
	keys := make([]setKey, 0, len(h.sets))
	for k := range h.sets {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].name != keys[j].name {
			return keys[i].name < keys[j].name
		}
		return keys[i].rrtype < keys[j].rrtype
	})

	var out []dns.RR
	for _, k := range keys {
		out = append(out, h.sets[k]...)
	}
	return out
}

// setPublicKey fills a DNSKEY's public key field from a signer.
//
// The DNSKEY wire formats are RFC 3110 for RSA, RFC 6605 for ECDSA and
// RFC 8080 for Ed25519. This is the encoding side of what dnssec.verify.go
// decodes, and the two are written from the same RFCs rather than from each
// other — a round trip that only agreed with itself would prove nothing.
func setPublicKey(key *dns.DNSKEY, signer crypto.Signer) error {
	priv, ok := signer.(interface{ Public() crypto.PublicKey })
	if !ok {
		return fmt.Errorf("lab: signer for %s exposes no public key", key.Hdr.Name)
	}
	encoded, err := encodePublicKey(priv.Public())
	if err != nil {
		return fmt.Errorf("lab: %s: %w", key.Hdr.Name, err)
	}
	key.PublicKey = encoded
	return nil
}

// Description renders the hierarchy for a human, one zone per line. Used by
// the CLI and by test failure output.
func (h *Hierarchy) Description() string {
	var b strings.Builder
	for i, z := range h.Zones {
		fmt.Fprintf(&b, "%s%s  alg=%s keytag=%d", strings.Repeat("  ", i), z.Name, z.Algorithm.Name(), z.Key.KeyTag())
		if z.DS != nil {
			fmt.Fprintf(&b, " ds=%s", z.DigestType.Name())
		} else {
			fmt.Fprintf(&b, " (trust anchor)")
		}
		b.WriteByte('\n')
	}
	return b.String()
}
