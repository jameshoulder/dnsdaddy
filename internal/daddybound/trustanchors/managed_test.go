package trustanchors_test

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/trustanchors"
)

// zone is a signed trust point under test: a set of keys and the ability to
// publish a DNSKEY RRset signed by whichever of them the test chooses.
//
// Real keys and real signatures, not a stub. The whole of RFC 5011's security
// is "was this RRset signed by a key you already trust", so a harness that let
// a test assert on signatures it did not actually make would be testing the
// wrong thing.
type zone struct {
	t    *testing.T
	name string
	keys map[uint16]*signingKey
	// published is the keys currently in the RRset, in publication order.
	published []uint16
	// revoked marks keys published with the REVOKE bit set.
	revoked map[uint16]bool
	// signers are the keys that sign the RRset.
	signers []uint16
	ttl     uint32
	now     func() time.Time
}

type signingKey struct {
	dnskey *dns.DNSKEY
	signer crypto.Signer
}

func newZone(t *testing.T, name string, now func() time.Time) *zone {
	t.Helper()
	return &zone{
		t: t, name: dns.CanonicalName(name),
		keys: map[uint16]*signingKey{}, revoked: map[uint16]bool{},
		ttl: 172800, now: now,
	}
}

// addKey mints a new key-signing key and returns its tag.
func (z *zone) addKey(seed byte) uint16 {
	z.t.Helper()

	// Ed25519 from a fixed seed, so a scenario is byte-identical on every run
	// and a failure is reproducible rather than a story about randomness.
	raw := make([]byte, ed25519.SeedSize)
	for i := range raw {
		raw[i] = seed
	}
	priv := ed25519.NewKeyFromSeed(raw)

	k := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: z.name, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: z.ttl},
		Flags:     dns.ZONE | dns.SEP,
		Protocol:  3,
		Algorithm: dns.ED25519,
	}
	k.PublicKey = toBase64(priv.Public().(ed25519.PublicKey))
	tag := k.KeyTag()
	z.keys[tag] = &signingKey{dnskey: k, signer: priv}
	return tag
}

// toBase64 encodes a public key the way a DNSKEY record carries it: standard
// base64 with padding, per RFC 4034 §2.1.
func toBase64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// adopt copies another zone's public key into this one, without its private
// half.
//
// For building the attack that matters: an RRset that genuinely contains the
// key a resolver trusts, alongside the attacker's, signed only by the
// attacker's. Every cheaper check — "is a trusted key present?" — passes, and
// only verifying the signatures rejects it.
func (z *zone) adopt(other *zone, tag uint16) uint16 {
	z.t.Helper()
	k := other.keys[tag]
	if k == nil {
		z.t.Fatalf("no key %d to adopt", tag)
	}
	copied := *k.dnskey
	copied.Hdr.Name = z.name
	// No signer: this zone holds the public half only, which is exactly the
	// attacker's position.
	z.keys[copied.KeyTag()] = &signingKey{dnskey: &copied}
	return copied.KeyTag()
}

// publish sets which keys appear in the RRset.
func (z *zone) publish(tags ...uint16) { z.published = tags }

// signWith sets which keys sign the RRset.
func (z *zone) signWith(tags ...uint16) { z.signers = tags }

// revoke marks a key as published with the REVOKE bit.
func (z *zone) revokeKey(tag uint16) { z.revoked[tag] = true }

// anchor returns the DS presentation form of a key, as IANA would publish it.
func (z *zone) anchor(tag uint16) string {
	z.t.Helper()
	k := z.keys[tag]
	if k == nil {
		z.t.Fatalf("no key %d", tag)
	}
	ds := k.dnskey.ToDS(dns.SHA256)
	return fmt.Sprintf("%s %d %d %d %s", z.name, ds.KeyTag, ds.Algorithm, ds.DigestType, ds.Digest)
}

// DNSKEY builds and signs the RRset, satisfying trustanchors.KeySource.
func (z *zone) DNSKEY(ctx context.Context, name string) ([]dns.RR, error) {
	if dns.CanonicalName(name) != z.name {
		return nil, fmt.Errorf("this laboratory serves %s, not %s", z.name, name)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var set []dns.RR
	for _, tag := range z.published {
		k := z.keys[tag]
		if k == nil {
			return nil, fmt.Errorf("no key %d", tag)
		}
		copied := *k.dnskey
		if z.revoked[tag] {
			copied.Flags |= dns.REVOKE
		}
		set = append(set, &copied)
	}
	if len(set) == 0 {
		return nil, errors.New("no keys published")
	}

	out := append([]dns.RR(nil), set...)
	now := z.now()
	for _, tag := range z.signers {
		k := z.keys[tag]
		if k == nil {
			return nil, fmt.Errorf("no signing key %d", tag)
		}
		flags := k.dnskey.Flags
		if z.revoked[tag] {
			flags |= dns.REVOKE
		}
		signing := *k.dnskey
		signing.Flags = flags

		sig := &dns.RRSIG{
			Hdr:         dns.RR_Header{Name: z.name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: z.ttl},
			TypeCovered: dns.TypeDNSKEY,
			Algorithm:   k.dnskey.Algorithm,
			Labels:      uint8(dns.CountLabel(z.name)),
			OrigTtl:     z.ttl,
			Inception:   uint32(now.Add(-time.Hour).Unix()),
			Expiration:  uint32(now.Add(14 * 24 * time.Hour).Unix()),
			KeyTag:      signing.KeyTag(),
			SignerName:  z.name,
		}
		if err := sig.Sign(k.signer, set); err != nil {
			return nil, fmt.Errorf("signing with key %d: %w", tag, err)
		}
		out = append(out, sig)
	}
	return out, nil
}

// clock is a test clock that a scenario advances by hand.
type clock struct{ at time.Time }

func (c *clock) now() time.Time      { return c.at }
func (c *clock) add(d time.Duration) { c.at = c.at.Add(d) }

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// harness builds a manager over a zone, seeded from the given key's digest.
func harness(t *testing.T, z *zone, c *clock, seedTags ...uint16) (*trustanchors.Manager, *trustanchors.MemoryStore) {
	t.Helper()

	var anchors []dnssec.TrustAnchor
	for _, tag := range seedTags {
		a, err := dnssec.ParseTrustAnchorDS(z.anchor(tag))
		if err != nil {
			t.Fatalf("parsing the seed anchor: %v", err)
		}
		anchors = append(anchors, a)
	}
	configured, err := dnssec.NewTrustAnchors(anchors...)
	if err != nil {
		t.Fatalf("building the configured anchors: %v", err)
	}

	store := &trustanchors.MemoryStore{}
	m, err := trustanchors.NewManager(trustanchors.ManagerConfig{
		Zone:       z.name,
		Configured: configured,
		Store:      store,
		Source:     z,
		Policy:     dnssec.DefaultPolicy(),
		Verifier:   dnssec.StdVerifier(),
		Limits:     dnssec.DefaultLimits(),
		Now:        c.now,
		Log:        quiet(),
	})
	if err != nil {
		t.Fatalf("building the manager: %v", err)
	}
	return m, store
}

// trusts reports whether the manager's current anchor set names this key.
func trusts(t *testing.T, m *trustanchors.Manager, z *zone, tag uint16) bool {
	t.Helper()
	key := z.keys[tag]
	if key == nil {
		t.Fatalf("no key %d", tag)
	}
	for _, a := range m.Anchors().Anchors() {
		if a.MatchesKey(dnssec.DefaultPolicy(), key.dnskey) == dnssec.ReasonNone {
			return true
		}
	}
	return false
}
