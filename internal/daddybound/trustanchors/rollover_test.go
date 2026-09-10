package trustanchors_test

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/trustanchors"
)

func ctx() context.Context { return context.Background() }

// A zone can hand this resolver a new trust anchor, and it takes thirty days.
//
// The whole point of RFC 5011, tested as a sequence rather than as a state
// assertion: the new key appears, is not trusted, stays published, is still not
// trusted a week later, and becomes a trust anchor only once the hold-down has
// been served in full.
func TestANewKeyBecomesATrustAnchorOnlyAfterItsHoldDown(t *testing.T) {
	c := &clock{at: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	z := newZone(t, ".", c.now)

	old := z.addKey(1)
	z.publish(old)
	z.signWith(old)

	m, _ := harness(t, z, c, old)

	if res := m.Refresh(ctx()); !res.OK {
		t.Fatalf("the first refresh failed: %s", res.Err)
	}
	if !trusts(t, m, z, old) {
		t.Fatal("the key this resolver was configured with is not trusted")
	}

	// The zone publishes a second key, signed by the first.
	fresh := z.addKey(2)
	z.publish(old, fresh)
	c.add(time.Hour)
	if res := m.Refresh(ctx()); !res.OK {
		t.Fatalf("refresh: %s", res.Err)
	}
	if trusts(t, m, z, fresh) {
		t.Fatal("a key was trusted the moment it appeared; the hold-down did nothing")
	}

	// A week in. Still not trusted: thirty days means thirty days.
	c.add(7 * 24 * time.Hour)
	if res := m.Refresh(ctx()); !res.OK {
		t.Fatalf("refresh: %s", res.Err)
	}
	if trusts(t, m, z, fresh) {
		t.Fatal("a key was trusted after a week of a thirty-day hold-down")
	}

	// Past thirty days, and one more refresh that sees the key still there.
	// RFC 5011 §2.4.1 wants both: the time, and a validated RRset after it.
	c.add(24 * 24 * time.Hour)
	res := m.Refresh(ctx())
	if !res.OK {
		t.Fatalf("refresh: %s", res.Err)
	}
	if !trusts(t, m, z, fresh) {
		t.Fatalf("the key did not become a trust anchor after its hold-down; changes: %v", res.Changes)
	}
	// And the old key is still trusted: adding one does not withdraw another.
	if !trusts(t, m, z, old) {
		t.Error("adding a key withdrew the one that vouched for it")
	}
}

// The hold-down has to be served continuously.
//
// A key that appears, vanishes and reappears has not been published for thirty
// days. Crediting it for the time it spent absent would let an attacker with
// intermittent control of the answer accumulate a hold-down they never served.
func TestAKeyThatDisappearsRestartsItsHoldDown(t *testing.T) {
	c := &clock{at: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	z := newZone(t, ".", c.now)

	old := z.addKey(1)
	z.publish(old)
	z.signWith(old)
	m, _ := harness(t, z, c, old)
	if res := m.Refresh(ctx()); !res.OK {
		t.Fatalf("refresh: %s", res.Err)
	}

	fresh := z.addKey(2)
	z.publish(old, fresh)
	c.add(time.Hour)
	if res := m.Refresh(ctx()); !res.OK {
		t.Fatalf("refresh: %s", res.Err)
	}

	// Twenty-nine days of patience, then the key vanishes.
	c.add(29 * 24 * time.Hour)
	z.publish(old)
	if res := m.Refresh(ctx()); !res.OK {
		t.Fatalf("refresh: %s", res.Err)
	}

	// It comes back the next day. Under a naive implementation the original
	// hold-down has now expired and the key is trusted immediately.
	c.add(24 * time.Hour)
	z.publish(old, fresh)
	if res := m.Refresh(ctx()); !res.OK {
		t.Fatalf("refresh: %s", res.Err)
	}
	if trusts(t, m, z, fresh) {
		t.Fatal("a key that was withdrawn mid-hold-down kept its accumulated time " +
			"and became a trust anchor a day later")
	}

	// It has to serve a fresh thirty days from its reappearance.
	c.add(31 * 24 * time.Hour)
	if res := m.Refresh(ctx()); !res.OK {
		t.Fatalf("refresh: %s", res.Err)
	}
	if !trusts(t, m, z, fresh) {
		t.Fatal("the key never became a trust anchor even after a full fresh hold-down")
	}
}

// A revoked key stops being a trust anchor immediately — including one this
// build shipped a digest for.
//
// This is the case an implementation gets wrong by treating configured anchors
// as unconditional. RFC 5011 §2.2 makes a revoked key unusable for every
// purpose, and a digest in the binary naming one does not change that: the
// configuration is out of date rather than authoritative about the zone's keys.
func TestARevokedKeyIsWithdrawnEvenWhenItIsAConfiguredAnchor(t *testing.T) {
	c := &clock{at: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	z := newZone(t, ".", c.now)

	old := z.addKey(1)
	fresh := z.addKey(2)
	z.publish(old, fresh)
	z.signWith(old)

	// Both are configured, so the successor is trusted from the start and the
	// revocation below leaves something to validate with.
	m, _ := harness(t, z, c, old, fresh)
	if res := m.Refresh(ctx()); !res.OK {
		t.Fatalf("refresh: %s", res.Err)
	}
	if !trusts(t, m, z, old) || !trusts(t, m, z, fresh) {
		t.Fatal("both configured keys should be trusted before the revocation")
	}

	// The zone revokes the old key. RFC 5011 §2.2 wants the announcement
	// signed by the key being withdrawn, so the outgoing key signs its own
	// retirement; the successor signs too, so the RRset stays usable to a
	// resolver that never trusted the outgoing one.
	z.revokeKey(old)
	z.signWith(old, fresh)
	c.add(time.Hour)
	res := m.Refresh(ctx())
	if !res.OK {
		t.Fatalf("refresh: %s", res.Err)
	}

	if trusts(t, m, z, old) {
		t.Fatalf("a revoked key is still a trust anchor; changes: %v", res.Changes)
	}
	if !trusts(t, m, z, fresh) {
		t.Error("revoking one key withdrew the other")
	}
	if m.TrustPoint().NeedsIntervention {
		t.Error("a trust point with a usable key was marked as needing an operator")
	}
}

// One key must not be able to revoke another.
//
// RFC 5011 §2.2 defines revocation as a key appearing with the REVOKE bit in a
// *self*-signed RRset, and the self-signature is what bounds a key compromise.
// An implementation that accepted a revocation announced by any trusted key
// would let a single stolen key withdraw every other key at the trust point —
// and a trust point with all its keys revoked can no longer be maintained
// automatically, so one theft would turn into a resolver that has to be fixed
// by hand everywhere it runs.
//
// This is the reasoning I originally got backwards, on the grounds that a key
// whose private half is gone could then never be retired. That cost is real
// and is the trade the RFC makes; it does not buy the attack back.
func TestOneKeyCannotRevokeAnother(t *testing.T) {
	c := &clock{at: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	z := newZone(t, ".", c.now)

	stolen := z.addKey(1)
	victim := z.addKey(2)
	z.publish(stolen, victim)
	z.signWith(stolen)

	m, _ := harness(t, z, c, stolen, victim)
	if res := m.Refresh(ctx()); !res.OK {
		t.Fatalf("refresh: %s", res.Err)
	}
	if !trusts(t, m, z, victim) {
		t.Fatal("the victim key should be trusted to begin with")
	}

	// The attacker holds `stolen` and uses it to announce that `victim` is
	// revoked. Every signature on this RRset verifies — against a key this
	// resolver trusts — so an implementation that checked only "did a trusted
	// key sign this" would accept the revocation.
	z.revokeKey(victim)
	c.add(time.Hour)
	res := m.Refresh(ctx())
	if !res.OK {
		t.Fatalf("refresh: %s", res.Err)
	}

	if !trusts(t, m, z, victim) {
		t.Fatalf("one key revoked another; changes: %v", res.Changes)
	}
	for _, k := range m.TrustPoint().Keys {
		if k.State == trustanchors.StateRevoked {
			t.Errorf("key %d was recorded as revoked without signing its own revocation", k.KeyTag)
		}
	}
}

// A DNSKEY RRset that does not authenticate changes nothing at all.
//
// The single most important property here. A refresh that could not
// authenticate has learned nothing — not that the keys changed, not that they
// did not — and anything it did to the state on that basis would be a change
// an attacker who can rewrite packets got to choose. So: no promotion, no
// revocation, no withdrawal, and the anchors in force are exactly what they
// were.
func TestAnUnauthenticatedRRsetChangesNothing(t *testing.T) {
	c := &clock{at: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	z := newZone(t, ".", c.now)

	old := z.addKey(1)
	z.publish(old)
	z.signWith(old)
	m, _ := harness(t, z, c, old)
	if res := m.Refresh(ctx()); !res.OK {
		t.Fatalf("refresh: %s", res.Err)
	}
	before := m.Anchors().Anchors()

	// The attack that gets past every cheap check. The RRset genuinely
	// contains the key this resolver trusts — copied from the real zone,
	// public half only — alongside the attacker's own, and it is signed only
	// by the attacker's. "Is a trusted key present?" is satisfied; nothing
	// but verifying the signatures rejects it.
	attacker := newZone(t, ".", c.now)
	stolen := attacker.adopt(z, old)
	evil := attacker.addKey(9)
	attacker.publish(stolen, evil)
	attacker.signWith(evil)

	// A manager configured with the real key's digest, fed by the attacker.
	hostile := attackerManager(t, z, attacker, c)

	res := hostile.Refresh(ctx())
	if res.OK {
		t.Fatal("a DNSKEY RRset signed only by an untrusted key was accepted")
	}
	if len(res.Changes) != 0 {
		t.Errorf("a failed refresh changed state: %v", res.Changes)
	}
	if trusts(t, hostile, attacker, evil) {
		t.Fatal("an attacker's key became a trust anchor by asserting itself")
	}
	if got := len(hostile.Anchors().Anchors()); got != len(before) {
		t.Errorf("the anchor set changed size on a failed refresh: %d, was %d", got, len(before))
	}
	if hostile.TrustPoint().LastError == "" {
		t.Error("a failed refresh recorded no error; an operator would see a healthy trust point")
	}
}

// attackerManager builds a manager configured with real's anchor but fed by
// evil's zone.
func attackerManager(t *testing.T, real, evil *zone, c *clock) *trustanchors.Manager {
	t.Helper()

	// Configured with the real zone's key, the one the attacker copied.
	a, err := dnssec.ParseTrustAnchorDS(real.anchor(real.published[0]))
	if err != nil {
		t.Fatalf("parsing the anchor: %v", err)
	}
	configured, err := dnssec.NewTrustAnchors(a)
	if err != nil {
		t.Fatalf("building the anchors: %v", err)
	}
	m, err := trustanchors.NewManager(trustanchors.ManagerConfig{
		Zone: ".", Configured: configured, Store: &trustanchors.MemoryStore{},
		Source: evil, Policy: dnssec.DefaultPolicy(), Verifier: dnssec.StdVerifier(),
		Limits: dnssec.DefaultLimits(), Now: c.now, Log: quiet(),
	})
	if err != nil {
		t.Fatalf("building the manager: %v", err)
	}
	return m
}

// A refresh that cannot reach the zone leaves the anchors alone and says so.
//
// A resolver whose trust anchors evaporated because the network was down would
// be one an outage turns into a non-validating resolver. The failure is
// recorded, loudly and persistently, and nothing else moves.
func TestAnUnreachableZoneLeavesTheAnchorsInForce(t *testing.T) {
	c := &clock{at: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	z := newZone(t, ".", c.now)
	old := z.addKey(1)
	z.publish(old)
	z.signWith(old)

	m, store := harness(t, z, c, old)
	if res := m.Refresh(ctx()); !res.OK {
		t.Fatalf("refresh: %s", res.Err)
	}
	before := len(m.Anchors().Anchors())

	// The zone stops answering.
	z.publish()
	c.add(time.Hour)
	res := m.Refresh(ctx())
	if res.OK {
		t.Fatal("a refresh that fetched nothing reported success")
	}
	if !trusts(t, m, z, old) {
		t.Fatal("an unreachable zone cost this resolver its trust anchor")
	}
	if got := len(m.Anchors().Anchors()); got != before {
		t.Errorf("the anchor set changed on an unreachable refresh: %d, was %d", got, before)
	}
	if res.NextRefresh.Before(c.now().Add(time.Hour - time.Second)) {
		t.Errorf("the retry was scheduled for %s, sooner than RFC 5011 §2.3's one-hour floor",
			res.NextRefresh.Sub(c.now()))
	}
	// The failure is on disk, so an operator can see refreshes have been
	// failing rather than a trust point that merely looks quiet.
	saved, err := store.Load()
	if err != nil {
		t.Fatalf("loading the saved state: %v", err)
	}
	if saved.LastError == "" {
		t.Error("the failure was not persisted")
	}
	if !saved.LastSuccess.Before(saved.LastRefresh) {
		t.Error("LastSuccess moved on a failed refresh; an operator could not tell how old the evidence is")
	}
}

// A key must be recognised by its material, not by its tag.
//
// A key tag is a 16-bit checksum over the RDATA (RFC 4034 Appendix B), not an
// identifier. Matching a stored trust anchor on the tag alone would let anyone
// who found a collision have their key treated as one this resolver already
// trusts — which is the whole game.
func TestAKeyIsIdentifiedByItsMaterialRatherThanItsTag(t *testing.T) {
	c := &clock{at: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	z := newZone(t, ".", c.now)
	old := z.addKey(1)
	z.publish(old)
	z.signWith(old)
	m, _ := harness(t, z, c, old)
	if res := m.Refresh(ctx()); !res.OK {
		t.Fatalf("refresh: %s", res.Err)
	}

	// A different key wearing the trusted key's tag. It cannot be given a
	// real colliding tag here, so the check is made where it matters: the
	// anchor comparison must reject it on the digest even though the tag and
	// algorithm select it as a candidate.
	impostor := z.keys[z.addKey(7)].dnskey
	impostor.Hdr.Name = "."
	for _, a := range m.Anchors().Anchors() {
		forged := *impostor
		if a.MatchesKey(dnssec.DefaultPolicy(), &forged) == dnssec.ReasonNone {
			t.Fatal("a different key matched a configured anchor")
		}
	}
}

// State survives a restart, and a corrupt state file does not take the
// resolver down with it.
func TestStateSurvivesARestartAndACorruptFileFallsBackToConfiguration(t *testing.T) {
	c := &clock{at: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	z := newZone(t, ".", c.now)
	old := z.addKey(1)
	fresh := z.addKey(2)
	z.publish(old, fresh)
	z.signWith(old)

	m, store := harness(t, z, c, old)
	if res := m.Refresh(ctx()); !res.OK {
		t.Fatalf("refresh: %s", res.Err)
	}
	c.add(31 * 24 * time.Hour)
	if res := m.Refresh(ctx()); !res.OK {
		t.Fatalf("refresh: %s", res.Err)
	}
	if !trusts(t, m, z, fresh) {
		t.Fatal("the successor never completed its hold-down")
	}

	// Restart: a new manager over the same store.
	restarted := managerOver(t, z, c, store, old)
	if !trusts(t, restarted, z, fresh) {
		t.Fatal("a key promoted before the restart is not trusted after it; " +
			"the hold-down would have to be served again on every restart")
	}

	// A store that cannot be read at all. The resolver falls back to the
	// anchors it shipped rather than to nothing.
	broken := managerOver(t, z, c, failingStore{}, old)
	if !trusts(t, broken, z, old) {
		t.Fatal("an unreadable state file left the resolver with no trust anchor")
	}
	if trusts(t, broken, z, fresh) {
		t.Error("an unreadable state file somehow produced a managed key")
	}
}

// managerOver builds a manager over an existing store, as a restart would.
func managerOver(t *testing.T, z *zone, c *clock, store trustanchors.Store, seed uint16) *trustanchors.Manager {
	t.Helper()
	a, err := dnssec.ParseTrustAnchorDS(z.anchor(seed))
	if err != nil {
		t.Fatalf("parsing the anchor: %v", err)
	}
	configured, err := dnssec.NewTrustAnchors(a)
	if err != nil {
		t.Fatalf("building the anchors: %v", err)
	}
	m, err := trustanchors.NewManager(trustanchors.ManagerConfig{
		Zone: z.name, Configured: configured, Store: store, Source: z,
		Policy: dnssec.DefaultPolicy(), Verifier: dnssec.StdVerifier(),
		Limits: dnssec.DefaultLimits(), Now: c.now, Log: quiet(),
	})
	if err != nil {
		t.Fatalf("building the manager: %v", err)
	}
	return m
}

type failingStore struct{}

func (failingStore) Load() (trustanchors.TrustPoint, error) {
	return trustanchors.TrustPoint{}, errDeliberate
}
func (failingStore) Save(trustanchors.TrustPoint) error { return errDeliberate }

var errDeliberate = errDeliberateType{}

type errDeliberateType struct{}

func (errDeliberateType) Error() string { return "this store is deliberately broken" }

// When every key is revoked, the resolver says it cannot tell — it does not
// quietly become a non-validating resolver.
//
// RFC 5011 §5 deletes the trust point, after which data below it evaluates as
// though nothing were configured: Insecure. That is reasonable for a
// general-purpose resolver and wrong here, because Live mode's premise is that
// answers were validated. A resolver that silently stopped validating the root
// and carried on serving would be making a claim it could no longer support.
//
// So the anchor set empties, which makes every verdict Indeterminate — "this
// validator cannot tell" — and the trust point is marked for an operator.
func TestRevokingEveryKeyFailsClosedRatherThanGoingInsecure(t *testing.T) {
	c := &clock{at: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	z := newZone(t, ".", c.now)
	only := z.addKey(1)
	z.publish(only)
	z.signWith(only)

	m, _ := harness(t, z, c, only)
	if res := m.Refresh(ctx()); !res.OK {
		t.Fatalf("refresh: %s", res.Err)
	}

	z.revokeKey(only)
	c.add(time.Hour)
	res := m.Refresh(ctx())
	if !res.OK {
		t.Fatalf("the revocation refresh failed: %s", res.Err)
	}

	if n := len(m.Anchors().Anchors()); n != 0 {
		t.Fatalf("%d anchors survive after every key was revoked; a revoked key is still in use", n)
	}
	if m.Viable() {
		t.Error("a trust point with no usable key reports itself viable")
	}
	tp := m.TrustPoint()
	if !tp.NeedsIntervention {
		t.Fatal("a trust point with every key revoked was not marked as needing an operator")
	}
	if tp.InterventionNote == "" {
		t.Error("no explanation was recorded for an operator to act on")
	}

	// And a validator built on that set reports Indeterminate rather than
	// Insecure. This is the property that keeps Live honest.
	v := dnssec.New(nil, dnssec.Config{Anchors: m.Anchors()})
	got := v.Validate(ctx(), "www.example.com.", dns.TypeA)
	if got.Status != dnssec.StatusIndeterminate {
		t.Errorf("with no anchors the verdict is %s, want indeterminate — "+
			"anything else would have this resolver assert something it cannot check", got.Status)
	}
}

// The refresh schedule follows RFC 5011 §2.3 rather than a number somebody
// liked.
func TestTheRefreshScheduleFollowsTheSpecifiedBounds(t *testing.T) {
	c := &clock{at: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	z := newZone(t, ".", c.now)
	old := z.addKey(1)
	z.publish(old)
	z.signWith(old)
	m, _ := harness(t, z, c, old)

	res := m.Refresh(ctx())
	if !res.OK {
		t.Fatalf("refresh: %s", res.Err)
	}
	// The laboratory publishes a 172800-second (two-day) TTL and signatures
	// valid for fourteen days, so §2.3's MIN picks half the TTL: one day.
	want := 24 * time.Hour
	if got := res.NextRefresh.Sub(c.now()); got != want {
		t.Errorf("next refresh in %s, want %s — MAX(1hr, MIN(15 days, ½ TTL, ½ signature life))",
			got, want)
	}
	// Never more often than hourly, whatever the zone says.
	z.ttl = 2
	c.add(time.Hour)
	res = m.Refresh(ctx())
	if !res.OK {
		t.Fatalf("refresh: %s", res.Err)
	}
	if got := res.NextRefresh.Sub(c.now()); got < time.Hour {
		t.Errorf("a one-second TTL scheduled a refresh in %s; §2.3's floor is one hour", got)
	}
}
