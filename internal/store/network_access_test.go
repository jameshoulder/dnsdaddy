package store

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func mustCreateNetwork(t *testing.T, st *Store, in NetworkInput) Network {
	t.Helper()
	n, err := st.CreateNetwork(context.Background(), in)
	if err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	return n
}

// A private range needs no ceremony: tick the box, and it is permitted.
func TestPrivateNetworkIsPermittedWithoutAcknowledgement(t *testing.T) {
	st := newTestStore(t)

	n := mustCreateNetwork(t, st, NetworkInput{
		Name:          ptr("Home"),
		CIDRs:         ptr([]string{"192.168.1.0/24"}),
		AllowResolver: ptr(true),
	})
	if !n.AllowResolver {
		t.Fatal("allowResolver did not persist")
	}
	if len(n.AcknowledgedPublicCIDRs) != 0 {
		t.Errorf("a private range was recorded as acknowledged: %v", n.AcknowledgedPublicCIDRs)
	}
}

// The affirmation required by a public address is a real gate, not a warning
// the caller can ignore: without it nothing is permitted at all.
func TestPublicRangeRequiresAcknowledgement(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	_, err := st.CreateNetwork(ctx, NetworkInput{
		Name:          ptr("VPS client"),
		CIDRs:         ptr([]string{"203.0.113.25/32"}),
		AllowResolver: ptr(true),
	})
	var needAck *ErrPublicAckRequired
	if !errors.As(err, &needAck) {
		t.Fatalf("err = %v, want ErrPublicAckRequired", err)
	}
	if got := needAck.PublicCIDRs(); len(got) != 1 || got[0] != "203.0.113.25/32" {
		t.Errorf("PublicCIDRs = %v, want the offending range named", got)
	}
	// The operator has to be told what they are agreeing to, and that DNS
	// Daddy is not going to configure their firewall for them.
	for _, want := range []string{"port 53", "firewall"} {
		if !strings.Contains(needAck.Error(), want) {
			t.Errorf("error does not mention %q: %s", want, needAck.Error())
		}
	}

	// Nothing was written.
	all, err := st.ListNetworks(ctx)
	if err != nil {
		t.Fatalf("ListNetworks: %v", err)
	}
	for _, n := range all {
		if n.Name == "VPS client" {
			t.Fatal("the refused network was created anyway")
		}
	}
}

func TestPublicRangeIsPermittedOnceAcknowledged(t *testing.T) {
	st := newTestStore(t)

	n := mustCreateNetwork(t, st, NetworkInput{
		Name:          ptr("VPS client"),
		CIDRs:         ptr([]string{"203.0.113.25/32"}),
		AllowResolver: ptr(true),
		PublicAck:     ptr(true),
	})
	if !n.AllowResolver {
		t.Fatal("allowResolver did not persist")
	}
	if len(n.AcknowledgedPublicCIDRs) != 1 || n.AcknowledgedPublicCIDRs[0] != "203.0.113.25/32" {
		t.Errorf("acknowledged = %v, want the public range recorded", n.AcknowledgedPublicCIDRs)
	}
}

// A public range recorded while the network was unpermitted still needs the
// affirmation when the permission is granted: it is the permission that
// exposes the resolver, not the row in the CIDR table.
func TestPermittingAnExistingPublicRangeStillNeedsAcknowledgement(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	n := mustCreateNetwork(t, st, NetworkInput{
		Name:  ptr("VPS client"),
		CIDRs: ptr([]string{"203.0.113.25/32"}),
	})

	_, err := st.UpdateNetwork(ctx, n.ID, NetworkInput{AllowResolver: ptr(true)})
	var needAck *ErrPublicAckRequired
	if !errors.As(err, &needAck) {
		t.Fatalf("err = %v, want ErrPublicAckRequired — flipping the permission is what exposes it", err)
	}
}

// The mirror image: adding a public range to a network that is *already*
// permitted must be caught too. Validating the request in isolation rather
// than the merged result is how either half of a two-step change slips past.
func TestAddingAPublicRangeToAPermittedNetworkNeedsAcknowledgement(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	n := mustCreateNetwork(t, st, NetworkInput{
		Name:          ptr("Home"),
		CIDRs:         ptr([]string{"192.168.1.0/24"}),
		AllowResolver: ptr(true),
	})

	_, err := st.UpdateNetwork(ctx, n.ID, NetworkInput{
		CIDRs: ptr([]string{"192.168.1.0/24", "203.0.113.25/32"}),
	})
	var needAck *ErrPublicAckRequired
	if !errors.As(err, &needAck) {
		t.Fatalf("err = %v, want ErrPublicAckRequired", err)
	}
}

// Having acknowledged a range once, an unrelated edit must not ask again —
// otherwise renaming a network becomes a security prompt and the prompt stops
// meaning anything.
func TestAcknowledgementIsRememberedAcrossUnrelatedEdits(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	n := mustCreateNetwork(t, st, NetworkInput{
		Name:          ptr("VPS client"),
		CIDRs:         ptr([]string{"203.0.113.25/32"}),
		AllowResolver: ptr(true),
		PublicAck:     ptr(true),
	})

	renamed, err := st.UpdateNetwork(ctx, n.ID, NetworkInput{Name: ptr("Head office")})
	if err != nil {
		t.Fatalf("renaming a network with an acknowledged public range failed: %v", err)
	}
	if !renamed.AllowResolver {
		t.Error("renaming revoked the permission")
	}
	if len(renamed.AcknowledgedPublicCIDRs) != 1 {
		t.Errorf("acknowledged = %v, want the affirmation remembered", renamed.AcknowledgedPublicCIDRs)
	}
}

// But a *different* public range is a different decision.
func TestANewPublicRangeNeedsItsOwnAcknowledgement(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	n := mustCreateNetwork(t, st, NetworkInput{
		Name:          ptr("VPS client"),
		CIDRs:         ptr([]string{"203.0.113.25/32"}),
		AllowResolver: ptr(true),
		PublicAck:     ptr(true),
	})

	_, err := st.UpdateNetwork(ctx, n.ID, NetworkInput{
		CIDRs: ptr([]string{"203.0.113.25/32", "198.51.100.10/32"}),
	})
	var needAck *ErrPublicAckRequired
	if !errors.As(err, &needAck) {
		t.Fatalf("err = %v, want ErrPublicAckRequired for the new range", err)
	}
	if got := needAck.PublicCIDRs(); len(got) != 1 || got[0] != "198.51.100.10/32" {
		t.Errorf("PublicCIDRs = %v, want only the range that was not acknowledged", got)
	}
}

// The open-resolver guard. A default route must not be permittable from the
// dashboard at any level of confirmation — dns.allow_public_resolver is the
// authority for that, and it lives in configuration on purpose.
func TestDefaultRouteCannotBePermitted(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	for _, cidr := range []string{"0.0.0.0/0", "::/0"} {
		t.Run(cidr, func(t *testing.T) {
			_, err := st.CreateNetwork(ctx, NetworkInput{
				Name:          ptr("Everyone"),
				CIDRs:         ptr([]string{cidr}),
				AllowResolver: ptr(true),
				// Even with the acknowledgement, which is the point: this is
				// not a range you can affirm your way into.
				PublicAck: ptr(true),
			})
			if err == nil {
				t.Fatal("a default route was accepted as a resolver permission")
			}
			var needAck *ErrPublicAckRequired
			if errors.As(err, &needAck) {
				t.Fatal("a default route was treated as merely needing acknowledgement")
			}
			if !strings.Contains(err.Error(), "allow_public_resolver") {
				t.Errorf("the error does not point at the setting that does permit this: %v", err)
			}
		})
	}
}

// A default route remains a legal *policy* range. "Everything already allowed
// in gets this policy" is a reasonable thing to express, and rejecting it
// would break configurations that predate resolver access entirely.
func TestDefaultRouteIsStillAllowedForPolicyAttribution(t *testing.T) {
	st := newTestStore(t)
	n := mustCreateNetwork(t, st, NetworkInput{
		Name:  ptr("Catch-all"),
		CIDRs: ptr([]string{"0.0.0.0/0"}),
	})
	if n.AllowResolver {
		t.Fatal("a network created without a permission came back permitted")
	}
	if len(n.CIDRs) != 1 || n.CIDRs[0] != "0.0.0.0/0" {
		t.Errorf("cidrs = %v, want the default route stored for policy attribution", n.CIDRs)
	}
}

// A PATCH that mentions only one field must leave the rest alone. Silently
// revoking access because a client did not resend the field would be the same
// class of surprise this work exists to remove.
func TestPartialUpdatePreservesResolverAccess(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	n := mustCreateNetwork(t, st, NetworkInput{
		Name:          ptr("Home"),
		CIDRs:         ptr([]string{"192.168.1.0/24"}),
		AllowResolver: ptr(true),
	})

	updated, err := st.UpdateNetwork(ctx, n.ID, NetworkInput{Location: ptr("Leeds")})
	if err != nil {
		t.Fatalf("UpdateNetwork: %v", err)
	}
	if !updated.AllowResolver {
		t.Error("an unrelated update revoked resolver access")
	}
}

func TestRevokingResolverAccessPersists(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	n := mustCreateNetwork(t, st, NetworkInput{
		Name:          ptr("Home"),
		CIDRs:         ptr([]string{"192.168.1.0/24"}),
		AllowResolver: ptr(true),
	})
	updated, err := st.UpdateNetwork(ctx, n.ID, NetworkInput{AllowResolver: ptr(false)})
	if err != nil {
		t.Fatalf("UpdateNetwork: %v", err)
	}
	if updated.AllowResolver {
		t.Fatal("revoking access did not persist")
	}

	reread, err := st.GetNetwork(ctx, n.ID)
	if err != nil {
		t.Fatalf("GetNetwork: %v", err)
	}
	if reread.AllowResolver {
		t.Error("the revocation was not stored")
	}
}

// State has to survive a restart, which for SQLite means closing and
// reopening the file rather than trusting an in-memory copy.
func TestResolverAccessSurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/test.db"

	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	n := mustCreateNetwork(t, st, NetworkInput{
		Name:          ptr("VPS client"),
		CIDRs:         ptr([]string{"203.0.113.25/32"}),
		AllowResolver: ptr(true),
		PublicAck:     ptr(true),
	})
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()

	got, err := reopened.GetNetwork(context.Background(), n.ID)
	if err != nil {
		t.Fatalf("GetNetwork: %v", err)
	}
	if !got.AllowResolver {
		t.Error("resolver access did not survive a restart")
	}
	if len(got.AcknowledgedPublicCIDRs) != 1 {
		t.Errorf("acknowledged = %v, want the affirmation to survive a restart", got.AcknowledgedPublicCIDRs)
	}
}

// The migration has to leave existing deployments exactly as they were: every
// network that predates the column is unpermitted, so the bootstrap ACL alone
// keeps admitting whoever it admitted before.
func TestSeededNetworkIsNotPermittedByDefault(t *testing.T) {
	st := newTestStore(t)

	networks, err := st.ListNetworks(context.Background())
	if err != nil {
		t.Fatalf("ListNetworks: %v", err)
	}
	if len(networks) == 0 {
		t.Fatal("expected the seeded catch-all network")
	}
	for _, n := range networks {
		if n.AllowResolver {
			t.Errorf("network %q is permitted to resolve out of the box; an upgrade would widen "+
				"the ACL without anyone asking", n.Name)
		}
	}
}

// CIDRs are canonicalised by the same function that classifies them, so an
// acknowledgement can never be recorded against a string the ACL will not
// recognise.
func TestCIDRCanonicalisationMatchesTheAdmissionCheck(t *testing.T) {
	st := newTestStore(t)

	n := mustCreateNetwork(t, st, NetworkInput{
		Name:          ptr("Odd input"),
		CIDRs:         ptr([]string{"10.1.2.3/8", "192.168.1.7", " 172.16.0.0/12 "}),
		AllowResolver: ptr(true),
	})
	want := map[string]bool{"10.0.0.0/8": true, "192.168.1.7/32": true, "172.16.0.0/12": true}
	if len(n.CIDRs) != len(want) {
		t.Fatalf("cidrs = %v, want %d canonical entries", n.CIDRs, len(want))
	}
	for _, c := range n.CIDRs {
		if !want[c] {
			t.Errorf("unexpected stored form %q", c)
		}
	}
}

func TestInvalidCIDRIsRejected(t *testing.T) {
	st := newTestStore(t)
	_, err := st.CreateNetwork(context.Background(), NetworkInput{
		Name:  ptr("Bad"),
		CIDRs: ptr([]string{"192.168.1.0/33"}),
	})
	if err == nil {
		t.Fatal("an invalid CIDR was accepted")
	}
}

// A database written by an older release can hold a CIDR in that release's
// canonical form. Planning canonicalises, so the acknowledgement was keyed on
// the new spelling while the rows were written under the old one: public_ack
// came out 0 on a permitted public range, and every unrelated edit afterwards
// demanded the acknowledgement again.
func TestLegacyCIDRSpellingDoesNotLoseTheAcknowledgement(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	n := mustCreateNetwork(t, st, NetworkInput{
		Name:  ptr("Branch office"),
		CIDRs: ptr([]string{"203.0.113.25/32"}),
	})

	// Rewrite the row the way an older release would have spelled it.
	if _, err := st.DB().ExecContext(ctx,
		"UPDATE network_cidrs SET cidr = ? WHERE network_id = ?",
		"::ffff:203.0.113.25/128", n.ID); err != nil {
		t.Fatalf("seed the legacy spelling: %v", err)
	}

	updated, err := st.UpdateNetwork(ctx, n.ID, NetworkInput{
		AllowResolver: ptr(true),
		PublicAck:     ptr(true),
	})
	if err != nil {
		t.Fatalf("UpdateNetwork: %v", err)
	}
	if !updated.AllowResolver {
		t.Fatal("the permission did not persist")
	}
	if len(updated.AcknowledgedPublicCIDRs) != 1 {
		t.Fatalf("acknowledged = %v, want the affirmation recorded against the stored range",
			updated.AcknowledgedPublicCIDRs)
	}
	// The row is migrated to the canonical spelling on the way past, so the
	// ACL and the acknowledgement agree from here on.
	if updated.CIDRs[0] != "203.0.113.25/32" {
		t.Errorf("cidrs = %v, want the canonical spelling", updated.CIDRs)
	}

	// And an unrelated later edit must not ask again.
	renamed, err := st.UpdateNetwork(ctx, n.ID, NetworkInput{Location: ptr("Leeds")})
	if err != nil {
		t.Fatalf("an unrelated edit re-demanded the acknowledgement: %v", err)
	}
	if !renamed.AllowResolver || len(renamed.AcknowledgedPublicCIDRs) != 1 {
		t.Errorf("state after an unrelated edit = %+v", renamed)
	}
}

// Deleting a network has to report the row as it was deleted, not as it was
// some moments earlier, because the caller decides from that report whether a
// permission was revoked — and therefore whether a failed ACL reload has left
// one in force.
//
// Reading before deleting left a window: a PATCH landing in between could
// permit the network and publish that snapshot, and the delete would then
// report "unpermitted", so the reload failure would be recorded as affecting
// nobody and the response would be a 204 saying the revocation had taken.
//
// The invariant this pins is the one the window broke. If both writes succeed,
// the update must have committed first — a transaction that read before the
// update cannot then commit a delete over it — so the deleted row has to carry
// the permission the update granted.
func TestDeleteReportsTheNetworkAsItWasDeletedUnderAConcurrentPermit(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	var deletes, races int
	for i := 0; i < 200; i++ {
		created, err := st.CreateNetwork(ctx, NetworkInput{
			Name:  ptr(fmt.Sprintf("Branch %d", i)),
			CIDRs: ptr([]string{"192.168.7.0/24"}),
		})
		if err != nil {
			t.Fatalf("CreateNetwork: %v", err)
		}

		var (
			wg        sync.WaitGroup
			updateErr error
			deleted   Network
			deleteErr error
		)
		wg.Add(2)
		// Swept rather than simultaneous. Started together, the delete's
		// transaction always opened first and the update always lost, so the
		// interleaving this exists to pin was never reached — the test passed
		// while proving nothing. The sweep walks the update across the
		// delete's whole window, from well before it to inside it.
		delay := time.Duration(i%20) * 50 * time.Microsecond
		go func() {
			defer wg.Done()
			_, updateErr = st.UpdateNetwork(ctx, created.ID, NetworkInput{AllowResolver: ptr(true)})
		}()
		go func() {
			defer wg.Done()
			time.Sleep(delay)
			deleted, deleteErr = st.DeleteNetwork(ctx, created.ID)
		}()
		wg.Wait()

		if deleteErr == nil {
			deletes++
			if updateErr == nil {
				races++
				if !deleted.AllowResolver {
					t.Fatalf("round %d: the update granted resolver access and committed, and "+
						"the delete then succeeded, but reported the network as unpermitted — "+
						"a failed reload here would leave the grant in force with nothing said",
						i)
				}
			}
		}

		// Whichever way the round went, do not leave the row behind.
		if deleteErr != nil {
			_, _ = st.DeleteNetwork(ctx, created.ID)
		}
	}

	if deletes == 0 {
		t.Fatal("no round managed to delete anything, so the invariant was never exercised")
	}
	t.Logf("%d/200 rounds deleted, %d of those with a concurrently committed permit", deletes, races)
}

// loadNetworkTx and ListNetworks scan the same columns from the same tables,
// which is duplication, and duplication of a row scan is how two reads of one
// row start disagreeing: a column added to the model and to one scanner is
// silently absent from the other, and the caller gets a Network with a zero
// field it has no way to notice.
//
// Pinning the agreement is cheaper than removing the duplication, because the
// transactional read has to happen on a *sql.Tx and the list read has to stay
// a single pass over every network.
func TestTheTransactionalReadAgreesWithTheListRead(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	// Every field the model carries, set to something distinguishable: a
	// scanner that dropped one would otherwise match on zero values.
	created, err := st.CreateNetwork(ctx, NetworkInput{
		Name:          ptr("Frankfurt VPS"),
		Location:      ptr("Hetzner FSN1"),
		CIDRs:         ptr([]string{"192.168.30.0/24", "203.0.113.25/32"}),
		Enabled:       ptr(true),
		AllowResolver: ptr(true),
		PublicAck:     ptr(true),
	})
	if err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	if len(created.AcknowledgedPublicCIDRs) == 0 {
		t.Fatal("the fixture recorded no acknowledgement, so that field is not being compared")
	}

	listed, err := st.GetNetwork(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetNetwork: %v", err)
	}

	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	defer tx.Rollback()
	loaded, err := loadNetworkTx(ctx, tx, created.ID)
	if err != nil {
		t.Fatalf("loadNetworkTx: %v", err)
	}

	if !reflect.DeepEqual(listed, loaded) {
		t.Errorf("the two reads of one row disagree, so a delete reports a network the rest of "+
			"the API would describe differently:\n  list: %+v\n    tx: %+v", listed, loaded)
	}
}

// And that a missing row is reported the same way by both, since the delete
// handler's 404 depends on it.
func TestTheTransactionalReadReportsAMissingRowAsNotFound(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	defer tx.Rollback()

	if _, err := loadNetworkTx(ctx, tx, "n_nonexistent"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound — the delete handler's 404 comes from this", err)
	}
}
