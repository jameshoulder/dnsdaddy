package clientacl

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
)

// Loader supplies the dashboard-managed networks.
//
// A function rather than a *store.Store so this package stays independent of
// persistence — which is not tidiness for its own sake: internal/store imports
// this package for the write-time validation rules, and taking a store here
// would close that into an import cycle.
type Loader func(ctx context.Context) ([]Network, error)

// Controller holds the live ACL and swaps it atomically when networks change.
//
// The DNS hot path reads Current() — one atomic load — and never touches the
// database. A reload builds a whole new Set and publishes it in one store, so
// a query is evaluated against exactly one snapshot: there is no window in
// which half an update is in force.
type Controller struct {
	snap atomic.Pointer[Set]

	// reloading serialises load, compute and publish.
	//
	// Without it two concurrent writes can publish out of order: request A
	// reads the database, request B reads it, commits and publishes, and then
	// A publishes the snapshot it read *before* B's change. B's grant or
	// revocation is silently absent from the live ACL, and — worse — the stale
	// flag is clear, so everything downstream reports it as current. The
	// window is small and the API handlers really do run concurrently.
	//
	// Held across the database read on purpose, so the last writer in wins
	// rather than the last reader. Reload happens only on configuration
	// writes; the DNS hot path reads Current, which stays lock-free.
	reloading sync.Mutex

	// stale records that the last reload failed, so the snapshot in force may
	// be older than what is stored.
	//
	// Kept rather than only returned, because the caller who could act on the
	// error is often gone by the time it matters. A revocation that did not
	// reload leaves the old permission being honoured, and the operator sees a
	// deleted network and assumes it is closed. This is what lets the
	// diagnostics keep saying otherwise until a reload succeeds.
	stale atomic.Bool

	bootstrap   []string
	allowPublic bool
	load        Loader
}

// NewController builds a controller and computes an initial set from the
// bootstrap configuration alone.
//
// The initial set is deliberately usable before the first Reload: startup
// order should never leave a window where the resolver is answering with no
// ACL because the database has not been read yet.
func NewController(bootstrapCIDRs []string, allowPublicResolver bool, load Loader) *Controller {
	c := &Controller{
		bootstrap:   append([]string(nil), bootstrapCIDRs...),
		allowPublic: allowPublicResolver,
		load:        load,
	}
	c.snap.Store(Compute(c.bootstrap, c.allowPublic, nil))
	return c
}

// Reload rebuilds the effective ACL from the current networks.
//
// On error the previous snapshot stays in force. That is the safe failure:
// a transient database error must not drop every client's permission, and it
// must not silently widen the ACL either.
func (c *Controller) Reload(ctx context.Context) error {
	return c.reload(ctx, true)
}

// ReloadAfterWrite republishes the effective ACL after a network write and
// reports whether the write could have changed who is admitted.
//
// The two happen under one lock, and that is the point rather than an
// implementation detail. Deciding from Current() before calling Reload read a
// snapshot that a concurrent reload was already in the middle of replacing: a
// PATCH that had loaded a newly permitted network but not yet published it
// left the snapshot short of that grant, so a DELETE of the same network
// concluded it was withdrawing nothing, and a reload failure after the PATCH
// published left the grant in force behind a 204 with nothing marked stale.
//
// Holding the lock across the comparison closes it in both directions. Any
// publish already in flight completes before the comparison sees the snapshot,
// and any that starts afterwards reads the database after this write
// committed, so it cannot reintroduce what this write removed.
func (c *Controller) ReloadAfterWrite(ctx context.Context, n Network) (bool, error) {
	after, _ := n.prefixes()
	return c.reloadFor(ctx, n.ID, after)
}

// ReloadAfterDelete is ReloadAfterWrite for a network that has been removed:
// it now contributes nothing, and what it was contributing is whatever the
// snapshot under the lock still holds for it.
func (c *Controller) ReloadAfterDelete(ctx context.Context, networkID string) (bool, error) {
	return c.reloadFor(ctx, networkID, nil)
}

func (c *Controller) reloadFor(ctx context.Context, networkID string, after []netip.Prefix) (bool, error) {
	if c == nil {
		return false, nil
	}

	c.reloading.Lock()
	defer c.reloading.Unlock()

	changed := c.snap.Load().admissionChanges(networkID, after)
	if err := c.publish(ctx); err != nil {
		// A write that cannot have changed admission leaves the enforced ACL
		// correct in every respect that decides it, and raising "a permission
		// you revoked may still be honoured" over one would be a false alarm —
		// and a persistent one, since nothing clears it until an unrelated
		// write succeeds or the daemon restarts.
		if changed {
			c.stale.Store(true)
		}
		return changed, err
	}
	return changed, nil
}

func (c *Controller) reload(ctx context.Context, marksStale bool) error {
	if c == nil {
		return nil
	}

	c.reloading.Lock()
	defer c.reloading.Unlock()

	if err := c.publish(ctx); err != nil {
		if marksStale {
			c.stale.Store(true)
		}
		return err
	}
	return nil
}

// publish rebuilds the snapshot from the current networks and swaps it in.
// The caller holds c.reloading.
func (c *Controller) publish(ctx context.Context) error {
	var networks []Network
	if c.load != nil {
		var err error
		networks, err = c.load(ctx)
		if err != nil {
			return err
		}
	}
	c.snap.Store(Compute(c.bootstrap, c.allowPublic, networks))
	// Cleared on any successful publish: whatever went wrong before, the
	// snapshot now in force was built from the current database.
	c.stale.Store(false)
	return nil
}

// Stale reports that the last reload failed, so the ACL being enforced may not
// match what is stored. It clears on the next successful reload.
func (c *Controller) Stale() bool { return c != nil && c.stale.Load() }

// Current returns the live snapshot. Never nil once the controller is built.
func (c *Controller) Current() *Set {
	if c == nil {
		return nil
	}
	return c.snap.Load()
}

// Allows reports whether addr may use the resolver under the live snapshot.
func (c *Controller) Allows(addr netip.Addr) bool { return c.Current().Allows(addr) }
