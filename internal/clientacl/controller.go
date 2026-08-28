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
// On error the previous snapshot stays in force and the controller is marked
// stale. Keeping the old snapshot is the safe failure: a transient database
// error must not drop every client's permission, and it must not silently
// widen the ACL either.
//
// Every failure marks stale, without trying to work out whether this
// particular write could have changed who is admitted. Four review rounds
// went into versions that did try, and each was wrong in one direction or the
// other, because the question cannot be answered at the moment it is asked:
// the thing that failed is the read of the desired state, so there is nothing
// left to compare the enforced state against.
//
// The sequence that settled it: two networks permitting the same range, each
// revoked in turn with the reload failing both times. Comparing against the
// snapshot classified both as changing nothing — the first because the second
// network still covered the range, the second because the *snapshot* still
// held the first network's grant, which the database no longer had. The
// database then permitted neither, the resolver went on admitting the range,
// and nothing anywhere said so.
//
// So a failed reload records exactly what is known — that the snapshot in
// force could not be confirmed against what is stored — and every surface
// says that rather than asserting which way it went.
func (c *Controller) Reload(ctx context.Context) error {
	return c.reload(ctx)
}

func (c *Controller) reload(ctx context.Context) error {
	if c == nil {
		return nil
	}

	c.reloading.Lock()
	defer c.reloading.Unlock()

	if err := c.publish(ctx); err != nil {
		c.stale.Store(true)
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
