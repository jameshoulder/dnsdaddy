package resolver

import (
	"context"
	"errors"
	"sync"

	"github.com/miekg/dns"
)

var (
	ErrForwardRouteRetired     = errors.New("DNS transport selection was retired")
	ErrForwardRouteUnavailable = errors.New("DNS transport selection is unavailable")
)

// ForwardRoute is one immutable transport selection. Generation must change
// whenever the controller changes the selection, including when it returns to
// a previously used transport. Encrypted nil selects the configured legacy
// forwarding and operating-system DNS transports.
//
// Close retires admission, cancels admitted work and waits for it to finish.
// It does not close Encrypted: the owner closes that bundle after the route
// and any other users of the same bundle have drained.
type ForwardRoute struct {
	generation uint64
	encrypted  *EncryptedUpstreams
	ctx        context.Context
	cancel     context.CancelCauseFunc
	mu         sync.Mutex
	retired    bool
	active     sync.WaitGroup
}

func NewForwardRoute(generation uint64, encrypted *EncryptedUpstreams) *ForwardRoute {
	ctx, cancel := context.WithCancelCause(context.Background())
	return &ForwardRoute{generation: generation, encrypted: encrypted, ctx: ctx, cancel: cancel}
}

func (r *ForwardRoute) Generation() uint64 {
	if r == nil {
		return 0
	}
	return r.generation
}

func (r *ForwardRoute) Encrypted() *EncryptedUpstreams {
	if r == nil {
		return nil
	}
	return r.encrypted
}

// Begin admits work under this exact selection. The returned context follows
// both parent cancellation and retirement. done must be called after all
// network activity owned by this admission has ended. A nil route preserves
// the legacy resolver API for embeddings which do not install a controller.
func (r *ForwardRoute) Begin(parent context.Context) (context.Context, func(), error) {
	if err := forwardContextError(parent); err != nil {
		return nil, nil, err
	}
	if r == nil {
		return parent, func() {}, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.retired {
		return nil, nil, ErrForwardRouteRetired
	}
	ctx, cancel := context.WithCancelCause(parent)
	stop := context.AfterFunc(r.ctx, func() { cancel(ErrForwardRouteRetired) })
	r.active.Add(1)
	done := sync.OnceFunc(func() {
		stop()
		cancel(context.Canceled)
		r.active.Done()
	})
	return ctx, done, nil
}

func (r *ForwardRoute) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	if !r.retired {
		r.retired = true
		r.cancel(ErrForwardRouteRetired)
	}
	r.mu.Unlock()
	r.active.Wait()
}

type forwardRouteProvider struct {
	current func() *ForwardRoute
}

// SetRouteProvider installs the controller's atomic selection callback. Call
// this once before listeners start. A configured provider returning nil fails
// closed; it never means permission to use the legacy plaintext route.
func (r *Resolver) SetRouteProvider(provider func() *ForwardRoute) {
	r.routeProvider.Store(&forwardRouteProvider{current: provider})
}

func (r *Resolver) currentRoute() (*ForwardRoute, error) {
	p := r.routeProvider.Load()
	if p == nil {
		return nil, nil
	}
	return selectedForwardRoute(p.current)
}

func selectedForwardRoute(provider func() *ForwardRoute) (*ForwardRoute, error) {
	if provider == nil {
		return nil, ErrForwardRouteUnavailable
	}
	r := provider()
	if r == nil {
		return nil, ErrForwardRouteUnavailable
	}
	return r, nil
}

func forwardContextError(ctx context.Context) error {
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}
	return nil
}

func (r *ForwardRoute) exchangeEncrypted(ctx context.Context, req *dns.Msg) (*dns.Msg, string, error) {
	ctx, done, err := r.Begin(ctx)
	if err != nil {
		return nil, "", err
	}
	defer done()
	msg, protocol, err := r.encrypted.ExchangeWithProtocol(ctx, req)
	if ctxErr := forwardContextError(ctx); ctxErr != nil {
		return nil, "", ctxErr
	}
	return msg, protocol, err
}

func exchangeForwardUpstream(ctx context.Context, route *ForwardRoute, upstream *Upstream, req *dns.Msg) (*dns.Msg, error) {
	ctx, done, err := route.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	msg, err := upstream.Exchange(ctx, req)
	if ctxErr := forwardContextError(ctx); ctxErr != nil {
		return nil, ctxErr
	}
	return msg, err
}
