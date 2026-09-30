package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/api"
	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/native"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/observe"
	"github.com/jameshoulder/dnsdaddy/internal/dnssecobs"
	"github.com/jameshoulder/dnsdaddy/internal/dnsserver"
	"github.com/jameshoulder/dnsdaddy/internal/resolver"
	"github.com/jameshoulder/dnsdaddy/internal/store"
	"github.com/miekg/dns"
)

type dnssecSelection struct {
	mode, source               string
	transport, transportSource string
	endpoints                  []resolver.EncryptedEndpoint
	route                      *resolver.ForwardRoute
	runtime                    *controlledNative
	learn                      *dnssecObservation
	lastLearn                  *dnssecObservation
	stopLearn                  context.CancelFunc
}

// A captured query keeps its chosen native path. Turning the runtime off
// cancels in-flight work and rejects late users of a captured pointer; it can
// never cause a native failure to become a forwarding request.
type controlledNative struct {
	base      *nativeRuntime
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.RWMutex
	closed    bool
	transport string
}

func (n *controlledNative) ResolveClient(ctx context.Context, req *dns.Msg) native.ClientResult {
	source := "native"
	if n.transport == config.ResolutionEncrypted {
		source = "encrypted_forwarded"
	}
	n.mu.RLock()
	defer n.mu.RUnlock()
	if n.closed || n.ctx.Err() != nil {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		m.RecursionAvailable = true
		return native.ClientResult{ResolutionSource: source, Msg: m, ValidationStatus: "internal_error", ReasonCode: "mode_changed", Reason: "Daddybound resolution stopped after a mode or transport change"}
	}
	qctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(n.ctx, cancel)
	defer func() { stop(); cancel() }()
	result := n.base.Client.ResolveClient(qctx, req)
	result.ResolutionSource = source
	return result
}

func (n *controlledNative) close() {
	if n == nil {
		return
	}
	n.cancel()
	n.mu.Lock()
	n.closed = true
	n.mu.Unlock()
	n.base.Stop()
	n.base.Wait()
}

type dnssecControl struct {
	ctx             context.Context
	cfg             config.Config
	st              *store.Store
	log             *slog.Logger
	pinned          bool
	transportPinned bool
	generation      uint64
	configured      string
	mu              sync.Mutex
	closed          bool
	current         atomic.Pointer[dnssecSelection]
	nativeWriter    *dnssecobs.Writer
	stopWriter      context.CancelFunc
	closeOnce       sync.Once
	buildNative     func(context.Context, config.Config, *slog.Logger) (*nativeRuntime, error)
}

func newDNSSECControl(ctx context.Context, cfg config.Config, st *store.Store, log *slog.Logger, pinned bool, source string) (*dnssecControl, error) {
	c := &dnssecControl{ctx: ctx, cfg: cfg, st: st, log: log, pinned: pinned, transportPinned: cfg.DNS.TransportConfigured(), configured: "unset",
		buildNative: func(ctx context.Context, cfg config.Config, log *slog.Logger) (*nativeRuntime, error) {
			return prepareNativeRuntimeWithTransport(ctx, cfg, log, nil, nil)
		}}
	if pinned {
		c.configured = cfg.DNS.LocalDNSSECMode()
	}
	selection, err := c.initialTransport(ctx, source)
	if err != nil {
		return nil, err
	}
	c.current.Store(selection)
	c.nativeWriter = dnssecobs.New(st, dnssecobs.Options{Log: log})
	wctx, stop := context.WithCancel(context.WithoutCancel(ctx))
	c.stopWriter = stop
	go c.nativeWriter.Run(wctx)
	if err := c.transition(ctx, cfg.DNS.LocalDNSSECMode(), source, false); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func (c *dnssecControl) NativeClient() dnsserver.NativeResolver {
	s := c.current.Load()
	if s.mode != config.LocalDNSSECEnforce || s.runtime == nil {
		return nil
	}
	return s.runtime
}

func (c *dnssecControl) Observe(r observe.Request) bool {
	s := c.current.Load()
	return s.mode == config.LocalDNSSECObserve && s.learn != nil && s.learn.observer.Observe(r)
}

// RecordNative stores the validation of the exact native result, without
// resolving it a second time. Native Live rows have no upstream comparison.
func (c *dnssecControl) RecordNative(e store.QueryEvent, q dns.Question, result native.ClientResult, persist bool) string {
	if !persist || result.CheckingDisabled || c.ctx.Err() != nil {
		return ""
	}
	id := observe.NewID()
	if id == "" {
		return ""
	}
	resolution := "native_live"
	if result.ResolutionSource == "encrypted_forwarded" {
		resolution = "encrypted_live"
	}
	c.nativeWriter.Record(observe.Observation{ID: id, Time: e.Time, Domain: e.Domain, QType: e.QType, Cached: result.Cached,
		Status: observe.Status(result.ValidationStatus), ReasonCode: result.ReasonCode, Reason: result.Reason,
		Duration: time.Duration(e.ElapsedMS) * time.Millisecond, Resolution: resolution})
	return id
}

func (c *dnssecControl) State() api.DNSSECRuntimeState {
	s := c.current.Load()
	out := api.DNSSECRuntimeState{Configured: c.configured, Effective: s.mode, ChosenBy: s.source, Transport: s.transport, Locked: c.pinned, NativeWriter: c.nativeWriter.Stats()}
	if c.pinned {
		out.Reason = api.ErrDNSSECModeLocked.Error()
	}
	if s.runtime != nil {
		out.NativeAvailable = true
		out.Native = s.runtime.base.Client.Stats()
		out.Anchors = s.runtime.base.Anchors
	}
	if s.learn != nil {
		out.Observer = s.learn.observer
		out.Writer = s.learn.writer
		out.ObserverActive = true
	} else if s.lastLearn != nil {
		// Keep the counters, not a frozen snapshot: a captured submission can
		// still report a stopped-observer drop after the workers have exited.
		out.Observer = s.lastLearn.observer
		out.Writer = s.lastLearn.writer
	}
	return out
}

func (c *dnssecControl) SetMode(ctx context.Context, mode string) error {
	if c.pinned {
		return api.ErrDNSSECModeLocked
	}
	return c.transition(ctx, mode, "dashboard", true)
}

func (c *dnssecControl) transition(ctx context.Context, mode, source string, persist bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return fmt.Errorf("DNS runtime controller is closed")
	}
	if mode != config.LocalDNSSECOff && mode != config.LocalDNSSECObserve && mode != config.LocalDNSSECEnforce {
		return fmt.Errorf("invalid Daddybound mode")
	}
	if err := c.ctx.Err(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	old := c.current.Load()
	if mode == old.mode && !persist {
		return nil
	}
	next := &dnssecSelection{mode: mode, source: source, runtime: old.runtime, lastLearn: old.lastLearn,
		transport: old.transport, transportSource: old.transportSource, endpoints: old.endpoints, route: old.route}
	created := false
	if mode != config.LocalDNSSECOff && next.runtime == nil {
		rctx, cancel := context.WithCancel(c.ctx)
		cfg := c.cfg
		cfg.DNS.LocalDNSSECValidation = mode
		cfg.DNS.ResolutionTransport = next.transport
		var r *nativeRuntime
		var err error
		if next.transport == config.ResolutionEncrypted {
			r, err = prepareNativeRuntimeWithTransport(rctx, cfg, c.log, next.route.Encrypted(), nil)
		} else {
			r, err = c.buildNative(rctx, cfg, c.log)
		}
		if err != nil {
			cancel()
			return err
		}
		next.runtime = &controlledNative{base: r, ctx: rctx, cancel: cancel, transport: next.transport}
		created = true
	}
	if persist {
		if err := c.st.SetSetting(ctx, api.DNSSECModeSetting, mode); err != nil {
			if created {
				next.runtime.close()
			}
			return fmt.Errorf("save Daddybound mode: %w", err)
		}
	}
	if mode == old.mode {
		next.learn = old.learn
		next.stopLearn = old.stopLearn
	}
	if mode == config.LocalDNSSECObserve && next.learn == nil {
		lctx, stop := context.WithCancel(next.runtime.ctx)
		next.stopLearn = stop
		next.learn = startLearnOnNative(lctx, c.cfg, c.st, c.log, next.runtime.base)
	}
	if mode == config.LocalDNSSECOff {
		next.runtime = nil
	}
	if old.learn != nil && next.learn != old.learn {
		next.lastLearn = old.learn
	}
	c.current.Store(next)
	if old.learn != nil && next.learn != old.learn {
		old.stopLearn()
		old.learn.Wait()
	}
	if old.runtime != nil && next.runtime != old.runtime {
		old.runtime.close()
	}
	if created {
		next.runtime.base.Activate()
	}
	logMode := strings.ReplaceAll(mode, "\n", "")
	logMode = strings.ReplaceAll(logMode, "\r", "")
	logSource := strings.ReplaceAll(source, "\n", "")
	logSource = strings.ReplaceAll(logSource, "\r", "")
	c.log.Info("Daddybound mode active", "mode", logMode, "source", logSource, "enforcing", mode == config.LocalDNSSECEnforce,
		"transport", next.transport)
	return nil
}

func startLearnOnNative(ctx context.Context, cfg config.Config, st *store.Store, log *slog.Logger, r *nativeRuntime) *dnssecObservation {
	w := dnssecobs.New(st, dnssecobs.Options{Log: log})
	wctx, stop := context.WithCancel(context.WithoutCancel(ctx))
	go w.Run(wctx)
	options := observe.Options{Workers: cfg.DNS.LocalDNSSECWorkers, Queue: cfg.DNS.LocalDNSSECQueue, Timeout: cfg.DNS.LocalDNSSECTimeout.D(), Log: log}
	o := observe.NewNative(native.NewLearn(r.Engine), w, options)
	if r.Resolver == nil {
		o = observe.NewEncrypted(native.NewLearn(r.Engine), w, options)
	}
	go o.Run(ctx)
	return &dnssecObservation{observer: o, writer: w, resolver: r.Resolver, anchors: r.Anchors, stopWriter: stop}
}

func (c *dnssecControl) Close() {
	if c == nil {
		return
	}
	c.closeOnce.Do(func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.closed = true
		s := c.current.Load()
		c.current.Store(&dnssecSelection{mode: config.LocalDNSSECOff, source: s.source,
			transport: s.transport, transportSource: s.transportSource, endpoints: s.endpoints, route: s.route})
		if s.learn != nil {
			s.stopLearn()
			s.learn.Wait()
		}
		if s.runtime != nil {
			s.runtime.close()
		}
		if s.route != nil {
			s.route.Close()
			if s.route.Encrypted() != nil {
				_ = s.route.Encrypted().Close()
			}
		}
		c.stopWriter()
		c.nativeWriter.Wait()
	})
}
