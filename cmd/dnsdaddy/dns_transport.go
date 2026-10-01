package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/jameshoulder/dnsdaddy/internal/api"
	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/resolver"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

type savedDNSTransport struct {
	Transport string                       `json:"transport"`
	Endpoints []resolver.EncryptedEndpoint `json:"endpoints"`
}

func cloneEncryptedEndpoints(in []resolver.EncryptedEndpoint) []resolver.EncryptedEndpoint {
	out := make([]resolver.EncryptedEndpoint, len(in))
	for i, e := range in {
		out[i] = e
		out[i].BootstrapIPs = append([]string{}, e.BootstrapIPs...)
	}
	return out
}

func (c *dnssecControl) initialTransport(ctx context.Context, source string) (*dnssecSelection, error) {
	selection := savedDNSTransport{Transport: c.cfg.DNS.TransportMode()}
	chosenBy := "default"
	if c.transportPinned {
		chosenBy = "config"
		for _, e := range c.cfg.DNS.EncryptedUpstreams {
			selection.Endpoints = append(selection.Endpoints, resolver.EncryptedEndpoint{
				Protocol: e.Protocol, Address: e.Address, ServerName: e.ServerName,
				BootstrapIPs: append([]string{}, e.BootstrapIPs...),
			})
		}
	} else {
		raw, err := c.st.GetSetting(ctx, api.DNSTransportSetting)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("read saved DNS transport: %w", err)
		}
		if err == nil {
			if len(raw) > 64<<10 {
				return nil, errors.New("saved DNS transport exceeds its size limit")
			}
			selection = savedDNSTransport{}
			dec := json.NewDecoder(strings.NewReader(raw))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&selection); err != nil {
				return nil, errors.New("saved DNS transport is invalid; repair the setting or configure dns.resolution_transport explicitly")
			}
			if err := dec.Decode(new(any)); err != io.EOF {
				return nil, errors.New("saved DNS transport contains trailing data")
			}
			chosenBy = "dashboard"
		}
	}
	if len(selection.Endpoints) > 0 {
		normalized, err := resolver.NormalizeEncryptedEndpoints(selection.Endpoints)
		if err != nil {
			return nil, fmt.Errorf("DNS transport endpoints: %w", err)
		}
		selection.Endpoints = normalized
	}
	client, err := c.makeEncryptedTransport(selection.Transport, selection.Endpoints)
	if err != nil {
		return nil, fmt.Errorf("DNS transport: %w", err)
	}
	c.generation = 1
	return &dnssecSelection{mode: config.LocalDNSSECOff, source: source,
		transport: selection.Transport, transportSource: chosenBy,
		endpoints: cloneEncryptedEndpoints(selection.Endpoints),
		route:     resolver.NewForwardRoute(c.generation, client)}, nil
}

func (c *dnssecControl) makeEncryptedTransport(transport string, endpoints []resolver.EncryptedEndpoint) (*resolver.EncryptedUpstreams, error) {
	if transport != config.ResolutionNative && transport != config.ResolutionEncrypted {
		return nil, errors.New("transport must be native or encrypted")
	}
	if transport == config.ResolutionNative && len(endpoints) == 0 {
		return nil, nil
	}
	client, err := resolver.NewEncryptedUpstreams(endpoints, c.cfg.DNS.Timeout.D())
	if err != nil {
		return nil, err
	}
	if transport == config.ResolutionNative {
		_ = client.Close()
		return nil, nil
	}
	return client, nil
}

// ForwardRoute is captured once for a query by both the DNS forwarder and
// the process hostname resolver. The same atomic selection supplies Live's
// local validator, so a transport switch cannot mix two active profiles.
func (c *dnssecControl) ForwardRoute() *resolver.ForwardRoute {
	return c.current.Load().route
}

func (c *dnssecControl) TransportState() api.DNSTransportState {
	s := c.current.Load()
	out := api.DNSTransportState{
		Transport: s.transport, Locked: c.transportPinned, ChosenBy: s.transportSource,
		Endpoints: cloneEncryptedEndpoints(s.endpoints), TLSMinimum: "1.3",
		EncryptedOnly: s.transport == config.ResolutionEncrypted,
		Bootstrap:     "system", DaddyboundMode: s.mode,
		Scope: "Forward and Learn answer through the configured upstreams. Daddybound native validation uses UDP/TCP port 53; background hostname resolution uses the system DNS servers.",
	}
	if c.transportPinned {
		out.Reason = api.ErrDNSTransportLocked.Error()
	}
	if out.EncryptedOnly {
		out.Bootstrap = "configured_ips"
		out.Scope = "This daemon's DNS answers, local validation, trust-anchor refresh and background hostname lookups use the approved encrypted endpoints. Client-to-server DNS and the provider's onward traffic are separate connections."
		if s.route != nil && s.route.Encrypted() != nil {
			stats := s.route.Encrypted().Stats()
			out.Stats = &stats
		}
	}
	return out
}

func (c *dnssecControl) SetTransport(ctx context.Context, transport string, endpoints []resolver.EncryptedEndpoint) error {
	if c.transportPinned {
		return api.ErrDNSTransportLocked
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errors.New("DNS runtime controller is closed")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := c.ctx.Err(); err != nil {
		return err
	}
	if len(endpoints) > 0 {
		normalized, err := resolver.NormalizeEncryptedEndpoints(endpoints)
		if err != nil {
			return err
		}
		endpoints = normalized
	}
	client, err := c.makeEncryptedTransport(transport, endpoints)
	if err != nil {
		return err
	}
	old := c.current.Load()
	c.generation++
	next := &dnssecSelection{mode: old.mode, source: old.source,
		transport: transport, transportSource: "dashboard",
		endpoints: cloneEncryptedEndpoints(endpoints),
		route:     resolver.NewForwardRoute(c.generation, client), lastLearn: old.lastLearn}
	cleanup := func() {
		if next.runtime != nil {
			next.runtime.close()
		}
		next.route.Close()
		if client != nil {
			_ = client.Close()
		}
	}
	if next.mode != config.LocalDNSSECOff {
		rctx, cancel := context.WithCancel(c.ctx)
		cfg := c.cfg
		cfg.DNS.LocalDNSSECValidation, cfg.DNS.ResolutionTransport = next.mode, transport
		var runtime *nativeRuntime
		if old.runtime != nil {
			runtime, err = prepareNativeRuntimeWithTransport(rctx, cfg, c.log, client, old.runtime.base.Anchors)
		} else {
			runtime, err = prepareNativeRuntimeWithTransport(rctx, cfg, c.log, client, nil)
		}
		if err != nil {
			cancel()
			cleanup()
			return err
		}
		next.runtime = &controlledNative{base: runtime, ctx: rctx, cancel: cancel, transport: transport}
	}
	value, err := json.Marshal(savedDNSTransport{Transport: transport, Endpoints: next.endpoints})
	if err != nil {
		cleanup()
		return err
	}
	if err := c.st.SetSetting(ctx, api.DNSTransportSetting, string(value)); err != nil {
		cleanup()
		return fmt.Errorf("save DNS transport: %w", err)
	}
	if old.learn != nil {
		next.lastLearn = old.learn
	}
	if next.mode == config.LocalDNSSECObserve {
		lctx, stop := context.WithCancel(next.runtime.ctx)
		next.stopLearn = stop
		next.learn = startLearnOnNative(lctx, c.cfg, c.st, c.log, next.runtime.base)
	}
	// Publication is the commit point. Retiring both old paths then prevents
	// a caller holding an old pointer from restarting plaintext work after a
	// successful encrypted selection. No fallible configuration work follows.
	c.current.Store(next)
	if old.learn != nil {
		old.stopLearn()
		old.learn.Wait()
	}
	if old.runtime != nil {
		old.runtime.close()
	}
	old.route.Close()
	if old.route.Encrypted() != nil {
		_ = old.route.Encrypted().Close()
	}
	if next.runtime != nil {
		next.runtime.base.Activate()
	}
	safeTransport := strings.ReplaceAll(transport, "\n", "")
	safeTransport = strings.ReplaceAll(safeTransport, "\r", "")
	c.log.Info("DNS transport active", "transport", safeTransport, "mode", next.mode,
		"approved_endpoints", len(next.endpoints), "plaintext_fallback", false)
	return nil
}
