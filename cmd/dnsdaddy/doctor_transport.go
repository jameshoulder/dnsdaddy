package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/api"
	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/diag"
	"github.com/jameshoulder/dnsdaddy/internal/resolver"
	"github.com/jameshoulder/dnsdaddy/internal/store"
	"github.com/miekg/dns"
)

// doctorTransport owns a read-only selection. Construction validates saved
// configuration but never creates a native resolver, writer or refresh worker.
type doctorTransport struct {
	selection *dnssecSelection
}

func (d *doctorTransport) Close() {
	if d == nil || d.selection == nil || d.selection.route == nil {
		return
	}
	d.selection.route.Close()
	if client := d.selection.route.Encrypted(); client != nil {
		_ = client.Close()
	}
}

func prepareDoctorTransport(ctx context.Context, st *store.Store, cfg config.Config) (*doctorTransport, config.Config, diag.Check) {
	c := diag.Check{Section: "DNS", Name: "Effective DNS transport", Status: diag.StatusFail}
	fail := func(err error) (*doctorTransport, config.Config, diag.Check) {
		c.Summary = "The effective DNS selection could not be determined; network probes are disabled."
		c.Evidence = []string{err.Error()}
		c.Action = "Correct the configuration or restore read access to the daemon's actual database before probing network access."
		return nil, cfg, c
	}
	if err := cfg.DNS.ValidateTransport(); err != nil {
		return fail(err)
	}
	if !cfg.DNS.TransportConfigured() && st == nil {
		return fail(errors.New("dns.resolution_transport is not pinned and the saved transport cannot be read"))
	}
	if err := doctorResolveDNSSECMode(ctx, st, &cfg); err != nil {
		return fail(err)
	}
	control := &dnssecControl{cfg: cfg, st: st, transportPinned: cfg.DNS.TransportConfigured()}
	selection, err := control.initialTransport(ctx, "config")
	if err != nil {
		return fail(err)
	}
	selection.mode = cfg.DNS.LocalDNSSECMode()
	cfg.DNS.ResolutionTransport = selection.transport
	cfg.DNS.EncryptedUpstreams = nil
	for _, endpoint := range selection.endpoints {
		cfg.DNS.EncryptedUpstreams = append(cfg.DNS.EncryptedUpstreams, config.EncryptedUpstream{
			Protocol: endpoint.Protocol, Address: endpoint.Address, ServerName: endpoint.ServerName,
			BootstrapIPs: append([]string{}, endpoint.BootstrapIPs...),
		})
	}
	c.Status = diag.StatusPass
	c.Summary = "Effective DNS transport: " + selection.transport + "."
	c.Evidence = []string{"chosen by: " + selection.transportSource,
		"Daddybound mode: " + selection.mode}
	if selection.transport == config.ResolutionEncrypted {
		c.Evidence = append(c.Evidence, fmt.Sprintf("%d approved encrypted endpoints; verified TLS 1.3 and literal bootstrap addresses", len(selection.endpoints)),
			"Network probes and this command's background hostname lookups never fall back to plaintext upstream DNS.",
			"Local listener checks are a separate client-to-daemon connection; provider onward traffic is outside this command.")
	} else {
		c.Evidence = append(c.Evidence, "Forward and Learn answer through configured upstreams; native local validation uses authoritative DNS over UDP/TCP port 53.")
	}
	return &doctorTransport{selection: selection}, cfg, c
}

func doctorResolveDNSSECMode(ctx context.Context, st *store.Store, cfg *config.Config) error {
	valid := func(mode string) bool {
		return mode == config.LocalDNSSECOff || mode == config.LocalDNSSECObserve || mode == config.LocalDNSSECEnforce
	}
	if cfg.DNS.LocalDNSSECConfigured() {
		if !valid(cfg.DNS.LocalDNSSECValidation) {
			return errors.New("configured Daddybound mode is invalid")
		}
		return nil
	}
	if st == nil {
		return errors.New("daddybound mode is not pinned and its saved mode cannot be read")
	}
	installation, err := st.GetSetting(ctx, store.SettingLocalDNSSECDefault)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("read Daddybound installation default: %w", err)
	}
	saved, savedErr := st.GetSetting(ctx, api.DNSSECModeSetting)
	if savedErr != nil && !errors.Is(savedErr, store.ErrNotFound) {
		return fmt.Errorf("read saved Daddybound mode: %w", savedErr)
	}
	if savedErr == nil {
		if !valid(saved) {
			return errors.New("saved Daddybound mode is invalid")
		}
		installation = saved
	} else if err == nil && !valid(installation) {
		return errors.New("saved Daddybound installation default is invalid")
	}
	cfg.ResolveLocalDNSSEC(installation)
	return nil
}

func doctorNetworkSkipped(reason string) diag.Check {
	return diag.Check{Section: "DNS", Name: "Network probes skipped", Status: diag.StatusFail,
		Summary: reason, Evidence: []string{"No DNS listener, dashboard or upstream network probes were sent."},
		Action: "Make the effective saved configuration readable, then run doctor again."}
}

func doctorEncryptedUpstreams(ctx context.Context, cfg config.Config, timeout time.Duration) []diag.Check {
	probes := make([]diag.UpstreamProbe, 0, len(cfg.DNS.EncryptedUpstreams))
	for _, endpoint := range cfg.DNS.EncryptedUpstreams {
		probes = append(probes, probeEncryptedUpstream(ctx, resolver.EncryptedEndpoint{
			Protocol: endpoint.Protocol, Address: endpoint.Address, ServerName: endpoint.ServerName,
			BootstrapIPs: append([]string{}, endpoint.BootstrapIPs...),
		}, timeout))
	}
	checks := diag.Upstreams(probes)
	for i := range checks {
		checks[i].Evidence = append(checks[i].Evidence, "Only approved encrypted endpoints were tested; legacy upstreams were not contacted.")
		if checks[i].Status != diag.StatusPass {
			checks[i].Action = "Check the approved endpoint's protocol, literal bootstrap IP, TLS certificate name and outbound port. No plaintext fallback was attempted."
		}
	}
	return checks
}

func probeEncryptedUpstream(ctx context.Context, endpoint resolver.EncryptedEndpoint, timeout time.Duration) diag.UpstreamProbe {
	p := diag.UpstreamProbe{Spec: endpoint.Protocol + " " + endpoint.Address}
	client, err := resolver.NewEncryptedUpstreams([]resolver.EncryptedEndpoint{endpoint}, timeout)
	if err != nil {
		p.Err = err
		return p
	}
	defer client.Close()
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	query := new(dns.Msg)
	query.SetQuestion(doctorProbeName, dns.TypeA)
	query.RecursionDesired = true
	start := time.Now()
	reply, err := client.Exchange(probeCtx, query)
	p.Elapsed = time.Since(start)
	switch {
	case err != nil:
		p.Err = err
	case reply == nil || !answersQuestion(reply, query.Question[0]):
		p.Err = errors.New("encrypted upstream did not answer the probe question")
	default:
		p.Rcode = rcodeName(reply.Rcode)
	}
	return p
}

// A listener probe belongs on this machine. Merely appearing in a listen
// string is not proof that an address is local; a mistaken public address or
// DNS hostname must not turn encrypted-only diagnostics into a plaintext
// query to another server.
func doctorLocalProbeTarget(listen string) (string, error) {
	target := probeTarget(listen)
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return "", errors.New("listen address must contain a literal local IP and port")
	}
	if host == "localhost" {
		host = "127.0.0.1"
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return "", errors.New("hostname-based listener probes are disabled; use a literal local address")
	}
	if address.IsLoopback() {
		return net.JoinHostPort(address.String(), port), nil
	}
	interfaces, err := net.InterfaceAddrs()
	if err != nil {
		return "", errors.New("local interface addresses could not be inspected")
	}
	for _, iface := range interfaces {
		prefix, err := netip.ParsePrefix(iface.String())
		if err == nil && prefix.Addr().Unmap() == address.Unmap() {
			return net.JoinHostPort(address.String(), port), nil
		}
	}
	return "", errors.New("configured listen address does not belong to this host or container")
}
