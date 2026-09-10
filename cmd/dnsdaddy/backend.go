package main

import (
	"fmt"
	"log/slog"

	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/resolution"
	"github.com/jameshoulder/dnsdaddy/internal/resolver"
)

// buildBackend selects the resolution backend from configuration.
//
// The one place the mode is read. Everything downstream sees a
// resolution.Backend and does not know which it has — that is the architectural
// point of this milestone, and it is only true if the choice is made here and
// nowhere else.
//
// The second return is the forwarding resolver, or nil in native mode. It
// exists for the surfaces that legitimately want forwarder-specific detail —
// per-upstream latency, the in-flight limit — and every one of them tolerates
// nil, because in native mode there is no forwarder and no honest number to
// show for one.
func buildBackend(
	cfg config.Config,
	db *daddyboundEngine,
	log *slog.Logger,
) (resolution.Backend, *resolver.Resolver, error) {
	if cfg.DNS.Native() {
		if db == nil {
			return nil, nil, fmt.Errorf(
				"resolution_mode is %q but no Daddybound engine was built", config.ResolutionNative)
		}
		backend, err := resolution.NewNative(db.engine, resolution.NativeOptions{})
		if err != nil {
			return nil, nil, err
		}
		log.Info("Daddybound is resolving DNS",
			"mode", config.ResolutionNative,
			"dnssec", "validated locally against the configured trust anchors",
			"upstreams", "not used",
			"note", "authoritative queries leave this host over plaintext port 53; "+
				"QNAME minimisation limits what each server on the path learns")
		return backend, nil, nil
	}

	res, err := resolver.New(cfg.DNS, cfg.Cache, log)
	if err != nil {
		return nil, nil, err
	}
	for _, u := range res.Upstreams() {
		if u.Protocol == "udp" || u.Protocol == "tcp" {
			log.Warn("upstream uses unencrypted DNS; anyone on the path can see and alter your lookups",
				"upstream", u.Spec)
		}
	}
	log.Info("forwarding DNS to the configured upstreams",
		"mode", config.ResolutionForward,
		"upstreams", len(res.Upstreams()),
		"dnssec", "whatever the upstream asserts; not validated here")
	return resolution.NewForward(res, nil), res, nil
}
