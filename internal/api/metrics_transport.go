package api

import (
	"fmt"
	"strings"

	"github.com/jameshoulder/dnsdaddy/internal/config"
)

func (a *API) writeTransportMetrics(b *strings.Builder) {
	s := a.transportState()
	metric(b, "dnsdaddy_dns_transport", "Effective outbound DNS transport selection", "gauge",
		fmt.Sprintf("dnsdaddy_dns_transport{transport=\"native\"} %d", boolGauge(s.Transport == config.ResolutionNative)),
		fmt.Sprintf("dnsdaddy_dns_transport{transport=\"encrypted\"} %d", boolGauge(s.Transport == config.ResolutionEncrypted)))
	if s.Stats == nil {
		return
	}
	stats := s.Stats
	for _, counter := range []struct {
		name, help string
		value      uint64
	}{
		{"queries", "Encrypted DNS exchanges since transport activation", stats.Queries},
		{"successes", "Successful authenticated encrypted DNS exchanges", stats.Successes},
		{"failures", "Encrypted DNS exchanges that failed across all approved endpoints", stats.Failures},
		{"rejected", "Encrypted DNS exchanges rejected by bounded admission", stats.Rejected},
		{"failovers", "Encrypted DNS attempts using a subsequent approved endpoint", stats.Failovers},
	} {
		name := "dnsdaddy_dns_encrypted_" + counter.name + "_total"
		metric(b, name, counter.help, "counter", fmt.Sprintf("%s %d", name, counter.value))
	}
	metric(b, "dnsdaddy_dns_encrypted_inflight", "Active encrypted exchanges", "gauge", fmt.Sprintf("dnsdaddy_dns_encrypted_inflight %d", stats.InFlight))
	metric(b, "dnsdaddy_dns_encrypted_max_concurrent", "Maximum concurrent encrypted exchanges", "gauge", fmt.Sprintf("dnsdaddy_dns_encrypted_max_concurrent %d", stats.MaxConcurrent))
	// Bounded numeric endpoint identifiers avoid putting names, addresses or
	// provider account paths into Prometheus label sets.
	for _, counter := range []struct{ name, help string }{
		{"attempts", "Attempts per configured encrypted endpoint"},
		{"failures", "Failed exchanges per configured encrypted endpoint"},
		{"dial_failures", "Failed connection attempts per encrypted endpoint"},
		{"connections_opened", "Authenticated connections opened per encrypted endpoint"},
	} {
		name := "dnsdaddy_dns_encrypted_endpoint_" + counter.name + "_total"
		lines := make([]string, 0, len(stats.Endpoints))
		for i, e := range stats.Endpoints {
			value := e.Attempts
			switch counter.name {
			case "failures":
				value = e.Failures
			case "dial_failures":
				value = e.DialFailures
			case "connections_opened":
				value = e.ConnectionsOpened
			}
			lines = append(lines, fmt.Sprintf("%s{endpoint=\"%d\",protocol=%q} %d", name, i+1, e.Protocol, value))
		}
		metric(b, name, counter.help, "counter", lines...)
	}
}
