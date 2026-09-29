package dnsserver

import (
	"context"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/native"
	"github.com/jameshoulder/dnsdaddy/internal/resolver"
)

// NativeResolver produces client answers from Daddybound's own recursion and
// exact-record validation. It is selected before the forwarding cache; a
// native failure is already a SERVFAIL response and must never fall through.
type NativeResolver interface {
	ResolveClient(context.Context, *dns.Msg) native.ClientResult
}

// NativeForwardResult adapts common response telemetry for the existing query
// recorder. Native ValidationStatus/ReasonCode must additionally be recorded
// by the caller: a local insecure verdict is different from an absent
// upstream AD bit, and a native failure is different from a policy block.
func NativeForwardResult(result native.ClientResult) resolver.Result {
	return resolver.Result{Msg: result.Msg, Cached: result.Cached,
		Upstream: "daddybound-native", Rcode: result.Msg.Rcode,
		Validated: !result.CheckingDisabled && result.Validation.Status == dnssec.StatusSecure,
		MinTTL:    result.MinTTL}
}
