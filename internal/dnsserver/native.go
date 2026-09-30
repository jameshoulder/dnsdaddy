package dnsserver

import (
	"context"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/native"
	"github.com/jameshoulder/dnsdaddy/internal/resolver"
)

// NativeResolver produces client answers with Daddybound's exact-record
// validation over the selected transport. It is selected before the forwarding
// cache; a Live failure is already a SERVFAIL and must never fall through.
type NativeResolver interface {
	ResolveClient(context.Context, *dns.Msg) native.ClientResult
}

// NativeForwardResult adapts common response telemetry for the existing query
// recorder. Native ValidationStatus/ReasonCode must additionally be recorded
// by the caller: a local insecure verdict is different from an absent
// upstream AD bit, and a native failure is different from a policy block.
func NativeForwardResult(result native.ClientResult) resolver.Result {
	upstream := "daddybound-native"
	if result.ResolutionSource == "encrypted_forwarded" {
		upstream = "daddybound-encrypted"
	}
	return resolver.Result{Msg: result.Msg, Cached: result.Cached,
		Upstream: upstream, Rcode: result.Msg.Rcode,
		Validated: !result.CheckingDisabled && result.Validation.Status == dnssec.StatusSecure,
		MinTTL:    result.MinTTL}
}
