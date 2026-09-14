package apiprovider

import (
	"net/netip"
	"syscall"

	"github.com/jameshoulder/dnsdaddy/internal/netguard"
)

// ErrBlockedAddress is returned when a provider's URL resolves somewhere this
// package refuses to connect.
//
// An alias for netguard.ErrBlocked rather than a wrapper of it. The difference
// matters: callers match with errors.Is, and a wrapper is a distinct error
// value that the refusals returned by netguard do not wrap — so wrapping here
// would have left every errors.Is check silently false while the address went
// on being correctly refused. A defence that still works but can no longer be
// asserted is one test away from being removed as dead.
var ErrBlockedAddress = netguard.ErrBlocked

// providerPolicy is how strict this package is about where it will connect.
//
// Deliberately narrow, and the narrowness is the design rather than an
// oversight. The whole feature is "fetch a URL an operator typed in", so most
// of what a server-side request forgery check would normally block is the
// point: private ranges have to stay reachable, because "an internal
// reputation service" is a stated use case and a self-hosted vendor appliance
// on 10.0.0.0/8 is the ordinary one.
//
// The cloud instance metadata service is the case where this control adds
// something the operator does not already have. It hands out credentials for
// the host, which is strictly more authority than administering this
// dashboard; somebody who can add a provider should not thereby become an
// admin of the account this VM runs in.
//
// The findings webhook uses netguard.PublicOnly instead, because a webhook
// endpoint is on the internet and there is no equivalent use case for pointing
// one at this machine. Two features, two honest answers, one deny list.
const providerPolicy = netguard.AllowPrivate

// dialControl refuses connections to the instance metadata service.
//
// It runs in Dialer.Control, which means it sees the address the connection is
// actually being made to, after DNS resolution and on every attempt. A
// hostname that resolves to 169.254.169.254 is caught, and so is one that
// resolves somewhere harmless on the first lookup and to metadata on the
// second — the check is per connection, not per configuration.
func dialControl(network, address string, c syscall.RawConn) error {
	return netguard.Control(providerPolicy)(network, address, c)
}

// checkAddr is dialControl's decision, separated so it can be tested without a
// socket.
func checkAddr(addr netip.Addr) error { return netguard.Check(addr, providerPolicy) }

// checkURLHost refuses a URL whose host is a blocked IP literal.
//
// This exists because Dialer.Control is not sufficient on its own. With
// HTTP_PROXY set — which a deployment behind a corporate egress proxy will
// have — the transport dials the proxy, so the control sees the proxy's
// address and the request to 169.254.169.254 is forwarded by somebody else.
// This sandbox happened to have 169.254.0.0/16 in NO_PROXY, which is exactly
// the kind of accident that makes a hole look closed.
//
// Only literals are checked, so this costs no DNS lookup. A hostname that
// resolves to metadata is still caught by the dialer in the un-proxied case,
// which is the one where it can be caught at all: through a proxy, the name is
// resolved by the proxy and nothing on this side can see the answer.
func checkURLHost(host string) error { return netguard.CheckURLHost(host, providerPolicy) }
