package apiprovider

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
)

// ErrBlockedAddress is returned when a provider's URL resolves somewhere this
// package refuses to connect.
var ErrBlockedAddress = errors.New("apiprovider: refusing to connect to a link-local address")

// dialControl refuses connections to link-local addresses.
//
// This is the one server-side request forgery control in the package, and it
// is deliberately narrow. The whole feature is "fetch a URL an operator typed
// in", so most of what an SSRF check would normally block is the point:
// private ranges have to stay reachable, because "an internal reputation
// service" is a stated use case and a self-hosted vendor appliance on
// 10.0.0.0/8 is the ordinary one.
//
// Link-local is different, and it is the only case where this control adds
// anything the operator does not already have. Every major cloud puts its
// instance metadata service on 169.254.169.254, and that endpoint hands out
// IAM credentials for the host — which is strictly more authority than
// administering this dashboard. Somebody who can add a provider is already
// admin here; they should not thereby become admin of the account this VM runs
// in.
//
// AWS's IPv6 metadata endpoint is the one address outside link-local that is
// blocked, by exact match. It sits in unique-local space, which is where an
// operator's own internal services legitimately live, so the range cannot be
// refused wholesale — but that single address is reserved by AWS for the same
// credential-issuing endpoint, so refusing it costs nobody anything.
//
// It runs in Dialer.Control, which means it sees the address the connection is
// actually being made to, after DNS resolution and on every attempt. A
// hostname that resolves to 169.254.169.254 is caught, and so is one that
// resolves somewhere harmless on the first lookup and to metadata on the
// second — the check is per connection, not per configuration.
func dialControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		// Control is called with a resolved host:port, so this cannot happen.
		// Refusing rather than allowing on a parse failure is the only safe
		// direction for a check whose whole job is to say no.
		return fmt.Errorf("%w: could not parse %q", ErrBlockedAddress, address)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("%w: could not parse address %q", ErrBlockedAddress, host)
	}
	return checkAddr(addr)
}

// checkAddr is dialControl's decision, separated so it can be tested without a
// socket.
func checkAddr(addr netip.Addr) error {
	// No Unmap here, deliberately: netip's IsLinkLocal* predicates already
	// unmap a 4-in-6 address before deciding, so ::ffff:169.254.169.254 is
	// caught by the same line as 169.254.169.254. An Unmap call sat here until
	// removing it changed no test, which is the definition of a defence that
	// was not defending anything.
	if addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
		return fmt.Errorf("%w: %s is link-local, which on a cloud instance is "+
			"the metadata service", ErrBlockedAddress, addr)
	}
	if addr == awsIPv6Metadata {
		return fmt.Errorf("%w: %s is the instance metadata service",
			ErrBlockedAddress, addr)
	}
	return nil
}

// awsIPv6Metadata is fd00:ec2::254, AWS's IPv6 instance metadata endpoint. It
// is a reserved single address rather than a range, so blocking it does not
// take any unique-local space away from an operator's own services.
var awsIPv6Metadata = netip.MustParseAddr("fd00:ec2::254")

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
func checkURLHost(host string) error {
	addr, err := netip.ParseAddr(host)
	if err != nil {
		// Not a literal — a hostname. Left to the dialer.
		return nil
	}
	return checkAddr(addr)
}
