// Package netguard decides which addresses this process may open an outbound
// connection to.
//
// # Why a policy rather than a list
//
// DNS Daddy makes outbound HTTP for two unrelated reasons, and they do not
// want the same answer.
//
// Threat-intelligence providers are URLs an operator types in so the resolver
// can ask somebody about a domain. "An internal reputation service" is a
// stated use case and a self-hosted vendor appliance on 10.0.0.0/8 is the
// ordinary one, so refusing private ranges there would break the feature. What
// must still be refused is the cloud instance metadata service: somebody who
// can add a provider is already an admin of this dashboard, and they should
// not thereby become an admin of the account the VM runs in.
//
// A findings webhook is a URL an operator types in so that alerts reach Slack,
// Teams or a chat tool. Those are on the public internet. A webhook pointed at
// 127.0.0.1 or 169.254.169.254 is not a deployment somebody wanted; it is
// either a mistake or somebody using the management API to make this process
// probe its own host — which is the textbook shape of a server-side request
// forgery. So that direction refuses everything that is not publicly routable.
//
// One deny list, two postures, and the difference is stated rather than
// duplicated. Before this package the first posture lived in internal/
// apiprovider and the second did not exist; writing it separately would have
// meant two hand-maintained lists of what counts as link-local, which is
// exactly how one of them ends up missing a range.
package netguard

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
)

// ErrBlocked is returned when an address is refused. Callers wrap it with
// their own package's language; this is the sentinel to match on.
var ErrBlocked = errors.New("refusing to connect to this address")

// Policy is how strict to be about a destination.
type Policy int

const (
	// AllowPrivate refuses the cloud instance metadata service and nothing
	// else. Private ranges, loopback and unique-local addresses stay
	// reachable, because reaching an appliance on the operator's own network
	// is the point of the feature using this.
	AllowPrivate Policy = iota

	// PublicOnly refuses everything that is not publicly routable: loopback,
	// link-local, private ranges, unique-local, the unspecified address,
	// multicast, and the metadata services.
	//
	// For destinations that are meant to be on the internet. The cost of being
	// wrong in the permissive direction is this process becoming a probe for
	// whatever is on its own host or LAN; the cost of being wrong in the
	// restrictive direction is an operator having to put a reverse proxy in
	// front of an internal endpoint, which is a normal thing to have to do.
	PublicOnly
)

// awsIPv6Metadata is fd00:ec2::254, AWS's IPv6 instance metadata endpoint.
//
// A reserved single address rather than a range, so blocking it takes no
// unique-local space away from an operator's own services — which matters
// under AllowPrivate, where the rest of that space is deliberately reachable.
var awsIPv6Metadata = netip.MustParseAddr("fd00:ec2::254")

// Check reports whether an address may be connected to under a policy.
//
// No Unmap call: netip's predicates already unmap a 4-in-6 address before
// deciding, so ::ffff:169.254.169.254 is caught by the same line as
// 169.254.169.254. An Unmap sat in the original of this code until removing it
// changed no test, which is the definition of a defence that was not
// defending anything.
func Check(addr netip.Addr, p Policy) error {
	if !addr.IsValid() {
		return fmt.Errorf("%w: not an address", ErrBlocked)
	}

	// Refused under every policy: on a cloud instance this is the credential
	// service, and it hands out more authority than this dashboard has.
	if addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
		return fmt.Errorf("%w: %s is link-local, which on a cloud instance is "+
			"the metadata service", ErrBlocked, addr)
	}
	if addr == awsIPv6Metadata {
		return fmt.Errorf("%w: %s is the instance metadata service", ErrBlocked, addr)
	}
	if p == AllowPrivate {
		return nil
	}

	// Order matters only for the wording. Every arm below refuses; what the
	// order decides is which sentence the operator reads, and a specific one
	// ("unique-local") is more use than a general one ("private network") when
	// they are working out why their URL was rejected.
	switch {
	case addr.IsLoopback():
		return fmt.Errorf("%w: %s is this machine", ErrBlocked, addr)
	case addr.IsUnspecified():
		return fmt.Errorf("%w: %s is not a destination", ErrBlocked, addr)
	case isUniqueLocal(addr):
		// Before IsPrivate, which also covers fc00::/7 and would otherwise
		// describe an IPv6 unique-local address as a private network.
		return fmt.Errorf("%w: %s is a unique-local address, not the internet", ErrBlocked, addr)
	case addr.IsPrivate():
		return fmt.Errorf("%w: %s is on a private network, not the internet", ErrBlocked, addr)
	case addr.IsMulticast() || addr.IsInterfaceLocalMulticast():
		return fmt.Errorf("%w: %s is a multicast address, not a destination", ErrBlocked, addr)
	case isCGNAT(addr):
		// 100.64.0.0/10 is carrier-grade NAT, and it is also where several
		// mesh VPNs put their addresses. Neither is the public internet.
		return fmt.Errorf("%w: %s is carrier-grade NAT space, not the internet", ErrBlocked, addr)
	}
	return nil
}

// cgnat is 100.64.0.0/10. netip has no predicate for it.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

func isCGNAT(addr netip.Addr) bool {
	a := addr.Unmap()
	return a.Is4() && cgnat.Contains(a)
}

// uniqueLocal is fc00::/7. Go's IsPrivate covers it too, so this exists only
// so the refusal names the thing it actually is.
var uniqueLocal = netip.MustParsePrefix("fc00::/7")

func isUniqueLocal(addr netip.Addr) bool {
	a := addr.Unmap()
	return a.Is6() && uniqueLocal.Contains(a)
}

// Control returns a net.Dialer Control function enforcing a policy.
//
// It runs after DNS resolution, on every attempt, so it sees the address the
// connection is actually being made to. A hostname that resolves to a refused
// address is caught, and so is one that resolves somewhere harmless on the
// first lookup and somewhere refused on the second — the check is per
// connection, not per configuration.
func Control(p Policy) func(network, address string, c syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			// Control is called with a resolved host:port, so this cannot
			// happen. Refusing rather than allowing on a parse failure is the
			// only safe direction for a check whose whole job is to say no.
			return fmt.Errorf("%w: could not parse %q", ErrBlocked, address)
		}
		addr, err := netip.ParseAddr(host)
		if err != nil {
			return fmt.Errorf("%w: could not parse address %q", ErrBlocked, host)
		}
		return Check(addr, p)
	}
}

// CheckURLHost refuses a URL whose host is a blocked IP literal.
//
// Dialer.Control is not sufficient on its own. With HTTP_PROXY set — which a
// deployment behind a corporate egress proxy will have — the transport dials
// the proxy, so the control sees the proxy's address and the request to the
// refused destination is forwarded by somebody else.
//
// Only literals are checked here, so this costs no DNS lookup. A hostname that
// resolves somewhere refused is still caught by the dialer in the un-proxied
// case, which is the one where it can be caught at all: through a proxy the
// name is resolved by the proxy and nothing on this side can see the answer.
func CheckURLHost(host string, p Policy) error {
	addr, err := netip.ParseAddr(host)
	if err != nil {
		// Not a literal — a hostname. Left to the dialer.
		return nil
	}
	return Check(addr, p)
}
