// Package resolveraddr answers the first question every operator asks: what do
// I type into my router?
//
// It is a harder question than it looks, and getting it wrong is worse than not
// answering. A machine can see the addresses on its own interfaces; it cannot
// see how the rest of the world reaches it. On a VPS the two are routinely
// different — the NIC holds an RFC 1918 address and the provider applies a
// public one by NAT — so a dashboard that printed the interface address would
// be confidently telling the operator to configure a number nothing can reach.
//
// So this package does two things and refuses to do a third.
//
// It reports what the operator configured, marked as configured, and treats it
// as authoritative. Nobody on the machine knows better than the person who set
// it up.
//
// It reports what it can see on the interfaces, marked as discovered, with the
// kind of address each one is. On a home LAN — the common deployment — that is
// exactly right and needs no configuration at all.
//
// It does not ask a third-party service what its public address is. That would
// mean a self-hosted DNS resolver making an outbound HTTPS call to somebody
// else's server, to learn something the operator already knows, and reporting
// whatever came back as fact. The dependency is not worth it and the answer
// would be wrong behind any NAT the operator does not control.
package resolveraddr

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// Source says where an address came from.
type Source string

const (
	// SourceConfigured: the operator told us. Authoritative.
	SourceConfigured Source = "configured"
	// SourceInterface: found on a network interface of this machine.
	//
	// Right on a LAN and not necessarily right anywhere else: a NATed host
	// sees its private address here and the world sees another. The
	// distinction is carried through to the dashboard rather than smoothed
	// over, because an operator who is behind NAT needs to know that this is a
	// guess.
	SourceInterface Source = "interface"
)

// Kind describes what sort of address this is, so an operator can tell which
// of several to use.
type Kind string

const (
	// KindPrivate is an RFC 1918 or unique-local address: the one to
	// configure on a LAN.
	KindPrivate Kind = "private"
	// KindPublic is globally routable.
	KindPublic Kind = "public"
	// KindLoopback reaches only this machine.
	KindLoopback Kind = "loopback"
	// KindLinkLocal is reachable only on the local segment.
	KindLinkLocal Kind = "link-local"
)

// Address is one address clients might be pointed at.
type Address struct {
	Address string `json:"address"`
	// Family is "ipv4" or "ipv6".
	Family string `json:"family"`
	Kind   Kind   `json:"kind"`
	Source Source `json:"source"`
	// Recommended marks the one to put in front of the operator.
	//
	// One at most. A list of six addresses with no recommendation is a list
	// that makes the operator choose, and the whole point is that they should
	// not have to.
	Recommended bool `json:"recommended"`
	// Note explains a caveat worth reading before using this address, or is
	// empty. The NAT case in particular: a private address discovered on a
	// cloud host is very likely not how clients reach it.
	Note string `json:"note,omitempty"`
}

// Options configures discovery.
type Options struct {
	// Configured are the operator's advertised addresses, from
	// dns.advertised_addresses. Authoritative when present.
	Configured []string
	// Interfaces lists the machine's addresses. Nil means ask the system;
	// a test supplies its own.
	Interfaces func() ([]netip.Addr, error)
}

// Discover returns the addresses clients could be pointed at, best first.
//
// Never an error for the caller to handle: a machine whose interfaces cannot be
// enumerated still has whatever the operator configured, and an operator with
// neither gets an empty list and a dashboard that says so. Failing the whole
// status page because a network interface was being reconfigured would be worse
// than showing less.
func Discover(o Options) []Address {
	var out []Address
	seen := map[string]bool{}

	for _, raw := range o.Configured {
		addr, err := parse(raw)
		if err != nil {
			// A malformed entry is skipped rather than fatal: this feeds a
			// status page, and one bad line in a list should not blank it.
			// Configuration validation is where a typo is reported.
			continue
		}
		if seen[addr.String()] {
			continue
		}
		seen[addr.String()] = true
		out = append(out, describe(addr, SourceConfigured))
	}

	enumerate := o.Interfaces
	if enumerate == nil {
		enumerate = systemAddresses
	}
	if found, err := enumerate(); err == nil {
		for _, addr := range found {
			if seen[addr.String()] {
				continue
			}
			seen[addr.String()] = true
			out = append(out, describe(addr, SourceInterface))
		}
	}

	sort.SliceStable(out, func(i, j int) bool { return rank(out[i]) < rank(out[j]) })
	recommend(out)
	return out
}

// describe classifies an address and attaches any caveat worth reading.
func describe(addr netip.Addr, src Source) Address {
	a := Address{
		Address: addr.String(),
		Family:  family(addr),
		Kind:    kindOf(addr),
		Source:  src,
	}
	switch {
	case src == SourceInterface && a.Kind == KindPrivate:
		a.Note = "found on this machine's own interface. Correct on a local network. " +
			"On a cloud host or behind NAT, clients outside reach this machine by a " +
			"different address — set dns.advertised_addresses to the one they use."
	case src == SourceInterface && a.Kind == KindPublic:
		a.Note = "found on this machine's own interface and globally routable. " +
			"Check that only permitted networks may use the resolver before " +
			"pointing anything at it."
	case a.Kind == KindLoopback:
		a.Note = "reaches only this machine. Useful for testing from the host itself."
	case a.Kind == KindLinkLocal:
		a.Note = "reachable only on the local network segment."
	}
	return a
}

// rank orders addresses by how likely each is to be the right answer.
//
// Configured first, always: the operator knows how their network is reached and
// this package does not. Then private addresses, because the common deployment
// is a resolver on a LAN. Public next. Loopback and link-local last — they are
// worth listing, because a loopback address is how you test from the host, and
// worth listing last, because neither is what a client should be configured
// with.
func rank(a Address) int {
	base := 0
	if a.Source != SourceConfigured {
		base = 10
	}
	switch a.Kind {
	case KindPrivate:
		return base + 0
	case KindPublic:
		return base + 1
	case KindLoopback:
		return base + 8
	default:
		return base + 9
	}
}

// recommend marks at most one address as the one to put in front of the
// operator.
//
// Loopback and link-local are never recommended, however few alternatives there
// are: neither is an address a client on the network can use, and recommending
// one would send somebody to configure 127.0.0.1 on their router. A deployment
// with nothing else gets no recommendation, which is the honest outcome — the
// dashboard then asks the operator for an advertised address instead of
// inventing one.
func recommend(addrs []Address) {
	for i := range addrs {
		switch addrs[i].Kind {
		case KindLoopback, KindLinkLocal:
			continue
		}
		addrs[i].Recommended = true
		return
	}
}

func family(addr netip.Addr) string {
	if addr.Is4() || addr.Is4In6() {
		return "ipv4"
	}
	return "ipv6"
}

func kindOf(addr netip.Addr) Kind {
	addr = addr.Unmap()
	switch {
	case addr.IsLoopback():
		return KindLoopback
	case addr.IsLinkLocalUnicast():
		return KindLinkLocal
	case addr.IsPrivate():
		return KindPrivate
	}
	// Unique-local IPv6 (fc00::/7) is the IPv6 equivalent of RFC 1918 and
	// netip does not fold it into IsPrivate.
	if addr.Is6() {
		if b := addr.As16(); b[0]&0xfe == 0xfc {
			return KindPrivate
		}
	}
	// Carrier-grade NAT. Not private by RFC 1918 and not something a client
	// outside the carrier's network can reach, so it is listed as private:
	// an operator seeing it needs the same warning.
	if addr.Is4() {
		if b := addr.As4(); b[0] == 100 && b[1]&0xc0 == 64 {
			return KindPrivate
		}
	}
	return KindPublic
}

// parse accepts an address, optionally with a port, and returns the address.
//
// A port is tolerated because an operator copying from their configuration may
// well include one, and refusing the line over it would be pedantry. The port
// the resolver listens on is reported separately and authoritatively.
func parse(raw string) (netip.Addr, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return netip.Addr{}, fmt.Errorf("empty address")
	}
	if addr, err := netip.ParseAddr(raw); err == nil {
		return addr, nil
	}
	if ap, err := netip.ParseAddrPort(raw); err == nil {
		return ap.Addr(), nil
	}
	return netip.Addr{}, fmt.Errorf("%q is not an IP address", raw)
}

// systemAddresses enumerates this machine's usable addresses.
//
// Interfaces that are down are skipped: an address on a down interface is not
// somewhere a client can reach. Everything else is reported and classified,
// including loopback, because "how do I test this from the host" is a real
// question with a real answer.
func systemAddresses() ([]netip.Addr, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			// One interface that cannot be read does not invalidate the
			// others. A machine mid-reconfiguration should still show what it
			// can see.
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			addr, ok := netip.AddrFromSlice(ipnet.IP)
			if !ok {
				continue
			}
			addr = addr.Unmap()
			if !addr.IsValid() || addr.IsMulticast() || addr.IsUnspecified() {
				continue
			}
			// A zone-scoped address is meaningless to anybody else — the zone
			// names an interface on *this* machine — so the scope is dropped
			// and the address reported plainly.
			out = append(out, addr.WithZone(""))
		}
	}
	return out, nil
}

// Port extracts the port from a listen address, or 0 when there is none.
//
// The listen addresses are configuration ("0.0.0.0:53", ":53", "[::]:53") and
// the port is the half an operator has to type into a client that lets them
// choose one.
func Port(listen string) int {
	if listen == "" {
		return 0
	}
	_, portStr, err := net.SplitHostPort(listen)
	if err != nil {
		return 0
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return 0
	}
	return port
}
