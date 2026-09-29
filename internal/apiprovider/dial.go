package apiprovider

import (
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
)

// ErrBlockedAddress never includes a URL or credential. The check is repeated
// against every actual dial destination, after DNS resolution, so changing DNS
// answers cannot turn an approved public hostname into a metadata request.
var ErrBlockedAddress = errors.New("apiprovider: destination address is not permitted")

var awsIPv6Metadata = netip.MustParseAddr("fd00:ec2::254")
var globalIPv6 = netip.MustParsePrefix("2000::/3")
var reservedIPv6 = []netip.Prefix{
	netip.MustParsePrefix("2001::/32"), // Teredo contains an embedded IPv4 destination.
	netip.MustParsePrefix("2001:2::/48"),
	netip.MustParsePrefix("2001:10::/28"),
	netip.MustParsePrefix("2001:20::/28"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"), // 6to4 can encode a forbidden IPv4 address.
	netip.MustParsePrefix("3fff::/20"),
}

var reservedIPv4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

func destinationControl(allowPrivate bool) func(string, string, syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return ErrBlockedAddress
		}
		addr, err := netip.ParseAddr(host)
		if err != nil {
			return ErrBlockedAddress
		}
		return CheckDestinationAddress(addr, allowPrivate)
	}
}

// CheckDestinationAddress permits public unicast destinations. An operator may
// explicitly allow RFC 1918 / IPv6 ULA services; that never allows loopback,
// link-local, cloud metadata, multicast, unspecified or reserved addresses.
func CheckDestinationAddress(addr netip.Addr, allowPrivate bool) error {
	addr = addr.Unmap()
	if !addr.IsValid() || addr.Zone() != "" || !addr.IsGlobalUnicast() || addr.IsLoopback() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr == awsIPv6Metadata {
		return ErrBlockedAddress
	}
	if addr.IsPrivate() {
		if allowPrivate {
			return nil
		}
		return ErrBlockedAddress
	}
	if addr.Is4() {
		for _, p := range reservedIPv4 {
			if p.Contains(addr) {
				return ErrBlockedAddress
			}
		}
	} else if !globalIPv6.Contains(addr) {
		// Excludes translation/tunnel and special-purpose ranges whose embedded
		// IPv4 destination could otherwise bypass the IPv4 checks above.
		return ErrBlockedAddress
	} else {
		for _, p := range reservedIPv6 {
			if p.Contains(addr) {
				return ErrBlockedAddress
			}
		}
	}
	return nil
}

// ValidateEndpoint performs configuration-only validation: it never resolves a
// hostname or contacts a service. Live DNS answers are checked at dial time.
func ValidateEndpoint(raw string, allowPrivate bool) error {
	if len(raw) > 4096 {
		return errors.New("provider endpoint is too long")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return errors.New("provider endpoint must be an HTTPS URL without credentials or a fragment")
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || host == "metadata.google.internal" || host == "instance-data" {
		return ErrBlockedAddress
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return CheckDestinationAddress(addr, allowPrivate)
	}
	if strings.ContainsAny(host, "{}%\\\r\n\t ") {
		return errors.New("provider endpoint hostname is not valid")
	}
	return nil
}
