// Package feedpolicy enforces remote-feed URL, redirect and connection policy.
// Errors deliberately contain no URL, response text or underlying network error.
package feedpolicy

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/apiprovider"
)

var (
	ErrURL           = errors.New("feed URL must be an absolute HTTPS URL without userinfo or fragment")
	ErrDestination   = errors.New("feed destination is denied; use a public HTTPS endpoint or an explicit origin/CIDR rule")
	ErrRedirect      = errors.New("feed redirect is denied; only HTTPS redirects to the same or an explicitly approved origin are permitted")
	ErrRedirectLimit = errors.New("feed redirect limit reached")
	ErrRules         = errors.New("invalid feed network rules; use exact HTTPS origins and private destination CIDRs")
)

// Rule is trusted startup configuration, never inferred from a feed response.
// PrivateCIDRs apply only to this exact origin; metadata/loopback are never allowed.
// RedirectOrigins grants redirect permission, not private-address permission.
type Rule struct {
	Origin          string   `yaml:"origin"`
	PrivateCIDRs    []string `yaml:"private_cidrs"`
	RedirectOrigins []string `yaml:"redirect_origins"`
}
type compiledRule struct {
	private   []netip.Prefix
	redirects map[string]bool
}
type Policy struct{ rules map[string]compiledRule }

var privateRanges = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("fc00::/7")}

// endpoint parses syntax only. Literal destinations are checked by ValidateURL.
func endpoint(raw string) (*url.URL, string, error) {
	if len(raw) > 4096 || strings.ContainsAny(raw, "\r\n\t") {
		return nil, "", ErrURL
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.RawFragment != "" {
		return nil, "", ErrURL
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if strings.ContainsAny(host, "%\\{} /\r\n\t") {
		return nil, "", ErrURL
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return nil, "", ErrURL
	}
	// Canonicalise numeric ports and equivalent default-port spellings.
	origin := "https://" + net.JoinHostPort(host, strconv.Itoa(n))
	return u, origin, nil
}
func ruleOrigin(raw string) (string, error) {
	u, o, err := endpoint(raw)
	if err != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery {
		return "", ErrRules
	}
	return o, nil
}
func New(rules []Rule) (*Policy, error) {
	if len(rules) > 32 {
		return nil, ErrRules
	}
	p := &Policy{rules: map[string]compiledRule{}}
	for _, r := range rules {
		origin, err := ruleOrigin(r.Origin)
		if err != nil {
			return nil, err
		}
		if _, ok := p.rules[origin]; ok {
			return nil, ErrRules
		}
		if len(r.PrivateCIDRs) > 16 || len(r.RedirectOrigins) > 16 {
			return nil, ErrRules
		}
		c := compiledRule{redirects: map[string]bool{}}
		for _, raw := range r.PrivateCIDRs {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil || prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() {
				return nil, ErrRules
			}
			prefix = prefix.Masked()
			contained := false
			for _, allowed := range privateRanges {
				if allowed.Addr().BitLen() == prefix.Addr().BitLen() && prefix.Bits() >= allowed.Bits() && allowed.Contains(prefix.Addr()) {
					contained = true
				}
			}
			if !contained {
				return nil, ErrRules
			}
			c.private = append(c.private, prefix)
		}
		for _, raw := range r.RedirectOrigins {
			o, err := ruleOrigin(raw)
			if err != nil {
				return nil, err
			}
			c.redirects[o] = true
		}
		p.rules[origin] = c
	}
	return p, nil
}
func (p *Policy) checkAddress(origin string, addr netip.Addr) error {
	if apiprovider.CheckDestinationAddress(addr, false) == nil {
		return nil
	}
	// The existing shared policy still refuses metadata and reserved addresses
	// when private access is requested. Exceptions cannot broaden those classes.
	if apiprovider.CheckDestinationAddress(addr, true) != nil {
		return ErrDestination
	}
	addr = addr.Unmap()
	for _, prefix := range p.rules[origin].private {
		if prefix.Contains(addr) {
			return nil
		}
	}
	return ErrDestination
}
func (p *Policy) ValidateURL(raw string) error {
	u, origin, err := endpoint(raw)
	if err != nil {
		return err
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || host == "metadata.google.internal" || host == "instance-data" {
		return ErrDestination
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return p.checkAddress(origin, addr)
	}
	return nil
}

// ValidatePublicURL is also used at store admission. Rules are installed at startup.
func ValidatePublicURL(raw string) error { p, _ := New(nil); return p.ValidateURL(raw) }
func (p *Policy) CheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return ErrRedirectLimit
	}
	if len(via) == 0 || p.ValidateURL(req.URL.String()) != nil {
		return ErrRedirect
	}
	_, from, err := endpoint(via[0].URL.String())
	if err != nil {
		return ErrRedirect
	}
	_, to, err := endpoint(req.URL.String())
	if err != nil {
		return ErrRedirect
	}
	if to != from && !p.rules[from].redirects[to] {
		return ErrRedirect
	}
	// A URL path/query can be a credential too. Never emit it as a Referer.
	req.Header.Del("Referer")
	_, previous, _ := endpoint(via[len(via)-1].URL.String())
	if to != previous {
		// Do not inherit authentication or endpoint-specific conditional headers.
		// #nosec G119 -- Replacing the entire map drops all inherited headers;
		// TestRedirectOriginsAndHeaders verifies cross-origin credential removal.
		req.Header = make(http.Header)
		req.Header.Set("Accept", "text/plain, application/json")
	}
	return nil
}

type originKey struct{}
type Transport struct {
	policy *Policy
	inner  *http.Transport
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil {
		return nil, ErrURL
	}
	if err := t.policy.ValidateURL(req.URL.String()); err != nil {
		return nil, err
	}
	_, origin, _ := endpoint(req.URL.String())
	return t.inner.RoundTrip(req.Clone(context.WithValue(req.Context(), originKey{}, origin)))
}
func (t *Transport) CloseIdleConnections() { t.inner.CloseIdleConnections() }
func (p *Policy) control(ctx context.Context, _, address string, _ syscall.RawConn) error {
	origin, ok := ctx.Value(originKey{}).(string)
	if !ok {
		return ErrDestination
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return ErrDestination
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return ErrDestination
	}
	return p.checkAddress(origin, addr)
}
func (p *Policy) NewClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second, ControlContext: p.control}
	transport := &Transport{policy: p, inner: &http.Transport{
		Proxy: nil, DialContext: dialer.DialContext, ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 5 * time.Second,
		MaxIdleConns: 8, MaxIdleConnsPerHost: 2, MaxConnsPerHost: 4, IdleConnTimeout: 90 * time.Second, ResponseHeaderTimeout: timeout,
	}}
	return &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: p.CheckRedirect}
}

// Failure never serialises err, which may wrap URL credentials or hostile text.
func Failure(err error) string {
	switch {
	case errors.Is(err, ErrURL):
		return ErrURL.Error()
	case errors.Is(err, ErrDestination):
		return ErrDestination.Error()
	case errors.Is(err, ErrRedirect):
		return ErrRedirect.Error()
	case errors.Is(err, ErrRedirectLimit):
		return ErrRedirectLimit.Error()
	case errors.Is(err, context.Canceled):
		return "feed request cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		return "feed request timed out"
	default:
		return "feed request failed (network, TLS or response error)"
	}
}
