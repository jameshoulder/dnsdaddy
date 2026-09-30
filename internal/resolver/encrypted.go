package resolver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"golang.org/x/net/idna"
)

const (
	// MaxEncryptedEndpoints bounds configuration, connections and statistics.
	MaxEncryptedEndpoints      = 16
	maxEncryptedBootstrapIPs   = 8
	maxEncryptedConcurrent     = 128
	maxEncryptedPerEndpoint    = 32
	maxEncryptedTLSConnections = 4
	maxEncryptedMessageBytes   = 65535
	maxEncryptedHeaderBytes    = 16 << 10
	encryptedReconnectDelay    = time.Second
)

var (
	ErrEncryptedClosed   = errors.New("encrypted upstreams are closed")
	ErrEncryptedCapacity = errors.New("encrypted upstream capacity reached")
	ErrEncryptedResponse = errors.New("invalid encrypted DNS response")
	errEncryptedCooldown = errors.New("encrypted endpoint reconnect backoff")
)

// EncryptedEndpoint describes one explicitly approved encrypted DNS service.
// A named address requires literal bootstrap IPs: no system DNS lookup is used.
type EncryptedEndpoint struct {
	Protocol     string   `json:"protocol" yaml:"protocol"`
	Address      string   `json:"address" yaml:"address"`
	ServerName   string   `json:"serverName,omitempty" yaml:"server_name,omitempty"`
	BootstrapIPs []string `json:"bootstrapIPs,omitempty" yaml:"bootstrap_ips,omitempty"`
}

// EncryptedEndpointStats reports authenticated transport, not DNSSEC status.
type EncryptedEndpointStats struct {
	Protocol          string    `json:"protocol"`
	Address           string    `json:"address"`
	ServerName        string    `json:"serverName"`
	Attempts          uint64    `json:"attempts"`
	Successes         uint64    `json:"successes"`
	Failures          uint64    `json:"failures"`
	DialFailures      uint64    `json:"dialFailures"`
	ConnectionsOpened uint64    `json:"connectionsOpened"`
	InFlight          int64     `json:"inFlight"`
	MaxConcurrent     int       `json:"maxConcurrent"`
	LastSuccess       time.Time `json:"lastSuccess,omitzero"`
	LastFailure       time.Time `json:"lastFailure,omitzero"`
	LastError         string    `json:"lastError,omitempty"`
	TLSVersion        string    `json:"tlsVersion,omitempty"`
	RemoteAddress     string    `json:"remoteAddress,omitempty"`
}

type EncryptedStats struct {
	Queries       uint64                   `json:"queries"`
	Successes     uint64                   `json:"successes"`
	Failures      uint64                   `json:"failures"`
	Rejected      uint64                   `json:"rejected"`
	Failovers     uint64                   `json:"failovers"`
	InFlight      int64                    `json:"inFlight"`
	MaxConcurrent int                      `json:"maxConcurrent"`
	Endpoints     []EncryptedEndpointStats `json:"endpoints"`
}

// EncryptedUpstreams owns a bounded, ordered set of approved encrypted routes.
// It never calls ordinary DNS, discovers another provider or downgrades TLS.
type EncryptedUpstreams struct {
	endpoints []*encryptedEndpoint
	timeout   time.Duration
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	closed    bool
	done      chan struct{}
	wg        sync.WaitGroup
	slots     chan struct{}
	queries   atomic.Uint64
	successes atomic.Uint64
	failures  atomic.Uint64
	rejected  atomic.Uint64
	failovers atomic.Uint64
	inFlight  atomic.Int64
}

type encryptedEndpoint struct {
	config     EncryptedEndpoint
	targets    []string
	tlsConfig  *tls.Config
	slots      chan struct{}
	http       *encryptedHTTP
	tlsSlots   chan struct{}
	tlsConns   map[*encryptedTLSConn]struct{}
	connMu     sync.Mutex
	conn       *quic.Conn
	dialing    *encryptedDial
	closed     bool
	statsMu    sync.Mutex
	stats      EncryptedEndpointStats
	retryAfter time.Time
}

type encryptedDial struct {
	done chan struct{}
	err  error
}

// NewEncryptedUpstreams requires WebPKI certificate verification and TLS 1.3.
// Endpoint order is also the encrypted-only failover order. Timeout is the
// total exchange budget, divided among remaining endpoints after each failure.
func NewEncryptedUpstreams(endpoints []EncryptedEndpoint, timeout time.Duration) (*EncryptedUpstreams, error) {
	return newEncryptedUpstreamsWithRoots(endpoints, timeout, nil)
}

// The unexported roots seam lets isolated tests authenticate their own CA.
// Production configuration cannot disable verification or inject trust roots.
func newEncryptedUpstreamsWithRoots(endpoints []EncryptedEndpoint, timeout time.Duration, roots *x509.CertPool) (*EncryptedUpstreams, error) {
	if len(endpoints) == 0 || len(endpoints) > MaxEncryptedEndpoints {
		return nil, fmt.Errorf("configure between 1 and %d encrypted endpoints", MaxEncryptedEndpoints)
	}
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	if timeout > 30*time.Second {
		return nil, errors.New("encrypted exchange timeout must not exceed 30 seconds")
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &EncryptedUpstreams{timeout: timeout, ctx: ctx, cancel: cancel, done: make(chan struct{}), slots: make(chan struct{}, maxEncryptedConcurrent)}
	for i, config := range endpoints {
		normalized, targets, err := normalizeEncryptedEndpoint(config)
		if err != nil {
			_ = c.Close()
			return nil, fmt.Errorf("encrypted endpoint %d: %w", i+1, err)
		}
		ep := &encryptedEndpoint{
			config: normalized, targets: targets,
			slots:     make(chan struct{}, maxEncryptedPerEndpoint),
			tlsSlots:  make(chan struct{}, maxEncryptedTLSConnections),
			tlsConns:  make(map[*encryptedTLSConn]struct{}),
			tlsConfig: &tls.Config{MinVersion: tls.VersionTLS13, ServerName: normalized.ServerName, RootCAs: roots},
			stats:     EncryptedEndpointStats{Protocol: normalized.Protocol, Address: normalized.Address, ServerName: normalized.ServerName, MaxConcurrent: maxEncryptedPerEndpoint},
		}
		if normalized.Protocol != "doq" {
			ep.http = newEncryptedHTTP(ep)
		}
		c.endpoints = append(c.endpoints, ep)
	}
	return c, nil
}

// ValidateEncryptedEndpoints performs configuration validation without opening
// connections, reading credentials or making DNS requests.
func ValidateEncryptedEndpoints(endpoints []EncryptedEndpoint) error {
	_, err := NormalizeEncryptedEndpoints(endpoints)
	return err
}

// NormalizeEncryptedEndpoints returns a defensive copy of validated endpoint
// settings without opening connections or invoking name resolution.
func NormalizeEncryptedEndpoints(endpoints []EncryptedEndpoint) ([]EncryptedEndpoint, error) {
	if len(endpoints) == 0 || len(endpoints) > MaxEncryptedEndpoints {
		return nil, fmt.Errorf("configure between 1 and %d encrypted endpoints", MaxEncryptedEndpoints)
	}
	normalized := make([]EncryptedEndpoint, 0, len(endpoints))
	for i, endpoint := range endpoints {
		result, _, err := normalizeEncryptedEndpoint(endpoint)
		if err != nil {
			return nil, fmt.Errorf("encrypted endpoint %d: %w", i+1, err)
		}
		normalized = append(normalized, result)
	}
	return normalized, nil
}

func normalizeEncryptedEndpoint(in EncryptedEndpoint) (EncryptedEndpoint, []string, error) {
	in.Protocol = strings.ToLower(strings.TrimSpace(in.Protocol))
	in.Address = strings.TrimSpace(in.Address)
	if len(in.Address) == 0 || len(in.Address) > 2048 {
		return in, nil, errors.New("address must contain between 1 and 2048 characters")
	}
	var host, port string
	var parsed *url.URL
	switch in.Protocol {
	case "doq":
		if strings.ContainsAny(in.Address, "/?#@") {
			return in, nil, errors.New("DoQ address must be a host or host:port, without a URL scheme")
		}
		var err error
		host, port, err = net.SplitHostPort(in.Address)
		if err != nil {
			host, port = strings.Trim(in.Address, "[]"), "853"
		}
	case "doh3", "doh2":
		var err error
		parsed, err = url.Parse(in.Address)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Opaque != "" {
			return in, nil, errors.New("DoH requires an absolute https:// endpoint URL")
		}
		if parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || strings.Contains(in.Address, "#") {
			return in, nil, errors.New("DoH URL must not contain credentials, a query string or a fragment")
		}
		host, port = parsed.Hostname(), parsed.Port()
		if port == "" {
			port = "443"
		}
		if parsed.Path == "" {
			return in, nil, errors.New("DoH URL must include its provider's DNS query path")
		}
	default:
		return in, nil, errors.New("protocol must be doq, doh3 or doh2")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return in, nil, errors.New("port must be between 1 and 65535")
	}
	port = strconv.Itoa(portNumber)
	if in.Protocol == "doq" && portNumber == 53 {
		return in, nil, errors.New("DoQ must not use UDP port 53; use port 853 or another explicitly configured port")
	}
	host, err = encryptedAuthName(host)
	if err != nil {
		return in, nil, errors.New("address must contain a valid DNS name or literal IP")
	}
	hostIP, hostIPErr := netip.ParseAddr(host)
	if hostIPErr == nil && !validEncryptedIP(hostIP) {
		return in, nil, errors.New("endpoint IP must be unicast, nonzero and without a zone")
	}
	if in.ServerName == "" {
		in.ServerName = host
	} else {
		in.ServerName, err = encryptedAuthName(in.ServerName)
		if err != nil {
			return in, nil, errors.New("certificate name must be a DNS name or literal IP")
		}
		if parsed != nil && hostIPErr != nil && in.ServerName != host {
			return in, nil, errors.New("a named DoH URL must authenticate that same hostname")
		}
	}
	if len(in.BootstrapIPs) > maxEncryptedBootstrapIPs {
		return in, nil, fmt.Errorf("at most %d literal bootstrap IPs are allowed", maxEncryptedBootstrapIPs)
	}
	ips := append([]string(nil), in.BootstrapIPs...)
	if len(ips) == 0 {
		if hostIPErr != nil {
			return in, nil, errors.New("named endpoints require literal bootstrap IPs; system DNS is not used")
		}
		ips = []string{hostIP.String()}
	}
	seen := make(map[netip.Addr]struct{}, len(ips))
	in.BootstrapIPs = nil
	var targets []string
	for _, raw := range ips {
		ip, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil || !validEncryptedIP(ip) {
			return in, nil, errors.New("bootstrap addresses must be literal unicast IPs, without ports or zones")
		}
		ip = ip.Unmap()
		if _, duplicate := seen[ip]; duplicate {
			continue
		}
		seen[ip] = struct{}{}
		in.BootstrapIPs = append(in.BootstrapIPs, ip.String())
		targets = append(targets, net.JoinHostPort(ip.String(), port))
	}
	if parsed != nil {
		parsed.Host = net.JoinHostPort(host, port)
		in.Address = parsed.String()
	} else {
		in.Address = net.JoinHostPort(host, port)
	}
	return in, targets, nil
}

func encryptedAuthName(name string) (string, error) {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if ip, err := netip.ParseAddr(name); err == nil {
		if ip.Zone() != "" {
			return "", errors.New("zone is not a certificate name")
		}
		return ip.Unmap().String(), nil
	}
	if strings.ContainsAny(name, ":/\\@#?%*[]") {
		return "", errors.New("invalid certificate name")
	}
	ascii, err := idna.Lookup.ToASCII(name)
	if err != nil || ascii == "" || len(ascii) > 253 {
		return "", errors.New("invalid certificate name")
	}
	if _, ok := dns.IsDomainName(ascii); !ok {
		return "", errors.New("invalid certificate name")
	}
	return strings.ToLower(ascii), nil
}

func validEncryptedIP(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	return !ip.IsUnspecified() && !ip.IsMulticast() && ip != netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

func (c *EncryptedUpstreams) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	response, _, err := c.ExchangeWithProtocol(ctx, m)
	return response, err
}

// ExchangeWithProtocol returns the actual transport used by the selected
// endpoint. Its label must not be mistaken for local DNSSEC verification.
func (c *EncryptedUpstreams) ExchangeWithProtocol(ctx context.Context, m *dns.Msg) (*dns.Msg, string, error) {
	c.queries.Add(1)
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		c.failures.Add(1)
		return nil, "", ErrEncryptedClosed
	}
	select {
	case c.slots <- struct{}{}:
		c.wg.Add(1)
		c.inFlight.Add(1)
	default:
		c.mu.Unlock()
		c.rejected.Add(1)
		c.failures.Add(1)
		return nil, "", ErrEncryptedCapacity
	}
	c.mu.Unlock()
	defer func() { <-c.slots; c.inFlight.Add(-1); c.wg.Done() }()
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	stop := context.AfterFunc(c.ctx, cancel)
	defer stop()
	defer cancel()
	query, wire, err := prepareEncryptedQuery(m)
	if err != nil {
		c.rejected.Add(1)
		c.failures.Add(1)
		return nil, "", err
	}
	var lastErr error
	for i, endpoint := range c.endpoints {
		if err := ctx.Err(); err != nil {
			lastErr = err
			break
		}
		if i > 0 {
			c.failovers.Add(1)
		}
		attemptCtx, attemptCancel := encryptedAttemptContext(ctx, len(c.endpoints)-i)
		response, err := endpoint.exchange(attemptCtx, query, wire)
		attemptCancel()
		if err == nil {
			c.mu.Lock()
			if c.closed {
				lastErr = ErrEncryptedClosed
			} else {
				lastErr = ctx.Err()
			}
			if lastErr != nil {
				c.mu.Unlock()
				break
			}
			response.Id = m.Id
			c.successes.Add(1)
			c.mu.Unlock()
			return response, endpoint.config.Protocol, nil
		}
		lastErr = err
	}
	c.failures.Add(1)
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	return nil, "", fmt.Errorf("all approved encrypted endpoints failed: %w", lastErr)
}

func encryptedAttemptContext(ctx context.Context, remaining int) (context.Context, context.CancelFunc) {
	deadline, ok := ctx.Deadline()
	if !ok || remaining < 1 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, time.Until(deadline)/time.Duration(remaining))
}

func (ep *encryptedEndpoint) exchange(ctx context.Context, query *dns.Msg, wire []byte) (*dns.Msg, error) {
	select {
	case ep.slots <- struct{}{}:
		defer func() { <-ep.slots }()
	default:
		return nil, ErrEncryptedCapacity
	}
	ep.statsMu.Lock()
	ep.stats.Attempts++
	ep.stats.InFlight++
	inBackoff := time.Now().Before(ep.retryAfter)
	ep.statsMu.Unlock()
	var response *dns.Msg
	var err error
	if inBackoff {
		err = errEncryptedCooldown
	} else if ep.config.Protocol == "doq" {
		response, err = ep.exchangeDoQ(ctx, query, wire)
	} else {
		response, err = ep.http.exchange(ctx, query, wire)
	}
	if ctx.Err() != nil {
		response, err = nil, ctx.Err()
	}
	ep.statsMu.Lock()
	ep.stats.InFlight--
	if err == nil {
		ep.stats.Successes++
		ep.stats.LastSuccess = time.Now().UTC()
		ep.stats.LastError = ""
	} else {
		ep.stats.Failures++
		ep.stats.LastFailure = time.Now().UTC()
		ep.stats.LastError = encryptedErrorReason(err)
	}
	ep.statsMu.Unlock()
	if err != nil {
		return nil, &encryptedExchangeError{protocol: ep.config.Protocol, reason: encryptedErrorReason(err), cause: err}
	}
	return response, nil
}

type encryptedExchangeError struct {
	protocol, reason string
	cause            error
}

func (e *encryptedExchangeError) Error() string { return e.protocol + ": " + e.reason }
func (e *encryptedExchangeError) Unwrap() error { return e.cause }

func encryptedErrorReason(err error) string {
	var verification *tls.CertificateVerificationError
	var hostError x509.HostnameError
	var invalid x509.CertificateInvalidError
	var authority x509.UnknownAuthorityError
	switch {
	case errors.Is(err, context.Canceled):
		return "request canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "request timed out"
	case errors.Is(err, ErrEncryptedClosed):
		return "endpoint closed"
	case errors.Is(err, ErrEncryptedCapacity):
		return "endpoint capacity reached"
	case errors.Is(err, errEncryptedCooldown):
		return "reconnect backoff"
	case errors.Is(err, ErrEncryptedResponse):
		return "invalid DNS or HTTP response"
	case errors.As(err, &verification), errors.As(err, &hostError), errors.As(err, &invalid), errors.As(err, &authority):
		return "certificate verification failed"
	default:
		return "encrypted connection failed"
	}
}

func (ep *encryptedEndpoint) recordDial(connState *tls.ConnectionState, remote string, err error) {
	ep.statsMu.Lock()
	defer ep.statsMu.Unlock()
	if err != nil {
		ep.stats.DialFailures++
		ep.retryAfter = time.Now().Add(encryptedReconnectDelay)
		return
	}
	ep.stats.ConnectionsOpened++
	ep.stats.TLSVersion = tls.VersionName(connState.Version)
	ep.stats.RemoteAddress = remote
	ep.retryAfter = time.Time{}
}

func (c *EncryptedUpstreams) Stats() EncryptedStats {
	stats := EncryptedStats{Queries: c.queries.Load(), Successes: c.successes.Load(), Failures: c.failures.Load(), Rejected: c.rejected.Load(), Failovers: c.failovers.Load(), InFlight: c.inFlight.Load(), MaxConcurrent: maxEncryptedConcurrent, Endpoints: make([]EncryptedEndpointStats, 0, len(c.endpoints))}
	for _, ep := range c.endpoints {
		ep.statsMu.Lock()
		stats.Endpoints = append(stats.Endpoints, ep.stats)
		ep.statsMu.Unlock()
	}
	return stats
}

// Close revokes this generation, cancels requests and waits for their exit.
// It is safe to call more than once, including concurrently.
func (c *EncryptedUpstreams) Close() error {
	c.mu.Lock()
	if c.closed {
		done := c.done
		c.mu.Unlock()
		<-done
		return nil
	}
	c.closed = true
	c.cancel()
	c.mu.Unlock()
	for _, ep := range c.endpoints {
		ep.connMu.Lock()
		ep.closed = true
		conn := ep.conn
		ep.conn = nil
		tlsConns := make([]*encryptedTLSConn, 0, len(ep.tlsConns))
		for tlsConn := range ep.tlsConns {
			tlsConns = append(tlsConns, tlsConn)
		}
		ep.connMu.Unlock()
		if conn != nil {
			_ = conn.CloseWithError(0, "")
		}
		for _, tlsConn := range tlsConns {
			_ = tlsConn.Close()
		}
		if ep.http != nil {
			ep.http.close()
		}
	}
	c.wg.Wait()
	close(c.done)
	return nil
}
