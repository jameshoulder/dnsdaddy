package resolver

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Upstream is a single configured forwarder.
type Upstream struct {
	// Spec is the original configuration string, shown in the dashboard.
	Spec     string
	Protocol string // udp, tcp, tls, https
	Address  string
	// ServerName is the TLS certificate name for DoT, taken from the "#name"
	// suffix. Without it a DoT connection to a bare IP cannot be verified,
	// which would defeat the point of encrypting the query in the first place.
	ServerName string

	client  *dns.Client
	httpc   *http.Client
	url     string
	mu      sync.Mutex
	conn    *dns.Conn
	connAge time.Time

	queries atomicCounter
	errors  atomicCounter
	latency atomicCounter // cumulative milliseconds
}

// ParseUpstream builds an Upstream from a configuration string.
//
// Accepted forms:
//
//	1.1.1.1                          → udp, port 53
//	udp://9.9.9.9:53
//	tcp://9.9.9.9:53
//	tls://9.9.9.9:853#dns.quad9.net  → DNS-over-TLS, certificate verified as dns.quad9.net
//	https://dns.quad9.net/dns-query  → DNS-over-HTTPS
func ParseUpstream(spec string, timeout time.Duration) (*Upstream, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("empty upstream")
	}
	if timeout <= 0 {
		timeout = 4 * time.Second
	}

	u := &Upstream{Spec: spec}

	serverName := ""
	if i := strings.Index(spec, "#"); i >= 0 {
		serverName = spec[i+1:]
		spec = spec[:i]
	}
	u.ServerName = serverName

	scheme, rest := "udp", spec
	if i := strings.Index(spec, "://"); i >= 0 {
		scheme, rest = spec[:i], spec[i+3:]
	}
	u.Protocol = scheme

	switch scheme {
	case "udp", "tcp", "tls":
		port := "53"
		if scheme == "tls" {
			port = "853"
		}
		host := rest
		if h, p, err := net.SplitHostPort(rest); err == nil {
			host, port = h, p
		}
		if host == "" {
			return nil, fmt.Errorf("upstream %q has no host", u.Spec)
		}
		u.Address = net.JoinHostPort(host, port)

		net_ := scheme
		if scheme == "tls" {
			net_ = "tcp-tls"
			if u.ServerName == "" {
				// Fall back to the host itself; if it is an IP this will fail
				// verification, and failing loudly beats silently not verifying.
				u.ServerName = host
			}
		}
		u.client = &dns.Client{
			Net:     net_,
			Timeout: timeout,
			TLSConfig: &tls.Config{
				ServerName: u.ServerName,
				MinVersion: tls.VersionTLS12,
			},
		}

	case "https":
		parsed, err := url.Parse(u.Spec)
		if err != nil {
			return nil, fmt.Errorf("invalid DoH upstream %q: %w", u.Spec, err)
		}
		u.url = parsed.String()
		u.Address = parsed.Host
		u.httpc = &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				MaxIdleConns:        4,
				MaxIdleConnsPerHost: 4,
				IdleConnTimeout:     90 * time.Second,
				ForceAttemptHTTP2:   true,
				TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			},
		}

	default:
		return nil, fmt.Errorf("unsupported upstream scheme %q in %q", scheme, u.Spec)
	}

	return u, nil
}

// Exchange sends a query and returns the response.
func (u *Upstream) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	start := time.Now()
	u.queries.inc()

	var (
		resp *dns.Msg
		err  error
	)
	if u.Protocol == "https" {
		resp, err = u.exchangeDoH(ctx, m)
	} else {
		resp, err = u.exchangeDNS(ctx, m)
	}

	// A negative elapsed time is possible if the wall clock steps backwards
	// mid-exchange; converting that straight to uint64 would add ~18 quintillion
	// to the latency total and permanently wreck the average. Flagged by gosec G115.
	if elapsed := time.Since(start).Milliseconds(); elapsed > 0 {
		u.latency.add(uint64(elapsed))
	}
	if err != nil {
		u.errors.inc()
	}
	return resp, err
}

func (u *Upstream) exchangeDNS(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	// UDP is stateless; open, ask, close.
	if u.Protocol == "udp" {
		resp, _, err := u.client.ExchangeContext(ctx, m, u.Address)
		if err != nil {
			return nil, err
		}
		if resp.Truncated {
			// Retry over TCP rather than handing a client a truncated answer.
			return u.exchangeOverTCP(ctx, m)
		}
		return resp, nil
	}

	// TCP and DoT keep one pooled connection. Re-handshaking TLS on every
	// query would dominate resolution latency on a single-vCPU box.
	conn, reused, err := u.borrowConn(ctx)
	if err != nil {
		return nil, err
	}

	resp, err := u.exchangeOnConn(ctx, conn, m)
	if err != nil && reused {
		// A pooled connection the far end has already closed fails on first
		// write; one clean retry on a fresh connection hides that from callers.
		conn.Close()
		conn, _, err2 := u.borrowConn(ctx)
		if err2 != nil {
			return nil, err
		}
		resp, err = u.exchangeOnConn(ctx, conn, m)
	}
	if err != nil {
		if conn != nil {
			conn.Close()
		}
		return nil, err
	}
	u.returnConn(conn)
	return resp, nil
}

func (u *Upstream) exchangeOverTCP(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	c := &dns.Client{Net: "tcp", Timeout: u.client.Timeout}
	resp, _, err := c.ExchangeContext(ctx, m, u.Address)
	return resp, err
}

// borrowConn returns a pooled connection, or dials a new one. The bool reports
// whether the connection came from the pool.
func (u *Upstream) borrowConn(ctx context.Context) (*dns.Conn, bool, error) {
	u.mu.Lock()
	if u.conn != nil && time.Since(u.connAge) < 5*time.Minute {
		c := u.conn
		u.conn = nil
		u.mu.Unlock()
		return c, true, nil
	}
	if u.conn != nil {
		u.conn.Close()
		u.conn = nil
	}
	u.mu.Unlock()

	c, err := u.client.DialContext(ctx, u.Address)
	if err != nil {
		return nil, false, err
	}
	return c, false, nil
}

func (u *Upstream) returnConn(c *dns.Conn) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.conn != nil {
		// Another goroutine got there first; one pooled connection is enough
		// for the query rate a small office generates.
		c.Close()
		return
	}
	u.conn = c
	u.connAge = time.Now()
}

func (u *Upstream) exchangeOnConn(ctx context.Context, conn *dns.Conn, m *dns.Msg) (*dns.Msg, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(u.client.Timeout)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if err := conn.WriteMsg(m); err != nil {
		return nil, err
	}
	for {
		resp, err := conn.ReadMsg()
		if err != nil {
			return nil, err
		}
		// A pooled connection can carry interleaved responses; skip anything
		// that is not the answer to the question we just asked.
		if resp.Id == m.Id {
			return resp, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timed out waiting for response id %d", m.Id)
		}
	}
}

func (u *Upstream) exchangeDoH(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	packed, err := m.Pack()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.url, bytes.NewReader(packed))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := u.httpc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH upstream returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, dns.MaxMsgSize))
	if err != nil {
		return nil, err
	}
	out := new(dns.Msg)
	if err := out.Unpack(body); err != nil {
		return nil, err
	}
	return out, nil
}

// Close releases any pooled connection.
func (u *Upstream) Close() {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.conn != nil {
		u.conn.Close()
		u.conn = nil
	}
}

// Stats reports per-upstream counters for the dashboard and /metrics.
func (u *Upstream) Stats() (queries, errors uint64, avgLatencyMS float64) {
	q := u.queries.get()
	e := u.errors.get()
	var avg float64
	if q > 0 {
		avg = float64(u.latency.get()) / float64(q)
	}
	return q, e, avg
}
