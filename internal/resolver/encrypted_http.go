package resolver

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go/http3"
)

const encryptedH2ALPN = "h2"

type encryptedHTTP struct {
	endpoint     *encryptedEndpoint
	client       *http.Client
	h2           *http.Transport
	h3           *http3.Transport
	connection   *http3.ClientConn // guarded by endpoint.connMu
	h2Connection *http.ClientConn  // guarded by endpoint.connMu
	h2Socket     *encryptedTLSConn // guarded by endpoint.connMu
}

func newEncryptedHTTP(endpoint *encryptedEndpoint) *encryptedHTTP {
	h := &encryptedHTTP{endpoint: endpoint}
	if endpoint.config.Protocol == "doh3" {
		h.h3 = &http3.Transport{
			TLSClientConfig:        endpoint.tlsConfig.Clone(),
			QUICConfig:             encryptedQUICConfig(true),
			MaxResponseHeaderBytes: maxEncryptedHeaderBytes,
			DisableCompression:     true,
		}
		// Own one QUIC connection instead of Transport's internal pool. Its
		// retry path may remove an errored connection without closing it;
		// repeated malicious replies must not accumulate idle connections.
	} else {
		protocols := new(http.Protocols)
		protocols.SetHTTP2(true) // Neither HTTP/1 nor cleartext HTTP/2 is permitted.
		h.h2 = &http.Transport{
			TLSClientConfig:        endpoint.tlsConfig.Clone(),
			Protocols:              protocols,
			DisableCompression:     true,
			MaxResponseHeaderBytes: int64(maxEncryptedHeaderBytes),
			IdleConnTimeout:        30 * time.Second,
			HTTP2: &http.HTTP2Config{
				StrictMaxConcurrentRequests: true,
				SendPingTimeout:             15 * time.Second,
				PingTimeout:                 5 * time.Second,
				WriteByteTimeout:            5 * time.Second,
			},
		}
	}
	h.client = &http.Client{
		Transport:     h,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	return h
}

func (h *encryptedHTTP) RoundTrip(request *http.Request) (*http.Response, error) {
	if h.h2 != nil {
		client, socket, err := h.http2Conn(request.Context())
		if err != nil {
			return nil, err
		}
		response, err := client.RoundTrip(request)
		if err != nil && request.Context().Err() == nil {
			_ = socket.Close()
		}
		return response, err
	}
	conn, err := h.endpoint.quicConn(request.Context())
	if err != nil {
		return nil, err
	}
	h.endpoint.connMu.Lock()
	client := h.connection
	if h.endpoint.conn != conn {
		client = nil
	}
	h.endpoint.connMu.Unlock()
	if client == nil {
		return nil, ErrEncryptedClosed
	}
	response, err := client.RoundTrip(request)
	if err != nil && request.Context().Err() == nil {
		// No hidden retries. Retire a protocol-failed connection and let the
		// outer ordered policy decide whether another endpoint is approved.
		_ = conn.CloseWithError(0, "")
	}
	return response, err
}

// http2Conn owns exactly one reusable HTTP/2 connection per endpoint. Using
// ClientConn directly avoids automatic pool retries and concurrent cold dials.
// Endpoint admission bounds requests waiting for the peer's stream limit.
func (h *encryptedHTTP) http2Conn(ctx context.Context) (*http.ClientConn, *encryptedTLSConn, error) {
	ep := h.endpoint
	for {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		ep.connMu.Lock()
		if ep.closed {
			ep.connMu.Unlock()
			return nil, nil, ErrEncryptedClosed
		}
		if client, socket := h.h2Connection, h.h2Socket; client != nil {
			// Do not query a protocol implementation's state while holding
			// our mutex. An unrelated stalled writer must not delay this
			// request's context before RoundTrip handles stream admission.
			if !socket.closed.Load() {
				ep.connMu.Unlock()
				return client, socket, nil
			}
			h.h2Connection, h.h2Socket = nil, nil
			ep.connMu.Unlock()
			continue
		}
		if pending := ep.dialing; pending != nil {
			ep.connMu.Unlock()
			select {
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			case <-pending.done:
				if pending.err != nil {
					return nil, nil, pending.err
				}
				continue
			}
		}
		pending := &encryptedDial{done: make(chan struct{})}
		ep.dialing = pending
		ep.connMu.Unlock()

		client, socket, err := h.openHTTP2(ctx)
		ep.connMu.Lock()
		if err == nil {
			if ep.closed {
				err = ErrEncryptedClosed
			} else if ctx.Err() != nil {
				err = ctx.Err()
			} else {
				h.h2Connection, h.h2Socket = client, socket
			}
		}
		pending.err = err
		ep.dialing = nil
		close(pending.done)
		ep.connMu.Unlock()
		if err != nil {
			if socket != nil {
				_ = socket.Close()
			}
			return nil, nil, err
		}
		return client, socket, nil
	}
}

func (h *encryptedHTTP) openHTTP2(ctx context.Context) (*http.ClientConn, *encryptedTLSConn, error) {
	target, err := url.Parse(h.endpoint.config.Address)
	if err != nil || target.Scheme != "https" || target.Host == "" {
		return nil, nil, errors.New("invalid encrypted HTTP/2 endpoint")
	}
	conn, err := h.dialTLS(ctx, "tcp", "", h.endpoint.tlsConfig)
	if err != nil {
		return nil, nil, err
	}
	socket := conn.(*encryptedTLSConn) // dialTLS returns only authenticated, owned TLS sockets.
	if deadline, ok := ctx.Deadline(); ok {
		if err := socket.SetDeadline(deadline); err != nil {
			return nil, socket, err
		}
	}
	// Go's supported ClientConn API creates its connection through the
	// transport. Give it this already authenticated, literal-IP-dialled
	// socket exactly once, never an opportunity to dial an unapproved host,
	// use an environment proxy, or silently retry through a connection pool.
	transport := h.h2.Clone()
	var handedOff atomic.Bool
	transport.DialTLSContext = func(dialCtx context.Context, _, _ string) (net.Conn, error) {
		if err := dialCtx.Err(); err != nil {
			return nil, err
		}
		if handedOff.Swap(true) {
			return nil, errors.New("encrypted HTTP/2 socket already handed off")
		}
		return socket, nil
	}
	stop := context.AfterFunc(ctx, func() { _ = socket.Close() })
	client, err := transport.NewClientConn(ctx, "https", target.Host)
	stop()
	if ctx.Err() != nil {
		return nil, socket, ctx.Err()
	}
	if err != nil {
		return nil, socket, err
	}
	if err := socket.SetDeadline(time.Time{}); err != nil {
		return nil, socket, err
	}
	return client, socket, nil
}

type encryptedTLSConn struct {
	*tls.Conn
	endpoint *encryptedEndpoint
	once     sync.Once
	closed   atomic.Bool
	closeErr error
}

func (c *encryptedTLSConn) Close() error {
	c.closed.Store(true)
	c.once.Do(func() {
		// This owned wrapper must provide its own close bound: an
		// unresponsive peer must not stall cancellation while TLS sends
		// its close_notify. ConnectionState is promoted for standard HTTP/2
		// ALPN support on wrapped TLS connections (Go 1.27).
		forceClose := time.AfterFunc(250*time.Millisecond, func() { _ = c.Conn.NetConn().Close() })
		c.closeErr = c.Conn.Close()
		forceClose.Stop()
		c.endpoint.connMu.Lock()
		delete(c.endpoint.tlsConns, c)
		c.endpoint.connMu.Unlock()
		<-c.endpoint.tlsSlots
	})
	return c.closeErr
}

func (h *encryptedHTTP) dialTLS(ctx context.Context, _, _ string, config *tls.Config) (net.Conn, error) {
	select {
	case h.endpoint.tlsSlots <- struct{}{}:
	default:
		return nil, ErrEncryptedCapacity
	}
	transferred := false
	defer func() {
		if !transferred {
			<-h.endpoint.tlsSlots
		}
	}()
	var lastErr error
	for i, target := range h.endpoint.targets {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		attemptCtx, cancel := encryptedAttemptContext(ctx, len(h.endpoint.targets)-i)
		cfg := config.Clone()
		cfg.MinVersion = tls.VersionTLS13
		cfg.ServerName = h.endpoint.config.ServerName
		cfg.NextProtos = []string{encryptedH2ALPN}
		dialer := &tls.Dialer{NetDialer: &net.Dialer{}, Config: cfg}
		conn, err := dialer.DialContext(attemptCtx, "tcp", target)
		cancel()
		if err != nil {
			h.endpoint.recordDial(nil, "", err)
			lastErr = err
			continue
		}
		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			_ = conn.Close()
			lastErr = errors.New("endpoint did not negotiate TLS")
			h.endpoint.recordDial(nil, "", lastErr)
			continue
		}
		state := tlsConn.ConnectionState()
		if !state.HandshakeComplete || state.Version < tls.VersionTLS13 || len(state.VerifiedChains) == 0 || state.NegotiatedProtocol != encryptedH2ALPN {
			// A rejected peer has no reusable application session. Abort the
			// socket before TLS close_notify can wait on an unresponsive peer.
			_ = tlsConn.NetConn().Close()
			_ = tlsConn.Close()
			lastErr = errors.New("endpoint did not negotiate authenticated HTTP/2 over TLS 1.3")
			h.endpoint.recordDial(nil, "", lastErr)
			continue
		}
		h.endpoint.recordDial(&state, conn.RemoteAddr().String(), nil)
		owned := &encryptedTLSConn{Conn: tlsConn, endpoint: h.endpoint}
		h.endpoint.connMu.Lock()
		if h.endpoint.closed {
			h.endpoint.connMu.Unlock()
			_ = tlsConn.NetConn().Close()
			_ = tlsConn.Close()
			return nil, ErrEncryptedClosed
		}
		transferred = true
		h.endpoint.tlsConns[owned] = struct{}{}
		h.endpoint.connMu.Unlock()
		return owned, nil
	}
	return nil, lastErr
}

func (h *encryptedHTTP) exchange(ctx context.Context, query *dns.Msg, wire []byte) (*dns.Msg, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, h.endpoint.config.Address, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/dns-message")
	request.Header.Set("Content-Type", "application/dns-message")
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("User-Agent", "")
	response, err := h.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	expectedProtocol := 2
	if h.h3 != nil {
		expectedProtocol = 3
	}
	if response.ProtoMajor != expectedProtocol || response.TLS == nil || response.TLS.Version < tls.VersionTLS13 || len(response.TLS.VerifiedChains) == 0 {
		return nil, fmt.Errorf("%w: unexpected HTTPS transport", ErrEncryptedResponse)
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: endpoint did not return HTTP 200", ErrEncryptedResponse)
	}
	mediaType, params, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/dns-message" || len(params) != 0 {
		return nil, fmt.Errorf("%w: endpoint did not return a DNS wire message", ErrEncryptedResponse)
	}
	if encoding := response.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
		return nil, fmt.Errorf("%w: compressed DNS bodies are not accepted", ErrEncryptedResponse)
	}
	if response.ContentLength > maxEncryptedMessageBytes {
		return nil, fmt.Errorf("%w: oversized DNS body", ErrEncryptedResponse)
	}
	// DNS wire responses are complete bodies. Trailers add no DNS semantics.
	// Reject them rather than relying on transport-specific truncation.
	if len(response.Trailer) != 0 || response.Header.Get("Trailer") != "" {
		return nil, fmt.Errorf("%w: DoH trailers are not accepted", ErrEncryptedResponse)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxEncryptedMessageBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxEncryptedMessageBytes {
		return nil, fmt.Errorf("%w: oversized DNS body", ErrEncryptedResponse)
	}
	if len(response.Trailer) != 0 {
		return nil, fmt.Errorf("%w: DoH trailers are not accepted", ErrEncryptedResponse)
	}
	return validateEncryptedReply(body, query)
}

func (h *encryptedHTTP) close() {
	if h.h3 != nil {
		_ = h.h3.Close()
	}
	if h.h2 != nil {
		h.h2.CloseIdleConnections()
	}
}
