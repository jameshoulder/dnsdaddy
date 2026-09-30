package resolver

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

const doqProtocolError quic.ApplicationErrorCode = 2
const doqRequestCanceled quic.StreamErrorCode = 3

func encryptedQUICConfig(http3 bool) *quic.Config {
	uni := int64(-1)
	if http3 {
		// HTTP/3 needs its control stream and two QPACK streams. DoQ has no
		// server-initiated streams of either direction.
		uni = 3
	}
	return &quic.Config{
		HandshakeIdleTimeout:           2 * time.Second,
		MaxIdleTimeout:                 30 * time.Second,
		MaxIncomingStreams:             -1,
		MaxIncomingUniStreams:          uni,
		InitialStreamReceiveWindow:     128 << 10,
		MaxStreamReceiveWindow:         128 << 10,
		InitialConnectionReceiveWindow: 1 << 20,
		MaxConnectionReceiveWindow:     1 << 20,
	}
}

func (ep *encryptedEndpoint) dialQUIC(ctx context.Context, tlsConfig *tls.Config, config *quic.Config) (*quic.Conn, error) {
	var lastErr error
	for i, target := range ep.targets {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		attemptCtx, cancel := encryptedAttemptContext(ctx, len(ep.targets)-i)
		// Targets are validated IP literals. DialAddr therefore cannot invoke
		// plaintext hostname resolution. DialAddrEarly is deliberately unused:
		// Config.Allow0RTT only governs servers, not client early data.
		conn, err := quic.DialAddr(attemptCtx, target, tlsConfig.Clone(), config.Clone())
		cancel()
		if err != nil {
			ep.recordDial(nil, "", err)
			lastErr = err
			continue
		}
		state := conn.ConnectionState()
		if !state.TLS.HandshakeComplete || state.TLS.Version < tls.VersionTLS13 || len(state.TLS.VerifiedChains) == 0 || state.Used0RTT || len(tlsConfig.NextProtos) != 1 || state.TLS.NegotiatedProtocol != tlsConfig.NextProtos[0] {
			_ = conn.CloseWithError(doqProtocolError, "")
			lastErr = errors.New("encrypted peer did not complete authenticated TLS 1.3")
			ep.recordDial(nil, "", lastErr)
			continue
		}
		ep.recordDial(&state.TLS, conn.RemoteAddr().String(), nil)
		return conn, nil
	}
	return nil, lastErr
}

func (ep *encryptedEndpoint) quicConn(ctx context.Context) (*quic.Conn, error) {
	for {
		ep.connMu.Lock()
		if ep.closed {
			ep.connMu.Unlock()
			return nil, ErrEncryptedClosed
		}
		if ep.conn != nil && ep.conn.Context().Err() == nil {
			conn := ep.conn
			ep.connMu.Unlock()
			return conn, nil
		}
		if pending := ep.dialing; pending != nil {
			ep.connMu.Unlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-pending.done:
				if pending.err != nil {
					return nil, pending.err
				}
				continue
			}
		}
		pending := &encryptedDial{done: make(chan struct{})}
		ep.dialing = pending
		ep.connMu.Unlock()
		tlsConfig := ep.tlsConfig.Clone()
		alpn := "doq"
		isHTTP3 := ep.config.Protocol == "doh3"
		if isHTTP3 {
			alpn = "h3"
		}
		tlsConfig.NextProtos = []string{alpn}
		conn, err := ep.dialQUIC(ctx, tlsConfig, encryptedQUICConfig(isHTTP3))
		ep.connMu.Lock()
		var lateConn *quic.Conn
		if ep.closed && err == nil {
			lateConn = conn
			conn, err = nil, ErrEncryptedClosed
		}
		if err == nil {
			ep.conn = conn
			if isHTTP3 {
				ep.http.connection = ep.http.h3.NewClientConn(conn)
			}
		}
		pending.err = err
		ep.dialing = nil
		close(pending.done)
		ep.connMu.Unlock()
		if lateConn != nil {
			_ = lateConn.CloseWithError(0, "")
		}
		return conn, err
	}
}

func (ep *encryptedEndpoint) exchangeDoQ(ctx context.Context, query *dns.Msg, wire []byte) (*dns.Msg, error) {
	conn, err := ep.quicConn(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = stream.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() {
		stream.CancelRead(doqRequestCanceled)
		stream.CancelWrite(doqRequestCanceled)
	})
	defer stop()
	defer stream.CancelRead(doqRequestCanceled)
	defer stream.CancelWrite(doqRequestCanceled)
	// len(wire) is checked before narrowing to the two-byte DNS frame length.
	wireSize := len(wire)
	if wireSize < 12 || wireSize > maxEncryptedMessageBytes {
		return nil, ErrEncryptedResponse
	}
	framed := make([]byte, wireSize+2)
	binary.BigEndian.PutUint16(framed, uint16(wireSize))
	copy(framed[2:], wire)
	if written, err := stream.Write(framed); err != nil {
		return nil, err
	} else if written != len(framed) {
		return nil, io.ErrShortWrite
	}
	if err := stream.Close(); err != nil {
		return nil, err
	} // FIN is part of the DoQ request.
	var prefix [2]byte
	if _, err := io.ReadFull(stream, prefix[:]); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint16(prefix[:]))
	if size < 12 {
		_ = conn.CloseWithError(doqProtocolError, "")
		return nil, fmt.Errorf("%w: invalid DoQ frame size", ErrEncryptedResponse)
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(stream, body); err != nil {
		return nil, err
	}
	var extra [1]byte
	n, err := stream.Read(extra[:])
	if n != 0 || err != io.EOF {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		_ = conn.CloseWithError(doqProtocolError, "")
		return nil, fmt.Errorf("%w: DoQ requires exactly one response followed by FIN", ErrEncryptedResponse)
	}
	response, err := validateEncryptedReply(body, query)
	if err != nil {
		_ = conn.CloseWithError(doqProtocolError, "")
	}
	return response, err
}
