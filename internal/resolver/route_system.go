package resolver

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	maxSystemDNSBridges = 64
	maxSystemDNSMessage = 65535
	maxSystemDNSTimeout = 30 * time.Second
)

var errSystemDNSBusy = errors.New("process DNS concurrency limit reached")

// NewSystemResolver routes process-owned hostname lookups through the same
// selection as client DNS. PreferGo prevents libc from bypassing Dial. The
// hook never resolves an encrypted endpoint's hostname: that bundle already
// owns literal bootstrap addresses and verified TLS server names.
//
// Each Dial returns a one-question, length-prefixed in-memory stream. Go's
// resolver uses stream framing whenever Dial returns a non-net.PacketConn,
// even when the requested network was UDP. A bounded worker exchanges that
// question using the selected encrypted bundle, or the supplied literal OS
// nameserver only while the captured route explicitly allows native DNS.
//
// The returned resolver can be installed once as net.DefaultResolver before
// any network workers or listeners start. It does not reconfigure the host OS.
func NewSystemResolver(provider func() *ForwardRoute, timeout time.Duration) *net.Resolver {
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	if timeout > maxSystemDNSTimeout {
		timeout = maxSystemDNSTimeout
	}
	b := &systemDNSBridge{provider: provider, timeout: timeout, slots: make(chan struct{}, maxSystemDNSBridges)}
	return &net.Resolver{PreferGo: true, StrictErrors: true, Dial: b.dial}
}

type systemDNSBridge struct {
	provider func() *ForwardRoute
	timeout  time.Duration
	slots    chan struct{}
}

func (b *systemDNSBridge) dial(parent context.Context, network, address string) (net.Conn, error) {
	if network != "udp" && network != "tcp" {
		return nil, errors.New("unsupported process DNS transport")
	}
	route, err := selectedForwardRoute(b.provider)
	if err != nil {
		return nil, err
	}
	ctx, routeDone, err := route.Begin(parent)
	if err != nil {
		return nil, err
	}
	if route.Encrypted() == nil {
		// net.Resolver supplies an IP from resolv.conf. Refuse a hostname here
		// rather than recursively invoking this same resolver to find it.
		server, parseErr := netip.ParseAddrPort(address)
		if parseErr != nil || !server.Addr().IsValid() || server.Port() == 0 {
			routeDone()
			return nil, errors.New("operating-system DNS server must be a literal IP address and port")
		}
	}
	select {
	case b.slots <- struct{}{}:
	case <-ctx.Done():
		routeDone()
		return nil, forwardContextError(ctx)
	default:
		routeDone()
		return nil, errSystemDNSBusy
	}
	ctx, cancel := context.WithTimeout(ctx, b.timeout)
	client, server := net.Pipe()
	// Retirement closes both ends even when the caller never sends a frame
	// or abandons a response. No bridge can hold route.Close indefinitely.
	stop := context.AfterFunc(ctx, func() {
		_ = client.Close()
		_ = server.Close()
	})
	go func() {
		defer func() {
			stop()
			cancel()
			_ = server.Close()
			<-b.slots
			routeDone()
		}()
		if deadline, ok := ctx.Deadline(); ok {
			_ = server.SetDeadline(deadline)
		}
		b.exchange(ctx, server, route, network, address)
	}()
	return &systemDNSConn{Conn: client, cancel: cancel}, nil
}

// systemDNSConn deliberately does not implement net.PacketConn. Close also
// cancels a response already in flight, rather than leaving a detached worker
// to run until its maximum timeout.
type systemDNSConn struct {
	net.Conn
	cancel context.CancelFunc
	once   sync.Once
}

func (c *systemDNSConn) Close() error {
	c.once.Do(c.cancel)
	return c.Conn.Close()
}

func (b *systemDNSBridge) exchange(ctx context.Context, conn net.Conn, route *ForwardRoute, network, address string) {
	var size [2]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		return
	}
	n := int(binary.BigEndian.Uint16(size[:]))
	if n < 12 || n > maxSystemDNSMessage {
		return
	}
	queryWire := make([]byte, n)
	if _, err := io.ReadFull(conn, queryWire); err != nil {
		return
	}
	query := new(dns.Msg)
	if err := query.Unpack(queryWire); err != nil || query.Response || query.Opcode != dns.OpcodeQuery || len(query.Question) != 1 {
		return
	}
	if forwardContextError(ctx) != nil {
		return
	}
	var (
		reply *dns.Msg
		err   error
	)
	if route.Encrypted() != nil {
		reply, _, err = route.exchangeEncrypted(ctx, query)
	} else {
		reply, err = exchangeSystemDNS(ctx, network, address, query, b.timeout)
	}
	if err != nil || forwardContextError(ctx) != nil || !systemDNSAnswerMatches(reply, query) {
		return
	}
	wire, err := reply.Pack()
	if err != nil {
		return
	}
	wireSize := len(wire)
	if wireSize < 12 || wireSize > maxSystemDNSMessage {
		return
	}
	binary.BigEndian.PutUint16(size[:], uint16(wireSize))
	if _, err := conn.Write(size[:]); err != nil {
		return
	}
	_, _ = conn.Write(wire)
}

func systemDNSAnswerMatches(reply, query *dns.Msg) bool {
	if reply == nil || !reply.Response || reply.Opcode != query.Opcode || reply.Id != query.Id || len(reply.Question) != 1 {
		return false
	}
	want, got := query.Question[0], reply.Question[0]
	return want.Qclass == got.Qclass && want.Qtype == got.Qtype && strings.EqualFold(want.Name, got.Name)
}

func exchangeSystemDNS(ctx context.Context, network, address string, query *dns.Msg, timeout time.Duration) (*dns.Msg, error) {
	// The address was checked before admission. The explicit connection lets
	// route retirement interrupt a UDP read, not just wait for its deadline.
	client := &dns.Client{Net: network, Timeout: timeout}
	return exchangeDNSContext(ctx, client, query, address)
}
