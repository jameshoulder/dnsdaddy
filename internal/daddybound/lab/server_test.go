package lab_test

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/lab"
)

// The lab server must return an address on which UDP and TCP are both
// genuinely serving.
//
// UDP and TCP have independent port spaces, so asking the kernel for an
// ephemeral port on one says nothing about whether that number is free on the
// other. StartServer originally bound UDP and then reused its number for TCP,
// which is a race against every other process on the machine; it lost on a CI
// runner under -race and surfaced as "serve: bind: address already in use"
// inside a differential scenario — a harness bug wearing a scenario's clothes,
// which is the most expensive shape one can take.
//
// What this test pins is the property, not the retry: the returned address
// must answer real DNS on both protocols. A retry loop that gave up half
// bound, or returned the address of a socket it had closed, fails here. The
// collision itself cannot be forced from outside — the kernel chooses the
// port — so this squats a spread of UDP ports to make one possible rather than
// claiming to compel it, and repeats enough times to be worth running.
func TestTheLabServerAnswersOnBothProtocols(t *testing.T) {
	h, err := lab.Standard()
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	// Held for the duration: a UDP port taken here is one whose TCP
	// counterpart is free, which is exactly the shape that defeated the
	// original code.
	var squatters []net.PacketConn
	for i := 0; i < 128; i++ {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			break
		}
		squatters = append(squatters, pc)
	}
	defer func() {
		for _, pc := range squatters {
			_ = pc.Close()
		}
	}()

	for i := 0; i < 24; i++ {
		srv, err := h.StartServer()
		if err != nil {
			t.Fatalf("start %d: %v", i, err)
		}
		addr := srv.Addr()
		if !strings.HasPrefix(addr, "127.0.0.1:") {
			_ = srv.Close()
			t.Fatalf("addr = %q, want a loopback address", addr)
		}

		// A real query on each protocol. net.Dial on UDP is connectionless
		// and succeeds against nothing at all, so dialling would prove
		// nothing; an answer proves the handler is attached.
		for _, network := range []string{"udp", "tcp"} {
			m := new(dns.Msg)
			m.SetQuestion(lab.AnswerName, dns.TypeA)
			m.SetEdns0(4096, true)

			c := &dns.Client{Net: network, Timeout: 5 * time.Second}
			resp, _, err := c.Exchange(m, addr)
			if err != nil {
				_ = srv.Close()
				t.Fatalf("%s query to %s: %v", network, addr, err)
			}
			if len(resp.Answer) == 0 {
				_ = srv.Close()
				t.Fatalf("%s query to %s returned no answer", network, addr)
			}
		}
		if err := srv.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
	}
}
