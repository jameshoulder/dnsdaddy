package dnsserver

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/config"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// freePort returns a port nothing is listening on. There is an unavoidable gap
// between closing the probe and the server binding. Within one test binary that
// gap is uncontended, but `go test ./...` runs a binary per package in
// parallel, so a sibling package's harness can take the port in between. A
// caller that would misread the theft as a product failure has to say so
// itself — see TestStartReleasesBoundListenersWhenAnotherFailsToBind.
func freePort(t *testing.T) string {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	if err := pc.Close(); err != nil {
		t.Fatalf("probe close: %v", err)
	}
	return "127.0.0.1:" + strconv.Itoa(port)
}

// The shutdown path is reached precisely because the parent context was
// cancelled. If shutdown inherited that cancellation it would be born dead:
// ShutdownContext would return the moment it was called and in-flight queries
// would be dropped rather than drained. This is the property that makes the
// difference between a graceful stop and a hard one, and nothing else in the
// tree would notice if it regressed.
func TestShutdownContextSurvivesCancelledParent(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	cancelParent()

	ctx, cancel := shutdownContext(parent)
	defer cancel()

	select {
	case <-ctx.Done():
		t.Fatal("shutdown context is already cancelled; it inherited the parent's cancellation")
	default:
	}

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("shutdown context has no deadline; shutdown is unbounded")
	}
	if d := time.Until(deadline); d <= 0 || d > shutdownTimeout {
		t.Errorf("deadline is %v away, want a positive value no larger than %v", d, shutdownTimeout)
	}
}

// The cancel function is the reason detachedContext and shutdownContext return
// two values rather than one: dropping it leaves the timer armed until the
// full timeout elapses, whatever the work actually did.
func TestShutdownContextCancelReleasesTheContext(t *testing.T) {
	ctx, cancel := shutdownContext(context.Background())
	cancel()

	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("cancel did not release the shutdown context")
	}
	if err := ctx.Err(); err != context.Canceled {
		t.Errorf("Err = %v, want %v", err, context.Canceled)
	}
}

// A context passed to Start must actually stop the listeners. This is what the
// process relies on to release its ports on SIGTERM, and it exercises the
// shutdown goroutine end to end rather than just the context it builds.
func TestStartStopsListenersWhenContextIsCancelled(t *testing.T) {
	h := newHarnessWithOptions(t, nil)
	addr := freePort(t)

	srv, err := NewServer(config.DNS{ListenUDP: addr, ListenTCP: addr}, h.handler, discardLogger())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	c := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	if _, _, err := c.Exchange(query("example.com", dns.TypeA), addr); err != nil {
		t.Fatalf("the listener did not answer before shutdown: %v", err)
	}

	cancel()

	// Shutdown runs in a goroutine, so poll for the port coming free rather
	// than assuming it has happened by the time cancel returns.
	deadline := time.Now().Add(10 * time.Second)
	for {
		pc, err := net.ListenPacket("udp", addr)
		if err == nil {
			if err := pc.Close(); err != nil {
				t.Fatalf("close rebound listener: %v", err)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the UDP port was still bound %v after the context was cancelled: %v", 10*time.Second, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A bind failure has to unwind the listeners that did come up, or a failed
// start leaves ports held by a process that is about to report an error and
// carry on.
// The listeners bind concurrently, so which one reports first is a race and a
// single run proves very little: the version of this test that polled the port
// the instant Start returned passed against a Start with the unwind deleted
// outright, because it re-bound the port before the surviving listener had got
// to it. Settle first, then ask the listener itself, and run it enough times to
// exercise both orderings.
func TestStartReleasesBoundListenersWhenAnotherFailsToBind(t *testing.T) {
	const runs = 20

	conclusive := 0
	for i := 0; i < runs; i++ {
		if startUnwindAttempt(t, i) {
			conclusive++
		}
	}
	// Every run being inconclusive would make the test vacuous by another
	// route, so say so rather than reporting green.
	if conclusive == 0 {
		t.Fatalf("all %d runs were inconclusive; the unwind path was never exercised", runs)
	}
}

// startUnwindAttempt runs the scenario once and reports whether it exercised
// the unwind path. A false return means the port was taken from under us, not
// that the product misbehaved — freePort closes its probe before returning, so
// anything else on the machine may claim the port in between, and reporting
// that theft as a DNS Daddy failure would be a different bug entirely.
// Anything that is a real failure is reported through t directly, so the
// caller's tolerance of inconclusive runs can never mask one.
func startUnwindAttempt(t *testing.T, run int) bool {
	t.Helper()

	good := freePort(t)

	// Occupy a port so the TCP listener cannot have it.
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy port: %v", err)
	}
	defer taken.Close()

	h := newHarnessWithOptions(t, nil)

	srv, err := NewServer(config.DNS{ListenUDP: good, ListenTCP: taken.Addr().String()}, h.handler, discardLogger())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	startErr := srv.Start(context.Background())
	if startErr == nil {
		t.Fatalf("run %d: Start returned nil despite an unbindable listener", run)
	}
	// Start labels the failure with the listener it belongs to. If it names the
	// UDP address, that listener never bound and there was nothing to unwind.
	if strings.Contains(startErr.Error(), "udp "+good) {
		return false
	}

	// Give a listener that Start might have abandoned mid-bind time to finish
	// binding. The point of the fix is that there is no such listener; without
	// the wait, a leak simply arrives after the assertion.
	time.Sleep(250 * time.Millisecond)

	// Ask the listener rather than the port. A closed socket answers nothing,
	// and an answer here means DNS Daddy is serving queries on a port it has
	// just told the caller it could not open.
	c := &dns.Client{Net: "udp", Timeout: time.Second}
	if _, _, err := c.Exchange(query("example.com", dns.TypeA), good); err == nil {
		t.Fatalf("run %d: %s is still answering queries after Start reported %v", run, good, startErr)
	}

	pc, err := net.ListenPacket("udp", good)
	if err != nil {
		t.Fatalf("run %d: the UDP port stayed bound after a failed Start: %v", run, err)
	}
	if err := pc.Close(); err != nil {
		t.Fatalf("run %d: close rebound listener: %v", run, err)
	}
	return true
}
