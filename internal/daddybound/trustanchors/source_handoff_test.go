package trustanchors_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/trustanchors"
	"github.com/miekg/dns"
)

type handoffSource func(context.Context, string) ([]dns.RR, error)

func (s handoffSource) DNSKEY(ctx context.Context, zone string) ([]dns.RR, error) {
	return s(ctx, zone)
}

func TestSourceHandoffWaitsForRefreshAndPreservesPendingTrust(t *testing.T) {
	c := &clock{at: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)}
	z := newZone(t, ".", c.now)
	oldKey, successor := z.addKey(71), z.addKey(72)
	z.publish(oldKey)
	z.signWith(oldKey)
	m, _ := harness(t, z, c, oldKey)
	if got := m.Refresh(context.Background()); !got.OK {
		t.Fatal(got.Err)
	}
	c.add(24 * time.Hour)
	z.publish(oldKey, successor)
	if got := m.Refresh(context.Background()); !got.OK {
		t.Fatal(got.Err)
	}
	var pending trustanchors.ManagedKey
	for _, key := range m.TrustPoint().Keys {
		if key.KeyTag == successor {
			pending = key
		}
	}
	if pending.State != trustanchors.StateAddPend {
		t.Fatalf("successor not pending: %+v", pending)
	}

	entered, release := make(chan struct{}), make(chan struct{})
	m.SetSource(handoffSource(func(ctx context.Context, zone string) ([]dns.RR, error) {
		close(entered)
		<-release
		return z.DNSKEY(ctx, zone)
	}))
	refreshDone := make(chan trustanchors.RefreshResult, 1)
	go func() { refreshDone <- m.Refresh(context.Background()) }()
	<-entered
	var newCalls atomic.Int32
	attempted, switched := make(chan struct{}), make(chan struct{})
	go func() {
		close(attempted)
		m.SetSource(handoffSource(func(ctx context.Context, zone string) ([]dns.RR, error) {
			newCalls.Add(1)
			return z.DNSKEY(ctx, zone)
		}))
		close(switched)
	}()
	<-attempted
	select {
	case <-switched:
		close(release)
		t.Fatal("source changed while the previous refresh owned the trust point")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if got := <-refreshDone; !got.OK {
		t.Fatal(got.Err)
	}
	select {
	case <-switched:
	case <-time.After(time.Second):
		t.Fatal("source handoff did not complete")
	}
	if got := m.Refresh(context.Background()); !got.OK {
		t.Fatal(got.Err)
	}
	if newCalls.Load() != 1 {
		t.Fatalf("new source called %d times", newCalls.Load())
	}
	retained := false
	for _, key := range m.TrustPoint().Keys {
		if key.KeyTag != successor {
			continue
		}
		retained = true
		if !key.FirstSeen.Equal(pending.FirstSeen) || !key.AddHoldDownUntil.Equal(pending.AddHoldDownUntil) || key.State != pending.State {
			t.Fatalf("transport change reset or promoted pending trust: before=%+v after=%+v", pending, key)
		}
	}
	if !retained {
		t.Fatal("transport source handoff lost the pending successor")
	}
	if !trusts(t, m, z, oldKey) || trusts(t, m, z, successor) {
		t.Fatal("transport source changed the trust decision")
	}
}
