package observe_test

import (
	"context"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/observe"
)

func TestEncryptedLearnRetainsTransportProvenanceAndMaterialCost(t *testing.T) {
	r := &fakeResolver{out: observe.Outcome{
		Result:  dnssec.ValidationResult{Status: dnssec.StatusSecure, Reason: dnssec.ReasonVerified},
		Queries: 7, Lookups: 6,
	}}
	sink := &collector{}
	o := observe.NewEncrypted(r, sink, observe.Options{Workers: 1, Queue: 4, Timeout: time.Second, Log: quietLog()})
	ctx, cancel := context.WithCancel(context.Background())
	go o.Run(ctx)
	t.Cleanup(func() { cancel(); o.Wait() })
	if !o.Observe(request("www.example.com.")) {
		t.Fatal("observation was not admitted")
	}
	if !waitFor(t, 5*time.Second, func() bool { return len(sink.all()) == 1 }) {
		t.Fatal("observation was not recorded")
	}
	got := sink.all()[0]
	if got.Resolution != observe.ResolutionEncrypted || got.Queries != 7 || got.Delegations != 0 || got.Lookups != 6 {
		t.Fatalf("incorrect encrypted provenance: %+v", got)
	}
	if s := o.Stats(); s.Resolution != observe.ResolutionEncrypted || s.Queries != 7 || s.Delegations != 0 {
		t.Fatalf("incorrect encrypted aggregate provenance: %+v", s)
	}
}
