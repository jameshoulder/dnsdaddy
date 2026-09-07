//go:build cgo && daddybound_unbound

package refunbound

/*
#cgo LDFLAGS: -lunbound
#include <stdlib.h>
#include <unbound.h>
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/differential"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
)

// Available reports whether this build includes the libunbound oracle.
func Available() bool { return true }

// Why is empty in this build; the oracle is present.
func Why() string { return "" }

// Config is the oracle's settings.
type Config struct {
	// Forward is the host:port of the authoritative server holding the
	// hierarchy under test.
	Forward string
	// TrustAnchor is a DS record in presentation form.
	TrustAnchor string
}

// oracle wraps a libunbound context.
//
// libunbound's ub_resolve is synchronous and its context is not documented as
// safe for concurrent use, so a mutex serialises calls. The alternative,
// ub_resolve_async with ub_process, buys nothing here: the comparison runs one
// scenario at a time by design, because a report that interleaved scenarios
// would be harder to attribute when something disagreed.
type oracle struct {
	mu  sync.Mutex
	ctx *C.struct_ub_ctx
}

// New builds a libunbound context pointed at one lab hierarchy.
func New(cfg Config) (differential.Reference, error) {
	if cfg.Forward == "" {
		return nil, errors.New("refunbound: no forwarder address")
	}
	if cfg.TrustAnchor == "" {
		// Refused rather than defaulted. libunbound with no anchor validates
		// nothing and reports every answer as neither secure nor bogus,
		// which would silently turn the whole differential suite into a
		// comparison against a validator that was not validating.
		return nil, errors.New("refunbound: no trust anchor")
	}

	ctx := C.ub_ctx_create()
	if ctx == nil {
		return nil, errors.New("refunbound: ub_ctx_create returned nil")
	}
	o := &oracle{ctx: ctx}

	// Options are set before the anchor and the forwarder, because
	// libunbound applies some settings only until the context is first used.
	//
	// Each of these makes the oracle's behaviour a property of the zone
	// under test rather than of unbound's operational defaults. Without
	// them the comparison measures unbound's caching and hardening policy
	// instead of its validation logic.
	for _, opt := range [][2]string{
		// The lab server is on loopback. Unbound refuses to query it by
		// default, and the refusal presents as an unresolvable name rather
		// than as a configuration problem.
		{"do-not-query-localhost:", "no"},
		// Permissive mode reports bogus answers as insecure. That would
		// erase exactly the verdicts this comparison depends on.
		{"val-permissive-mode:", "no"},
		// QNAME minimisation changes which questions reach the lab server.
		// The lab answers them all, but keeping it off means the queries in
		// a packet capture match the scenario being run.
		{"qname-minimisation:", "no"},
		// A stripped DNSSEC response must be a failure, not a downgrade to
		// insecure.
		{"harden-dnssec-stripped:", "yes"},
		// 0x20 case randomisation is off for determinism. The lab server
		// handles case-insensitive queries — an earlier harness did not, and
		// the resulting NXDOMAINs looked like a validation bug — and that
		// behaviour is asserted directly by a test rather than left to
		// whether this option happens to be on.
		{"use-caps-for-id:", "no"},
	} {
		if err := o.setOption(opt[0], opt[1]); err != nil {
			o.Close()
			return nil, err
		}
	}

	anchor := C.CString(cfg.TrustAnchor)
	defer C.free(unsafe.Pointer(anchor))
	if rc := C.ub_ctx_add_ta(o.ctx, anchor); rc != 0 {
		defer o.Close()
		return nil, fmt.Errorf("refunbound: ub_ctx_add_ta(%q): %s", cfg.TrustAnchor, ubError(rc))
	}

	// libunbound wants host@port.
	fwd := C.CString(atPort(cfg.Forward))
	defer C.free(unsafe.Pointer(fwd))
	if rc := C.ub_ctx_set_fwd(o.ctx, fwd); rc != 0 {
		defer o.Close()
		return nil, fmt.Errorf("refunbound: ub_ctx_set_fwd(%q): %s", cfg.Forward, ubError(rc))
	}

	return o, nil
}

func (o *oracle) setOption(name, value string) error {
	cName := C.CString(name)
	cValue := C.CString(value)
	defer C.free(unsafe.Pointer(cName))
	defer C.free(unsafe.Pointer(cValue))
	if rc := C.ub_ctx_set_option(o.ctx, cName, cValue); rc != 0 {
		return fmt.Errorf("refunbound: ub_ctx_set_option(%s %s): %s", name, value, ubError(rc))
	}
	return nil
}

// Name identifies the oracle, with its version, so a report can be
// reproduced.
func (o *oracle) Name() string {
	return "libunbound " + C.GoString(C.ub_version())
}

// Validate asks libunbound for its verdict.
func (o *oracle) Validate(ctx context.Context, qname string, qtype uint16) (differential.ReferenceResult, error) {
	type outcome struct {
		res differential.ReferenceResult
		err error
	}
	done := make(chan outcome, 1)

	go func() {
		o.mu.Lock()
		defer o.mu.Unlock()
		res, err := o.resolve(qname, qtype)
		done <- outcome{res, err}
	}()

	select {
	case out := <-done:
		return out.res, out.err
	case <-ctx.Done():
		// ub_resolve is a blocking C call and cannot be interrupted, so the
		// goroutine is left to finish and its result discarded. The channel
		// is buffered so it cannot block forever on a receiver that has
		// already given up. This is acceptable in a test oracle and would
		// not be in production code, which is one more reason this adapter
		// is behind a build tag.
		return differential.ReferenceResult{}, ctx.Err()
	}
}

func (o *oracle) resolve(qname string, qtype uint16) (differential.ReferenceResult, error) {
	cName := C.CString(qname)
	defer C.free(unsafe.Pointer(cName))

	var result *C.struct_ub_result
	rc := C.ub_resolve(o.ctx, cName, C.int(qtype), C.int(1 /* IN */), &result)
	if rc != 0 {
		return differential.ReferenceResult{}, fmt.Errorf("refunbound: ub_resolve(%s): %s", qname, ubError(rc))
	}
	if result == nil {
		return differential.ReferenceResult{}, fmt.Errorf("refunbound: ub_resolve(%s) returned no result", qname)
	}
	defer C.ub_resolve_free(result)

	out := differential.ReferenceResult{}
	switch {
	case result.bogus != 0:
		out.Status = dnssec.StatusBogus
		out.Detail = C.GoString(result.why_bogus)
	case result.secure != 0:
		out.Status = dnssec.StatusSecure
	default:
		// Neither flag set. libunbound does not distinguish RFC 4033's
		// Insecure from its Indeterminate here, so the status is recorded as
		// the more specific of the two and Unresolved says the oracle did
		// not actually choose between them.
		out.Status = dnssec.StatusInsecure
		out.Unresolved = true
	}

	if result.havedata == 0 && out.Status != dnssec.StatusBogus {
		out.Detail = appendDetail(out.Detail, fmt.Sprintf("no data (rcode %d)", int(result.rcode)))
	}
	return out, nil
}

// Close releases the libunbound context.
func (o *oracle) Close() {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.ctx != nil {
		C.ub_ctx_delete(o.ctx)
		o.ctx = nil
	}
}

func ubError(rc C.int) string { return C.GoString(C.ub_strerror(rc)) }

// atPort converts host:port to the host@port spelling libunbound expects.
func atPort(addr string) string {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i] + "@" + addr[i+1:]
		}
	}
	return addr
}

func appendDetail(existing, extra string) string {
	if existing == "" {
		return extra
	}
	return existing + "; " + extra
}
