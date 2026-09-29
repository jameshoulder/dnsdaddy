package native

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/recursive"
)

// ClientEngine is the native answer path, never a forwarded answer followed
// by a separate validation. Engine implements it; the seam also permits
// deterministic tests of timeouts, overload and protocol flags.
type ClientEngine interface {
	Resolve(context.Context, string, uint16) (*Answer, error)
	ResolveUnchecked(context.Context, string, uint16) (*Answer, error)
}

type ClientOptions struct {
	Timeout     time.Duration
	MaxInflight int
}

// ClientResult records the distinction between a DNSSEC verdict and an
// operational inability to resolve. Msg is always the complete response to
// send, including SERVFAIL and an Extended DNS Error for EDNS clients.
type ClientResult struct {
	Msg              *dns.Msg
	Validation       dnssec.ValidationResult
	ValidationStatus string
	ReasonCode       string
	Reason           string
	Enforced         bool
	CheckingDisabled bool
	Cached           bool
	MinTTL           uint32
}

// ClientStats contain no names or client addresses and remain available when
// query logging is disabled. Counts distinguish rejected validation from an
// outage, exhausted capacity and an explicit client CD request.
type ClientStats struct {
	Queries            uint64 `json:"queries"`
	Secure             uint64 `json:"secure"`
	Insecure           uint64 `json:"insecure"`
	Bogus              uint64 `json:"bogus"`
	Indeterminate      uint64 `json:"indeterminate"`
	CheckingDisabled   uint64 `json:"checkingDisabled"`
	ResolutionFailures uint64 `json:"resolutionFailures"`
	LimitRejected      uint64 `json:"limitRejected"`
	Panics             uint64 `json:"panics"`
	Inflight           int64  `json:"inflight"`
	InflightPeak       int64  `json:"inflightPeak"`
	MaxInflight        int    `json:"maxInflight"`
}

// Client is the enforcing native DNS wire adapter. It has no upstream
// fallback and no answer/verdict cache; the native material cache is always
// revalidated with the current clock and trust anchors for a CD=0 query.
type Client struct {
	engine                                            ClientEngine
	timeout                                           time.Duration
	sem                                               chan struct{}
	queries, secure, insecure, bogus, indeterminate   atomic.Uint64
	checkingDisabled, failures, limitRejected, panics atomic.Uint64
	inflight, peak                                    atomic.Int64
}

func NewClient(engine ClientEngine, opt ClientOptions) (*Client, error) {
	if engine == nil {
		return nil, errors.New("native: a client engine is required")
	}
	if opt.Timeout <= 0 {
		opt.Timeout = 5 * time.Second
	}
	if opt.MaxInflight <= 0 {
		opt.MaxInflight = 128
	}
	if opt.MaxInflight > 4096 || opt.Timeout > time.Minute {
		return nil, errors.New("native: client bounds exceed 4096 in-flight resolutions or one minute")
	}
	return &Client{engine: engine, timeout: opt.Timeout, sem: make(chan struct{}, opt.MaxInflight)}, nil
}

// ResolveClient applies RFC 4035 sections 3.2.1-3.2.3 and RFC 6840 section
// 5.8. CD disables DNSSEC enforcement only; callers must have already applied
// access control and policy, and must still apply rebinding protection.
func (c *Client) ResolveClient(ctx context.Context, req *dns.Msg) (result ClientResult) {
	c.queries.Add(1)
	defer func() {
		if recover() != nil {
			c.panics.Add(1)
			c.failures.Add(1)
			result = clientFailure(req, "internal_error", "native_internal_error", "Native resolver failed internally", dns.ExtendedErrorCodeOther)
		}
	}()
	if req == nil || len(req.Question) != 1 || req.Response {
		return protocolFailure(req, dns.RcodeFormatError, "invalid_question", "Exactly one DNS question is required")
	}
	q := req.Question[0]
	if req.Opcode != dns.OpcodeQuery || q.Qclass != dns.ClassINET {
		return protocolFailure(req, dns.RcodeNotImplemented, "unsupported_question", "Native resolution supports standard IN questions")
	}
	if _, valid := dns.IsDomainName(q.Name); !valid {
		return protocolFailure(req, dns.RcodeFormatError, "invalid_name", "The question name is invalid")
	}
	if opt := req.IsEdns0(); opt != nil && opt.Version() != 0 {
		return protocolFailure(req, dns.RcodeBadVers, "unsupported_edns_version", "Only EDNS version 0 is supported")
	}
	if !req.RecursionDesired {
		return protocolFailure(req, dns.RcodeRefused, "recursion_required", "Set RD to request native recursion")
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	select {
	case <-ctx.Done():
		c.failures.Add(1)
		return clientFailure(req, "timeout", "native_deadline", "Native resolution deadline expired", dns.ExtendedErrorCodeNetworkError)
	case c.sem <- struct{}{}:
		current := c.inflight.Add(1)
		for peak := c.peak.Load(); current > peak; peak = c.peak.Load() {
			if c.peak.CompareAndSwap(peak, current) {
				break
			}
		}
		defer func() { c.inflight.Add(-1); <-c.sem }()
	default:
		c.limitRejected.Add(1)
		return clientFailure(req, "resource_limit", "native_capacity", "Native resolver is at its in-flight limit", dns.ExtendedErrorCodeNotReady)
	}
	var answer *Answer
	var err error
	if req.CheckingDisabled {
		answer, err = c.engine.ResolveUnchecked(ctx, q.Name, q.Qtype)
	} else {
		answer, err = c.engine.Resolve(ctx, q.Name, q.Qtype)
	}
	if err != nil {
		c.failures.Add(1)
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			return clientFailure(req, "timeout", "native_deadline", "Native resolution deadline expired", dns.ExtendedErrorCodeNetworkError)
		case errors.Is(err, recursive.ErrLimit):
			c.limitRejected.Add(1)
			return clientFailure(req, "resource_limit", "native_work_limit", "Native resolution reached its work limit", dns.ExtendedErrorCodeNotReady)
		default:
			return clientFailure(req, "unreachable", "native_resolution_failed", "No complete authoritative answer was obtained", dns.ExtendedErrorCodeNoReachableAuthority)
		}
	}
	if answer == nil || answer.Msg == nil || answer.Msg.Truncated {
		c.failures.Add(1)
		return clientFailure(req, "internal_error", "native_incomplete_answer", "Native resolution returned no complete answer", dns.ExtendedErrorCodeOther)
	}
	if ctx.Err() != nil {
		c.failures.Add(1)
		return clientFailure(req, "timeout", "native_deadline", "Native resolution deadline expired", dns.ExtendedErrorCodeNetworkError)
	}
	result = ClientResult{
		Validation:       answer.Validation,
		ValidationStatus: answer.Validation.Status.String(),
		ReasonCode:       answer.Validation.Reason.String(),
		Reason:           answer.Validation.Reason.Explain(),
		Cached:           answer.Cached,
		CheckingDisabled: req.CheckingDisabled,
		Enforced:         !req.CheckingDisabled,
	}
	if req.CheckingDisabled {
		c.checkingDisabled.Add(1)
		result.ValidationStatus = "checking_disabled"
		result.ReasonCode = "client_checking_disabled"
		result.Reason = "The client disabled DNSSEC checking; native answer is not authenticated"
	} else {
		switch answer.Validation.Status {
		case dnssec.StatusSecure:
			c.secure.Add(1)
			result.Reason = "Native answer authenticated with DNSSEC"
		case dnssec.StatusInsecure:
			c.insecure.Add(1)
			result.Reason = "An unsigned delegation was proved; this native answer is not authenticated"
		case dnssec.StatusBogus:
			c.bogus.Add(1)
			failure := clientFailure(req, "bogus", result.ReasonCode, "DNSSEC validation failed: "+result.Reason, dns.ExtendedErrorCodeDNSBogus)
			failure.Validation = answer.Validation
			return failure
		default:
			c.indeterminate.Add(1)
			failure := clientFailure(req, "indeterminate", result.ReasonCode, "DNSSEC validation could not complete: "+result.Reason, dns.ExtendedErrorCodeDNSSECIndeterminate)
			failure.Validation = answer.Validation
			return failure
		}
	}
	result.Msg = clientMessage(req, answer.Msg, answer.Validation.Secure() && !req.CheckingDisabled)
	for i, rr := range result.Msg.Answer {
		if i == 0 || rr.Header().Ttl < result.MinTTL {
			result.MinTTL = rr.Header().Ttl
		}
	}
	return result
}

func clientMessage(req, answer *dns.Msg, secure bool) *dns.Msg {
	out := answer.Copy()
	out.Id = req.Id
	out.Response = true
	out.Opcode = dns.OpcodeQuery
	out.Question = append([]dns.Question(nil), req.Question...)
	out.Authoritative = false
	out.RecursionAvailable = true
	out.RecursionDesired = req.RecursionDesired
	out.CheckingDisabled = req.CheckingDisabled
	out.Zero = false
	out.AuthenticatedData = secure && (req.AuthenticatedData || clientDO(req))
	out.Compress = true
	out.Extra = nil // authoritative cookies, ECS and AD are never inherited
	if !clientDO(req) {
		strip := func(records []dns.RR) []dns.RR {
			kept := records[:0]
			for _, rr := range records {
				typ := rr.Header().Rrtype
				switch typ {
				case dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3, dns.TypeNSEC3PARAM, dns.TypeDS, dns.TypeDNSKEY:
					if typ != req.Question[0].Qtype {
						continue
					}
				}
				kept = append(kept, rr)
			}
			return kept
		}
		out.Answer, out.Ns = strip(out.Answer), strip(out.Ns)
	}
	if req.IsEdns0() != nil {
		out.SetEdns0(clientUDPSize(req), clientDO(req))
	}
	return out
}

func clientDO(req *dns.Msg) bool {
	return req != nil && req.IsEdns0() != nil && req.IsEdns0().Do()
}

func clientUDPSize(req *dns.Msg) uint16 {
	size := uint16(1232)
	if req != nil && req.IsEdns0() != nil {
		size = req.IsEdns0().UDPSize()
	}
	if size < 512 {
		return 512
	}
	if size > 4096 {
		return 4096
	}
	return size
}

func clientFailure(req *dns.Msg, status, code, reason string, ede uint16) ClientResult {
	out := new(dns.Msg)
	if req != nil {
		out.SetReply(req)
	}
	out.Rcode = dns.RcodeServerFailure
	out.RecursionAvailable = true
	out.AuthenticatedData = false
	if req != nil && req.IsEdns0() != nil {
		out.SetEdns0(clientUDPSize(req), clientDO(req))
		out.IsEdns0().Option = append(out.IsEdns0().Option, &dns.EDNS0_EDE{InfoCode: ede, ExtraText: code})
	}
	return ClientResult{Msg: out, ValidationStatus: status, ReasonCode: code, Reason: reason,
		Enforced: req != nil && !req.CheckingDisabled, CheckingDisabled: req != nil && req.CheckingDisabled}
}

func protocolFailure(req *dns.Msg, rcode int, code, reason string) ClientResult {
	out := clientFailure(req, "not_attempted", code, reason, dns.ExtendedErrorCodeNotSupported)
	out.Msg.Rcode = rcode
	out.Enforced = false
	return out
}

func (c *Client) Stats() ClientStats {
	return ClientStats{
		Queries: c.queries.Load(), Secure: c.secure.Load(), Insecure: c.insecure.Load(),
		Bogus: c.bogus.Load(), Indeterminate: c.indeterminate.Load(),
		CheckingDisabled: c.checkingDisabled.Load(), ResolutionFailures: c.failures.Load(),
		LimitRejected: c.limitRejected.Load(), Panics: c.panics.Load(),
		Inflight: c.inflight.Load(), InflightPeak: c.peak.Load(), MaxInflight: cap(c.sem),
	}
}

// ResolveUnchecked honours CD without using any forwarded or previously
// authenticated client answer. The native material path and response
// projection are shared, while signature checks are explicitly skipped.
func (e *Engine) ResolveUnchecked(ctx context.Context, name string, rrtype uint16) (*Answer, error) {
	started := time.Now()
	res, err := e.cfg.Resolver.Resolve(ctx, name, rrtype)
	if err != nil {
		return nil, err
	}
	msg, _, _, err := clientContent(res, name, rrtype)
	if err != nil {
		return nil, fmt.Errorf("native unchecked answer: %w", err)
	}
	return &Answer{Msg: msg, Zone: res.Zone, Delegations: res.Delegations, Trace: res.Trace,
		Queries: res.Queries, Cached: res.Queries == 0, ResolveElapsed: time.Since(started)}, nil
}
