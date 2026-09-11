package api

import (
	"net/http"

	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/resolution"
	"github.com/jameshoulder/dnsdaddy/internal/resolver"
	"github.com/jameshoulder/dnsdaddy/internal/resolveraddr"
)

// ResolverStatus is the answer to the four questions an operator actually has:
// am I protected, what address do I configure, what is resolving my DNS, and is
// DNSSEC being checked.
//
// One endpoint rather than four, because the dashboard shows them together and
// a page that assembled this from four requests would show three of them and a
// spinner.
type ResolverStatus struct {
	// Protecting reports that the resolver is up and answering.
	Protecting bool `json:"protecting"`

	// Mode is "native" or "forward". Engine is the human name of what is
	// running: "Daddybound Native" or "External forwarder".
	Mode   string `json:"mode"`
	Engine string `json:"engine"`
	// EngineID is the machine-readable backend name, for anything that needs
	// to branch rather than display.
	EngineID string `json:"engineId"`

	// Addresses are what clients should be pointed at, best first.
	Addresses []resolveraddr.Address `json:"addresses"`
	// UDPPort and TCPPort are the ports the resolver listens on. Zero when
	// that transport is not enabled.
	UDPPort int `json:"udpPort"`
	TCPPort int `json:"tcpPort"`
	// DoTPort and DoHURL are the encrypted transports, empty when off.
	DoTPort int    `json:"dotPort,omitempty"`
	DoHURL  string `json:"dohUrl,omitempty"`

	// DNSSEC says what is actually happening to DNSSEC, in one word an
	// operator can act on. See dnssecPosture.
	DNSSEC string `json:"dnssec"`
	// DNSSECDetail is the sentence behind that word.
	DNSSECDetail string `json:"dnssecDetail"`

	// Health is the resolver's own rolling picture. Every figure covers the
	// same window, which is reported alongside them.
	Health ResolverHealth `json:"health"`

	// Upstreams are the configured forwarders. Empty in native mode, where
	// there are none — an empty table is the truth and a row of zeroes would
	// be an invention.
	Upstreams []UpstreamStatus `json:"upstreams"`

	// Beta marks a resolution mode that is not yet recommended as a default.
	// See the note; it is displayed rather than hidden.
	Beta bool   `json:"beta"`
	Note string `json:"note,omitempty"`
}

// ResolverHealth is the rolling operational picture.
type ResolverHealth struct {
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
	// WindowSeconds is the period every figure below covers. Reported so a
	// reader cannot mistake these for lifetime counters — which is exactly
	// the confusion the numbers they replace produced.
	WindowSeconds int    `json:"windowSeconds"`
	Queries       uint64 `json:"queries"`
	Errors        uint64 `json:"errors"`
	Servfail      uint64 `json:"servfail"`
	// Bogus counts answers refused because they did not authenticate.
	// Reported apart from Errors: that is the resolver working, not failing.
	Bogus                 uint64 `json:"dnssecBogus"`
	AuthoritativeTimeouts uint64 `json:"authoritativeTimeouts"`
	Collapsed             uint64 `json:"collapsed"`
	// CacheHitRate is a percentage, or null when nothing was measured in the
	// window. Null rather than zero: a cache that answered none of the
	// lookups it saw and a cache that saw none are different facts.
	CacheHitRate *float64 `json:"cacheHitRate"`
	// Latency percentiles in milliseconds. Bucketed, so each is the upper
	// edge of the bucket the percentile falls in — an overestimate by
	// construction, never an underestimate.
	P50MS float64 `json:"p50Ms"`
	P95MS float64 `json:"p95Ms"`
	P99MS float64 `json:"p99Ms"`
}

func (a *API) handleResolverStatus(w http.ResponseWriter, r *http.Request) {
	h := a.Backend.Health()

	status := ResolverStatus{
		Protecting: true,
		Mode:       a.Config.DNS.EffectiveResolutionMode(),
		EngineID:   a.Backend.Name(),
		Engine:     engineName(a.Backend.Name()),
		Addresses: resolveraddr.Discover(resolveraddr.Options{
			Configured: a.Config.DNS.AdvertisedAddresses,
		}),
		UDPPort: resolveraddr.Port(a.Config.DNS.ListenUDP),
		TCPPort: resolveraddr.Port(a.Config.DNS.ListenTCP),
		DoTPort: resolveraddr.Port(a.Config.DNS.ListenDoT),
		Health: ResolverHealth{
			OK:                    h.OK,
			Detail:                h.Detail,
			WindowSeconds:         int(h.Window.Seconds()),
			Queries:               h.Queries,
			Errors:                h.Errors,
			Servfail:              h.Servfail,
			Bogus:                 h.Bogus,
			AuthoritativeTimeouts: h.AuthoritativeTimeouts,
			Collapsed:             h.Collapsed,
			P50MS:                 round2(float64(h.P50.Microseconds()) / 1000),
			P95MS:                 round2(float64(h.P95.Microseconds()) / 1000),
			P99MS:                 round2(float64(h.P99.Microseconds()) / 1000),
		},
		Upstreams: nonNilSlice(upstreamStatuses(a.Forwarder)),
	}
	if h.CacheHitRate >= 0 {
		rate := round2(h.CacheHitRate * 100)
		status.Health.CacheHitRate = &rate
	}
	status.DNSSEC, status.DNSSECDetail = dnssecPosture(a.Config)

	if a.Config.DNS.Native() {
		status.Beta = true
		status.Note = "Daddybound Native resolves DNS from the root servers itself and " +
			"validates what it fetched. It is newer than the forwarding path and is " +
			"offered as a production beta rather than the default; see " +
			"docs/daddybound/native-resolution.md."
	}

	writeJSON(w, http.StatusOK, status)
}

// engineName is the operator-facing name of a backend.
//
// Not the identifier. "daddybound-native" is what a metric label and a stored
// row should say; a person reading a dashboard should be told what is resolving
// their DNS in words.
func engineName(backend string) string {
	switch backend {
	case resolution.BackendNative:
		return "Daddybound Native"
	case resolution.BackendForward:
		return "External forwarder"
	default:
		return backend
	}
}

// dnssecPosture says what is actually happening to DNSSEC, in one word.
//
// The words are chosen so that none of them can be read as a stronger claim
// than the configuration supports, and the detail sentence says who is doing
// the checking. "Enforcing" in particular is reserved for the one arrangement
// where this deployment validates and refuses: an operator who saw "enforcing"
// on a forwarding resolver would believe their answers were being checked here,
// when all that is happening is an upstream setting a bit.
func dnssecPosture(cfg config.Config) (string, string) {
	if cfg.DNS.Native() {
		return "Enforcing", "Daddybound validates every answer it resolves against the " +
			"IANA root trust anchors. An answer that fails validation is refused with " +
			"SERVFAIL rather than returned."
	}
	if cfg.DNS.ObserveDNSSEC() {
		return "Observing", "DNS is answered by the configured upstream resolvers. " +
			"Daddybound independently resolves and validates the same names alongside " +
			"and records what it finds, but does not change any answer."
	}
	return "Upstream", "DNS is answered by the configured upstream resolvers. " +
		"Whether an answer was validated is whatever those resolvers report; " +
		"nothing is checked here."
}

// upstreamStatuses reports the configured forwarders, or nothing in native mode
// where there are none.
func upstreamStatuses(r *resolver.Resolver) []UpstreamStatus {
	if r == nil {
		return nil
	}
	var out []UpstreamStatus
	for _, u := range r.Upstreams() {
		q, e, avg := u.Stats()
		out = append(out, UpstreamStatus{
			Spec:         u.Spec,
			Protocol:     u.Protocol,
			Address:      u.Address,
			Queries:      q,
			Errors:       e,
			AvgLatencyMS: round2(avg),
		})
	}
	return out
}
