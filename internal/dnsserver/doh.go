package dnsserver

import (
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/httpx"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// DoHHandler serves RFC 8484 DNS-over-HTTPS.
//
// Two paths are exposed:
//
//	/dns-query           — attribution falls back to the client IP
//	/dns-query/{token}   — the token identifies a network, so a roaming laptop
//	                       keeps its policy wherever it connects from
//
// TLS termination is expected to be done by a reverse proxy (Caddy or nginx);
// see docs/deploy.md. That keeps certificate renewal out of the resolver and
// off the critical path.
type DoHHandler struct {
	handler *Handler
	store   *store.Store
	log     *slog.Logger

	// trustedProxies bounds whose X-Forwarded-For is believed. Trusting that
	// header from an arbitrary peer would let any client claim any source
	// address, and with it any network's filtering policy.
	trustedProxies *httpx.TrustedProxies

	// allowUntokenized permits the bare /dns-query path. Off by default:
	// behind a public reverse proxy it would otherwise be an open DoH
	// resolver for anyone who guesses the path.
	allowUntokenized bool
}

// DoHOptions configures the DoH endpoint.
type DoHOptions struct {
	TrustedProxies   *httpx.TrustedProxies
	AllowUntokenized bool
}

// NewDoHHandler builds the DoH endpoint.
func NewDoHHandler(h *Handler, st *store.Store, log *slog.Logger, o DoHOptions) *DoHHandler {
	trusted := o.TrustedProxies
	if trusted == nil {
		trusted = &httpx.TrustedProxies{}
	}
	return &DoHHandler{
		handler:          h,
		store:            st,
		log:              log,
		trustedProxies:   trusted,
		allowUntokenized: o.AllowUntokenized,
	}
}

const maxDoHBody = 4096 // RFC 8484 messages are small; anything larger is abuse

func (d *DoHHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token := strings.Trim(strings.TrimPrefix(r.URL.Path, "/dns-query"), "/")

	if token == "" && !d.allowUntokenized {
		// Refuse before parsing anything: an unauthenticated open DoH
		// resolver is exactly what http.allow_untokenized_doh exists to
		// prevent, and there is no reason to do work for it.
		http.Error(w, "a per-network resolver token is required; "+
			"use /dns-query/{token} from the Setup page, or set http.allow_untokenized_doh",
			http.StatusForbidden)
		return
	}

	raw, err := d.readMessage(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	req := new(dns.Msg)
	if err := req.Unpack(raw); err != nil {
		http.Error(w, "malformed DNS message", http.StatusBadRequest)
		return
	}

	meta := requestMeta{proto: "doh", clientAddr: d.clientAddr(r)}
	if token != "" {
		networkID, err := d.store.NetworkByToken(r.Context(), token)
		if err != nil {
			// An unknown token must not silently fall back to IP attribution:
			// that would quietly apply the wrong policy to a roaming device.
			http.Error(w, "unknown resolver token", http.StatusNotFound)
			return
		}
		meta.networkID = networkID
	}

	resp := d.handler.Handle(r.Context(), req, meta)
	if resp == nil {
		http.Error(w, "no response", http.StatusInternalServerError)
		return
	}

	packed, err := resp.Pack()
	if err != nil {
		d.log.Error("pack DoH response", "error", err)
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	// A browser reflecting this response must not be tempted to sniff and
	// reinterpret raw DNS wire format as something else.
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "max-age="+strconv.Itoa(dohTTL(resp)))
	w.Header().Set("Content-Length", strconv.Itoa(len(packed)))
	w.WriteHeader(http.StatusOK)
	// nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
	// Binary DNS wire format (RFC 8484), not HTML. html/template is not
	// applicable to a packed dns.Msg; Content-Type plus nosniff above is the
	// correct control for a non-HTML body.
	if _, err := w.Write(packed); err != nil {
		d.log.Debug("write DoH response", "error", err)
	}
}

func (d *DoHHandler) readMessage(r *http.Request) ([]byte, error) {
	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query().Get("dns")
		if q == "" {
			return nil, errBadRequest("missing dns parameter")
		}
		// RFC 8484 mandates unpadded base64url.
		raw, err := base64.RawURLEncoding.DecodeString(q)
		if err != nil {
			return nil, errBadRequest("dns parameter is not valid base64url")
		}
		if len(raw) > maxDoHBody {
			return nil, errBadRequest("query too large")
		}
		return raw, nil

	case http.MethodPost:
		if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/dns-message") {
			return nil, errBadRequest("expected Content-Type: application/dns-message")
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, maxDoHBody+1))
		if err != nil {
			return nil, errBadRequest("could not read body")
		}
		if len(raw) > maxDoHBody {
			return nil, errBadRequest("query too large")
		}
		return raw, nil

	default:
		return nil, errBadRequest("method not allowed")
	}
}

func (d *DoHHandler) clientAddr(r *http.Request) netip.Addr {
	return httpx.ClientAddr(r, d.trustedProxies)
}

type errBadRequest string

func (e errBadRequest) Error() string { return string(e) }

// dohTTL returns the smallest TTL in the response, which the HTTP layer
// advertises so intermediary caches expire in step with DNS.
func dohTTL(m *dns.Msg) int {
	ttl := 0
	first := true
	for _, section := range [][]dns.RR{m.Answer, m.Ns} {
		for _, rr := range section {
			if rr.Header().Rrtype == dns.TypeOPT {
				continue
			}
			t := int(rr.Header().Ttl)
			if first || t < ttl {
				ttl, first = t, false
			}
		}
	}
	if ttl < 0 {
		return 0
	}
	return ttl
}

// compile-time assertion that the DoH handler satisfies http.Handler.
var _ http.Handler = (*DoHHandler)(nil)
