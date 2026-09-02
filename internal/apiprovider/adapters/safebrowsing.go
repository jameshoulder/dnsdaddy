package adapters

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/jameshoulder/dnsdaddy/internal/apiprovider"
	"github.com/jameshoulder/dnsdaddy/internal/version"
)

// safeBrowsing talks to Google Safe Browsing's Lookup API (v4).
//
// Written against the documented v4 request and response shapes and tested
// against them replayed by an httptest server. It has NOT been exercised
// against the live service.
//
// A note on which API this uses, because it is the privacy-relevant choice:
// Safe Browsing offers a Lookup API, which sends the full URL, and an Update
// API, which sends only a 32-bit hash prefix and does the matching locally.
// The Update API is strictly better for privacy and materially more work — a
// local database, incremental updates, and a full-hash confirmation round.
// This adapter uses Lookup, and says so in its privacy note rather than
// leaving an operator to discover it. The Update API is the obvious next
// improvement and is recorded as such in docs/external-apis.md §5.1.
type safeBrowsing struct {
	cfg     apiprovider.InstanceConfig
	baseURL string
	// clientID identifies this software to Google, as the API requires. Not a
	// credential and not a secret; the API key is.
	clientID string
}

const safeBrowsingDefaultBase = "https://safebrowsing.googleapis.com/v4"

func newSafeBrowsing(cfg apiprovider.InstanceConfig) (apiprovider.Provider, error) {
	if strings.TrimSpace(cfg.Secret) == "" {
		return nil, apiprovider.ErrNoCredential
	}
	return &safeBrowsing{
		cfg:      cfg,
		baseURL:  strings.TrimRight(cfg.Setting("base_url", safeBrowsingDefaultBase), "/"),
		clientID: cfg.Setting("client_id", "dnsdaddy"),
	}, nil
}

func (s *safeBrowsing) Descriptor() apiprovider.Descriptor {
	return apiprovider.Descriptor{
		Kind:         "safebrowsing",
		DisplayName:  "Google Safe Browsing",
		Capabilities: []apiprovider.Capability{apiprovider.CapReputation},
		DocsURL:      "https://developers.google.com/safe-browsing/v4/lookup-api",
		PrivacyNote: "Uses the Lookup API, which sends the full domain to Google on " +
			"every cache miss. The hash-prefix Update API would not; this adapter " +
			"does not implement it yet.",
	}
}

// sbRequest is the v4 threatMatches:find body.
type sbRequest struct {
	Client struct {
		ClientID      string `json:"clientId"`
		ClientVersion string `json:"clientVersion"`
	} `json:"client"`
	ThreatInfo struct {
		ThreatTypes      []string       `json:"threatTypes"`
		PlatformTypes    []string       `json:"platformTypes"`
		ThreatEntryTypes []string       `json:"threatEntryTypes"`
		ThreatEntries    []sbThreatItem `json:"threatEntries"`
	} `json:"threatInfo"`
}

type sbThreatItem struct {
	URL string `json:"url"`
}

// sbResponse is the subset of the reply this adapter reads.
//
// An empty matches array is Safe Browsing's way of saying "not on any list",
// which is a real benign answer rather than an absence of one — the API
// answers definitively for the lists it was asked about.
type sbResponse struct {
	Matches []struct {
		ThreatType    string       `json:"threatType"`
		PlatformType  string       `json:"platformType"`
		Threat        sbThreatItem `json:"threat"`
		CacheDuration string       `json:"cacheDuration"`
	} `json:"matches"`
}

// threatTypes are the lists queried. All of them: an operator enabling Safe
// Browsing wants Safe Browsing, and asking for a subset would silently not
// find things they would reasonably expect it to.
var threatTypes = []string{
	"MALWARE",
	"SOCIAL_ENGINEERING",
	"UNWANTED_SOFTWARE",
	"POTENTIALLY_HARMFUL_APPLICATION",
}

func (s *safeBrowsing) Reputation(ctx context.Context, subject apiprovider.Subject) (apiprovider.Verdict, error) {
	if subject.Kind != apiprovider.SubjectDomain {
		return apiprovider.Verdict{}, apiprovider.ErrNotSupported
	}

	var body sbRequest
	body.Client.ClientID = s.clientID
	body.Client.ClientVersion = version.String()
	body.ThreatInfo.ThreatTypes = threatTypes
	body.ThreatInfo.PlatformTypes = []string{"ANY_PLATFORM"}
	body.ThreatInfo.ThreatEntryTypes = []string{"URL"}
	// Safe Browsing matches on URLs. A bare domain is the canonical way to ask
	// about the whole host.
	body.ThreatInfo.ThreatEntries = []sbThreatItem{{URL: subject.Value}}

	encoded, err := json.Marshal(body)
	if err != nil {
		return apiprovider.Verdict{}, fmt.Errorf("encode request: %w", err)
	}

	// The key goes in the query string because that is the only place this API
	// accepts it. It therefore reaches Google's access logs, which is a
	// property of the API rather than a choice here — but it is also why the
	// URL is never put into an error or a log line on this side.
	target := s.baseURL + "/threatMatches:find?key=" + s.cfg.Secret

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(encoded))
	if err != nil {
		return apiprovider.Verdict{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// GetBody, so the client's single retry can replay the body. Without it a
	// retried request would be sent with an exhausted reader.
	req.GetBody = func() (io.ReadCloser, error) { return newBytesBody(encoded), nil }

	resp, err := s.cfg.Client.Do(ctx, req)
	if err != nil {
		return apiprovider.Verdict{}, err
	}

	var doc sbResponse
	if err := resp.DecodeJSON(&doc); err != nil {
		return apiprovider.Verdict{}, err
	}

	out := apiprovider.Verdict{
		Raw: s.cfg.SafeExcerpt(resp, 1024),
		TTL: s.cfg.CacheTTL,
	}
	if len(doc.Matches) == 0 {
		// Safe Browsing answers definitively for the lists it was asked
		// about, so no match really is "not on these lists" — a benign answer
		// rather than an unknown one.
		out.Disposition = apiprovider.DispositionBenign
		return out, nil
	}

	// Any match is a match. Safe Browsing does not score, and inventing a
	// gradient over a binary answer would be presenting a confidence the
	// source never expressed.
	out.Disposition = apiprovider.DispositionMalicious
	out.Score = 1
	for _, m := range doc.Matches {
		if c := safeBrowsingCategory(m.ThreatType); c != "" {
			out.Categories = appendUnique(out.Categories, c)
		}
	}
	return out, nil
}

// CheckHealth asks about a domain from the reserved documentation range.
//
// Safe Browsing has no free health endpoint, so this costs one lookup. It uses
// example.com rather than anything the operator's network resolves, so testing
// a connection discloses nothing about the deployment.
func (s *safeBrowsing) CheckHealth(ctx context.Context) error {
	_, err := s.Reputation(ctx, apiprovider.DomainSubject("example.com"))
	return err
}

func safeBrowsingCategory(threatType string) string {
	switch threatType {
	case "MALWARE":
		return "malware"
	case "SOCIAL_ENGINEERING":
		return "phishing"
	case "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION":
		return "malware"
	}
	return ""
}

// bytesBody is a re-readable request body for the retry path.
type bytesBody struct{ *bytes.Reader }

func newBytesBody(b []byte) *bytesBody { return &bytesBody{bytes.NewReader(b)} }

func (bytesBody) Close() error { return nil }

func init() {
	// #nosec G101 -- these are field labels and help text describing WHERE an
	// operator should put their credential. There is no credential here, and
	// there is nowhere in this package one could be: adapters receive theirs
	// through InstanceConfig, sealed on disk until the moment it is used.
	apiprovider.Register("safebrowsing", newSafeBrowsing, apiprovider.Template{
		DisplayName: "Google Safe Browsing",
		Summary: "Google's malware and social-engineering lists. " +
			"Free, with a generous quota, and answers definitively for the lists it covers.",
		DocsURL: "https://developers.google.com/safe-browsing/v4/get-started",
		PrivacyNote: "Uses the Lookup API, which sends the full domain to Google on " +
			"every cache miss. The hash-prefix Update API would not; this adapter " +
			"does not implement it yet.",
		Capabilities: []apiprovider.Capability{apiprovider.CapReputation},
		Verification: "Exercised in CI against captured Safe Browsing responses. " +
			"Not verified against the live service.",
		SecretLabel:    "Google API key",
		SecretRequired: true,
		Fields: []apiprovider.TemplateField{
			{Key: "client_id", Label: "Client ID", Default: "dnsdaddy",
				Help: "Identifies this software to Google. Not a credential."},
			{Key: "base_url", Label: "API base URL", Default: safeBrowsingDefaultBase,
				Help: "Change only if you are proxying the API."},
		},
		DefaultTimeoutMS:     2000,
		DefaultRatePerMinute: 300,
		DefaultCacheTTLSecs:  6 * 3600,
	})
}
