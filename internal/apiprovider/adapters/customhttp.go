// Package adapters holds the concrete external intelligence providers.
//
// One file per provider, each registering itself with the apiprovider registry
// in an init function. The dependency runs one way — adapters import
// apiprovider and never the reverse — so adding a provider is one new file and
// one registration, and removing one is deleting a file.
//
// Rules every adapter here follows, and which the tests enforce:
//
//   - Never log, wrap into an error, or return the credential.
//   - Never construct an http.Client. The one handed over in InstanceConfig
//     already carries this provider's timeout, rate limit and circuit breaker,
//     and there is deliberately nothing else to call.
//   - Clamp the normalised score. A provider outside [0,1] clears every
//     threshold downstream.
//   - Return ErrNotSupported for a capability that is not implemented, rather
//     than a zero value that reads as a real answer.
//   - Treat every response field as absent by default. A provider that changes
//     its schema must degrade to "unknown", not panic.
//
// See docs/external-apis.md §9 for the guide to writing a new one.
package adapters

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/jameshoulder/dnsdaddy/internal/apiprovider"
)

// customHTTP is the escape hatch: any HTTP endpoint that returns JSON.
//
// It exists because the set of reputation services is unbounded and a
// self-hosted product should not require a code change to talk to an
// operator's internal one. The configuration is deliberately declarative — a
// URL template, a header name, two field paths — rather than a scripting
// language, because a scripting language in a resolver's configuration is a
// remote code execution feature nobody asked for.
type customHTTP struct {
	cfg apiprovider.InstanceConfig

	urlTemplate     string
	method          string
	authHeader      string
	authPrefix      string
	authQuery       string
	scoreField      string
	verdictField    string
	maliciousValues []string
}

func newCustomHTTP(cfg apiprovider.InstanceConfig) (apiprovider.Provider, error) {
	tmpl := cfg.Setting("url", "")
	if tmpl == "" {
		return nil, fmt.Errorf("custom provider needs a url")
	}
	// Parsed at construction so a malformed URL is a configuration error the
	// operator sees when they save, not a failure per lookup afterwards.
	if _, err := url.Parse(strings.ReplaceAll(tmpl, "{subject}", "example.com")); err != nil {
		return nil, fmt.Errorf("custom provider url is not a valid URL: %w", err)
	}

	method := strings.ToUpper(cfg.Setting("method", http.MethodGet))
	switch method {
	case http.MethodGet, http.MethodPost:
	default:
		return nil, fmt.Errorf("custom provider method must be GET or POST, not %q", method)
	}

	c := &customHTTP{
		cfg:          cfg,
		urlTemplate:  tmpl,
		method:       method,
		authHeader:   cfg.Setting("auth_header", "Authorization"),
		authPrefix:   cfg.Setting("auth_prefix", "Bearer "),
		authQuery:    strings.TrimSpace(cfg.Setting("auth_query", "")),
		scoreField:   cfg.Setting("score_field", "score"),
		verdictField: cfg.Setting("verdict_field", ""),
	}
	for _, v := range strings.Split(cfg.Setting("malicious_values", "malicious,bad,block"), ",") {
		if v = strings.ToLower(strings.TrimSpace(v)); v != "" {
			c.maliciousValues = append(c.maliciousValues, v)
		}
	}
	return c, nil
}

// authenticate attaches the credential to a request.
//
// Two shapes, because services use both: a header, and a query parameter. The
// query form exists specifically so an operator never has to paste a key into
// the url setting. Everything in a provider's settings map is stored
// unencrypted and returned by the management API — that is what makes it
// settings rather than a credential — so a key living there would defeat the
// encryption on the one field that has it.
func (c *customHTTP) authenticate(req *http.Request) error {
	if c.cfg.Secret == "" {
		return nil
	}
	if c.authQuery != "" {
		q := req.URL.Query()
		q.Set(c.authQuery, c.cfg.Secret)
		req.URL.RawQuery = q.Encode()
		return nil
	}
	if c.authHeader != "" {
		req.Header.Set(c.authHeader, c.authPrefix+c.cfg.Secret)
	}
	return nil
}

func (c *customHTTP) Descriptor() apiprovider.Descriptor {
	return apiprovider.Descriptor{
		Kind:         "customhttp",
		DisplayName:  "Custom HTTP endpoint",
		Capabilities: []apiprovider.Capability{apiprovider.CapReputation},
		PrivacyNote: "Sends the domain being resolved to the URL you configure. " +
			"What that service does with it is between you and them.",
	}
}

// Reputation asks the configured endpoint about one subject.
func (c *customHTTP) Reputation(ctx context.Context, s apiprovider.Subject) (apiprovider.Verdict, error) {
	// url.QueryEscape, not raw interpolation. The subject is a name from the
	// network — attacker-influenced by definition, since anyone who can make a
	// client resolve a name controls it — and splicing it unescaped into a URL
	// is how it reaches a different path or a different host.
	target := strings.ReplaceAll(c.urlTemplate, "{subject}", url.QueryEscape(s.Value))

	req, err := http.NewRequestWithContext(ctx, c.method, target, nil)
	if err != nil {
		return apiprovider.Verdict{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if err := c.authenticate(req); err != nil {
		return apiprovider.Verdict{}, err
	}

	resp, err := c.cfg.Client.Do(ctx, req)
	if err != nil {
		// Returned unwrapped so the sentinel survives errors.Is at the call
		// site. Nothing is added: the request carries the credential, and an
		// error that quotes it is an error that logs it.
		return apiprovider.Verdict{}, err
	}

	var body map[string]any
	if err := resp.DecodeJSON(&body); err != nil {
		return apiprovider.Verdict{}, err
	}

	v := apiprovider.Verdict{
		Disposition: apiprovider.DispositionUnknown,
		Raw:         c.cfg.SafeExcerpt(resp, 1024),
		TTL:         c.cfg.CacheTTL,
	}

	// An explicit verdict field wins over a score: a service that says
	// "malicious" has told us more than one that says 0.8, and the thresholds
	// we would apply to that 0.8 are ours rather than theirs.
	if c.verdictField != "" {
		if raw, ok := lookupPath(body, c.verdictField); ok {
			word := strings.ToLower(strings.TrimSpace(fmt.Sprint(raw)))
			for _, m := range c.maliciousValues {
				if word == m {
					v.Disposition = apiprovider.DispositionMalicious
					v.Score = 1
					return v, nil
				}
			}
			// A recognised response that is not in the malicious set is a
			// benign answer, which is different from no answer at all.
			v.Disposition = apiprovider.DispositionBenign
		}
	}

	if raw, ok := lookupPath(body, c.scoreField); ok {
		if f, ok := toFloat(raw); ok {
			v.Score = apiprovider.Clamp01(f)
			v.Disposition = apiprovider.DispositionFor(v.Score)
		}
	}
	return v, nil
}

// CheckHealth proves the endpoint answers and accepts the credential.
//
// Uses a name from the reserved documentation domain rather than something an
// operator's network really resolves, so a connection test discloses nothing
// about the deployment to a service that may not yet be trusted.
func (c *customHTTP) CheckHealth(ctx context.Context) error {
	_, err := c.Reputation(ctx, apiprovider.DomainSubject("example.com"))
	return err
}

// lookupPath walks a dotted path through decoded JSON.
//
// Deliberately not JSONPath: a query language is a parser, an evaluation
// engine, and a surface for a configuration value to become something more
// than a lookup. Dotted keys and numeric array indices cover the shapes real
// reputation APIs use, and anything more exotic is a reason to write a proper
// adapter rather than to grow this.
func lookupPath(doc map[string]any, path string) (any, bool) {
	if path == "" {
		return nil, false
	}
	var cur any = doc
	for _, part := range strings.Split(path, ".") {
		switch node := cur.(type) {
		case map[string]any:
			next, ok := node[part]
			if !ok {
				return nil, false
			}
			cur = next
		case []any:
			i, err := strconv.Atoi(part)
			if err != nil || i < 0 || i >= len(node) {
				return nil, false
			}
			cur = node[i]
		default:
			return nil, false
		}
	}
	return cur, true
}

// toFloat accepts the several ways a JSON document can express a number.
//
// A provider that returns "0.8" as a string is not broken enough to ignore,
// and a boolean verdict field is common. Anything else is refused rather than
// coerced: guessing what a value meant is how a malformed response becomes a
// confident block.
func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case bool:
		if n {
			return 1, true
		}
		return 0, true
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(n), 64)
		if err != nil {
			return 0, false
		}
		return f, true
	}
	return 0, false
}

func init() {
	apiprovider.Register("customhttp", newCustomHTTP, apiprovider.Template{
		DisplayName: "Custom HTTP endpoint",
		Summary: "Any service that answers a GET or POST with JSON. " +
			"Use this for an internal reputation service, or a vendor with no adapter here yet.",
		PrivacyNote: "Sends the domain being resolved to the URL you configure. " +
			"What that service does with it is between you and them.",
		Capabilities: []apiprovider.Capability{apiprovider.CapReputation},
		Verification: "Exercised in CI against a local test server. Whatever endpoint " +
			"you point it at is yours to verify — use Test connection.",
		SecretLabel:    "API key or token",
		SecretRequired: false,
		Fields: []apiprovider.TemplateField{
			{Key: "url", Label: "URL", Required: true,
				Placeholder: "https://intel.example.internal/lookup?domain={subject}",
				Help: "{subject} is replaced with the domain, URL-escaped. " +
					"Never put a credential in here — this value is stored unencrypted " +
					"and shown in the dashboard. Use the credential fields below."},
			{Key: "method", Label: "Method", Default: "GET",
				Help: "GET or POST."},
			{Key: "auth_header", Label: "Credential header", Default: "Authorization",
				Help: "Which header carries the credential. Leave the prefix empty for a bare key."},
			{Key: "auth_prefix", Label: "Credential prefix", Default: "Bearer ",
				Help: `Put in front of the credential. Often "Bearer " — mind the trailing space.`},
			{Key: "auth_query", Label: "Credential query parameter",
				Help: "For services that authenticate by query string. Set this to the " +
					"parameter name — for example apikey — and the encrypted credential " +
					"is appended for you. Takes precedence over the header."},
			{Key: "score_field", Label: "Score field", Default: "score",
				Help: "Dotted path to a 0–1 score, e.g. result.risk.score"},
			{Key: "verdict_field", Label: "Verdict field",
				Help: "Optional dotted path to a word like \"malicious\". Takes precedence over the score."},
			{Key: "malicious_values", Label: "Values meaning malicious", Default: "malicious,bad,block",
				Help: "Comma separated, compared case-insensitively."},
		},
		DefaultTimeoutMS:     2000,
		DefaultRatePerMinute: 120,
		DefaultCacheTTLSecs:  6 * 3600,
	})
}
