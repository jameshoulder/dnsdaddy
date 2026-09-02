package adapters

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/jameshoulder/dnsdaddy/internal/apiprovider"
)

// virusTotal talks to VirusTotal's v3 domain endpoint.
//
// Written against the documented v3 API shape and tested against captured
// response shapes replayed by an httptest server. It has NOT been exercised
// against the live service — that needs a credential, and a test that needs a
// credential is a test nobody runs. See docs/external-apis.md.
type virusTotal struct {
	cfg     apiprovider.InstanceConfig
	baseURL string
}

const virusTotalDefaultBase = "https://www.virustotal.com/api/v3"

func newVirusTotal(cfg apiprovider.InstanceConfig) (apiprovider.Provider, error) {
	if strings.TrimSpace(cfg.Secret) == "" {
		// Refused at construction rather than at the first lookup: an operator
		// who saved a provider with no key should be told immediately, not
		// discover it as a stream of failures an hour later.
		return nil, apiprovider.ErrNoCredential
	}
	return &virusTotal{
		cfg:     cfg,
		baseURL: strings.TrimRight(cfg.Setting("base_url", virusTotalDefaultBase), "/"),
	}, nil
}

func (v *virusTotal) Descriptor() apiprovider.Descriptor {
	return apiprovider.Descriptor{
		Kind:        "virustotal",
		DisplayName: "VirusTotal",
		Capabilities: []apiprovider.Capability{
			apiprovider.CapReputation,
			apiprovider.CapEnrichment,
		},
		DocsURL: "https://docs.virustotal.com/reference/domain-info",
		PrivacyNote: "Sends every looked-up domain to VirusTotal, which retains and " +
			"may share submissions. Do not enable this for a network whose internal " +
			"names are sensitive.",
	}
}

// vtDomainResponse is the subset of VirusTotal's v3 domain object this adapter
// uses.
//
// A typed struct rather than a map: unknown fields are ignored by
// encoding/json, so a provider adding fields cannot change what we read, and a
// provider removing one degrades to the zero value rather than a panic.
type vtDomainResponse struct {
	Data struct {
		Attributes struct {
			LastAnalysisStats struct {
				Harmless   int `json:"harmless"`
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Undetected int `json:"undetected"`
				Timeout    int `json:"timeout"`
			} `json:"last_analysis_stats"`
			Reputation int               `json:"reputation"`
			Categories map[string]string `json:"categories"`
			Registrar  string            `json:"registrar"`
			// Seconds since the epoch. Left as a number rather than parsed
			// into a time: it is shown to an operator as enrichment, and a
			// provider sending something unparseable should not fail a lookup.
			CreationDate int64 `json:"creation_date"`
		} `json:"attributes"`
	} `json:"data"`
}

// Reputation scores a domain from the engine consensus.
//
// The score is the share of engines that called it malicious or suspicious,
// weighted so that a suspicious verdict counts for half a malicious one.
// Deliberately a proportion rather than a raw count: "3 engines" means
// something very different when 4 engines answered and when 70 did, and a
// threshold set against a count would be quietly wrong for one of those.
func (v *virusTotal) Reputation(ctx context.Context, s apiprovider.Subject) (apiprovider.Verdict, error) {
	if s.Kind != apiprovider.SubjectDomain {
		return apiprovider.Verdict{}, apiprovider.ErrNotSupported
	}

	resp, err := v.get(ctx, "/domains/"+url.PathEscape(s.Value))
	if err != nil {
		return apiprovider.Verdict{}, err
	}

	var doc vtDomainResponse
	if err := resp.DecodeJSON(&doc); err != nil {
		return apiprovider.Verdict{}, err
	}

	st := doc.Data.Attributes.LastAnalysisStats
	total := st.Harmless + st.Malicious + st.Suspicious + st.Undetected + st.Timeout

	out := apiprovider.Verdict{
		Disposition: apiprovider.DispositionUnknown,
		Raw:         v.cfg.SafeExcerpt(resp, 1024),
		TTL:         v.cfg.CacheTTL,
	}
	if total == 0 {
		// No engine answered. That is not a clean bill of health, and
		// reporting it as benign would be the single most misleading thing
		// this adapter could do.
		return out, nil
	}

	weighted := float64(st.Malicious) + 0.5*float64(st.Suspicious)
	out.Score = apiprovider.Clamp01(weighted / float64(total))

	switch {
	case st.Malicious >= 2:
		// Two independent engines is the conventional bar. One is noisy
		// enough that acting on it blocks working domains.
		out.Disposition = apiprovider.DispositionMalicious
	case st.Malicious == 1 || st.Suspicious > 0:
		out.Disposition = apiprovider.DispositionSuspicious
	default:
		out.Disposition = apiprovider.DispositionBenign
	}

	for _, c := range doc.Data.Attributes.Categories {
		if mapped := mapCategory(c); mapped != "" {
			out.Categories = appendUnique(out.Categories, mapped)
		}
	}
	return out, nil
}

// Enrich returns the context worth showing beside a query-log row.
func (v *virusTotal) Enrich(ctx context.Context, s apiprovider.Subject) (apiprovider.Enrichment, error) {
	if s.Kind != apiprovider.SubjectDomain {
		return apiprovider.Enrichment{}, apiprovider.ErrNotSupported
	}

	resp, err := v.get(ctx, "/domains/"+url.PathEscape(s.Value))
	if err != nil {
		return apiprovider.Enrichment{}, err
	}
	var doc vtDomainResponse
	if err := resp.DecodeJSON(&doc); err != nil {
		return apiprovider.Enrichment{}, err
	}

	attrs := doc.Data.Attributes
	data := map[string]string{}
	if attrs.Registrar != "" {
		data["registrar"] = attrs.Registrar
	}
	if attrs.CreationDate > 0 {
		data["created"] = fmt.Sprintf("%d", attrs.CreationDate)
	}
	st := attrs.LastAnalysisStats
	if total := st.Harmless + st.Malicious + st.Suspicious + st.Undetected + st.Timeout; total > 0 {
		data["detections"] = fmt.Sprintf("%d/%d", st.Malicious, total)
	}
	// The vendor's own categories, kept verbatim beside our mapped ones: our
	// mapping is lossy on purpose, and an analyst should be able to see what
	// was actually said.
	if len(attrs.Categories) > 0 {
		var cats []string
		for source, c := range attrs.Categories {
			cats = append(cats, source+": "+c)
		}
		data["categories"] = strings.Join(cats, "; ")
	}

	return apiprovider.Enrichment{Data: data, TTL: v.cfg.CacheTTL}, nil
}

// CheckHealth calls the quota endpoint rather than a lookup.
//
// Testing a connection must not spend a lookup from a metered quota: an
// operator clicking "test" three times should not be three domains poorer.
func (v *virusTotal) CheckHealth(ctx context.Context) error {
	_, err := v.get(ctx, "/users/"+url.PathEscape(v.usernameForQuota())+"/overall_quotas")
	// A 404 here means the key works and the username guess did not, which is
	// a successful authentication: VirusTotal rejects a bad key with 401.
	if err != nil && strings.Contains(err.Error(), "404") {
		return nil
	}
	return err
}

// usernameForQuota is the account the quota endpoint is asked about.
//
// VirusTotal's quota path is per-user and this adapter has no way to learn the
// username from the key. The setting exists for operators who want a health
// check that fully succeeds; when it is unset the check still distinguishes a
// good key from a bad one, because authentication happens before routing.
func (v *virusTotal) usernameForQuota() string {
	return v.cfg.Setting("username", "me")
}

func (v *virusTotal) get(ctx context.Context, path string) (*apiprovider.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.baseURL+path, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-apikey", v.cfg.Secret)
	return v.cfg.Client.Do(ctx, req)
}

// mapCategory translates a vendor category onto DNS Daddy's catalogue.
//
// Unmapped categories are dropped rather than passed through. The catalogue is
// what policies are written against, and a vendor string appearing as a
// category would be a category no policy can enable and no operator can see in
// the list — a value that looks configured and does nothing.
func mapCategory(vendor string) string {
	v := strings.ToLower(vendor)
	switch {
	case strings.Contains(v, "malware"), strings.Contains(v, "malicious"):
		return "malware"
	case strings.Contains(v, "phishing"), strings.Contains(v, "scam"):
		return "phishing"
	case strings.Contains(v, "command"), strings.Contains(v, "c2"), strings.Contains(v, "botnet"):
		return "c2"
	case strings.Contains(v, "cryptomin"), strings.Contains(v, "coin"):
		return "cryptomining"
	case strings.Contains(v, "advertis"), strings.Contains(v, "tracking"):
		return "ads"
	case strings.Contains(v, "adult"), strings.Contains(v, "porn"):
		return "adult"
	case strings.Contains(v, "gambl"):
		return "gambling"
	}
	return ""
}

func appendUnique(list []string, s string) []string {
	for _, existing := range list {
		if existing == s {
			return list
		}
	}
	return append(list, s)
}

func init() {
	apiprovider.Register("virustotal", newVirusTotal, apiprovider.Template{
		DisplayName: "VirusTotal",
		Summary: "Engine-consensus reputation and domain context. " +
			"The free tier is four lookups a minute, which the default rate matches.",
		DocsURL: "https://docs.virustotal.com/reference/domain-info",
		PrivacyNote: "Sends every looked-up domain to VirusTotal, which retains and " +
			"may share submissions. Do not enable this for a network whose internal " +
			"names are sensitive.",
		Capabilities: []apiprovider.Capability{
			apiprovider.CapReputation,
			apiprovider.CapEnrichment,
		},
		Verification: "Exercised in CI against captured VirusTotal responses. " +
			"Not verified against the live service.",
		SecretLabel:    "API key",
		SecretRequired: true,
		Fields: []apiprovider.TemplateField{
			{Key: "username", Label: "Account username",
				Help: "Optional. Only used to check your quota when testing the connection."},
			{Key: "base_url", Label: "API base URL", Default: virusTotalDefaultBase,
				Help: "Change only for an enterprise endpoint."},
		},
		DefaultTimeoutMS: 3000,
		// The public tier allows four requests a minute. Defaulting above it
		// would mean every operator's first experience is a 429.
		DefaultRatePerMinute: 4,
		DefaultCacheTTLSecs:  24 * 3600,
	})
}
