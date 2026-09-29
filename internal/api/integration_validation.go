package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"strings"

	"github.com/jameshoulder/dnsdaddy/internal/apiprovider"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// This validates configuration without DNS resolution, credential checks or
// provider requests. Saving a disabled draft is a strictly local operation.
func validateProviderConfiguration(p store.APIProvider, secret *string) error {
	t, ok := apiprovider.TemplateFor(p.Kind)
	if !ok {
		return errors.New("provider adapter is not available")
	}
	if len(strings.TrimSpace(p.Name)) == 0 || len(p.Name) > 128 {
		return errors.New("provider name must be between 1 and 128 characters")
	}
	if secret != nil && (len(*secret) > 16384 || strings.ContainsAny(*secret, "\r\n\x00")) {
		return errors.New("credential is too long")
	}
	if len(p.PolicyScope) > 64 {
		return errors.New("at most 64 policies can be selected")
	}
	for _, id := range p.PolicyScope {
		if len(id) > 128 {
			return errors.New("policy identifier is too long")
		}
	}
	if p.TimeoutMS < 0 || p.TimeoutMS > 15000 {
		return errors.New("timeoutMs must be between 1 and 15000, or 0 for the default")
	}
	if p.RatePerMinute < 0 || p.RatePerMinute > 6000 {
		return errors.New("ratePerMinute must be between 1 and 6000, or 0 for the default")
	}
	if p.CacheTTLSeconds < 0 || p.CacheTTLSeconds > 30*24*3600 {
		return errors.New("cacheTtlSeconds must not exceed 30 days")
	}
	allowedCaps := map[string]bool{}
	for _, cap := range t.Capabilities {
		allowedCaps[string(cap)] = true
	}
	for _, cap := range p.Capabilities {
		if !allowedCaps[cap] {
			return errors.New("provider does not support a selected capability")
		}
	}
	fields := map[string]apiprovider.TemplateField{}
	for _, f := range t.Fields {
		fields[f.Key] = f
	}
	for key, value := range p.Config {
		if _, ok := fields[key]; !ok {
			return errors.New("unknown provider setting; use the fields declared by its template")
		}
		if len(value) > 4096 || strings.ContainsAny(value, "\r\n\x00") {
			return errors.New("provider setting is too long or contains control characters")
		}
		if secret != nil && len(*secret) >= 4 && strings.Contains(value, *secret) {
			return errors.New("credentials must only be entered in the encrypted credential field")
		}
	}
	for _, f := range t.Fields {
		if f.Required && strings.TrimSpace(p.Config[f.Key]) == "" && f.Default == "" {
			return errors.New("a required provider setting is missing")
		}
	}
	allowPrivate := p.Config["allow_private"] == "true"
	if v := p.Config["allow_private"]; v != "" && v != "true" && v != "false" {
		return errors.New("allow_private must be true or false")
	}
	for _, key := range []string{"url", "base_url"} {
		raw := strings.TrimSpace(p.Config[key])
		if raw == "" {
			continue
		}
		// A subject may vary only the path/query, never the destination host.
		u, err := url.Parse(raw)
		if err != nil {
			return errors.New("provider endpoint is not a valid URL")
		}
		if strings.Contains(u.Host, "{subject}") {
			return errors.New("subject substitution is only allowed in the endpoint path or query")
		}
		if err := apiprovider.ValidateEndpoint(strings.ReplaceAll(raw, "{subject}", "example.com"), allowPrivate); err != nil {
			return err
		}
		for q, values := range u.Query() {
			q = strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(q, "_", ""), "-", ""))
			if q == "key" || q == "apikey" || q == "token" || q == "accesstoken" || q == "secret" || q == "password" || q == "signature" {
				for _, value := range values {
					if value != "" {
						return errors.New("do not put credentials in endpoint URLs; use the encrypted credential field and auth_query instead")
					}
				}
			}
		}
	}
	if method := p.Config["method"]; method != "" && method != "GET" && method != "POST" {
		return errors.New("provider method must be GET or POST")
	}
	for _, key := range []string{"auth_header", "auth_query"} {
		v := p.Config[key]
		if len(v) > 128 || strings.ContainsAny(v, " \t\r\n:()<>@,;\\\"/[]?={}\x00") {
			return errors.New("credential header or query parameter name is invalid")
		}
	}
	switch strings.ToLower(p.Config["auth_header"]) {
	case "host", "cookie", "set-cookie", "proxy-authorization", "connection", "content-length", "transfer-encoding":
		return errors.New("this credential header is not permitted")
	}
	return nil
}

type providerTestRecord struct {
	testResult
	Fingerprint string `json:"configFingerprint"`
}

func providerFingerprint(p store.APIProvider) string {
	b, _ := json.Marshal(struct {
		Kind      string
		Config    map[string]string
		SecretSet bool
		RotatedAt any
	}{p.Kind, p.Config, p.SecretSet, p.RotatedAt})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (a *API) providerLastTest(ctx context.Context, row store.APIProvider) *providerTestRecord {
	value, err := a.Store.GetSetting(ctx, "integrations.provider_test."+row.ID)
	if err != nil || value == "" {
		return nil
	}
	var result providerTestRecord
	if err := json.Unmarshal([]byte(value), &result); err != nil || result.Fingerprint != providerFingerprint(row) {
		return nil
	}
	return &result
}

func (a *API) currentProviderView(ctx context.Context, row store.APIProvider) providerView {
	var inst *apiprovider.Instance
	for _, candidate := range a.Providers.Instances() {
		if candidate.ID == row.ID {
			inst = candidate
			break
		}
	}
	v := a.viewOf(row, inst)
	v.LastTest = a.providerLastTest(ctx, row)
	return v
}
