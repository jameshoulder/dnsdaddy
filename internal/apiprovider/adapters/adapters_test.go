package adapters

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/apiprovider"
)

// theSecret is the credential every test in this file configures. Distinctive
// on purpose: the leak scan looks for exactly this string in everything an
// adapter produces, and a value like "test" would appear by coincidence.
const theSecret = "SECRET-2f4b9c1e-do-not-disclose"

func instance(t *testing.T, srv *httptest.Server, settings map[string]string) apiprovider.InstanceConfig {
	t.Helper()
	return apiprovider.InstanceConfig{
		ID:       "apr_test",
		Name:     "test provider",
		Settings: settings,
		Secret:   theSecret,
		Client: apiprovider.NewClient(apiprovider.ClientOptions{
			ProviderID:    "apr_test",
			Timeout:       2 * time.Second,
			RatePerMinute: 6000,
			Transport:     srv.Client().Transport,
		}),
		CacheTTL: time.Hour,
	}
}

// ---------------------------------------------------------------------------
// VirusTotal
// ---------------------------------------------------------------------------

// vtBody is the shape VirusTotal's v3 domain endpoint documents. Captured
// structure, synthetic values.
func vtBody(harmless, malicious, suspicious, undetected int) string {
	doc := map[string]any{
		"data": map[string]any{
			"attributes": map[string]any{
				"last_analysis_stats": map[string]any{
					"harmless": harmless, "malicious": malicious,
					"suspicious": suspicious, "undetected": undetected, "timeout": 0,
				},
				"reputation":    -12,
				"registrar":     "Example Registrar, Inc.",
				"creation_date": 1609459200,
				"categories":    map[string]string{"Forcepoint ThreatSeeker": "malware sites"},
			},
		},
	}
	b, _ := json.Marshal(doc)
	return string(b)
}

func TestVirusTotalScoresFromEngineConsensus(t *testing.T) {
	for _, tc := range []struct {
		name                            string
		harmless, malicious, suspicious int
		wantDisposition                 apiprovider.Disposition
		minScore, maxScore              float64
	}{
		// Two independent engines is the conventional bar for acting.
		{"many engines agree", 60, 8, 2, apiprovider.DispositionMalicious, 0.1, 0.2},
		{"two engines", 68, 2, 0, apiprovider.DispositionMalicious, 0.0, 0.1},
		// One engine is noisy enough that blocking on it breaks working sites.
		{"one engine", 69, 1, 0, apiprovider.DispositionSuspicious, 0.0, 0.1},
		{"suspicious only", 69, 0, 1, apiprovider.DispositionSuspicious, 0.0, 0.1},
		{"clean", 70, 0, 0, apiprovider.DispositionBenign, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(vtBody(tc.harmless, tc.malicious, tc.suspicious, 0)))
			}))
			defer srv.Close()

			p, err := newVirusTotal(instance(t, srv, map[string]string{"base_url": srv.URL}))
			if err != nil {
				t.Fatal(err)
			}
			v, err := p.(apiprovider.ReputationProvider).Reputation(
				context.Background(), apiprovider.DomainSubject("evil.example"))
			if err != nil {
				t.Fatal(err)
			}
			if v.Disposition != tc.wantDisposition {
				t.Errorf("disposition = %s, want %s", v.Disposition, tc.wantDisposition)
			}
			if v.Score < tc.minScore || v.Score > tc.maxScore {
				t.Errorf("score = %v, want between %v and %v", v.Score, tc.minScore, tc.maxScore)
			}
		})
	}
}

// The most misleading answer this adapter could give: no engine answered, and
// we report "clean". A zero total is an absence of evidence, not evidence of
// absence, and only "unknown" says that.
func TestVirusTotalWithNoEngineResultsIsUnknownNotBenign(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(vtBody(0, 0, 0, 0)))
	}))
	defer srv.Close()

	p, _ := newVirusTotal(instance(t, srv, map[string]string{"base_url": srv.URL}))
	v, err := p.(apiprovider.ReputationProvider).Reputation(
		context.Background(), apiprovider.DomainSubject("unknown.example"))
	if err != nil {
		t.Fatal(err)
	}
	if v.Disposition != apiprovider.DispositionUnknown {
		t.Errorf("disposition = %s, want unknown — no engine answered", v.Disposition)
	}
	if v.Score != 0 {
		t.Errorf("score = %v, want 0", v.Score)
	}
}

// A provider that changes its schema must degrade to unknown, not panic and
// not invent a verdict.
func TestVirusTotalSurvivesAnUnexpectedShape(t *testing.T) {
	for _, body := range []string{
		`{}`,
		`{"data":null}`,
		`{"data":{"attributes":null}}`,
		`{"data":{"attributes":{"last_analysis_stats":null}}}`,
		`{"data":{"attributes":{"categories":null}}}`,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(body))
		}))
		p, err := newVirusTotal(instance(t, srv, map[string]string{"base_url": srv.URL}))
		if err != nil {
			srv.Close()
			t.Fatal(err)
		}
		v, err := p.(apiprovider.ReputationProvider).Reputation(
			context.Background(), apiprovider.DomainSubject("x.example"))
		srv.Close()
		if err != nil {
			t.Errorf("body %s produced an error: %v", body, err)
			continue
		}
		if v.Disposition != apiprovider.DispositionUnknown {
			t.Errorf("body %s produced disposition %s, want unknown", body, v.Disposition)
		}
	}
}

func TestVirusTotalRefusesToBuildWithoutACredential(t *testing.T) {
	cfg := apiprovider.InstanceConfig{ID: "apr_1", Secret: ""}
	if _, err := newVirusTotal(cfg); !errors.Is(err, apiprovider.ErrNoCredential) {
		t.Errorf("building without a key returned %v, want ErrNoCredential", err)
	}
}

func TestVirusTotalSendsTheKeyInTheDocumentedHeader(t *testing.T) {
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("x-apikey")
		_, _ = w.Write([]byte(vtBody(70, 0, 0, 0)))
	}))
	defer srv.Close()

	p, _ := newVirusTotal(instance(t, srv, map[string]string{"base_url": srv.URL}))
	if _, err := p.(apiprovider.ReputationProvider).Reputation(
		context.Background(), apiprovider.DomainSubject("x.example")); err != nil {
		t.Fatal(err)
	}
	if seen != theSecret {
		t.Errorf("x-apikey header was %q", seen)
	}
}

func TestVirusTotalEnrichmentCarriesContextNotAJudgement(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(vtBody(60, 8, 2, 0)))
	}))
	defer srv.Close()

	p, _ := newVirusTotal(instance(t, srv, map[string]string{"base_url": srv.URL}))
	e, err := p.(apiprovider.Enricher).Enrich(context.Background(), apiprovider.DomainSubject("x.example"))
	if err != nil {
		t.Fatal(err)
	}
	if e.Data["registrar"] != "Example Registrar, Inc." {
		t.Errorf("registrar = %q", e.Data["registrar"])
	}
	if e.Data["detections"] != "8/70" {
		t.Errorf("detections = %q, want 8/70", e.Data["detections"])
	}
	if !strings.Contains(e.Data["categories"], "malware sites") {
		t.Errorf("the vendor's own category was not kept verbatim: %q", e.Data["categories"])
	}
}

// ---------------------------------------------------------------------------
// Safe Browsing
// ---------------------------------------------------------------------------

func TestSafeBrowsingNoMatchIsBenignNotUnknown(t *testing.T) {
	// Safe Browsing answers definitively for the lists it was asked about, so
	// an empty matches array is a real answer. Reporting it as unknown would
	// throw away the one thing this provider is good at.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	p, _ := newSafeBrowsing(instance(t, srv, map[string]string{"base_url": srv.URL}))
	v, err := p.(apiprovider.ReputationProvider).Reputation(
		context.Background(), apiprovider.DomainSubject("good.example"))
	if err != nil {
		t.Fatal(err)
	}
	if v.Disposition != apiprovider.DispositionBenign {
		t.Errorf("disposition = %s, want benign", v.Disposition)
	}
}

func TestSafeBrowsingMatchIsMalicious(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The request shape is part of the contract with the API.
		var req sbRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("request body did not decode: %v", err)
		}
		if len(req.ThreatInfo.ThreatEntries) != 1 || req.ThreatInfo.ThreatEntries[0].URL != "evil.example" {
			t.Errorf("threat entries = %+v", req.ThreatInfo.ThreatEntries)
		}
		_, _ = w.Write([]byte(`{"matches":[
			{"threatType":"MALWARE","platformType":"ANY_PLATFORM","threat":{"url":"evil.example"}},
			{"threatType":"SOCIAL_ENGINEERING","platformType":"ANY_PLATFORM","threat":{"url":"evil.example"}}
		]}`))
	}))
	defer srv.Close()

	p, _ := newSafeBrowsing(instance(t, srv, map[string]string{"base_url": srv.URL}))
	v, err := p.(apiprovider.ReputationProvider).Reputation(
		context.Background(), apiprovider.DomainSubject("evil.example"))
	if err != nil {
		t.Fatal(err)
	}
	if v.Disposition != apiprovider.DispositionMalicious {
		t.Errorf("disposition = %s, want malicious", v.Disposition)
	}
	if v.Score != 1 {
		t.Errorf("score = %v, want 1 — Safe Browsing does not score, so a gradient would be invented", v.Score)
	}
	want := map[string]bool{"malware": true, "phishing": true}
	for _, c := range v.Categories {
		delete(want, c)
	}
	if len(want) != 0 {
		t.Errorf("categories %v missed %v", v.Categories, want)
	}
}

// ---------------------------------------------------------------------------
// Custom HTTP
// ---------------------------------------------------------------------------

func TestCustomHTTPReadsAScoreFromADottedPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"result":{"risk":{"score":0.91}}}`))
	}))
	defer srv.Close()

	p, err := newCustomHTTP(instance(t, srv, map[string]string{
		"url":         srv.URL + "/lookup?domain={subject}",
		"score_field": "result.risk.score",
	}))
	if err != nil {
		t.Fatal(err)
	}
	v, err := p.(apiprovider.ReputationProvider).Reputation(
		context.Background(), apiprovider.DomainSubject("evil.example"))
	if err != nil {
		t.Fatal(err)
	}
	if v.Score != 0.91 {
		t.Errorf("score = %v, want 0.91", v.Score)
	}
	if v.Disposition != apiprovider.DispositionMalicious {
		t.Errorf("disposition = %s, want malicious for 0.91", v.Disposition)
	}
}

// A score outside [0,1] is the easiest way for a buggy or hostile endpoint to
// clear every threshold downstream.
func TestCustomHTTPClampsAHostileScore(t *testing.T) {
	for _, body := range []string{
		`{"score": 1000000}`,
		`{"score": -5}`,
		`{"score": "not a number"}`,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(body))
		}))
		p, err := newCustomHTTP(instance(t, srv, map[string]string{"url": srv.URL + "?d={subject}"}))
		if err != nil {
			srv.Close()
			t.Fatal(err)
		}
		v, err := p.(apiprovider.ReputationProvider).Reputation(
			context.Background(), apiprovider.DomainSubject("x.example"))
		srv.Close()
		if err != nil {
			t.Errorf("body %s: %v", body, err)
			continue
		}
		if v.Score < 0 || v.Score > 1 {
			t.Errorf("body %s produced score %v, outside [0,1]", body, v.Score)
		}
	}
}

// The subject is a name from the network, so it is attacker-influenced by
// definition: anyone who can make a client resolve a name controls it.
// Splicing it unescaped into a URL is how it reaches a different path or host.
func TestCustomHTTPEscapesTheSubjectIntoTheURL(t *testing.T) {
	var gotPath, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.Query().Get("domain")
		_, _ = w.Write([]byte(`{"score":0}`))
	}))
	defer srv.Close()

	p, err := newCustomHTTP(instance(t, srv, map[string]string{
		"url": srv.URL + "/lookup?domain={subject}",
	}))
	if err != nil {
		t.Fatal(err)
	}
	// A name carrying URL syntax: an unescaped interpolation would send this
	// to /admin with the lookup path discarded.
	hostile := apiprovider.Subject{
		Kind:  apiprovider.SubjectDomain,
		Value: "evil.example&admin=1#/../../admin",
	}
	if _, err := p.(apiprovider.ReputationProvider).Reputation(context.Background(), hostile); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/lookup" {
		t.Errorf("request reached path %q, want /lookup — the subject escaped its parameter", gotPath)
	}
	if gotQuery != hostile.Value {
		t.Errorf("domain parameter = %q, want the whole subject %q", gotQuery, hostile.Value)
	}
}

func TestCustomHTTPVerdictFieldBeatsScore(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// A low score and an explicit malicious verdict. The word wins: the
		// service has told us more than a number we would threshold ourselves.
		_, _ = w.Write([]byte(`{"score":0.01,"verdict":"MALICIOUS"}`))
	}))
	defer srv.Close()

	p, _ := newCustomHTTP(instance(t, srv, map[string]string{
		"url":           srv.URL + "?d={subject}",
		"verdict_field": "verdict",
	}))
	v, err := p.(apiprovider.ReputationProvider).Reputation(
		context.Background(), apiprovider.DomainSubject("x.example"))
	if err != nil {
		t.Fatal(err)
	}
	if v.Disposition != apiprovider.DispositionMalicious {
		t.Errorf("disposition = %s, want malicious", v.Disposition)
	}
}

func TestCustomHTTPRefusesAnUnusableConfiguration(t *testing.T) {
	if _, err := newCustomHTTP(apiprovider.InstanceConfig{}); err == nil {
		t.Error("a provider with no URL was accepted")
	}
	if _, err := newCustomHTTP(apiprovider.InstanceConfig{
		Settings: map[string]string{"url": "https://x.example", "method": "DELETE"},
	}); err == nil {
		t.Error("a provider with method DELETE was accepted")
	}
}

// ---------------------------------------------------------------------------
// The rule that applies to every adapter
// ---------------------------------------------------------------------------

// No adapter may put the credential into anything a caller can see.
//
// Both paths, because they leak differently and the success path is the
// likelier one. On failure the risk is an error that wrapped the request URL —
// Safe Browsing puts the key in the query string, so an error quoting the URL
// quotes the key. On success the risk is the Raw excerpt: it is a slice of a
// third party's response, and a service that echoes the request back — a
// misconfigured proxy in front of one, say — would carry the key into the
// database and onto the dashboard.
//
// The first version of this test only covered failure, and a deliberately
// planted leak into Raw went undetected: a 400 makes the client return an
// error with no Response at all, so Raw was empty and there was nothing to
// find.
func TestNoAdapterDisclosesTheCredential(t *testing.T) {
	// Echoes the request back, which is the shape that would carry a key.
	echoErr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error":"bad request to %s","auth":%q}`,
			r.URL.String(), r.Header.Get("x-apikey")+r.Header.Get("Authorization"))
	}))
	defer echoErr.Close()

	// Answers successfully AND echoes the credential in a field an adapter
	// might excerpt.
	echoOK := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"data":{"attributes":{"last_analysis_stats":`+
			`{"harmless":70,"malicious":0,"suspicious":0,"undetected":0,"timeout":0}}}`+
			`,"echo":{"url":%q,"key":%q}}`,
			r.URL.String(), r.Header.Get("x-apikey")+r.Header.Get("Authorization"))
	}))
	defer echoOK.Close()

	for _, srvCase := range []struct {
		name string
		srv  *httptest.Server
	}{
		{"provider fails and echoes the request", echoErr},
		{"provider succeeds and echoes the request", echoOK},
	} {
		for _, tc := range []struct {
			kind     string
			build    func(apiprovider.InstanceConfig) (apiprovider.Provider, error)
			settings func(base string) map[string]string
		}{
			{"virustotal", newVirusTotal, func(b string) map[string]string {
				return map[string]string{"base_url": b}
			}},
			{"safebrowsing", newSafeBrowsing, func(b string) map[string]string {
				return map[string]string{"base_url": b}
			}},
			{"customhttp", newCustomHTTP, func(b string) map[string]string {
				return map[string]string{"url": b + "?d={subject}"}
			}},
		} {
			t.Run(srvCase.name+"/"+tc.kind, func(t *testing.T) {
				cfg := instance(t, srvCase.srv, tc.settings(srvCase.srv.URL))
				p, err := tc.build(cfg)
				if err != nil {
					t.Fatalf("build: %v", err)
				}
				rep, ok := p.(apiprovider.ReputationProvider)
				if !ok {
					t.Fatal("adapter does not implement reputation")
				}

				v, repErr := rep.Reputation(context.Background(), apiprovider.DomainSubject("x.example"))

				observed := map[string]string{
					"verdict (%v)":  fmt.Sprintf("%v", v),
					"verdict (%+v)": fmt.Sprintf("%+v", v),
					"verdict.Raw":   v.Raw,
					"descriptor":    fmt.Sprintf("%+v", p.Descriptor()),
				}
				if repErr != nil {
					observed["error"] = repErr.Error()
					observed["error (%+v)"] = fmt.Sprintf("%+v", repErr)
				}
				// Enrichment too, where the adapter offers it.
				if enr, ok := p.(apiprovider.Enricher); ok {
					e, enrErr := enr.Enrich(context.Background(), apiprovider.DomainSubject("x.example"))
					observed["enrichment"] = fmt.Sprintf("%+v", e)
					if enrErr != nil {
						observed["enrichment error"] = enrErr.Error()
					}
				}

				for where, s := range observed {
					if strings.Contains(s, theSecret) {
						t.Errorf("the credential appears in %s: %s", where, s)
					}
				}
			})
		}
	}
}

// Every registered adapter must describe itself completely. A provider whose
// privacy note nobody wrote is one an operator cannot make an informed
// decision about, and this feature's whole premise is informed consent.
func TestEveryTemplateIsCompleteEnoughToChooseFrom(t *testing.T) {
	templates := apiprovider.Templates()
	if len(templates) < 3 {
		t.Fatalf("only %d templates registered", len(templates))
	}
	for _, tpl := range templates {
		t.Run(tpl.Kind, func(t *testing.T) {
			if tpl.DisplayName == "" {
				t.Error("no display name")
			}
			if len(tpl.Summary) < 20 {
				t.Errorf("summary is too short to be useful: %q", tpl.Summary)
			}
			if len(tpl.PrivacyNote) < 40 {
				t.Errorf("privacy note is too short to be an informed disclosure: %q", tpl.PrivacyNote)
			}
			if len(tpl.Capabilities) == 0 {
				t.Error("no capabilities")
			}
			for _, c := range tpl.Capabilities {
				if !c.Valid() {
					t.Errorf("unknown capability %q", c)
				}
			}
			if tpl.SecretRequired && tpl.SecretLabel == "" {
				t.Error("a credential is required and the form does not say what to call it")
			}
			if tpl.DefaultTimeoutMS <= 0 || tpl.DefaultRatePerMinute <= 0 || tpl.DefaultCacheTTLSecs <= 0 {
				t.Errorf("incomplete defaults: timeout=%d rate=%d ttl=%d",
					tpl.DefaultTimeoutMS, tpl.DefaultRatePerMinute, tpl.DefaultCacheTTLSecs)
			}
			// Every declared field needs a label, or the form renders a box
			// with no idea what goes in it.
			for _, f := range tpl.Fields {
				if f.Key == "" || f.Label == "" {
					t.Errorf("field %+v has no key or label", f)
				}
			}
		})
	}
}

// The descriptor and the template must agree. They are written in the same
// file and drift the first time somebody edits one of them.
func TestDescriptorsAgreeWithTemplates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	for _, tpl := range apiprovider.Templates() {
		settings := map[string]string{"base_url": srv.URL, "url": srv.URL + "?d={subject}"}
		p, err := apiprovider.New(tpl.Kind, instance(t, srv, settings))
		if err != nil {
			t.Fatalf("%s: build: %v", tpl.Kind, err)
		}
		d := p.Descriptor()
		if d.Kind != tpl.Kind {
			t.Errorf("%s: descriptor kind is %q", tpl.Kind, d.Kind)
		}
		if d.DisplayName != tpl.DisplayName {
			t.Errorf("%s: descriptor says %q, template says %q", tpl.Kind, d.DisplayName, tpl.DisplayName)
		}
		if d.PrivacyNote != tpl.PrivacyNote {
			t.Errorf("%s: privacy notes differ between descriptor and template", tpl.Kind)
		}
		// Everything the descriptor claims must actually be implemented.
		for _, c := range d.Capabilities {
			if !apiprovider.Supports(p, c) {
				t.Errorf("%s: declares %s but does not implement the interface", tpl.Kind, c)
			}
		}
	}
}

func TestAdaptersAreSafeToUseConcurrently(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(vtBody(70, 0, 0, 0)))
	}))
	defer srv.Close()

	p, _ := newVirusTotal(instance(t, srv, map[string]string{"base_url": srv.URL}))
	rep := p.(apiprovider.ReputationProvider)

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				if _, err := rep.Reputation(context.Background(),
					apiprovider.DomainSubject(fmt.Sprintf("host%d-%d.example", n, j))); err != nil {
					t.Errorf("reputation: %v", err)
					return
				}
			}
		}(i)
	}
	wg.Wait()
}
