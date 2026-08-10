package api

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// hostileValues are the strings a report must survive. Feed and network names
// are free text set through the management API; blocked domains come from the
// query log, which stores the raw qname when normalisation fails.
var hostileValues = []struct {
	name  string
	value string
}{
	{"table pipe", "a|b"},
	{"escaped newline sequence", `a\nb`},
	{"real newline", "a\nb"},
	{"carriage return", "a\rb"},
	{"CRLF header injection attempt", "a\r\nX-Injected: yes"},
	{"script tag", "<script>alert(1)</script>"},
	{"img onerror", `<img src=x onerror=alert(1)>`},
	{"anchor tag", `<a href="https://evil.example">click</a>`},
	{"backslash", `a\b`},
	{"backtick", "a`b`c"},
	{"row break", "a|b\n|---|\n| injected |"},
	{"html entity", "&lt;script&gt;"},
	{"null byte", "a\x00b"},
	{"bare control chars", "a\x01\x02b"},
}

func TestEscapeMarkdownCell(t *testing.T) {
	for _, tt := range hostileValues {
		t.Run(tt.name, func(t *testing.T) {
			got := escapeMarkdownCell(tt.value)

			if strings.ContainsAny(got, "\n\r") {
				t.Errorf("escaped value still contains a line break: %q", got)
			}
			// An unescaped pipe would end the cell and shift every column
			// after it.
			if strings.Contains(strings.ReplaceAll(got, `\|`, ""), "|") {
				t.Errorf("escaped value still contains an unescaped pipe: %q", got)
			}
			if strings.ContainsAny(got, "<>") {
				t.Errorf("escaped value still contains raw HTML delimiters: %q", got)
			}
			for _, r := range got {
				if r < 0x20 || r == 0x7f {
					t.Errorf("escaped value still contains control character %#U: %q", r, got)
				}
			}
		})
	}
}

func TestEscapeMarkdownCellKeepsOrdinaryTextReadable(t *testing.T) {
	tests := []struct{ in, want string }{
		{"Head Office", "Head Office"},
		{"URLhaus", "URLhaus"},
		{"  padded  ", "padded"},
		{"", ""},
		{"Malware & Phishing", "Malware &amp; Phishing"},
		{"a|b", `a\|b`},
	}
	for _, tt := range tests {
		if got := escapeMarkdownCell(tt.in); got != tt.want {
			t.Errorf("escapeMarkdownCell(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// A backtick cannot be escaped inside a code span, so such values must fall
// back to a plain escaped cell rather than breaking out of the span.
func TestMarkdownCode(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"ordinary domain", "evil.example", "`evil.example`"},
		{"pipe is escaped inside the span", "a|b.example", "`a\\|b.example`"},
		{"backtick falls back to a plain cell", "a`b", "a\\`b"},
		{"empty is a dash", "", "—"},
		{"newline is flattened", "a\nb.example", "`a b.example`"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := markdownCode(tt.in); got != tt.want {
				t.Errorf("markdownCode(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// The report must stay a valid Markdown table no matter what is in the
// database, and must never carry executable HTML through to the reader.
func TestRenderMarkdownNeutralisesHostileValues(t *testing.T) {
	for _, tt := range hostileValues {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Now()
			out := renderMarkdown(ReportSummary{
				From: now.AddDate(0, 0, -7), To: now, PeriodDays: 7,
				GeneratedAt: now, Version: "test",
				Categories: []CategoryBreakdown{{Category: tt.value, Label: tt.value, Count: 1}},
				Networks: []ReportNetwork{{
					Name: tt.value, Location: tt.value, Policy: tt.value, Queries: 1, Blocked: 1,
				}},
				TopDomains: []store.TopBlocked{{
					Domain: tt.value, Category: tt.value, Count: 1, LastSeen: now,
				}},
				Feeds: []ReportFeed{{Name: tt.value, Category: tt.value, Domains: 1}},
			})

			// The report's own text contains no angle brackets, so any that
			// survive came from the data and could open an HTML tag. Checking
			// for the character itself is stricter than blocklisting tag names,
			// and does not mistake inert text like "onerror=" — harmless once
			// its bracket is escaped — for executable markup.
			if strings.ContainsAny(out, "<>") {
				t.Errorf("hostile value produced a raw HTML delimiter in the report:\n%s", out)
			}

			// Every table row must keep the column count its header declared,
			// or a pipe or newline has broken out of its cell.
			assertTableRowsIntact(t, out)
		})
	}
}

// assertTableRowsIntact walks the rendered Markdown and checks that each row
// under a table header has the same number of cells as that header.
func assertTableRowsIntact(t *testing.T, out string) {
	t.Helper()

	cells := func(line string) int {
		return strings.Count(strings.ReplaceAll(line, `\|`, ""), "|")
	}

	want := 0
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "|") {
			want = 0
			continue
		}
		if strings.HasPrefix(line, "|---") {
			continue // the alignment row
		}
		if want == 0 {
			want = cells(line) // a header row establishes the width
			continue
		}
		if got := cells(line); got != want {
			t.Errorf("table row has %d cell delimiters, want %d: %q", got, want, line)
		}
	}
}

func TestReportMarkdownResponseHeaders(t *testing.T) {
	h := newHarness(t)
	h.login()

	resp, raw := h.do("GET", "/api/v1/reports/summary?format=markdown", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", resp.StatusCode, raw)
	}

	assertHeader(t, resp, "Content-Type", "text/markdown; charset=utf-8")
	assertHeader(t, resp, "X-Content-Type-Options", "nosniff")

	cd := resp.Header.Get("Content-Disposition")
	if !strings.HasPrefix(cd, `attachment; filename="dns-daddy-report-`) {
		t.Errorf("Content-Disposition = %q, want an attachment with a fixed-format filename", cd)
	}
	// The filename is built from a date format with no request input, so no
	// caller can steer it. Verify no header carries a stray CR or LF.
	for name, values := range resp.Header {
		for _, v := range values {
			if strings.ContainsAny(v, "\r\n") {
				t.Errorf("header %s contains a line break: %q", name, v)
			}
		}
	}
}

func TestMetricsResponseHeaders(t *testing.T) {
	h := newHarness(t)
	h.login()

	resp, raw := h.do("GET", "/metrics", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", resp.StatusCode, raw)
	}

	assertHeader(t, resp, "Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	assertHeader(t, resp, "X-Content-Type-Options", "nosniff")

	// Prometheus exposition format: every line is a comment, a sample, or
	// blank. A label value that broke out of its quoting would show up here.
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.Contains(line, " ") {
			t.Errorf("metrics line is not a valid sample: %q", line)
		}
	}
	if !strings.Contains(string(raw), "# TYPE dnsdaddy_queries_total counter") {
		t.Error("metrics output is missing the expected TYPE declaration")
	}
}

func TestOpenAPIResponseHeaders(t *testing.T) {
	h := newHarness(t)

	resp, raw := h.do("GET", "/openapi.yaml", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	assertHeader(t, resp, "Content-Type", "application/yaml; charset=utf-8")
	assertHeader(t, resp, "X-Content-Type-Options", "nosniff")
	if cc := resp.Header.Get("Cache-Control"); cc == "" {
		t.Error("the OpenAPI document is served with no Cache-Control")
	}

	// The response is a static embedded asset: byte-identical to the file, and
	// carrying nothing from the request.
	if string(raw) != string(openAPISpec) {
		t.Error("the served OpenAPI document differs from the embedded spec")
	}
	if !strings.HasPrefix(string(raw), "openapi: 3.1.0") {
		t.Errorf("unexpected OpenAPI document start: %.40q", raw)
	}
}

func assertHeader(t *testing.T, resp *http.Response, name, want string) {
	t.Helper()
	if got := resp.Header.Get(name); got != want {
		t.Errorf("%s = %q, want %q", name, got, want)
	}
}
