package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/catalog"
	"github.com/jameshoulder/dnsdaddy/internal/store"
	"github.com/jameshoulder/dnsdaddy/internal/version"
)

// ReportSummary is the evidence pack: what was blocked, where, and how often.
//
// This exists because the question that actually gets DNS filtering bought is
// "can you show me what we're blocking?" — from a director, an insurer, or a
// Cyber Essentials assessor. A JSON blob is for tooling; the Markdown rendering
// is meant to be pasted straight into an email.
type ReportSummary struct {
	GeneratedAt time.Time           `json:"generatedAt"`
	PeriodDays  int                 `json:"periodDays"`
	From        time.Time           `json:"from"`
	To          time.Time           `json:"to"`
	Version     string              `json:"version"`
	Totals      store.Totals        `json:"totals"`
	BlockRate   float64             `json:"blockRate"`
	Categories  []CategoryBreakdown `json:"categories"`
	TopDomains  []store.TopBlocked  `json:"topBlockedDomains"`
	Networks    []ReportNetwork     `json:"networks"`
	Feeds       []ReportFeed        `json:"feeds"`
	Blocklist   int                 `json:"blocklistDomains"`
}

// ReportNetwork is per-site activity within the reporting period.
type ReportNetwork struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Location string `json:"location"`
	Policy   string `json:"policy"`
	Queries  int64  `json:"queries"`
	Blocked  int64  `json:"blocked"`
}

// ReportFeed records which intelligence sources were in force, so the reader
// can see where the blocking decisions came from.
type ReportFeed struct {
	Name        string     `json:"name"`
	Category    string     `json:"category"`
	Domains     int        `json:"domains"`
	LastRefresh *time.Time `json:"lastRefreshedAt"`
}

func (a *API) handleReportSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	days := intParam(r, "days", 7)
	if days <= 0 || days > 90 {
		days = 7
	}
	from := time.Now().AddDate(0, 0, -days)

	totals, err := a.Store.TotalsSince(ctx, from)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	cats, err := a.Store.ThreatsByCategory(ctx, from)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	top, err := a.Store.TopBlockedDomains(ctx, from, 20)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	networks, err := a.Store.ListNetworks(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	activity, err := a.Store.NetworkActivitySince(ctx, from)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	policies, err := a.Store.ListPolicies(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	feeds, err := a.Store.ListFeeds(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	policyNames := map[string]string{}
	for _, p := range policies {
		policyNames[p.ID] = p.Name
	}

	summary := ReportSummary{
		GeneratedAt: time.Now().UTC(),
		PeriodDays:  days,
		From:        from.UTC(),
		To:          time.Now().UTC(),
		Version:     version.String(),
		Totals:      totals,
		Blocklist:   a.Lists.Load().Len(),
		TopDomains:  top,
	}
	if totals.Queries > 0 {
		summary.BlockRate = round2(float64(totals.Blocked) / float64(totals.Queries) * 100)
	}

	for _, c := range cats {
		label := c.Category
		if cat, ok := catalog.CategoryByID(c.Category); ok {
			label = cat.Label
		} else if c.Category == "custom" {
			label = "Custom block-list"
		}
		summary.Categories = append(summary.Categories, CategoryBreakdown{
			Category: c.Category, Label: label, Count: c.Count,
		})
	}

	for _, n := range networks {
		act := activity[n.ID]
		summary.Networks = append(summary.Networks, ReportNetwork{
			ID:       n.ID,
			Name:     n.Name,
			Location: n.Location,
			Policy:   policyNames[n.PolicyID],
			Queries:  act.Queries,
			Blocked:  act.Blocked,
		})
	}

	indexed := a.Lists.Load().CountsByFeed()
	for _, f := range feeds {
		if !f.Enabled {
			continue
		}
		summary.Feeds = append(summary.Feeds, ReportFeed{
			Name:        f.Name,
			Category:    f.Category,
			Domains:     indexed[f.ID],
			LastRefresh: f.LastRefresh,
		})
	}

	// Go marshals a nil slice to null, and every one of these is built by
	// appending — so a deployment that has not blocked anything yet, which is
	// every deployment on its first day, sent the dashboard
	// "categories": null. It calls .map on that, and the Reports page died
	// with "Cannot read properties of null" at exactly the moment a new user
	// went looking for evidence the product works.
	//
	// The spec says these are arrays. Empty is an array.
	summary.Categories = nonNilSlice(summary.Categories)
	summary.TopDomains = nonNilSlice(summary.TopDomains)
	summary.Networks = nonNilSlice(summary.Networks)
	summary.Feeds = nonNilSlice(summary.Feeds)

	if strings.EqualFold(r.URL.Query().Get("format"), "markdown") {
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Disposition",
			fmt.Sprintf("attachment; filename=\"dns-daddy-report-%s.md\"", time.Now().Format("2006-01-02")))
		// nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
		// Markdown, not HTML: html/template would escape the report into
		// unreadability, and the response is never rendered as a document —
		// Content-Type is text/markdown, nosniff is set, and it is served as an
		// attachment with a fixed date-formatted filename.
		//
		// Every database-controlled value in the body goes through
		// escapeMarkdownCell or markdownCode first, which neutralise table
		// pipes, row-breaking newlines, and raw HTML delimiters. That covers
		// feed names and categories, network names, locations, policy names,
		// category labels, and blocked domains. Proven by
		// TestRenderMarkdownNeutralisesHostileValues and TestEscapeMarkdownCell.
		if _, err := w.Write([]byte(renderMarkdown(summary))); err != nil {
			a.Log.Debug("write markdown report", "error", err)
		}
		return
	}

	writeJSON(w, http.StatusOK, summary)
}

// renderMarkdown formats the summary for forwarding to a non-technical reader.
func renderMarkdown(s ReportSummary) string {
	var b strings.Builder

	fmt.Fprintf(&b, "# Protective DNS report\n\n")
	fmt.Fprintf(&b, "**Period:** %s to %s (%d days)  \n",
		s.From.Format("2 January 2006"), s.To.Format("2 January 2006"), s.PeriodDays)
	fmt.Fprintf(&b, "**Generated:** %s  \n", s.GeneratedAt.Format("2 January 2006 15:04 MST"))
	fmt.Fprintf(&b, "**Produced by:** DNS Daddy %s\n\n", s.Version)

	fmt.Fprintf(&b, "## Summary\n\n")
	fmt.Fprintf(&b, "| Measure | Value |\n|---|---|\n")
	fmt.Fprintf(&b, "| DNS queries handled | %s |\n", humanInt(s.Totals.Queries))
	fmt.Fprintf(&b, "| Threats blocked | %s |\n", humanInt(s.Totals.Blocked))
	fmt.Fprintf(&b, "| Proportion blocked | %.2f%% |\n", s.BlockRate)
	fmt.Fprintf(&b, "| Domains on active blocklists | %s |\n", humanInt(int64(s.Blocklist)))
	fmt.Fprintf(&b, "| Networks protected | %d |\n\n", len(s.Networks))

	if len(s.Categories) > 0 {
		fmt.Fprintf(&b, "## What was blocked\n\n| Category | Blocked |\n|---|---|\n")
		for _, c := range s.Categories {
			fmt.Fprintf(&b, "| %s | %s |\n", escapeMarkdownCell(c.Label), humanInt(c.Count))
		}
		b.WriteString("\n")
	}

	if len(s.Networks) > 0 {
		fmt.Fprintf(&b, "## By network\n\n| Network | Location | Policy | Queries | Blocked |\n|---|---|---|---|---|\n")
		for _, n := range s.Networks {
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n",
				escapeMarkdownCell(n.Name), orDash(n.Location), orDash(n.Policy),
				humanInt(n.Queries), humanInt(n.Blocked))
		}
		b.WriteString("\n")
	}

	if len(s.TopDomains) > 0 {
		fmt.Fprintf(&b, "## Most frequently blocked domains\n\n| Domain | Category | Times blocked | Last seen |\n|---|---|---|---|\n")
		for _, d := range s.TopDomains {
			label := d.Category
			if c, ok := catalog.CategoryByID(d.Category); ok {
				label = c.Label
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n",
				markdownCode(d.Domain), orDash(label), humanInt(d.Count),
				d.LastSeen.Format("2 Jan 15:04"))
		}
		b.WriteString("\n")
	}

	if len(s.Feeds) > 0 {
		fmt.Fprintf(&b, "## Threat intelligence in force\n\n| Source | Category | Domains contributed | Last updated |\n|---|---|---|---|\n")
		for _, f := range s.Feeds {
			last := "never"
			if f.LastRefresh != nil {
				last = f.LastRefresh.Format("2 Jan 2006 15:04")
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n",
				escapeMarkdownCell(f.Name), escapeMarkdownCell(f.Category),
				humanInt(int64(f.Domains)), last)
		}
		b.WriteString("\n")
	}

	b.WriteString("---\n\n")
	b.WriteString("Protective DNS blocks connections to known-malicious domains at the point of name resolution, ")
	b.WriteString("before a device can reach the destination. It covers every device on the network, including ")
	b.WriteString("printers, cameras, and equipment that cannot run endpoint security software.\n")

	return b.String()
}

// escapeMarkdownCell makes an arbitrary string safe to place in a Markdown
// table cell.
//
// Almost everything in this report is free text from the database: feed names
// and categories, network names, locations, and policy names are all set
// through the management API, and blocked domains come from the query log,
// which records the raw qname whenever normalisation fails
// (dnsserver.Handler falls back to it). A subdomain of an already-blocked
// domain is enough to get an attacker-chosen string into that table.
//
// Three things go wrong if such a value is interpolated raw:
//
//   - A pipe ends the cell early and corrupts every following column.
//   - A newline ends the row and destroys the table below it.
//   - Most Markdown renderers pass raw HTML straight through, so an
//     <img onerror=…> in a feed name becomes script execution in whoever opens
//     the report — typically someone senior, in a different application, days
//     later, with no reason to distrust it.
//
// Proven by TestEscapeMarkdownCell and TestRenderMarkdownNeutralisesHostileValues.
func escapeMarkdownCell(s string) string {
	s = flattenControl(s)

	var b strings.Builder
	b.Grow(len(s) + 8)
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '|':
			// GFM's documented table escape; works inside other inline spans.
			b.WriteString(`\|`)
		case '`':
			b.WriteString("\\`")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '&':
			// Escaped so a value containing "&lt;" cannot round-trip back into
			// a literal "<" in the rendered output.
			b.WriteString("&amp;")
		default:
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

// markdownCode renders s as a code span, which is how domains are presented.
//
// Backslash escapes do not apply inside a code span, so nothing in it can be
// escaped in place: a backtick would close the span, and while a compliant
// renderer escapes HTML inside a code span, that is a property of the renderer
// rather than of the document. A blocked domain is attacker-influenced — the
// query log stores the raw qname when normalisation fails — so anything but
// plain text falls back to a fully escaped cell. Less pretty, safe under any
// renderer, and never reached by a normal domain.
func markdownCode(s string) string {
	s = flattenControl(s)
	if s == "" {
		return "—"
	}
	if strings.ContainsAny(s, "`<>&") {
		return escapeMarkdownCell(s)
	}
	// GFM honours \| inside code spans; the delimiter is all that is left.
	return "`" + strings.ReplaceAll(s, "|", `\|`) + "`"
}

// flattenControl turns row-breaking whitespace into spaces and drops the
// remaining control characters, so later escaping cannot be split across lines.
func flattenControl(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', '\t', '\v', '\f':
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

// orDash escapes a value for a table cell, showing an em dash when it is empty.
func orDash(s string) string {
	if e := escapeMarkdownCell(s); e != "" {
		return e
	}
	return "—"
}

// humanInt formats an integer with thousands separators.
func humanInt(n int64) string {
	neg := n < 0
	if neg {
		n = -n
	}
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		if neg {
			return "-" + s
		}
		return s
	}

	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	if neg {
		return "-" + string(out)
	}
	return string(out)
}
