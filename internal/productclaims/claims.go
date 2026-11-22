// Package productclaims loads the reviewed product-claims inventory, checks
// that referenced paths exist, and exports website/markdown artefacts from the
// same data. Maturity is never treated as proof of independent review.
package productclaims

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// InventoryFile is the reviewed source relative to the repository root.
const InventoryFile = "docs/product-claims.json"

// WebsiteArtifact is the static website-consumable export relative to the repo root.
const WebsiteArtifact = "docs/website/product-claims.json"

// MarkdownArtifact is the generated documentation table relative to the repo root.
const MarkdownArtifact = "docs/product-claims-table.md"

// Inventory is the reviewed product-claims document.
type Inventory struct {
	SchemaVersion          int          `json:"schemaVersion"`
	Title                  string       `json:"title"`
	Description            string       `json:"description"`
	ReviewedSourceRevision string       `json:"reviewedSourceRevision"`
	ReviewedSourceLabel    string       `json:"reviewedSourceLabel,omitempty"`
	ReviewedAt             string       `json:"reviewedAt"`
	Dependencies           []Dependency `json:"dependencies,omitempty"`
	Claims                 []Claim      `json:"claims"`
}

// Dependency records an open-PR or external blocker without advertising it as released.
type Dependency struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	URL    string `json:"url,omitempty"`
	Note   string `json:"note,omitempty"`
}

// Claim is one product statement with maturity kept separate from evidence strength.
type Claim struct {
	ID              string   `json:"id"`
	Title           string   `json:"title"`
	Maturity        string   `json:"maturity"`
	Availability    string   `json:"availability"`
	Scope           string   `json:"scope"`
	Caveats         []string `json:"caveats,omitempty"`
	Implementation  []string `json:"implementation,omitempty"`
	Documentation   []string `json:"documentation,omitempty"`
	Tests           []string `json:"tests,omitempty"`
	Critical        bool     `json:"critical,omitempty"`
	OpenPullRequest string   `json:"openPullRequest,omitempty"`
}

// WebsiteExport is the static artifact Lovable or other sites may import at build time.
type WebsiteExport struct {
	SchemaVersion         int            `json:"schemaVersion"`
	GeneratedFromRevision string         `json:"generatedFromRevision"`
	GeneratedAt           string         `json:"generatedAt"`
	Title                 string         `json:"title"`
	Description           string         `json:"description"`
	ImportGuidance        string         `json:"importGuidance"`
	CriticalClaimsDigest  string         `json:"criticalClaimsDigest"`
	OpenDependencies      []Dependency   `json:"openDependencies,omitempty"`
	Claims                []WebsiteClaim `json:"claims"`
}

// WebsiteClaim is a reduced, publishable claim row.
type WebsiteClaim struct {
	ID            string   `json:"id"`
	Title         string   `json:"title"`
	Maturity      string   `json:"maturity"`
	Availability  string   `json:"availability"`
	Scope         string   `json:"scope"`
	Caveats       []string `json:"caveats,omitempty"`
	Critical      bool     `json:"critical,omitempty"`
	Documentation []string `json:"documentation,omitempty"`
}

// Load reads and validates structural requirements of the inventory.
func Load(path string) (*Inventory, error) {
	// #nosec G304 -- Maintainer/CI path to the reviewed docs/product-claims.json
	// inventory (or an explicit -root). Not a remote-controlled inclusion.
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var inv Inventory
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&inv); err != nil {
		return nil, fmt.Errorf("decode product claims: %w", err)
	}
	if inv.SchemaVersion != 1 {
		return nil, fmt.Errorf("unsupported product-claims schemaVersion %d", inv.SchemaVersion)
	}
	if strings.TrimSpace(inv.ReviewedSourceRevision) == "" {
		return nil, fmt.Errorf("reviewedSourceRevision is required")
	}
	if len(inv.Claims) == 0 {
		return nil, fmt.Errorf("claims inventory is empty")
	}
	seen := map[string]struct{}{}
	for i, c := range inv.Claims {
		if c.ID == "" || c.Title == "" || c.Maturity == "" || c.Availability == "" || c.Scope == "" {
			return nil, fmt.Errorf("claim[%d] missing required fields", i)
		}
		switch c.Maturity {
		case "available", "experimental", "planned":
		default:
			return nil, fmt.Errorf("claim %s: invalid maturity %q", c.ID, c.Maturity)
		}
		switch c.Availability {
		case "main", "experimental", "planned", "open-pr":
		default:
			return nil, fmt.Errorf("claim %s: invalid availability %q", c.ID, c.Availability)
		}
		if _, ok := seen[c.ID]; ok {
			return nil, fmt.Errorf("duplicate claim id %q", c.ID)
		}
		seen[c.ID] = struct{}{}
		if c.Availability == "open-pr" && c.OpenPullRequest == "" {
			return nil, fmt.Errorf("claim %s: open-pr availability requires openPullRequest", c.ID)
		}
	}
	return &inv, nil
}

// CriticalDigest returns a stable digest over critical claim content so drift
// is detectable without embedding this commit's own hash into the inventory.
func (inv *Inventory) CriticalDigest() string {
	type row struct {
		ID           string
		Title        string
		Maturity     string
		Availability string
		Scope        string
		Caveats      []string
	}
	var rows []row
	for _, c := range inv.Claims {
		if !c.Critical {
			continue
		}
		caveats := append([]string(nil), c.Caveats...)
		sort.Strings(caveats)
		rows = append(rows, row{
			ID: c.ID, Title: c.Title, Maturity: c.Maturity,
			Availability: c.Availability, Scope: c.Scope, Caveats: caveats,
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	raw, err := json.Marshal(rows)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// CheckReferences verifies that every referenced path exists under root.
// Missing paths are returned as errors; empty implementation/tests lists are allowed.
func (inv *Inventory) CheckReferences(root string) []error {
	var errs []error
	check := func(claimID, kind, rel string) {
		rel = strings.TrimSpace(rel)
		if rel == "" {
			return
		}
		p := filepath.Join(root, filepath.FromSlash(rel))
		if _, err := os.Stat(p); err != nil {
			errs = append(errs, fmt.Errorf("claim %s %s %q: %v", claimID, kind, rel, err))
		}
	}
	for _, c := range inv.Claims {
		for _, p := range c.Implementation {
			check(c.ID, "implementation", p)
		}
		for _, p := range c.Documentation {
			check(c.ID, "documentation", p)
		}
		for _, p := range c.Tests {
			check(c.ID, "tests", p)
		}
	}
	return errs
}

// Website builds the static export for build-time import by marketing sites.
func (inv *Inventory) Website(generatedAt time.Time) WebsiteExport {
	out := WebsiteExport{
		SchemaVersion:         inv.SchemaVersion,
		GeneratedFromRevision: inv.ReviewedSourceRevision,
		GeneratedAt:           generatedAt.UTC().Format(time.RFC3339),
		Title:                 inv.Title,
		Description:           inv.Description,
		ImportGuidance: "Import this file at site build time from the repository " +
			"(for example docs/website/product-claims.json). Do not fetch an unauthenticated " +
			"operational endpoint from a live resolver. Treat availability open-pr as not released.",
		CriticalClaimsDigest: inv.CriticalDigest(),
	}
	for _, d := range inv.Dependencies {
		if strings.EqualFold(d.Status, "open") {
			out.OpenDependencies = append(out.OpenDependencies, d)
		}
	}
	for _, c := range inv.Claims {
		out.Claims = append(out.Claims, WebsiteClaim{
			ID:            c.ID,
			Title:         c.Title,
			Maturity:      c.Maturity,
			Availability:  c.Availability,
			Scope:         c.Scope,
			Caveats:       append([]string(nil), c.Caveats...),
			Critical:      c.Critical,
			Documentation: append([]string(nil), c.Documentation...),
		})
	}
	return out
}

// MarshalWebsite returns canonical JSON for the website artifact.
func (inv *Inventory) MarshalWebsite(generatedAt time.Time) ([]byte, error) {
	return json.MarshalIndent(inv.Website(generatedAt), "", "  ")
}

// MarkdownTable renders a documentation table from the inventory.
func (inv *Inventory) MarkdownTable() string {
	var b strings.Builder
	b.WriteString("<!-- Generated by `dnsdaddy claims export -format markdown`. Do not edit by hand. -->\n")
	b.WriteString("# Product claims table\n\n")
	b.WriteString("Generated from [`docs/product-claims.json`](product-claims.json). ")
	b.WriteString("Reviewed source revision: `")
	b.WriteString(inv.ReviewedSourceRevision)
	b.WriteString("`. Critical claims digest: `")
	b.WriteString(inv.CriticalDigest())
	b.WriteString("`.\n\n")
	b.WriteString("Maturity describes implementation status. It is **not** the strength of ")
	b.WriteString("validation evidence. An automated test is not an independent review.\n\n")
	if len(inv.Dependencies) > 0 {
		b.WriteString("## Open dependencies\n\n")
		for _, d := range inv.Dependencies {
			fmt.Fprintf(&b, "- **%s** (%s): %s", d.ID, d.Status, d.Note)
			if d.URL != "" {
				fmt.Fprintf(&b, " — %s", d.URL)
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	b.WriteString("| ID | Title | Maturity | Availability | Critical |\n")
	b.WriteString("|---|---|---|---|---|\n")
	claims := append([]Claim(nil), inv.Claims...)
	sort.Slice(claims, func(i, j int) bool { return claims[i].ID < claims[j].ID })
	for _, c := range claims {
		crit := "no"
		if c.Critical {
			crit = "yes"
		}
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s |\n",
			c.ID, escapeCell(c.Title), c.Maturity, c.Availability, crit)
	}
	b.WriteString("\n## Claim detail\n\n")
	for _, c := range claims {
		fmt.Fprintf(&b, "### `%s` — %s\n\n", c.ID, c.Title)
		fmt.Fprintf(&b, "- **Maturity:** %s\n- **Availability:** %s\n", c.Maturity, c.Availability)
		fmt.Fprintf(&b, "- **Scope:** %s\n", c.Scope)
		if len(c.Caveats) > 0 {
			b.WriteString("- **Caveats:**\n")
			for _, caveat := range c.Caveats {
				fmt.Fprintf(&b, "  - %s\n", caveat)
			}
		}
		if c.OpenPullRequest != "" {
			fmt.Fprintf(&b, "- **Open PR:** %s\n", c.OpenPullRequest)
		}
		b.WriteString("\n")
	}
	return b.String()
}

func escapeCell(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}

// WriteAtomic writes data to path with mode 0o644, replacing only on success.
func WriteAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	// #nosec G301 -- Public documentation artefacts under docs/ are world-readable by design.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".product-claims-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		tmp.Close()
		if !ok {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	// #nosec G302 -- Generated website/markdown claims artefacts are public docs (0644).
	if err := tmp.Chmod(0o644); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	ok = true
	return nil
}

// ArtefactsCurrent reports whether the generated website and markdown files
// match a fresh export. generatedAt is taken from the existing website file
// when present so timestamps do not create false drift; content is compared
// after normalising generatedAt.
func ArtefactsCurrent(root string, inv *Inventory) error {
	wantWebsite, err := inv.MarshalWebsite(time.Unix(0, 0).UTC())
	if err != nil {
		return err
	}
	// #nosec G304 -- Fixed relative artefact paths under the discovered repo root.
	gotWebsite, err := os.ReadFile(filepath.Join(root, WebsiteArtifact))
	if err != nil {
		return fmt.Errorf("%s: %w", WebsiteArtifact, err)
	}
	gotNorm, err := normalizeWebsiteGeneratedAt(gotWebsite)
	if err != nil {
		return err
	}
	if !bytes.Equal(gotNorm, wantWebsite) {
		return fmt.Errorf("%s is stale; run: dnsdaddy claims export", WebsiteArtifact)
	}
	wantMD := []byte(inv.MarkdownTable())
	// #nosec G304 -- Fixed relative artefact paths under the discovered repo root.
	gotMD, err := os.ReadFile(filepath.Join(root, MarkdownArtifact))
	if err != nil {
		return fmt.Errorf("%s: %w", MarkdownArtifact, err)
	}
	if !bytes.Equal(gotMD, wantMD) {
		return fmt.Errorf("%s is stale; run: dnsdaddy claims export", MarkdownArtifact)
	}
	return nil
}

func normalizeWebsiteGeneratedAt(raw []byte) ([]byte, error) {
	var export WebsiteExport
	if err := json.Unmarshal(raw, &export); err != nil {
		return nil, err
	}
	export.GeneratedAt = time.Unix(0, 0).UTC().Format(time.RFC3339)
	return json.MarshalIndent(export, "", "  ")
}

// Export writes website and markdown artefacts under root.
func Export(root string, inv *Inventory, now time.Time, w io.Writer) error {
	website, err := inv.MarshalWebsite(now)
	if err != nil {
		return err
	}
	website = append(website, '\n')
	if err := WriteAtomic(filepath.Join(root, WebsiteArtifact), website); err != nil {
		return err
	}
	md := []byte(inv.MarkdownTable())
	if err := WriteAtomic(filepath.Join(root, MarkdownArtifact), md); err != nil {
		return err
	}
	if w != nil {
		fmt.Fprintf(w, "Wrote %s\nWrote %s\nCritical claims digest: %s\n",
			WebsiteArtifact, MarkdownArtifact, inv.CriticalDigest())
	}
	return nil
}

// Check loads the inventory, verifies references and generated artefacts.
func Check(root string) error {
	inv, err := Load(filepath.Join(root, InventoryFile))
	if err != nil {
		return err
	}
	if errs := inv.CheckReferences(root); len(errs) > 0 {
		var b strings.Builder
		b.WriteString("product claims reference check failed:\n")
		for _, e := range errs {
			fmt.Fprintf(&b, "  - %v\n", e)
		}
		return fmt.Errorf("%s", b.String())
	}
	if err := ArtefactsCurrent(root, inv); err != nil {
		return err
	}
	return nil
}

// FindRepoRoot walks up from start looking for docs/product-claims.json.
func FindRepoRoot(start string) (string, error) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, InventoryFile)); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("could not find %s above %s", InventoryFile, start)
		}
		dir = parent
	}
}
