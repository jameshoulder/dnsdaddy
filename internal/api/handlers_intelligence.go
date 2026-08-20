package api

import (
	"net/http"
	"strings"

	"github.com/jameshoulder/dnsdaddy/internal/catalog"
	"github.com/jameshoulder/dnsdaddy/internal/detect"
	"github.com/jameshoulder/dnsdaddy/internal/domainutil"
)

// intelligenceSource is one feed's claim on a domain.
type intelligenceSource struct {
	Feed     string `json:"feed"`
	FeedID   string `json:"feedId"`
	Category string `json:"category"`
	// Deciding marks the claim that sets the block reason. Feeds are indexed
	// in category-priority order and the first claim wins, so this is the most
	// severe classification any source gave the name.
	Deciding bool `json:"deciding"`
}

// intelligenceResponse answers "what does DNS Daddy know about this name, and
// how sure is it?".
//
// It reports evidence, not a verdict on the domain's character. Whether a
// given client would actually be blocked additionally depends on which
// categories that client's policy enables, which is why Blocked is described
// as "listed" here and the enabling categories are named rather than assumed.
type intelligenceResponse struct {
	Domain string `json:"domain"`
	// MatchedName is the name that actually matched, which may be a parent of
	// the queried name: listing evil.com also covers login.evil.com. Stating
	// it prevents the most common misreading of a block.
	MatchedName string               `json:"matchedName,omitempty"`
	Listed      bool                 `json:"listed"`
	Category    string               `json:"category,omitempty"`
	Reason      string               `json:"reason,omitempty"`
	Sources     []intelligenceSource `json:"sources"`
	// IndependentSources is how many distinct feeds listed the name. Two or
	// more is corroboration; one is a single opinion.
	IndependentSources int `json:"independentSources"`
	// Assessment states the strength of the evidence in words, in the
	// deliberately cautious register the rest of the product uses.
	Assessment string `json:"assessment"`
	// Caveat records what this answer does not establish. It is always
	// populated: intelligence is a claim by a third party at a point in time,
	// and presenting it without that framing is how a listing becomes a fact.
	Caveat string `json:"caveat"`
	// NameAnalysis is what the name looks like on its own, independent of any
	// listing. It is computed from the name alone — no state, no lookups — and
	// is the weakest evidence here by a wide margin. Reported for every name,
	// listed or not, because "not on a feed" is the case where how a name
	// looks is the only thing there is to go on.
	NameAnalysis detect.NameAssessment `json:"nameAnalysis"`
}

// handleDomainIntelligence explains what threat intelligence DNS Daddy holds
// for one name.
//
// This reads the in-memory index, which is the same data the resolver consults,
// so the answer cannot drift from what would actually happen to a query. It
// does no network I/O of any kind.
func (a *API) handleDomainIntelligence(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimSpace(r.URL.Query().Get("domain"))
	if raw == "" {
		writeError(w, http.StatusBadRequest, "domain is required")
		return
	}
	if len(raw) > 512 {
		writeError(w, http.StatusBadRequest, "domain is too long")
		return
	}
	domain := domainutil.Normalize(raw)
	if domain == "" {
		writeError(w, http.StatusBadRequest, "domain is not a valid DNS name")
		return
	}

	resp := intelligenceResponse{
		Domain:  domain,
		Sources: []intelligenceSource{},
		Caveat: "Threat intelligence records that a third party observed this name " +
			"and classified it, at some point. It is evidence, not proof of current " +
			"behaviour: feeds carry false positives, and a name can be cleaned up " +
			"or taken over after it is listed.",
	}

	ix := a.Lists.Load()
	entry, listed := ix.Lookup(domain)
	if !listed {
		resp.Assessment = "No threat intelligence in the enabled feeds mentions this name. " +
			"That is an absence of evidence, not evidence that the name is safe: " +
			"DNS Daddy only knows what the feeds you have enabled contain."
		resp.NameAnalysis = detect.AssessName(domain)
		writeJSON(w, http.StatusOK, resp)
		return
	}

	resp.Listed = true
	resp.Category = entry.Category
	resp.Reason = catalog.CategoryReason(entry.Category)

	sources := ix.Sources(domain)
	for _, s := range sources {
		resp.Sources = append(resp.Sources, intelligenceSource{
			Feed:     s.FeedName,
			FeedID:   s.FeedID,
			Category: s.Category,
			Deciding: s == entry,
		})
	}
	resp.IndependentSources = len(sources)
	resp.MatchedName, _ = ix.MatchedName(domain)
	resp.Assessment = assessment(len(sources), resp.MatchedName, domain)
	resp.NameAnalysis = detect.AssessName(domain)

	writeJSON(w, http.StatusOK, resp)
}

func assessment(sources int, matched, domain string) string {
	var b strings.Builder
	switch {
	case sources >= 2:
		b.WriteString(plural(sources))
		b.WriteString(" independent feeds list this name, which is stronger " +
			"evidence than any single list. Feeds that republish each other are " +
			"not independent, so check the sources below rather than counting them.")
	default:
		b.WriteString("One feed lists this name. A single source is a lead " +
			"rather than a corroborated finding.")
	}
	if matched != "" && matched != domain {
		b.WriteString(" The listing is on the parent name " + matched +
			", so every name under it is covered.")
	}
	return b.String()
}

func plural(n int) string {
	switch n {
	case 2:
		return "Two"
	case 3:
		return "Three"
	case 4:
		return "Four"
	}
	return "Several"
}
