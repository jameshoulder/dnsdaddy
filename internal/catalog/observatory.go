package catalog

import (
	"slices"
	"strings"
)

// The DNS Daddy Threat Observatory is our own threat-intelligence platform.
// Unlike every other source in this catalog it is operated by us, which is
// exactly why it ships disabled: a self-hosted install must keep working, and
// keep blocking, with no runtime dependency on anything DNS Daddy runs. An
// operator who wants our intelligence turns it on deliberately.
//
// See docs/threat-intel.md for the endpoint contract these constants target.
const (
	// ObservatoryBaseURL is the root of the Observatory's public API.
	ObservatoryBaseURL = "https://threats.dnsdaddy.dev"

	// ObservatoryFeedURL serves the machine-readable indicator list used for
	// blocking. It is the only endpoint DNS Daddy needs.
	ObservatoryFeedURL = ObservatoryBaseURL + "/api/v1/feed.json"

	// ObservatoryFeedID is the catalog ID of the seeded Observatory feed.
	ObservatoryFeedID = "dnsdaddy-observatory"

	// ObservatorySource is the value the feed document carries in its "source"
	// field. A document claiming to be something else is still parsed — this is
	// for logging, not authentication; TLS is what says who served the file.
	ObservatorySource = "dnsdaddy-threat-observatory"
)

// observatoryCategories maps the labels the Observatory puts on an indicator
// onto the categories a DNS Daddy policy can enable.
//
// The Observatory classifies more finely than a policy needs to: an operator
// ticks "Malware", not "loader" and "stealer" and "dropper" separately. Keeping
// the translation here rather than in the parser means the mapping is auditable
// next to the category definitions it targets, and a new Observatory label is a
// one-line change rather than a parser change.
var observatoryCategories = map[string]string{
	// Command-and-control.
	"c2":                  "c2",
	"c&c":                 "c2",
	"cnc":                 "c2",
	"command-and-control": "c2",
	"botnet":              "c2",
	"rat":                 "c2",

	// Malware distribution.
	"malware":     "malware",
	"trojan":      "malware",
	"ransomware":  "malware",
	"loader":      "malware",
	"dropper":     "malware",
	"stealer":     "malware",
	"infostealer": "malware",
	"exploit-kit": "malware",
	"payload":     "malware",

	// Credential theft and impersonation.
	"phishing":              "phishing",
	"credential-harvesting": "phishing",
	"credential-theft":      "phishing",
	"brand-impersonation":   "phishing",
	"scam":                  "phishing",

	// Coin mining.
	"cryptomining":  "cryptomining",
	"cryptojacking": "cryptomining",
	"coinminer":     "cryptomining",
	"miner":         "cryptomining",
	"mining-pool":   "cryptomining",

	// Registration age.
	"newly-registered": "newly-registered",
	"nrd":              "newly-registered",
}

// MapObservatoryCategory translates one Observatory category label into a DNS
// Daddy category, reporting whether it is one we understand.
func MapObservatoryCategory(label string) (string, bool) {
	key := strings.ToLower(strings.TrimSpace(label))
	key = strings.ReplaceAll(key, "_", "-")
	key = strings.ReplaceAll(key, " ", "-")
	if key == "" {
		return "", false
	}
	if id, ok := observatoryCategories[key]; ok {
		return id, true
	}
	// A label that is already one of our own IDs needs no translation.
	if ValidCategory(key) {
		return key, true
	}
	return "", false
}

// MapObservatoryCategories translates an indicator's labels into the DNS Daddy
// categories they name, most severe first and without duplicates. It returns
// nil when none of the labels is one we understand.
//
// Every mapped category is returned, not just the most severe one. An indicator
// tagged both "malware" and "c2" is genuinely both, and a policy enabling
// either one has to block it — collapsing the two here would decide, on the
// operator's behalf and invisibly, that one of the categories they ticked does
// not apply.
func MapObservatoryCategories(labels []string) []string {
	var out []string
	for _, l := range labels {
		id, ok := MapObservatoryCategory(l)
		if !ok {
			continue
		}
		if slices.Contains(out, id) {
			continue
		}
		out = append(out, id)
	}
	// Most severe first, so the caller can take the head as the primary claim.
	slices.SortFunc(out, func(a, b string) int {
		return CategoryPriority(a) - CategoryPriority(b)
	})
	return out
}

// CategoryPriority returns a category's position in the canonical ordering,
// where a lower number is more severe. Unknown categories sort last.
func CategoryPriority(id string) int {
	for i, c := range Categories {
		if c.ID == id {
			return i
		}
	}
	return len(Categories)
}
