package catalog

import "strings"

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

// BestObservatoryCategory picks one category from an indicator's labels, using
// the canonical Categories ordering — so a domain tagged both "c2" and
// "malware" is reported as malware.
//
// That is the same ordering that decides which feed claims a domain shared
// between two lists, and using it here keeps the two consistent: a domain has
// one category whether it arrived on two feeds or on one indicator with two
// labels. The block reason in the query log is what an operator reads back to
// a user over the phone, and it should not depend on which path the domain
// took to get into the index.
func BestObservatoryCategory(labels []string) (string, bool) {
	best := ""
	bestRank := len(Categories)
	for _, l := range labels {
		id, ok := MapObservatoryCategory(l)
		if !ok {
			continue
		}
		if r := CategoryPriority(id); r < bestRank {
			best, bestRank = id, r
		}
	}
	return best, best != ""
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

// Observatory severities, most severe first. These mirror the "severity" field
// on an indicator.
var observatorySeverities = []string{"low", "medium", "high", "critical"}

// SeverityRank scores an Observatory severity so a minimum-severity floor can
// be applied. Higher is more severe; an unrecognised or absent severity scores
// 0, which callers treat as "unknown" rather than "lowest".
//
// That distinction matters. Dropping an indicator because a field we expected
// was missing would quietly lose protection over a schema gap, which is the
// wrong way round for a security control.
func SeverityRank(severity string) int {
	s := strings.ToLower(strings.TrimSpace(severity))
	for i, name := range observatorySeverities {
		if s == name {
			return i + 1
		}
	}
	return 0
}

// ValidSeverity reports whether s names an Observatory severity. The empty
// string is valid and means "no floor".
func ValidSeverity(s string) bool {
	return strings.TrimSpace(s) == "" || SeverityRank(s) > 0
}

// SeverityNames returns the recognised severities, least severe first.
func SeverityNames() []string {
	out := make([]string, len(observatorySeverities))
	copy(out, observatorySeverities)
	return out
}
