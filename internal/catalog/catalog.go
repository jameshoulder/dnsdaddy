// Package catalog defines the filtering categories DNS Daddy understands and
// the threat-intelligence feeds it ships with by default.
//
// Every default feed is a public, no-registration source. They are listed here
// rather than fetched from a DNS Daddy-operated index so that a self-hosted
// install has no runtime dependency on us, and so anyone can audit exactly
// where their blocking decisions come from. See docs/threat-intel.md.
//
// No built-in feed contacts a DNS Daddy-operated service. External APIs are
// separately configured by each operator with their own credentials.
package catalog

// Category identifies a class of domain that a policy can choose to block.
type Category struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Description string `json:"description"`
	// Reason is the plain-English explanation shown in query logs and block
	// pages. NEO's users need to be able to read it back to him over the phone.
	Reason string `json:"reason"`
	// DefaultOn marks categories included in the seeded "Standard business" policy.
	DefaultOn bool `json:"defaultOn"`
	// Class says what kind of decision blocking this category is. See the
	// Class* constants: a security category names something a curator judged
	// hostile, a preference category is content the operator chose not to
	// serve. A "threats blocked" figure that counted both would be the
	// overstatement this field exists to prevent.
	Class string `json:"class"`
}

// What kind of decision a block in a category is.
//
// The split is presentation-facing and deliberately coarse. It decides which
// headline a blocked query is counted under, and nothing else: enforcement
// treats every enabled category the same.
const (
	// ClassSecurity: a curated source asserts the domain is hostile —
	// malware, phishing, command and control, cryptojacking.
	ClassSecurity = "security"
	// ClassPrecaution: a risk indicator rather than a verdict. A domain
	// registered last week is over-represented in attacks and is also every
	// new business; blocking it is a precaution the operator chose.
	ClassPrecaution = "precaution"
	// ClassPreference: content the operator chose not to serve. Not a threat.
	ClassPreference = "preference"
	// ClassCustom: an operator's own block-list entry. Recorded on a query
	// as the category "custom"; it is not a catalogue category.
	ClassCustom = "custom"
	// ClassUnclassified: a category this build does not recognise — one a
	// newer build wrote, or one an external provider named — or no category
	// at all. Counted rather than dropped, so the classes still sum to the
	// total, and never counted as security.
	ClassUnclassified = "unclassified"
)

// BlockClasses is every class, in report order, so a consumer can render a
// stable set of rows and a count of zero is distinguishable from an absent
// class.
func BlockClasses() []string {
	return []string{ClassSecurity, ClassPrecaution, ClassPreference, ClassCustom, ClassUnclassified}
}

// ClassOfBlock says which class a blocked query's recorded category falls in.
//
// From the recorded category and nothing else: the classification is of the
// string the query log holds, so a report over old rows classifies them by
// what was written at the time, not by what a feed says today.
func ClassOfBlock(category string) string {
	if category == ClassCustom {
		return ClassCustom
	}
	if c, ok := CategoryByID(category); ok && c.Class != "" {
		return c.Class
	}
	return ClassUnclassified
}

// Categories is the canonical, ordered category list.
var Categories = []Category{
	{
		ID:          "malware",
		Label:       "Malware",
		Description: "Domains distributing malicious payloads or hosting exploit kits.",
		Reason:      "Domain is on a malware distribution list",
		DefaultOn:   true,
		Class:       ClassSecurity,
	},
	{
		ID:          "phishing",
		Label:       "Phishing",
		Description: "Credential harvesting and brand-impersonation domains.",
		Reason:      "Domain is on a phishing list",
		DefaultOn:   true,
		Class:       ClassSecurity,
	},
	{
		ID:          "c2",
		Label:       "C2 / Botnet",
		Description: "Command-and-control infrastructure that compromised devices call home to.",
		Reason:      "Domain is known command-and-control infrastructure",
		DefaultOn:   true,
		Class:       ClassSecurity,
	},
	{
		ID:          "cryptomining",
		Label:       "Cryptomining",
		Description: "Mining pools and in-browser cryptojacking scripts.",
		Reason:      "Domain is a cryptomining pool or cryptojacking host",
		DefaultOn:   true,
		Class:       ClassSecurity,
	},
	{
		ID:          "newly-registered",
		Label:       "Newly registered",
		Description: "Domains registered in the last 30 days, heavily over-represented in attacks.",
		Reason:      "Domain was registered very recently",
		DefaultOn:   false,
		Class:       ClassPrecaution,
	},
	{
		ID:          "ads",
		Label:       "Ads & tracking",
		Description: "Advertising and cross-site tracking endpoints.",
		Reason:      "Domain is an advertising or tracking endpoint",
		DefaultOn:   false,
		Class:       ClassPreference,
	},
	{
		ID:          "adult",
		Label:       "Adult content",
		Description: "Pornography and adult material.",
		Reason:      "Domain serves adult content",
		DefaultOn:   false,
		Class:       ClassPreference,
	},
	{
		ID:          "gambling",
		Label:       "Gambling",
		Description: "Online casinos, betting, and gambling affiliates.",
		Reason:      "Domain is a gambling site",
		DefaultOn:   false,
		Class:       ClassPreference,
	},
}

// CategoryByID returns the named category and whether it exists.
func CategoryByID(id string) (Category, bool) {
	for _, c := range Categories {
		if c.ID == id {
			return c, true
		}
	}
	return Category{}, false
}

// ValidCategory reports whether id names a known category.
func ValidCategory(id string) bool {
	_, ok := CategoryByID(id)
	return ok
}

// DefaultCategories returns the category IDs enabled in the seeded
// "Standard business" policy.
func DefaultCategories() []string {
	var out []string
	for _, c := range Categories {
		if c.DefaultOn {
			out = append(out, c.ID)
		}
	}
	return out
}

// CategoryReason returns the plain-English block reason for a category,
// falling back to a generic phrasing for unknown IDs.
func CategoryReason(id string) string {
	if c, ok := CategoryByID(id); ok {
		return c.Reason
	}
	return "Domain is on a blocklist"
}

// Feed describes a default threat-intelligence source.
type Feed struct {
	ID   string
	Name string
	URL  string
	// Category is the category every domain from this feed is filed under.
	// The "observatory" format is the one exception: its indicators carry
	// their own categories, and this acts as the fallback for an indicator
	// whose labels we do not recognise.
	Category string
	Format   string
	Enabled  bool
}

// DefaultFeeds are seeded on first run. The four security categories are
// enabled; content-filtering feeds are seeded disabled so a fresh install
// blocks threats and nothing else.
var DefaultFeeds = []Feed{
	{
		ID:       "urlhaus",
		Name:     "abuse.ch URLhaus",
		URL:      "https://urlhaus.abuse.ch/downloads/hostfile/",
		Category: "malware",
		Format:   "hosts",
		Enabled:  true,
	},
	{
		ID:       "hagezi-tif-mini",
		Name:     "HaGeZi Threat Intelligence Feeds (mini)",
		URL:      "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/tif.mini.txt",
		Category: "malware",
		Format:   "domains",
		Enabled:  true,
	},
	{
		ID:       "phishing-army",
		Name:     "Phishing Army (extended)",
		URL:      "https://phishing.army/download/phishing_army_blocklist_extended.txt",
		Category: "phishing",
		Format:   "domains",
		Enabled:  true,
	},
	{
		ID:       "blocklistproject-phishing",
		Name:     "The Block List Project — Phishing",
		URL:      "https://blocklistproject.github.io/Lists/phishing.txt",
		Category: "phishing",
		Format:   "hosts",
		Enabled:  true,
	},
	{
		ID:       "botnet-c2",
		Name:     "The Block List Project — Malware & C2",
		URL:      "https://blocklistproject.github.io/Lists/malware.txt",
		Category: "c2",
		Format:   "hosts",
		Enabled:  true,
	},
	{
		ID:       "coinblocker",
		Name:     "CoinBlockerLists",
		URL:      "https://raw.githubusercontent.com/ZeroDot1/CoinBlockerLists/master/list.txt",
		Category: "cryptomining",
		Format:   "domains",
		Enabled:  true,
	},
	{
		ID:       "nrd-30day",
		Name:     "Newly registered domains (30 day)",
		URL:      "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/nrds.30-onlydomains.txt",
		Category: "newly-registered",
		Format:   "domains",
		Enabled:  false,
	},
	{
		ID:       "stevenblack-ads",
		Name:     "StevenBlack unified hosts (ads & tracking)",
		URL:      "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
		Category: "ads",
		Format:   "hosts",
		Enabled:  false,
	},
	{
		ID:       "blocklistproject-porn",
		Name:     "The Block List Project — Adult",
		URL:      "https://blocklistproject.github.io/Lists/porn.txt",
		Category: "adult",
		Format:   "hosts",
		Enabled:  false,
	},
	{
		ID:       "blocklistproject-gambling",
		Name:     "The Block List Project — Gambling",
		URL:      "https://blocklistproject.github.io/Lists/gambling.txt",
		Category: "gambling",
		Format:   "hosts",
		Enabled:  false,
	},
}
