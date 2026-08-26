// Package catalog defines the filtering categories DNS Daddy understands and
// the threat-intelligence feeds it ships with by default.
//
// Every default feed is a public, no-registration source. They are listed here
// rather than fetched from a DNS Daddy-operated index so that a self-hosted
// install has no runtime dependency on us, and so anyone can audit exactly
// where their blocking decisions come from. See docs/threat-intel.md.
//
// The one DNS Daddy-operated source, the Threat Observatory, is defined in
// observatory.go and ships disabled for exactly that reason: everything a
// default install blocks still comes from somewhere you can fetch yourself.
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
}

// Categories is the canonical, ordered category list.
var Categories = []Category{
	{
		ID:          "malware",
		Label:       "Malware",
		Description: "Domains distributing malicious payloads or hosting exploit kits.",
		Reason:      "Domain is on a malware distribution list",
		DefaultOn:   true,
	},
	{
		ID:          "phishing",
		Label:       "Phishing",
		Description: "Credential harvesting and brand-impersonation domains.",
		Reason:      "Domain is on a phishing list",
		DefaultOn:   true,
	},
	{
		ID:          "c2",
		Label:       "C2 / Botnet",
		Description: "Command-and-control infrastructure that compromised devices call home to.",
		Reason:      "Domain is known command-and-control infrastructure",
		DefaultOn:   true,
	},
	{
		ID:          "cryptomining",
		Label:       "Cryptomining",
		Description: "Mining pools and in-browser cryptojacking scripts.",
		Reason:      "Domain is a cryptomining pool or cryptojacking host",
		DefaultOn:   true,
	},
	{
		ID:          "newly-registered",
		Label:       "Newly registered",
		Description: "Domains registered in the last 30 days, heavily over-represented in attacks.",
		Reason:      "Domain was registered very recently",
		DefaultOn:   false,
	},
	{
		ID:          "ads",
		Label:       "Ads & tracking",
		Description: "Advertising and cross-site tracking endpoints.",
		Reason:      "Domain is an advertising or tracking endpoint",
		DefaultOn:   false,
	},
	{
		ID:          "adult",
		Label:       "Adult content",
		Description: "Pornography and adult material.",
		Reason:      "Domain serves adult content",
		DefaultOn:   false,
	},
	{
		ID:          "gambling",
		Label:       "Gambling",
		Description: "Online casinos, betting, and gambling affiliates.",
		Reason:      "Domain is a gambling site",
		DefaultOn:   false,
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
		// Our own platform, and the only feed here that is. It is seeded
		// disabled on purpose: the point of listing every source in this file
		// is that a self-hosted install depends on nothing DNS Daddy operates,
		// and a default that quietly reached back to us would break that
		// promise for every install that never read this comment. Turn it on
		// deliberately — see docs/threat-intel.md.
		ID:       ObservatoryFeedID,
		Name:     "DNS Daddy Threat Observatory",
		URL:      ObservatoryFeedURL,
		Category: "malware",
		Format:   "observatory",
		Enabled:  false,
	},
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
