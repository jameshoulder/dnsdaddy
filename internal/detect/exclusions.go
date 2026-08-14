package detect

import (
	"github.com/jameshoulder/dnsdaddy/internal/domainutil"
)

// Exclusions are the parent domains whose normal operation looks exactly like
// the behaviour these detectors hunt for.
//
// This list is not a security control and it is not an allow-list for
// blocking: nothing here changes whether a domain resolves. It changes whether
// a *behavioural finding* is raised, and it exists because the alternative is
// a detector that fires on every mail server and every antivirus client on the
// network, which is a detector nobody leaves switched on.
//
// Each entry is here because the service genuinely encodes data into DNS
// labels, or genuinely generates enormous numbers of unique subdomains, as its
// designed mode of operation. That is the same mechanism a DNS tunnel uses.
// The difference is the destination, not the shape of the traffic — which is
// worth understanding, because it is also the reason an attacker who tunnels
// through a domain that looks like a CDN is harder to catch. That residual
// risk is documented in docs/detection/dns-tunnelling.md.
//
// Operators can extend this through detection.excluded_domains in the config.
// Matching is suffix-based, so an entry covers the domain and everything below
// it.
var defaultExclusions = []string{
	// --- Reverse DNS ---------------------------------------------------------
	// A PTR lookup for an IPv6 address is 32 single-hex-character labels. That
	// is maximal unique-subdomain cardinality and near-maximal entropy by
	// construction, and it is completely routine. Excluding .arpa outright is
	// the single most important entry in this list.
	"arpa",

	// --- Reputation and anti-spam lookups ------------------------------------
	// DNSBL and file-reputation services work by encoding the thing being
	// queried — an IP address, a file hash, a URL fingerprint — into the label
	// and looking it up. A mail server or an endpoint agent doing its job
	// produces thousands of unique, high-entropy subdomains under one parent.
	// This is DNS tunnelling's exact traffic profile, performed legitimately.
	"spamhaus.org",
	"zen.spamhaus.org",
	"dbl.spamhaus.org",
	"barracudacentral.org",
	"spamcop.net",
	"sorbs.net",
	"surbl.org",
	"uribl.com",
	"mailspike.net",
	"senderscore.com",
	"invaluement.com",
	"abuseat.org",
	"sophosxl.net",
	"avqs.mcafee.com",
	"avts.mcafee.com",
	"mcafee.com",
	"trendmicro.com",
	"cloudmark.com",
	"mailshell.net",
	"brightcloud.com",
	"webrootcloudav.com",
	"sophos.com",
	"eset.com",
	"kaspersky-labs.com",
	"bitdefender.net",
	"avast.com",
	"avira-update.com",

	// --- Content delivery and cloud edge -------------------------------------
	// Per-request and per-object hostnames are how these networks steer
	// traffic. High cardinality is the product working correctly.
	"akamai.net",
	"akamaiedge.net",
	"akamaized.net",
	"edgekey.net",
	"edgesuite.net",
	"cloudfront.net",
	"cloudflare.net",
	"cloudflare-dns.com",
	"fastly.net",
	"fastlylb.net",
	"azureedge.net",
	"azurefd.net",
	"trafficmanager.net",
	"msedge.net",
	"llnwd.net",
	"b-cdn.net",
	"cdn77.org",
	"stackpathdns.com",
	"amazonaws.com",
	"googleusercontent.com",
	"googlevideo.com",
	"1e100.net",
	"gvt1.com",
	"gvt2.com",
	"apple-dns.net",
	"aaplimg.com",
	"cdn-apple.com",

	// --- Certificate status and transparency ---------------------------------
	// OCSP and CRL endpoints are queried constantly and encode serials.
	"ocsp.digicert.com",
	"pki.goog",
	"ocsp.sectigo.com",
	"ocsp.usertrust.com",
	"letsencrypt.org",

	// --- Telemetry with per-event hostnames ----------------------------------
	"events.data.microsoft.com",
	"nel.cloudflare.com",
	"crashlytics.com",
	"sentry.io",
}

// txtInfrastructurePrefixes are the label prefixes that mark a TXT lookup as
// routine mail, certificate, or domain-verification infrastructure.
//
// SPF, DKIM, DMARC, MTA-STS and ACME all publish policy in TXT records, and a
// mail server or certificate agent queries them constantly. Counting those as
// "unusual TXT activity" would bury the one TXT lookup that matters under
// several thousand that never do.
var txtInfrastructurePrefixes = []string{
	"_dmarc",
	"_domainkey",
	"_spf",
	"_acme-challenge",
	"_mta-sts",
	"_smtp",
	"_tlsa",
	"_dnsauth",
	"_amazonses",
	"_atproto",
	"_github-challenge",
	"_globalsign-domain-verification",
	"selector1",
	"selector2",
	"default._domainkey",
}

// Exclusions decides whether a name is exempt from behavioural findings.
type Exclusions struct {
	suffixes map[string]bool
}

// NewExclusions builds an exclusion set from the defaults plus any extra
// operator-supplied domains.
//
// Passing skipDefaults gives an operator a completely bare set. That is
// supported because a lab wants to see detections fire on traffic the defaults
// would suppress, and because an operator who does not run mail or antivirus
// on the monitored network may reasonably want the tightest possible net. It
// is not the default: on a real network the defaults are what make the
// detectors usable.
func NewExclusions(extra []string, skipDefaults bool) *Exclusions {
	e := &Exclusions{suffixes: make(map[string]bool, len(defaultExclusions)+len(extra))}
	if !skipDefaults {
		for _, d := range defaultExclusions {
			if n := domainutil.Normalize(d); n != "" {
				e.suffixes[n] = true
			}
		}
	}
	for _, d := range extra {
		if n := domainutil.Normalize(d); n != "" {
			e.suffixes[n] = true
		}
	}
	return e
}

// Excluded reports whether name sits at or beneath an excluded domain.
// It allocates nothing: the suffix walk re-slices the name in place.
func (e *Exclusions) Excluded(name string) bool {
	if e == nil || len(e.suffixes) == 0 || name == "" {
		return false
	}
	found := false
	domainutil.Suffixes(name, func(suffix string) bool {
		if e.suffixes[suffix] {
			found = true
			return true
		}
		return false
	})
	return found
}

// Len reports how many suffixes are excluded, for the detector catalogue.
func (e *Exclusions) Len() int {
	if e == nil {
		return 0
	}
	return len(e.suffixes)
}

// isTXTInfrastructure reports whether a TXT query is one of the standard
// mail, certificate, or verification lookups.
func isTXTInfrastructure(name string) bool {
	for _, label := range labelsOf(name) {
		if len(label) == 0 || label[0] != '_' {
			// Selector labels for DKIM do not always start with an underscore
			// (selector1.example.com), so check those explicitly below.
			continue
		}
		for _, p := range txtInfrastructurePrefixes {
			if label == p {
				return true
			}
		}
	}
	// DKIM selectors: anything of the form <selector>._domainkey.<domain>.
	for _, label := range labelsOf(name) {
		if label == "_domainkey" {
			return true
		}
	}
	return false
}
