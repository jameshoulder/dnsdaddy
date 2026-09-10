package store

import "time"

// BlockMode decides what a blocked query is answered with.
type BlockMode string

const (
	// BlockNXDOMAIN answers NXDOMAIN. Fastest for clients to give up on.
	BlockNXDOMAIN BlockMode = "nxdomain"
	// BlockZeroIP answers 0.0.0.0 / ::. Useful when clients retry hard on NXDOMAIN.
	BlockZeroIP BlockMode = "zeroip"
	// BlockRefused answers REFUSED.
	BlockRefused BlockMode = "refused"
)

// Valid reports whether m is a block mode the resolver understands.
func (m BlockMode) Valid() bool {
	switch m {
	case BlockNXDOMAIN, BlockZeroIP, BlockRefused:
		return true
	}
	return false
}

// Policy is a named set of filtering rules that networks are assigned to.
type Policy struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Categories  []string  `json:"categories"`
	BlockMode   BlockMode `json:"blockMode"`

	// SafeSearch is stored and returned but never read by the resolver: no
	// search engine is rewritten and nothing about resolution changes when it
	// is true. It is deliberately kept rather than deleted — the REST API
	// promises fields are never removed within v1, and dropping the column
	// would break the "downgrade is a binary swap" migration guarantee — but
	// it is marked deprecated in the OpenAPI schema so a client reading only
	// the specification cannot mistake it for a working control.
	//
	// Deprecated: not enforced. See docs/roadmap.md.
	SafeSearch bool `json:"safeSearch"`

	LogQueries bool      `json:"logQueries"`
	IsDefault  bool      `json:"isDefault"`
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`

	// Populated by ListPolicies / GetPolicy.
	AllowDomains []string `json:"allowDomains"`
	BlockDomains []string `json:"blockDomains"`
	Assigned     int      `json:"assigned"`
}

// Network is a site, VLAN, or roaming profile that queries are attributed to.
type Network struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Location string `json:"location"`
	PolicyID string `json:"policyId"`
	Token    string `json:"token,omitempty"`
	Enabled  bool   `json:"enabled"`

	// AllowResolver is whether this network's addresses may query DNS Daddy
	// at all — a separate question from PolicyID, which decides what happens
	// to those queries once they are accepted.
	//
	// Two fields rather than one because they really are two decisions: a
	// network can exist for attribution alone (its addresses reach the
	// resolver through the bootstrap ACL, or through a broader permitted
	// range) and a permitted network still needs a policy. What changes here
	// is that the dashboard now sets both, in one place, instead of setting
	// the first and leaving the second to an environment variable and a
	// container restart.
	AllowResolver bool `json:"allowResolver"`

	CIDRs []string `json:"cidrs"`

	// AcknowledgedPublicCIDRs are the publicly routable ranges an operator has
	// explicitly affirmed. Permitting a public range requires one; it is
	// remembered per range so an unrelated later edit does not re-prompt,
	// while adding a new public range does.
	AcknowledgedPublicCIDRs []string `json:"acknowledgedPublicCidrs"`

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// Feed is a threat-intelligence source.
type Feed struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	URL         string     `json:"url"`
	Category    string     `json:"category"`
	Format      string     `json:"format"`
	Enabled     bool       `json:"enabled"`
	Builtin     bool       `json:"builtin"`
	DomainCount int        `json:"domainCount"`
	LastRefresh *time.Time `json:"lastRefreshedAt"`
	// LastSuccess is the last download that actually produced usable content,
	// which is not the same as LastRefresh: a feed erroring since Tuesday has
	// a refresh timestamp of a minute ago and intelligence three days old.
	// Nil means this feed has never downloaded successfully.
	LastSuccess *time.Time `json:"lastSuccessAt"`
	LastStatus  string     `json:"lastStatus"`
	LastError   string     `json:"lastError"`
	ETag        string     `json:"-"`
	CreatedAt   time.Time  `json:"createdAt"`
	UpdatedAt   time.Time  `json:"updatedAt"`
}

// QueryEvent is one resolved (or blocked) DNS question.
type QueryEvent struct {
	ID         int64     `json:"id"`
	Time       time.Time `json:"time"`
	ClientIP   string    `json:"clientIp"`
	ClientName string    `json:"clientName"`
	NetworkID  string    `json:"networkId"`
	Domain     string    `json:"domain"`
	QType      string    `json:"qtype"`
	Action     string    `json:"action"`
	Reason     string    `json:"reason"`
	Category   string    `json:"category"`
	Source     string    `json:"source"`
	Proto      string    `json:"proto"`
	ElapsedMS  int       `json:"elapsedMs"`
	Cached     bool      `json:"cached"`
	// DNSSEC is the security state recorded for this answer.
	//
	// Which vocabulary it uses depends on who reached the verdict, and the two
	// are deliberately different words. "validated" and "unvalidated" describe
	// what a *forwarder* observed: an upstream set the AD bit, or it did not.
	// "secure", "insecure", "bogus" and "indeterminate" are this deployment's
	// own conclusions, reached by Daddybound authenticating the records
	// against a local trust anchor.
	//
	// Keeping them apart is the point. A row that used one word for both would
	// let a claim by a machine somebody else runs be read, later, as something
	// this resolver established. See the DNSSEC* constants.
	DNSSEC string `json:"dnssec,omitempty"`
	// DNSSECReason is the typed reason behind DNSSEC where the verdict was
	// local, empty otherwise. Daddybound's own taxonomy; nothing branches on
	// it, it is there so an operator can ask why.
	DNSSECReason string `json:"dnssecReason,omitempty"`

	// Resolver names the backend that answered: "daddybound-native" or
	// "forward". Empty on rows written before the distinction existed.
	//
	// Part of what makes a query explainable. "How did DNS Daddy resolve
	// this?" is a question an operator should be able to answer from the row
	// rather than by remembering what the configuration said at the time.
	Resolver string `json:"resolver,omitempty"`

	// DNSSECObservationID correlates this query with the local Daddybound
	// observation of it, or is empty when local validation was off, not
	// attempted, or dropped because the observation queue was full.
	//
	// The correlation exists because the two rows are written by different
	// writers at different times: the answer is already on its way to the
	// client before validation starts. Matching them on name and time instead
	// would silently mis-attribute a verdict whenever the same name was asked
	// twice in the same instant, which is exactly what a busy resolver does.
	DNSSECObservationID string `json:"-"`
}

// DNSSEC validation statuses recorded against a query.
//
// These describe what the *upstream* resolver concluded, because that is the
// only thing a forwarder can observe. In particular DNSSECUnvalidated does not
// mean "provably unsigned" — it means no AD bit came back, which covers an
// unsigned zone and an upstream that does not validate equally. Claiming to
// distinguish them would be claiming to do validation we do not do.
const (
	// DNSSECValidated: the upstream set the AD bit, having validated the
	// answer against the chain of trust.
	DNSSECValidated = "validated"
	// DNSSECUnvalidated: an answer came back without the AD bit.
	DNSSECUnvalidated = "unvalidated"
	// DNSSECServfail: the upstream returned SERVFAIL. A failed DNSSEC
	// validation is one cause among several; see internal/detect.
	DNSSECServfail = "servfail"

	// The states below are this deployment's own verdicts, reached by
	// Daddybound authenticating records it fetched itself. They are spelled
	// differently from the three above on purpose: those describe what an
	// upstream claimed, these describe what this resolver established, and a
	// shared word would let the first be mistaken for the second.
	//
	// DNSSECSecureLocal: the records authenticate to a configured trust
	// anchor.
	DNSSECSecureLocal = "secure"
	// DNSSECInsecureLocal: an authenticated proof shows the data lies in an
	// unsigned part of the namespace. A proof, not an absence of one.
	DNSSECInsecureLocal = "insecure"
	// DNSSECBogusLocal: a secure delegation was established and the data
	// failed to validate under it. The client received SERVFAIL.
	DNSSECBogusLocal = "bogus"
	// DNSSECIndeterminateLocal: Daddybound could not decide, for a reason
	// about itself rather than about the data — no trust anchor covering the
	// name, an algorithm this build cannot read, a limit reached. The answer
	// was served with AD clear.
	DNSSECIndeterminateLocal = "indeterminate"
)

// LocalDNSSECStatuses are the states only local validation can produce.
func LocalDNSSECStatuses() []string {
	return []string{
		DNSSECSecureLocal, DNSSECInsecureLocal,
		DNSSECBogusLocal, DNSSECIndeterminateLocal,
	}
}

// Client is an operator-assigned friendly name for a device IP.
type Client struct {
	IP        string    `json:"ip"`
	Name      string    `json:"name"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// APIToken is a machine credential for the management API. The secret itself is
// only ever returned once, at creation.
type APIToken struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt *time.Time `json:"lastUsedAt"`
	Secret     string     `json:"secret,omitempty"`
}

// Actions recorded in the query log.
const (
	ActionAllowed = "allowed"
	ActionBlocked = "blocked"
	ActionError   = "error"
)
