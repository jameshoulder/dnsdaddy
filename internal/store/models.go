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
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Location  string    `json:"location"`
	PolicyID  string    `json:"policyId"`
	Token     string    `json:"token,omitempty"`
	Enabled   bool      `json:"enabled"`
	CIDRs     []string  `json:"cidrs"`
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
	// DNSSEC is the validation status the upstream reported. DNS Daddy
	// forwards rather than validating locally, so this is the upstream's
	// conclusion, not ours. See the DNSSEC* constants.
	DNSSEC string `json:"dnssec,omitempty"`
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
)

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
