package store

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/clientacl"
)

// ListNetworks returns every network with its CIDR list attached.
func (s *Store) ListNetworks(ctx context.Context) ([]Network, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, location, policy_id, COALESCE(token, ''), enabled, allow_resolver, created_at, updated_at
		FROM networks ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Network
	byID := map[string]int{}
	for rows.Next() {
		var (
			n                Network
			enabled, allow   int
			created, updated int64
		)
		if err := rows.Scan(&n.ID, &n.Name, &n.Location, &n.PolicyID, &n.Token,
			&enabled, &allow, &created, &updated); err != nil {
			return nil, err
		}
		n.Enabled = enabled == 1
		n.AllowResolver = allow == 1
		n.CreatedAt = fromUnixMilli(created)
		n.UpdatedAt = fromUnixMilli(updated)
		n.CIDRs = []string{}
		n.AcknowledgedPublicCIDRs = []string{}
		byID[n.ID] = len(out)
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	crows, err := s.db.QueryContext(ctx,
		"SELECT network_id, cidr, public_ack FROM network_cidrs ORDER BY cidr")
	if err != nil {
		return nil, err
	}
	defer crows.Close()
	for crows.Next() {
		var (
			nid, cidr string
			ack       int
		)
		if err := crows.Scan(&nid, &cidr, &ack); err != nil {
			return nil, err
		}
		i, ok := byID[nid]
		if !ok {
			continue
		}
		out[i].CIDRs = append(out[i].CIDRs, cidr)
		if ack == 1 {
			out[i].AcknowledgedPublicCIDRs = append(out[i].AcknowledgedPublicCIDRs, cidr)
		}
	}
	return out, crows.Err()
}

// GetNetwork returns a single network by ID.
func (s *Store) GetNetwork(ctx context.Context, id string) (Network, error) {
	all, err := s.ListNetworks(ctx)
	if err != nil {
		return Network{}, err
	}
	for _, n := range all {
		if n.ID == id {
			return n, nil
		}
	}
	return Network{}, ErrNotFound
}

// NetworkInput carries the mutable fields of a network.
//
// Pointers throughout, so a PATCH that mentions only one field leaves the rest
// alone. That matters more than usual for AllowResolver: a client updating a
// network's name must not silently revoke its resolver access because it did
// not think to send the field.
type NetworkInput struct {
	Name     *string
	Location *string
	PolicyID *string
	CIDRs    *[]string
	Enabled  *bool

	// AllowResolver permits this network's addresses to query the resolver.
	AllowResolver *bool

	// PublicAck is the operator's affirmation, made in this request, that the
	// publicly routable ranges it results in may reach the resolver.
	//
	// Request-scoped rather than stored directly: what is persisted is the set
	// of ranges that were acknowledged, so a later edit that touches nothing
	// public does not ask again, and one that introduces a new public range
	// does. An affirmation that a *different* range was safe is not an
	// affirmation about this one.
	PublicAck *bool
}

// ErrPublicAckRequired reports that permitting these ranges needs an explicit
// acknowledgement. It is a distinct type so the API can answer with the
// offending ranges rather than only with prose, and the dashboard can name
// them in its confirmation.
type ErrPublicAckRequired struct {
	CIDRs []string
}

func (e *ErrPublicAckRequired) Error() string {
	return fmt.Sprintf("%s is publicly routable: permitting DNS queries from it means DNS Daddy "+
		"will accept requests from the internet. Confirm you intend this, and make sure your "+
		"VPS or cloud firewall restricts TCP and UDP port 53 to addresses you trust — DNS Daddy "+
		"does not change your provider firewall.", strings.Join(e.CIDRs, ", "))
}

// PublicCIDRs returns the ranges needing acknowledgement.
func (e *ErrPublicAckRequired) PublicCIDRs() []string { return append([]string(nil), e.CIDRs...) }

// resolverAccessPlan is the validated outcome of a write, holding which ranges
// end up acknowledged.
type resolverAccessPlan struct {
	acked map[string]bool
}

// planResolverAccess enforces the resolver-access rules server-side.
//
// Server-side, and in the store rather than in a handler, because this is the
// rule that keeps DNS Daddy from becoming an open resolver: any future caller
// — a second API version, a CLI, a test fixture, an import — goes through
// here. UI validation is a convenience for the person typing; it is not a
// control.
//
// The rules, in the order they are checked:
//
//  1. A network that is not permitted to resolve needs no checks at all. In
//     particular 0.0.0.0/0 remains a legal *policy* range, because "everything
//     that is already allowed in gets this policy" is a reasonable thing to
//     express and rejecting it would break existing configurations.
//  2. A default route may never be permitted. There is already an authority
//     for "I intend to run a public resolver" — dns.allow_public_resolver, set
//     in configuration with a restart attached — and a second, easier route to
//     the same outcome through a web form would make it decorative.
//  3. A publicly routable range needs the operator's affirmation, either
//     carried in this request or remembered from when they made it.
//
// otherPermittedCIDRs returns the ranges every *other* enabled, permitted
// network contributes, read inside the caller's transaction.
//
// The open-resolver rule is about the ACL the dashboard produces, not about one
// row: two networks holding 0.0.0.0/1 and 128.0.0.0/1 admit the whole internet
// between them while each looks unremarkable on its own.
func otherPermittedCIDRs(ctx context.Context, tx *sql.Tx, exceptID string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT c.cidr FROM network_cidrs c
		  JOIN networks n ON n.id = c.network_id
		 WHERE n.enabled = 1 AND n.allow_resolver = 1 AND c.cidr <> '' AND n.id <> ?`, exceptID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func planResolverAccess(allow bool, cidrs []string, alreadyAcked map[string]bool, ackNow bool, otherPermitted []string) (resolverAccessPlan, error) {
	plan := resolverAccessPlan{acked: map[string]bool{}}
	if !allow {
		// Acknowledgements are still carried forward: revoking access and
		// restoring it later should not re-prompt for a range the operator
		// already affirmed, and nothing is exposed by remembering it.
		for c := range alreadyAcked {
			plan.acked[c] = true
		}
		// An affirmation made now is recorded too, even though this write
		// grants nothing. Staging a network disabled — or permitted but
		// switched off — and enabling it later is one intention, and asking
		// again at the moment it takes effect would be the same re-prompt the
		// per-range memory exists to avoid. Recording it admits nobody: only
		// enabled, permitted networks reach the ACL at all.
		if ackNow {
			for _, raw := range cidrs {
				if p, err := clientacl.ParsePrefix(raw); err == nil && clientacl.PrefixIsPublic(p) {
					plan.acked[p.String()] = true
				}
			}
		}
		return plan, nil
	}

	// The aggregate first, because a set can be an open resolver without any
	// member of it being one.
	aggregate := make([]netip.Prefix, 0, len(cidrs)+len(otherPermitted))
	for _, raw := range append(append([]string(nil), cidrs...), otherPermitted...) {
		if p, err := clientacl.ParsePrefix(raw); err == nil {
			aggregate = append(aggregate, p)
		}
	}
	if clientacl.CoversEntireFamily(aggregate) {
		return plan, fmt.Errorf(
			"the networks permitted after this change would together allow DNS queries from " +
				"every address on the internet, which is what an open resolver is — even though " +
				"no single range says so. DNS Daddy will not do that from the dashboard: an open " +
				"resolver is found and conscripted into amplification attacks within days. If " +
				"you genuinely intend to run one, set dns.allow_public_resolver " +
				"(DNSDADDY_ALLOW_PUBLIC_RESOLVER) in configuration, where it is a deliberate act " +
				"with a restart attached")
	}

	var needAck []string
	for _, raw := range cidrs {
		p, err := clientacl.ParsePrefix(raw)
		if err != nil {
			return plan, err
		}
		canon := p.String()

		if clientacl.IsUniversal(p) {
			return plan, fmt.Errorf(
				"%s would allow DNS queries from every address on the internet, which is what an "+
					"open resolver is. DNS Daddy will not do that from the dashboard: an open "+
					"resolver is found and conscripted into amplification attacks within days. "+
					"If you genuinely intend to run one, set dns.allow_public_resolver "+
					"(DNSDADDY_ALLOW_PUBLIC_RESOLVER) in configuration, where it is a deliberate "+
					"act with a restart attached", canon)
		}

		if !clientacl.PrefixIsPublic(p) {
			continue
		}
		switch {
		case alreadyAcked[canon], ackNow:
			plan.acked[canon] = true
		default:
			needAck = append(needAck, canon)
		}
	}
	if len(needAck) > 0 {
		return plan, &ErrPublicAckRequired{CIDRs: needAck}
	}
	return plan, nil
}

// CreateNetwork inserts a network and issues it a DoH/DoT token.
func (s *Store) CreateNetwork(ctx context.Context, in NetworkInput) (Network, error) {
	if in.Name == nil || strings.TrimSpace(*in.Name) == "" {
		return Network{}, fmt.Errorf("network name is required")
	}
	cidrs, err := normalizeCIDRs(in.CIDRs)
	if err != nil {
		return Network{}, err
	}

	policyID := "p_standard"
	if in.PolicyID != nil && *in.PolicyID != "" {
		policyID = *in.PolicyID
	}
	if err := s.assertPolicyExists(ctx, policyID); err != nil {
		return Network{}, err
	}

	enabled := derefBoolDefault(in.Enabled, true)
	allowResolver := derefBoolDefault(in.AllowResolver, false)

	id := NewID("n")
	now := unixMilli(time.Now())

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Network{}, err
	}
	defer tx.Rollback()

	// Inside the transaction, because the open-resolver rule is about the ACL
	// the dashboard produces as a whole: what the other permitted networks
	// contribute has to be read at the same instant as the row being written.
	others, err := otherPermittedCIDRs(ctx, tx, id)
	if err != nil {
		return Network{}, err
	}
	plan, err := planResolverAccess(enabled && allowResolver, cidrs, nil,
		derefBoolDefault(in.PublicAck, false), append(others, s.bootstrapCIDRs...))
	if err != nil {
		return Network{}, err
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO networks (id, name, location, policy_id, token, enabled, allow_resolver, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, strings.TrimSpace(*in.Name), derefString(in.Location), policyID, NewToken(10),
		boolToInt(enabled), boolToInt(allowResolver), now, now); err != nil {
		return Network{}, err
	}
	if err := replaceCIDRs(ctx, tx, id, cidrs, plan.acked); err != nil {
		return Network{}, err
	}
	if err := tx.Commit(); err != nil {
		return Network{}, err
	}
	return s.GetNetwork(ctx, id)
}

// UpdateNetwork applies a partial update.
func (s *Store) UpdateNetwork(ctx context.Context, id string, in NetworkInput) (Network, error) {
	cidrs, err := normalizeCIDRs(in.CIDRs)
	if err != nil {
		return Network{}, err
	}
	if in.PolicyID != nil {
		if err := s.assertPolicyExists(ctx, *in.PolicyID); err != nil {
			return Network{}, err
		}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Network{}, err
	}
	defer tx.Rollback()

	// Read the current state inside the transaction and validate the *result*
	// of the merge, not the request in isolation. A PATCH that only flips
	// allowResolver has to be judged against the CIDRs already stored, and one
	// that only adds a CIDR against the permission already granted — otherwise
	// either half of a two-step change slips past the open-resolver and
	// public-address rules.
	current, err := loadNetworkForUpdate(ctx, tx, id)
	if err != nil {
		return Network{}, err
	}

	resultCIDRs := current.cidrs
	if in.CIDRs != nil {
		resultCIDRs = cidrs
	}
	// Canonicalise before planning, because the stored form and the
	// acknowledgement key have to be the same string.
	//
	// A database written by an older release can hold a CIDR in that
	// release's canonical form — "::ffff:203.0.113.25/128" where this one
	// would write "203.0.113.25/32". Planning canonicalises, so the
	// acknowledgement was keyed on the new form while replaceCIDRs indexed
	// the map with the unchanged stored string, wrote public_ack = 0, and
	// left an enabled public grant recorded as unacknowledged — re-prompting
	// on every unrelated edit afterwards. Rewriting the rows in canonical
	// form fixes the mismatch and quietly migrates the legacy spelling.
	if canon, err := normalizeCIDRs(&resultCIDRs); err == nil {
		resultCIDRs = canon
	}
	resultAllow := current.allowResolver
	if in.AllowResolver != nil {
		resultAllow = *in.AllowResolver
	}
	resultEnabled := current.enabled
	if in.Enabled != nil {
		resultEnabled = *in.Enabled
	}
	others, err := otherPermittedCIDRs(ctx, tx, id)
	if err != nil {
		return Network{}, err
	}
	// The resulting enabled state, not just the permission: clientacl.Compute
	// skips a disabled network entirely, so one contributes nothing to the ACL
	// and must not be validated as though it did. Judging it by allow alone
	// refused the very write that closes a hole — disabling one of two networks
	// whose ranges complete a family was rejected as creating the family.
	plan, err := planResolverAccess(resultEnabled && resultAllow, resultCIDRs, current.acked,
		derefBoolDefault(in.PublicAck, false), append(others, s.bootstrapCIDRs...))
	if err != nil {
		return Network{}, err
	}

	sets := []string{"updated_at = ?"}
	args := []any{unixMilli(time.Now())}
	if in.Name != nil {
		if strings.TrimSpace(*in.Name) == "" {
			return Network{}, fmt.Errorf("network name must not be empty")
		}
		sets = append(sets, "name = ?")
		args = append(args, strings.TrimSpace(*in.Name))
	}
	if in.Location != nil {
		sets = append(sets, "location = ?")
		args = append(args, *in.Location)
	}
	if in.PolicyID != nil {
		sets = append(sets, "policy_id = ?")
		args = append(args, *in.PolicyID)
	}
	if in.Enabled != nil {
		sets = append(sets, "enabled = ?")
		args = append(args, boolToInt(*in.Enabled))
	}
	if in.AllowResolver != nil {
		sets = append(sets, "allow_resolver = ?")
		args = append(args, boolToInt(*in.AllowResolver))
	}
	args = append(args, id)

	// #nosec G202 -- sets holds only hardcoded column fragments ("name = ?");
	// every value is bound as a parameter. Never build a fragment from input.
	if _, err := tx.ExecContext(ctx, "UPDATE networks SET "+strings.Join(sets, ", ")+" WHERE id = ?", args...); err != nil {
		return Network{}, err
	}
	// The rows are rewritten whenever anything about them changes, not only
	// when in.CIDRs was supplied: the acknowledgement set can change without
	// the CIDR list changing (permitting a network whose public range was
	// already stored is exactly that case), and so can the canonical spelling
	// of a range written by an older release.
	if in.CIDRs != nil || !sameStringSet(plan.acked, current.acked) ||
		!sameStringSlice(resultCIDRs, current.cidrs) {
		if err := replaceCIDRs(ctx, tx, id, resultCIDRs, plan.acked); err != nil {
			return Network{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return Network{}, err
	}
	return s.GetNetwork(ctx, id)
}

// networkForUpdate is the stored state a write is merged onto.
type networkForUpdate struct {
	cidrs         []string
	acked         map[string]bool
	allowResolver bool
	enabled       bool
}

func loadNetworkForUpdate(ctx context.Context, tx *sql.Tx, id string) (networkForUpdate, error) {
	var out networkForUpdate

	var allow, enabled int
	err := tx.QueryRowContext(ctx,
		"SELECT allow_resolver, enabled FROM networks WHERE id = ?", id).Scan(&allow, &enabled)
	if err == sql.ErrNoRows {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	out.allowResolver = allow == 1
	out.enabled = enabled == 1
	out.acked = map[string]bool{}

	rows, err := tx.QueryContext(ctx, "SELECT cidr, public_ack FROM network_cidrs WHERE network_id = ?", id)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cidr string
			ack  int
		)
		if err := rows.Scan(&cidr, &ack); err != nil {
			return out, err
		}
		out.cidrs = append(out.cidrs, cidr)
		if ack == 1 {
			out.acked[cidr] = true
		}
	}
	return out, rows.Err()
}

// sameStringSlice compares two CIDR lists as sets: normalizeCIDRs
// deduplicates and preserves input order, so order carries no meaning here.
func sameStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]bool, len(a))
	for _, s := range a {
		seen[s] = true
	}
	for _, s := range b {
		if !seen[s] {
			return false
		}
	}
	return true
}

func sameStringSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// DeleteNetwork removes a network. The last remaining network cannot be
// deleted, because the resolver needs somewhere to attribute unmatched clients.
func (s *Store) DeleteNetwork(ctx context.Context, id string) (Network, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Network{}, err
	}
	defer tx.Rollback()

	var count int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM networks").Scan(&count); err != nil {
		return Network{}, err
	}
	if count <= 1 {
		return Network{}, fmt.Errorf("cannot delete the only network")
	}

	// Read inside the transaction that removes it, so what is returned is what
	// was deleted. Reading first and deleting after left a window: a PATCH
	// landing between the two could permit the network and publish that
	// snapshot, and the delete would then report the state it saw before —
	// unpermitted — so a failed reload would leave the grant in force with
	// nothing marked stale and a 204 saying the revocation had taken.
	deleted, err := loadNetworkTx(ctx, tx, id)
	if err != nil {
		return Network{}, err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM networks WHERE id = ?", id); err != nil {
		return Network{}, err
	}
	if err := tx.Commit(); err != nil {
		return Network{}, err
	}
	return deleted, nil
}

// loadNetworkTx reads one network, with its ranges, inside a transaction.
func loadNetworkTx(ctx context.Context, tx *sql.Tx, id string) (Network, error) {
	var (
		n                Network
		enabled, allow   int
		created, updated int64
	)
	err := tx.QueryRowContext(ctx, `
		SELECT id, name, location, policy_id, COALESCE(token, ''), enabled, allow_resolver, created_at, updated_at
		FROM networks WHERE id = ?`, id).
		Scan(&n.ID, &n.Name, &n.Location, &n.PolicyID, &n.Token, &enabled, &allow, &created, &updated)
	if err == sql.ErrNoRows {
		return Network{}, ErrNotFound
	}
	if err != nil {
		return Network{}, err
	}
	n.Enabled = enabled == 1
	n.AllowResolver = allow == 1
	n.CreatedAt = fromUnixMilli(created)
	n.UpdatedAt = fromUnixMilli(updated)
	n.CIDRs = []string{}
	n.AcknowledgedPublicCIDRs = []string{}

	rows, err := tx.QueryContext(ctx,
		"SELECT cidr, public_ack FROM network_cidrs WHERE network_id = ? ORDER BY cidr", id)
	if err != nil {
		return Network{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cidr string
			ack  int
		)
		if err := rows.Scan(&cidr, &ack); err != nil {
			return Network{}, err
		}
		n.CIDRs = append(n.CIDRs, cidr)
		if ack == 1 {
			n.AcknowledgedPublicCIDRs = append(n.AcknowledgedPublicCIDRs, cidr)
		}
	}
	return n, rows.Err()
}

// RotateNetworkToken issues a fresh DoH/DoT token, invalidating the old one.
func (s *Store) RotateNetworkToken(ctx context.Context, id string) (Network, error) {
	res, err := s.db.ExecContext(ctx, "UPDATE networks SET token = ?, updated_at = ? WHERE id = ?",
		NewToken(10), unixMilli(time.Now()), id)
	if err != nil {
		return Network{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return Network{}, ErrNotFound
	}
	return s.GetNetwork(ctx, id)
}

func (s *Store) assertPolicyExists(ctx context.Context, id string) error {
	var n int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM policies WHERE id = ?", id).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("policy %q does not exist", id)
	}
	return nil
}

// normalizeCIDRs canonicalises the stored form of a network's ranges.
//
// It shares clientacl.ParsePrefix with the admission check on purpose. Two
// canonicalisations that agree "usually" is how an acknowledgement recorded
// against "192.168.0.0/24" fails to match a row stored as
// "::ffff:192.168.0.0/120" — the permission silently does nothing, which is
// the whole class of bug this work exists to remove. One function, one answer.
func normalizeCIDRs(in *[]string) ([]string, error) {
	if in == nil {
		return nil, nil
	}
	out := make([]string, 0, len(*in))
	seen := map[string]bool{}
	for _, raw := range *in {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		p, err := clientacl.ParsePrefix(raw)
		if err != nil {
			return nil, err
		}
		canon := p.String()
		if !seen[canon] {
			seen[canon] = true
			out = append(out, canon)
		}
	}
	return out, nil
}

func replaceCIDRs(ctx context.Context, tx *sql.Tx, networkID string, cidrs []string, acked map[string]bool) error {
	if _, err := tx.ExecContext(ctx, "DELETE FROM network_cidrs WHERE network_id = ?", networkID); err != nil {
		return err
	}
	for _, c := range cidrs {
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO network_cidrs (network_id, cidr, public_ack) VALUES (?, ?, ?)",
			networkID, c, boolToInt(acked[c])); err != nil {
			return err
		}
	}
	return nil
}

// ListClients returns operator-assigned device names.
func (s *Store) ListClients(ctx context.Context) ([]Client, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT ip, name, updated_at FROM clients ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Client
	for rows.Next() {
		var c Client
		var updated int64
		if err := rows.Scan(&c.IP, &c.Name, &updated); err != nil {
			return nil, err
		}
		c.UpdatedAt = fromUnixMilli(updated)
		out = append(out, c)
	}
	return out, rows.Err()
}

// SetClientName names a device by IP, or clears the name if name is empty.
func (s *Store) SetClientName(ctx context.Context, ip, name string) error {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return fmt.Errorf("invalid IP %q", ip)
	}
	name = strings.TrimSpace(name)
	if name == "" {
		_, err := s.db.ExecContext(ctx, "DELETE FROM clients WHERE ip = ?", addr.String())
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO clients (ip, name, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(ip) DO UPDATE SET name = excluded.name, updated_at = excluded.updated_at`,
		addr.String(), name, unixMilli(time.Now()))
	return err
}

// ClientACLNetworks reduces stored networks to what admission needs.
//
// The adapter lives here, in the package that already imports internal/clientacl
// for its write-time rules, rather than in clientacl itself: clientacl is read
// on the DNS hot path and by `dnsdaddy doctor`, and giving it a dependency on
// persistence would put the database behind an import that has no business
// needing one.
func ClientACLNetworks(networks []Network) []clientacl.Network {
	out := make([]clientacl.Network, 0, len(networks))
	for _, n := range networks {
		out = append(out, ClientACLNetwork(n))
	}
	return out
}

// ClientACLNetwork projects one network onto the fields admission is decided
// from. Shared with the plural form so a caller asking "what would this one
// network contribute?" cannot answer it from a different set of fields.
func ClientACLNetwork(n Network) clientacl.Network {
	return clientacl.Network{
		ID:            n.ID,
		Name:          n.Name,
		Enabled:       n.Enabled,
		AllowResolver: n.AllowResolver,
		CIDRs:         n.CIDRs,
	}
}
