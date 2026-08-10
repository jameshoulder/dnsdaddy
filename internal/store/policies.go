package store

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/catalog"
)

// ListPolicies returns every policy with its allow/block rules and the number
// of networks assigned to it.
func (s *Store) ListPolicies(ctx context.Context) ([]Policy, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT p.id, p.name, p.description, p.categories, p.block_mode, p.safe_search,
		       p.log_queries, p.is_default, p.created_at, p.updated_at,
		       (SELECT COUNT(*) FROM networks n WHERE n.policy_id = p.id)
		FROM policies p
		ORDER BY p.is_default DESC, p.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Policy
	for rows.Next() {
		var (
			p                Policy
			cats, mode       string
			safe, logq, def  int
			created, updated int64
		)
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &cats, &mode, &safe,
			&logq, &def, &created, &updated, &p.Assigned); err != nil {
			return nil, err
		}
		p.Categories = nonNil(decodeStrings(cats))
		p.BlockMode = BlockMode(mode)
		p.SafeSearch = safe == 1
		p.LogQueries = logq == 1
		p.IsDefault = def == 1
		p.CreatedAt = fromUnixMilli(created)
		p.UpdatedAt = fromUnixMilli(updated)
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rules, err := s.allPolicyRules(ctx)
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i].AllowDomains = nonNil(rules[out[i].ID+"|allow"])
		out[i].BlockDomains = nonNil(rules[out[i].ID+"|block"])
	}
	return out, nil
}

func (s *Store) allPolicyRules(ctx context.Context) (map[string][]string, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT policy_id, kind, domain FROM policy_rules ORDER BY domain")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string][]string{}
	for rows.Next() {
		var pid, kind, domain string
		if err := rows.Scan(&pid, &kind, &domain); err != nil {
			return nil, err
		}
		out[pid+"|"+kind] = append(out[pid+"|"+kind], domain)
	}
	return out, rows.Err()
}

// GetPolicy returns a single policy by ID.
func (s *Store) GetPolicy(ctx context.Context, id string) (Policy, error) {
	all, err := s.ListPolicies(ctx)
	if err != nil {
		return Policy{}, err
	}
	for _, p := range all {
		if p.ID == id {
			return p, nil
		}
	}
	return Policy{}, ErrNotFound
}

// PolicyInput carries the mutable fields of a policy. Nil pointers mean "leave
// unchanged" on update.
type PolicyInput struct {
	Name         *string
	Description  *string
	Categories   *[]string
	BlockMode    *BlockMode
	SafeSearch   *bool
	LogQueries   *bool
	AllowDomains *[]string
	BlockDomains *[]string
}

// CreatePolicy inserts a new policy.
func (s *Store) CreatePolicy(ctx context.Context, in PolicyInput) (Policy, error) {
	if in.Name == nil || strings.TrimSpace(*in.Name) == "" {
		return Policy{}, fmt.Errorf("policy name is required")
	}
	if err := validateCategories(in.Categories); err != nil {
		return Policy{}, err
	}

	mode := BlockNXDOMAIN
	if in.BlockMode != nil {
		mode = *in.BlockMode
	}
	if !mode.Valid() {
		return Policy{}, fmt.Errorf("invalid block mode %q", mode)
	}

	id := NewID("p")
	now := unixMilli(time.Now())

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Policy{}, err
	}
	defer tx.Rollback()

	var cats []string
	if in.Categories != nil {
		cats = *in.Categories
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO policies (id, name, description, categories, block_mode, safe_search, log_queries, is_default, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)`,
		id, strings.TrimSpace(*in.Name), derefString(in.Description), encodeJSON(nonNil(cats)),
		string(mode), boolToInt(derefBool(in.SafeSearch)), boolToInt(derefBoolDefault(in.LogQueries, true)), now, now)
	if err != nil {
		return Policy{}, err
	}

	if err := replaceRules(ctx, tx, id, "allow", in.AllowDomains); err != nil {
		return Policy{}, err
	}
	if err := replaceRules(ctx, tx, id, "block", in.BlockDomains); err != nil {
		return Policy{}, err
	}
	if err := tx.Commit(); err != nil {
		return Policy{}, err
	}
	return s.GetPolicy(ctx, id)
}

// UpdatePolicy applies a partial update.
func (s *Store) UpdatePolicy(ctx context.Context, id string, in PolicyInput) (Policy, error) {
	if err := validateCategories(in.Categories); err != nil {
		return Policy{}, err
	}
	if in.BlockMode != nil && !in.BlockMode.Valid() {
		return Policy{}, fmt.Errorf("invalid block mode %q", *in.BlockMode)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Policy{}, err
	}
	defer tx.Rollback()

	var exists int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM policies WHERE id = ?", id).Scan(&exists); err != nil {
		return Policy{}, err
	}
	if exists == 0 {
		return Policy{}, ErrNotFound
	}

	sets := []string{"updated_at = ?"}
	args := []any{unixMilli(time.Now())}

	if in.Name != nil {
		if strings.TrimSpace(*in.Name) == "" {
			return Policy{}, fmt.Errorf("policy name must not be empty")
		}
		sets = append(sets, "name = ?")
		args = append(args, strings.TrimSpace(*in.Name))
	}
	if in.Description != nil {
		sets = append(sets, "description = ?")
		args = append(args, *in.Description)
	}
	if in.Categories != nil {
		sets = append(sets, "categories = ?")
		args = append(args, encodeJSON(nonNil(*in.Categories)))
	}
	if in.BlockMode != nil {
		sets = append(sets, "block_mode = ?")
		args = append(args, string(*in.BlockMode))
	}
	if in.SafeSearch != nil {
		sets = append(sets, "safe_search = ?")
		args = append(args, boolToInt(*in.SafeSearch))
	}
	if in.LogQueries != nil {
		sets = append(sets, "log_queries = ?")
		args = append(args, boolToInt(*in.LogQueries))
	}
	args = append(args, id)

	// #nosec G202 -- sets holds only hardcoded column fragments ("name = ?");
	// every value is bound as a parameter. Never build a fragment from input.
	if _, err := tx.ExecContext(ctx, "UPDATE policies SET "+strings.Join(sets, ", ")+" WHERE id = ?", args...); err != nil {
		return Policy{}, err
	}
	if err := replaceRules(ctx, tx, id, "allow", in.AllowDomains); err != nil {
		return Policy{}, err
	}
	if err := replaceRules(ctx, tx, id, "block", in.BlockDomains); err != nil {
		return Policy{}, err
	}
	if err := tx.Commit(); err != nil {
		return Policy{}, err
	}
	return s.GetPolicy(ctx, id)
}

// DeletePolicy removes a policy. The default policy cannot be deleted, and
// neither can one that networks are still assigned to.
func (s *Store) DeletePolicy(ctx context.Context, id string) error {
	var isDefault int
	err := s.db.QueryRowContext(ctx, "SELECT is_default FROM policies WHERE id = ?", id).Scan(&isDefault)
	if err == sql.ErrNoRows {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if isDefault == 1 {
		return fmt.Errorf("the default policy cannot be deleted")
	}

	var assigned int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM networks WHERE policy_id = ?", id).Scan(&assigned); err != nil {
		return err
	}
	if assigned > 0 {
		return fmt.Errorf("policy is assigned to %d network(s); reassign them first", assigned)
	}

	_, err = s.db.ExecContext(ctx, "DELETE FROM policies WHERE id = ?", id)
	return err
}

// AddPolicyRule adds a single allow or block entry, which is the common case
// from the dashboard ("this was a false positive, allow it").
func (s *Store) AddPolicyRule(ctx context.Context, policyID, kind, domain, note string) error {
	if kind != "allow" && kind != "block" {
		return fmt.Errorf("rule kind must be allow or block")
	}
	d := NormalizeDomain(domain)
	if d == "" {
		return fmt.Errorf("invalid domain %q", domain)
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO policy_rules (policy_id, kind, domain, note, created_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(policy_id, kind, domain) DO UPDATE SET note = excluded.note`,
		policyID, kind, d, note, unixMilli(time.Now()))
	return err
}

// DeletePolicyRule removes a single allow or block entry.
func (s *Store) DeletePolicyRule(ctx context.Context, policyID, kind, domain string) error {
	res, err := s.db.ExecContext(ctx,
		"DELETE FROM policy_rules WHERE policy_id = ? AND kind = ? AND domain = ?",
		policyID, kind, NormalizeDomain(domain))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func replaceRules(ctx context.Context, tx *sql.Tx, policyID, kind string, domains *[]string) error {
	if domains == nil {
		return nil
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM policy_rules WHERE policy_id = ? AND kind = ?", policyID, kind); err != nil {
		return err
	}
	now := unixMilli(time.Now())
	seen := map[string]bool{}
	for _, raw := range *domains {
		d := NormalizeDomain(raw)
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO policy_rules (policy_id, kind, domain, created_at) VALUES (?, ?, ?, ?)",
			policyID, kind, d, now); err != nil {
			return err
		}
	}
	return nil
}

func validateCategories(cats *[]string) error {
	if cats == nil {
		return nil
	}
	var bad []string
	for _, c := range *cats {
		if !catalog.ValidCategory(c) {
			bad = append(bad, c)
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return fmt.Errorf("unknown categor%s: %s", plural(len(bad), "y", "ies"), strings.Join(bad, ", "))
	}
	return nil
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func derefBool(p *bool) bool { return p != nil && *p }

func derefBoolDefault(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}
