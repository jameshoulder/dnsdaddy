package store

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// ListNetworks returns every network with its CIDR list attached.
func (s *Store) ListNetworks(ctx context.Context) ([]Network, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, location, policy_id, COALESCE(token, ''), enabled, created_at, updated_at
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
			enabled          int
			created, updated int64
		)
		if err := rows.Scan(&n.ID, &n.Name, &n.Location, &n.PolicyID, &n.Token, &enabled, &created, &updated); err != nil {
			return nil, err
		}
		n.Enabled = enabled == 1
		n.CreatedAt = fromUnixMilli(created)
		n.UpdatedAt = fromUnixMilli(updated)
		n.CIDRs = []string{}
		byID[n.ID] = len(out)
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	crows, err := s.db.QueryContext(ctx, "SELECT network_id, cidr FROM network_cidrs ORDER BY cidr")
	if err != nil {
		return nil, err
	}
	defer crows.Close()
	for crows.Next() {
		var nid, cidr string
		if err := crows.Scan(&nid, &cidr); err != nil {
			return nil, err
		}
		if i, ok := byID[nid]; ok {
			out[i].CIDRs = append(out[i].CIDRs, cidr)
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
type NetworkInput struct {
	Name     *string
	Location *string
	PolicyID *string
	CIDRs    *[]string
	Enabled  *bool
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

	id := NewID("n")
	now := unixMilli(time.Now())

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Network{}, err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO networks (id, name, location, policy_id, token, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		id, strings.TrimSpace(*in.Name), derefString(in.Location), policyID, NewToken(10),
		boolToInt(derefBoolDefault(in.Enabled, true)), now, now); err != nil {
		return Network{}, err
	}
	if err := replaceCIDRs(ctx, tx, id, cidrs); err != nil {
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

	var exists int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM networks WHERE id = ?", id).Scan(&exists); err != nil {
		return Network{}, err
	}
	if exists == 0 {
		return Network{}, ErrNotFound
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
	args = append(args, id)

	// #nosec G202 -- sets holds only hardcoded column fragments ("name = ?");
	// every value is bound as a parameter. Never build a fragment from input.
	if _, err := tx.ExecContext(ctx, "UPDATE networks SET "+strings.Join(sets, ", ")+" WHERE id = ?", args...); err != nil {
		return Network{}, err
	}
	if in.CIDRs != nil {
		if err := replaceCIDRs(ctx, tx, id, cidrs); err != nil {
			return Network{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return Network{}, err
	}
	return s.GetNetwork(ctx, id)
}

// DeleteNetwork removes a network. The last remaining network cannot be
// deleted, because the resolver needs somewhere to attribute unmatched clients.
func (s *Store) DeleteNetwork(ctx context.Context, id string) error {
	var count int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM networks").Scan(&count); err != nil {
		return err
	}
	if count <= 1 {
		return fmt.Errorf("cannot delete the only network")
	}
	res, err := s.db.ExecContext(ctx, "DELETE FROM networks WHERE id = ?", id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
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

func normalizeCIDRs(in *[]string) ([]string, error) {
	if in == nil {
		return nil, nil
	}
	out := make([]string, 0, len(*in))
	seen := map[string]bool{}
	for _, raw := range *in {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		// Accept a bare address as a single-host prefix, which is what people
		// type when they mean "just this machine".
		if !strings.Contains(raw, "/") {
			addr, err := netip.ParseAddr(raw)
			if err != nil {
				return nil, fmt.Errorf("invalid address %q", raw)
			}
			raw = fmt.Sprintf("%s/%d", addr.String(), addr.BitLen())
		}
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q", raw)
		}
		canon := p.Masked().String()
		if !seen[canon] {
			seen[canon] = true
			out = append(out, canon)
		}
	}
	return out, nil
}

func replaceCIDRs(ctx context.Context, tx *sql.Tx, networkID string, cidrs []string) error {
	if _, err := tx.ExecContext(ctx, "DELETE FROM network_cidrs WHERE network_id = ?", networkID); err != nil {
		return err
	}
	for _, c := range cidrs {
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO network_cidrs (network_id, cidr) VALUES (?, ?)", networkID, c); err != nil {
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
