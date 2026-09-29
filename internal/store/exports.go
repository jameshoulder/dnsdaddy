package store

import (
	"context"
	"fmt"
)

// ExportHighWater captures the latest insertion visible when a paged export
// starts. The caller carries this boundary through subsequent pages so late
// inserts, including backdated events, belong to a new export. Retention may
// still remove rows: this is not an online backup or a database transaction
// held open across HTTP requests.
func (s *Store) ExportHighWater(ctx context.Context, dataset string) (int64, error) {
	switch dataset {
	case "queries", "decisions", "findings":
	default:
		return 0, fmt.Errorf("unsupported export dataset")
	}
	var maxID int64
	err := s.db.QueryRowContext(ctx, `SELECT value FROM export_sequences WHERE dataset = ?`, dataset).Scan(&maxID)
	return maxID, err
}
