package store

import (
	"path/filepath"
	"testing"
)

func TestSchemaGenerationWrittenOnOpen(t *testing.T) {
	st := newTestStore(t)
	var gen int
	if err := st.db.QueryRow(`SELECT generation FROM schema_generation WHERE id = 1`).Scan(&gen); err != nil {
		t.Fatal(err)
	}
	if gen != SchemaGeneration {
		t.Fatalf("generation=%d want %d", gen, SchemaGeneration)
	}
}

func TestNewerSchemaGenerationIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "future.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`UPDATE schema_generation SET generation = ? WHERE id = 1`, SchemaGeneration+1); err != nil {
		st.Close()
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = Open(path)
	if err == nil {
		t.Fatal("expected refusal of newer schema generation")
	}
}
