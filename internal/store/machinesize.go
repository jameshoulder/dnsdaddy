package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// SettingMachineSizeDefault records whether this installation should size
// itself from the machine when the operator has not chosen a size.
//
// Written by seed, keyed off its own presence, like SettingRebindingDefault
// and for the same reason: installMarkerKey was already written by every
// installation that upgraded before this existed, so keying off it would skip
// exactly the installations whose size has never been decided.
//
// The distinction that matters is fresh install versus upgrade. On a fresh
// install there is no behaviour to inherit, so the machine decides. On an
// upgrade there is: a resolver that has been keeping a week of query history
// and caching fifty thousand answers is doing so because that is what the
// release they installed did, and a new release quietly cutting it to three
// days would be a change to their evidence trail arriving in a patch note
// nobody read. So an upgrade is left exactly as it was and told about, and
// adopting the sizing is one deliberate edit.
const SettingMachineSizeDefault = "install.machine_size_default_v1"

// The two values SettingMachineSizeDefault can hold.
const (
	// MachineSizeAuto: size this installation from the machine.
	MachineSizeAuto = "auto"
	// MachineSizeKeep: leave this installation's limits exactly as they are.
	MachineSizeKeep = "keep"
)

// SettingMachineSize records the size actually applied, once.
//
// What is recorded is the answer, never the question: "tiny", "small" or
// "full", never "auto".
const SettingMachineSize = "install.machine_size_v1"

// SettingMachineSizeDetail records what was seen when the size was decided:
// the memory and processors, and whether the size was chosen automatically.
//
// Stored so that "why is this box running the 1 GB limits?" is answerable from
// the database months later, on a machine that has since been resized.
const SettingMachineSizeDetail = "install.machine_size_detail_v1"

// MachineSizeRecord is what was decided, and what it was decided from.
type MachineSizeRecord struct {
	// Size is "tiny", "small" or "full". Never "auto": what is recorded is the
	// answer, not the question.
	Size string
	// MemoryMB and CPUs are what the machine looked like.
	MemoryMB int
	CPUs     int
	// Automatic reports that the machine chose, rather than the operator.
	Automatic bool
	// At is when it was decided.
	At time.Time
}

// MachineSize reads the recorded size, or ErrNotFound when none has been
// recorded — which is what an upgrade from a release before this existed looks
// like, and is the case the caller has to handle rather than paper over.
func (s *Store) MachineSize(ctx context.Context) (MachineSizeRecord, error) {
	size, err := s.GetSetting(ctx, SettingMachineSize)
	if err != nil {
		return MachineSizeRecord{}, err
	}
	rec := MachineSizeRecord{Size: size}

	// The detail is a convenience rather than the record. An installation
	// whose detail row is missing or damaged still has a size, and losing the
	// evidence about a decision is not a reason to discard the decision.
	detail, err := s.GetSetting(ctx, SettingMachineSizeDetail)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return rec, err
	}
	parseMachineDetail(detail, &rec)
	return rec, nil
}

// RecordMachineSize writes the size decision, once.
//
// It never overwrites: the value of a first-run record is that it describes
// the first run. A caller that wants to change the size in force says so in
// configuration, which wins over this on every start.
func (s *Store) RecordMachineSize(ctx context.Context, rec MachineSizeRecord) error {
	if rec.At.IsZero() {
		rec.At = time.Now().UTC()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var already int
	if err := tx.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM settings WHERE key = ?", SettingMachineSize,
	).Scan(&already); err != nil {
		return err
	}
	if already > 0 {
		return nil
	}
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO settings (key, value) VALUES (?, ?)", SettingMachineSize, rec.Size,
	); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		"INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
		SettingMachineSizeDetail, formatMachineDetail(rec),
	); err != nil {
		return err
	}
	return tx.Commit()
}

// formatMachineDetail renders the evidence as one readable line.
//
// Deliberately not JSON. It is read by a person looking at the settings table
// as often as by this program, and "memory=970 cpus=1 chosen=automatic" needs
// no tooling to understand.
func formatMachineDetail(rec MachineSizeRecord) string {
	chosen := "operator"
	if rec.Automatic {
		chosen = "automatic"
	}
	return fmt.Sprintf("memory=%d cpus=%d chosen=%s at=%s",
		rec.MemoryMB, rec.CPUs, chosen, rec.At.UTC().Format(time.RFC3339))
}

// parseMachineDetail fills in what it can and ignores what it cannot.
//
// Forgiving on purpose: this is evidence about a past decision, and a field
// that has grown a new spelling in a later release must not make an old record
// unreadable.
func parseMachineDetail(s string, rec *MachineSizeRecord) {
	for _, field := range strings.Fields(s) {
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		switch key {
		case "memory":
			rec.MemoryMB, _ = strconv.Atoi(value)
		case "cpus":
			rec.CPUs, _ = strconv.Atoi(value)
		case "chosen":
			rec.Automatic = value == "automatic"
		case "at":
			if t, err := time.Parse(time.RFC3339, value); err == nil {
				rec.At = t
			}
		}
	}
}

// WALBytes reports the size of the write-ahead log beside the database file,
// or 0 when there is none.
//
// Surfaced because the WAL is the one file in the data directory that can grow
// without the operator doing anything, and on a 25 GB disk shared with the
// query log that is worth being able to see. journal_size_limit bounds it, so
// a large one means either a very busy period in progress or a checkpoint that
// is not happening — both things somebody would want to know.
func (s *Store) WALBytes() int64 {
	if s.path == "" {
		return 0
	}
	info, err := os.Stat(s.path + "-wal")
	if err != nil {
		return 0
	}
	return info.Size()
}
