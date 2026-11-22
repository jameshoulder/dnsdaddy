package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/diag"
	"github.com/jameshoulder/dnsdaddy/internal/support"
	"github.com/jameshoulder/dnsdaddy/internal/version"
)

func runSupport(args []string) error {
	fs := newFlagSet("support")
	configPath := fs.String("config", envOr("DNSDADDY_CONFIG", "/etc/dnsdaddy/config.yaml"), "configuration file")
	output := fs.String("output", "", "new output directory (must not exist)")
	note := fs.String("note", "", "optional operator note (reviewed before sharing)")
	repro := fs.String("repro", "", "optional synthetic reproducer text")
	includeDoctor := fs.Bool("include-doctor", false, "run active doctor probes and label results separately (may send network queries)")
	timeout := fs.Duration("timeout", support.DefaultTimeout, "maximum collection duration")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *output == "" || *timeout <= 0 {
		return errors.New("usage: dnsdaddy support -config FILE -output NEW_DIRECTORY")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	opt := support.Options{
		ConfigPath:     *configPath,
		OutputDir:      *output,
		OperatorNote:   *note,
		SyntheticRepro: *repro,
		IncludeDoctor:  *includeDoctor,
		Version:        version.String(),
	}
	if *includeDoctor {
		opt.DoctorRuns = func(ctx context.Context, configPath string) (support.DoctorSection, error) {
			probeTimeout := 5 * time.Second
			if deadline, ok := ctx.Deadline(); ok {
				remain := time.Until(deadline)
				if remain <= 0 {
					return support.DoctorSection{}, context.DeadlineExceeded
				}
				if remain < probeTimeout {
					probeTimeout = remain
				}
			}
			checks := collectDoctorChecks(ctx, configPath, probeTimeout)
			if err := ctx.Err(); err != nil {
				return support.DoctorSection{}, err
			}
			raw, err := json.Marshal(sanitizeDoctorChecks(checks))
			if err != nil {
				return support.DoctorSection{}, err
			}
			return support.DoctorSection{
				Label:   "active-diagnostics",
				Summary: "Explicit doctor probes. Only section, status and stable check IDs are exported — names, summaries, evidence and actions are omitted because they may contain URLs, tokens or addresses.",
				Checks:  raw,
			}, nil
		}
	}
	res, err := support.Write(ctx, opt)
	if err != nil {
		return err
	}
	_ = support.WritePreview(os.Stdout, res.Preview)
	fmt.Fprintf(os.Stdout, "Wrote %s\nManifest %s\nNothing was uploaded.\n", res.Package, res.Manifest)
	return nil
}

// doctorCheckExport is the allowlisted doctor row for support packages.
// Free-form Name/Summary/Evidence/Action are intentionally omitted: they can
// embed upstream specs (including DoH path tokens), listen addresses and
// operator-assigned network names.
type doctorCheckExport struct {
	Section string `json:"section"`
	CheckID string `json:"checkId"`
	Status  string `json:"status"`
}

func sanitizeDoctorChecks(checks []diag.Check) []doctorCheckExport {
	out := make([]doctorCheckExport, 0, len(checks))
	for _, c := range checks {
		sum := sha256.Sum256([]byte(c.Section + "\x00" + c.Name))
		out = append(out, doctorCheckExport{
			Section: c.Section,
			CheckID: hex.EncodeToString(sum[:8]),
			Status:  string(c.Status),
		})
	}
	return out
}
