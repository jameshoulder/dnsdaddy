package main

import (
	"context"
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
			checks := collectDoctorChecks(ctx, configPath, 5*time.Second)
			raw, err := json.Marshal(sanitizeDoctorChecks(checks))
			if err != nil {
				return support.DoctorSection{}, err
			}
			return support.DoctorSection{
				Label:   "active-diagnostics",
				Summary: "Explicit doctor probes. Evidence strings may still need review before sharing.",
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

// sanitizeDoctorChecks keeps status fields and drops free-form evidence/action
// text that may contain addresses or paths.
type doctorCheckExport struct {
	Section string `json:"section"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	Summary string `json:"summary"`
}

func sanitizeDoctorChecks(checks []diag.Check) []doctorCheckExport {
	out := make([]doctorCheckExport, 0, len(checks))
	for _, c := range checks {
		out = append(out, doctorCheckExport{
			Section: c.Section,
			Name:    c.Name,
			Status:  string(c.Status),
			Summary: c.Summary,
		})
	}
	return out
}
