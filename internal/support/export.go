// Package support builds a local, allowlisted diagnostic package for operators.
//
// Default collection makes no outbound requests. Active doctor probes are a
// separate, explicitly requested result labelled as such. Sharing is manual.
package support

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/version"
)

const (
	// ManifestName is written beside the JSON package.
	ManifestName = "manifest.txt"
	// PackageName is the allowlisted JSON document.
	PackageName = "support-package.json"
	// MaxOperatorNoteBytes bounds free-text the operator may attach.
	MaxOperatorNoteBytes = 4 << 10
	// MaxPackageBytes is a hard ceiling on written JSON size.
	MaxPackageBytes = 1 << 20
	// DefaultTimeout bounds collection.
	DefaultTimeout = 30 * time.Second
)

// Options control support package collection.
type Options struct {
	ConfigPath     string
	OutputDir      string
	OperatorNote   string
	SyntheticRepro string
	IncludeDoctor  bool
	// DoctorRuns, when IncludeDoctor is true, collects active probe results.
	// It is injected so tests can assert no network by default and still
	// exercise the labelled doctor section without dialing.
	DoctorRuns func(ctx context.Context, configPath string) (DoctorSection, error)
	Now        func() time.Time
	Version    string
	CommitHint string
}

// DoctorSection is an optional, separately labelled active-diagnostic result.
type DoctorSection struct {
	Label   string          `json:"label"`
	Summary string          `json:"summary"`
	Checks  json.RawMessage `json:"checks,omitempty"`
	Error   string          `json:"error,omitempty"`
}

// Package is the allowlisted support document.
type Package struct {
	SchemaVersion  int            `json:"schemaVersion"`
	CreatedAt      string         `json:"createdAt"`
	Collection     CollectionMeta `json:"collection"`
	Build          BuildInfo      `json:"build"`
	Platform       PlatformInfo   `json:"platform"`
	Deployment     DeploymentInfo `json:"deployment"`
	Effective      EffectiveInfo  `json:"effective"`
	Counters       *CounterInfo   `json:"counters,omitempty"`
	Omitted        []string       `json:"omitted"`
	OperatorNote   string         `json:"operatorNote,omitempty"`
	SyntheticRepro string         `json:"syntheticRepro,omitempty"`
	Doctor         *DoctorSection `json:"doctor,omitempty"`
	ReviewRequired []string       `json:"reviewRequired,omitempty"`
}

// CollectionMeta describes how the package was gathered.
type CollectionMeta struct {
	Mode             string `json:"mode"`
	OutboundRequests string `json:"outboundRequests"`
	ActiveProbes     string `json:"activeProbes"`
	Sharing          string `json:"sharing"`
}

// BuildInfo is version/revision metadata.
type BuildInfo struct {
	Version string `json:"version"`
	Go      string `json:"go"`
}

// PlatformInfo is coarse platform data only.
type PlatformInfo struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

// DeploymentInfo is coarse deployment shape without host paths or env dumps.
type DeploymentInfo struct {
	ConfigLoadable bool   `json:"configLoadable"`
	ConfigError    string `json:"configError,omitempty"`
	ListenUDPSet   bool   `json:"listenUDPConfigured"`
	ListenTCPSet   bool   `json:"listenTCPConfigured"`
	HTTPListenSet  bool   `json:"httpListenConfigured"`
	DataDirSet     bool   `json:"dataDirConfigured"`
}

// EffectiveInfo is mode/transport without secrets.
type EffectiveInfo struct {
	LocalDNSSECMode string `json:"localDNSSECMode,omitempty"`
	DNSTransport    string `json:"dnsTransport,omitempty"`
	QueryLog        *bool  `json:"queryLogEnabled,omitempty"`
	Notes           string `json:"notes,omitempty"`
}

// CounterInfo holds bounded aggregate counters when available offline.
type CounterInfo struct {
	Status string `json:"status"`
	Note   string `json:"note"`
}

// Result is the written package plus preview text.
type Result struct {
	Directory string
	Package   string
	Manifest  string
	Preview   string
	Doc       Package
}

// Collect builds the allowlisted document without writing it.
func Collect(ctx context.Context, opt Options) (Package, error) {
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Version == "" {
		opt.Version = version.String()
	}
	note, noteWarn, err := sanitizeFreeText("operatorNote", opt.OperatorNote, MaxOperatorNoteBytes)
	if err != nil {
		return Package{}, err
	}
	repro, reproWarn, err := sanitizeFreeText("syntheticRepro", opt.SyntheticRepro, MaxOperatorNoteBytes)
	if err != nil {
		return Package{}, err
	}

	pkg := Package{
		SchemaVersion: 1,
		CreatedAt:     opt.Now().UTC().Format(time.RFC3339),
		Collection: CollectionMeta{
			Mode:             "local-allowlist",
			OutboundRequests: "none-by-default",
			ActiveProbes:     "disabled",
			Sharing:          "manual-only",
		},
		Build: BuildInfo{
			Version: opt.Version,
			Go:      runtime.Version(),
		},
		Platform: PlatformInfo{
			OS:   runtime.GOOS,
			Arch: runtime.GOARCH,
		},
		Omitted: []string{
			"query names and query history",
			"first-seen rows and findings",
			"raw logs and database copies",
			"client and public IP addresses",
			"device and host names",
			"private filesystem paths",
			"environment variable dumps",
			"passwords, cookies, API and DoH tokens",
			"master keys, TLS private keys and backups",
			"arbitrary HTTP headers, URL paths and error text that may contain secrets",
		},
		OperatorNote:   note,
		SyntheticRepro: repro,
		Counters: &CounterInfo{
			Status: "not-sampled-offline",
			Note:   "Process counters require a running daemon; this offline package does not scrape them or infer delivery from server-local totals.",
		},
	}
	if noteWarn != "" {
		pkg.ReviewRequired = append(pkg.ReviewRequired, noteWarn)
	}
	if reproWarn != "" {
		pkg.ReviewRequired = append(pkg.ReviewRequired, reproWarn)
	}

	cfg, cfgErr := loadConfigSafe(opt.ConfigPath)
	if cfgErr != nil {
		pkg.Deployment.ConfigLoadable = false
		pkg.Deployment.ConfigError = "configuration could not be loaded; details omitted to avoid leaking paths or secrets"
		pkg.Effective.Notes = "effective mode and transport unavailable because configuration did not load"
	} else {
		pkg.Deployment.ConfigLoadable = true
		pkg.Deployment.ListenUDPSet = strings.TrimSpace(cfg.DNS.ListenUDP) != ""
		pkg.Deployment.ListenTCPSet = strings.TrimSpace(cfg.DNS.ListenTCP) != ""
		pkg.Deployment.HTTPListenSet = strings.TrimSpace(cfg.HTTP.Listen) != ""
		pkg.Deployment.DataDirSet = strings.TrimSpace(cfg.DataDir) != ""
		pkg.Effective.LocalDNSSECMode = strings.TrimSpace(cfg.DNS.LocalDNSSECValidation)
		if pkg.Effective.LocalDNSSECMode == "" {
			pkg.Effective.LocalDNSSECMode = "unset-in-file"
		}
		// Transport selection may live in the database; offline export only
		// reports whether encrypted upstreams are configured in YAML.
		if len(cfg.DNS.EncryptedUpstreams) > 0 {
			pkg.Effective.DNSTransport = "encrypted-upstreams-configured-in-yaml"
		} else {
			pkg.Effective.DNSTransport = "standard-or-saved-selection-not-read-offline"
		}
		ql := cfg.Log.QueryLog
		pkg.Effective.QueryLog = &ql
		pkg.Effective.Notes = "Saved dashboard transport/mode overrides are not read by the offline collector; use doctor for live effective settings."
	}

	if opt.IncludeDoctor {
		pkg.Collection.ActiveProbes = "explicitly-requested"
		pkg.Collection.OutboundRequests = "possible-via-doctor-probes"
		section := DoctorSection{
			Label:   "active-diagnostics",
			Summary: "Results below were collected with explicit active probes. They are not part of the default offline package.",
		}
		if opt.DoctorRuns == nil {
			section.Error = "doctor collection was requested but no collector was configured"
		} else {
			got, err := opt.DoctorRuns(ctx, opt.ConfigPath)
			if err != nil {
				section.Error = "doctor collection failed; raw error text omitted"
			} else {
				if got.Label != "" {
					section.Label = got.Label
				}
				if got.Summary != "" {
					section.Summary = got.Summary
				}
				section.Checks = got.Checks
				section.Error = got.Error
			}
		}
		pkg.Doctor = &section
	}

	return pkg, nil
}

func loadConfigSafe(path string) (config.Config, error) {
	if strings.TrimSpace(path) == "" {
		return config.Config{}, errors.New("config path required")
	}
	return config.Load(path)
}

func sanitizeFreeText(field, text string, max int) (string, string, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return "", "", nil
	}
	if !utf8.ValidString(text) {
		return "", "", fmt.Errorf("%s must be valid UTF-8", field)
	}
	if len(text) > max {
		return "", "", fmt.Errorf("%s exceeds %d bytes", field, max)
	}
	lower := strings.ToLower(text)
	suspicious := []string{
		"authorization:", "cookie:", "set-cookie:", "password=", "admin_password",
		"dnsd_", "begin private key", "master key", "passphrase",
	}
	for _, s := range suspicious {
		if strings.Contains(lower, s) {
			return text, fmt.Sprintf("%s may contain sensitive material — review before sharing", field), nil
		}
	}
	if strings.Contains(lower, "http://") || strings.Contains(lower, "https://") {
		return text, fmt.Sprintf("%s contains a URL — confirm it does not embed tokens before sharing", field), nil
	}
	return text, "", nil
}

// Write creates outputDir (must not exist), writes the package and manifest with
// restrictive permissions, and returns a preview.
func Write(ctx context.Context, opt Options) (Result, error) {
	if strings.TrimSpace(opt.OutputDir) == "" {
		return Result{}, errors.New("output directory is required")
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	deadline := DefaultTimeout
	if dl, ok := ctx.Deadline(); ok {
		deadline = time.Until(dl)
		if deadline <= 0 {
			return Result{}, context.DeadlineExceeded
		}
	}
	ctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()

	pkg, err := Collect(ctx, opt)
	if err != nil {
		return Result{}, err
	}
	raw, err := json.MarshalIndent(pkg, "", "  ")
	if err != nil {
		return Result{}, err
	}
	raw = append(raw, '\n')
	if len(raw) > MaxPackageBytes {
		return Result{}, fmt.Errorf("support package exceeds %d bytes", MaxPackageBytes)
	}

	if err := os.Mkdir(opt.OutputDir, 0o700); err != nil {
		return Result{}, fmt.Errorf("create output directory: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(opt.OutputDir)
		}
	}()

	pkgPath := filepath.Join(opt.OutputDir, PackageName)
	if err := writePrivateFile(pkgPath, raw); err != nil {
		return Result{}, err
	}
	preview := previewText(pkg)
	manifest := fmt.Sprintf(
		"DNS Daddy support package\nCreated: %s\nMode: %s\nOutbound: %s\nActive probes: %s\nFiles:\n  - %s\n  - %s\nSharing: manual only; nothing was uploaded.\nReviewRequired: %s\n",
		pkg.CreatedAt,
		pkg.Collection.Mode,
		pkg.Collection.OutboundRequests,
		pkg.Collection.ActiveProbes,
		PackageName,
		ManifestName,
		strings.Join(pkg.ReviewRequired, "; "),
	)
	manPath := filepath.Join(opt.OutputDir, ManifestName)
	if err := writePrivateFile(manPath, []byte(manifest)); err != nil {
		return Result{}, err
	}
	ok = true
	return Result{
		Directory: opt.OutputDir,
		Package:   pkgPath,
		Manifest:  manPath,
		Preview:   preview,
		Doc:       pkg,
	}, nil
}

func writePrivateFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	return f.Sync()
}

func previewText(pkg Package) string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "Support package preview\n")
	fmt.Fprintf(&b, "  version: %s\n", pkg.Build.Version)
	fmt.Fprintf(&b, "  platform: %s/%s\n", pkg.Platform.OS, pkg.Platform.Arch)
	fmt.Fprintf(&b, "  config loadable: %v\n", pkg.Deployment.ConfigLoadable)
	fmt.Fprintf(&b, "  local DNSSEC mode (file): %s\n", pkg.Effective.LocalDNSSECMode)
	fmt.Fprintf(&b, "  transport hint: %s\n", pkg.Effective.DNSTransport)
	fmt.Fprintf(&b, "  active probes: %s\n", pkg.Collection.ActiveProbes)
	fmt.Fprintf(&b, "  omitted fields: %d categories\n", len(pkg.Omitted))
	if len(pkg.ReviewRequired) > 0 {
		fmt.Fprintf(&b, "  review before sharing: %s\n", strings.Join(pkg.ReviewRequired, "; "))
	}
	return b.String()
}

// WritePreview writes a human preview to w.
func WritePreview(w io.Writer, preview string) error {
	_, err := io.WriteString(w, preview)
	return err
}
