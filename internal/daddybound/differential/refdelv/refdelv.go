// Package refdelv adapts BIND's delv as a second differential test oracle.
//
// A second oracle matters more than a second opinion usually does. One
// reference validator tells you whether Daddybound agrees with that
// implementation; two independent ones tell you whether a disagreement is
// about Daddybound or about a quirk of how the first is configured. That
// distinction decided a real question in this repository — see
// docs/daddybound/validation-lab.md on the ancestor-signature case, where the
// second oracle overturned the conclusion drawn from the first.
//
// delv is a separate codebase from libunbound (ISC's BIND rather than NLnet
// Labs' Unbound) with its own validator, and it performs its own chain walk
// rather than relying on a forwarder. It is invoked as a subprocess, so
// nothing here links against BIND and the shipped binary is untouched.
package refdelv

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/differential"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
)

// Available reports whether delv is on PATH.
func Available() bool {
	_, err := exec.LookPath("delv")
	return err == nil
}

// Why explains the absence, for a test's skip message.
func Why() string {
	if Available() {
		return ""
	}
	return "delv is not installed (apt-get install bind9-dnsutils)"
}

// Config is the oracle's settings.
type Config struct {
	// Forward is the host:port of the server holding the hierarchy.
	Forward string
	// Anchor is the trust anchor to validate from.
	Anchor dnssec.TrustAnchor
	// WorkDir is where the generated trust-anchor file is written. A test's
	// t.TempDir() is the intended value.
	WorkDir string
}

type oracle struct {
	host, port string
	anchorFile string
	version    string
}

// New writes a trust-anchor file and returns an oracle backed by delv.
//
// Unlike the libunbound adapter, this one has no clock override: delv offers
// no equivalent of val-override-date, so it judges signatures against the
// wall clock. Callers must therefore hand it fixtures that are current when
// it runs — lab.Scenario.Shifted exists for exactly that. There is no way to
// enforce it from here, so the validation-lab documentation records the
// obligation and a test asserts the shift is applied.
func New(cfg Config) (differential.Reference, error) {
	if !Available() {
		return nil, errors.New("refdelv: " + Why())
	}
	if cfg.Forward == "" {
		return nil, errors.New("refdelv: no server address")
	}
	if len(cfg.Anchor.Digest) == 0 {
		return nil, errors.New("refdelv: no trust anchor")
	}
	if cfg.WorkDir == "" {
		return nil, errors.New("refdelv: no working directory for the anchor file")
	}

	host, port, err := splitHostPort(cfg.Forward)
	if err != nil {
		return nil, err
	}

	// BIND's static-ds form: the same fields as a DS record, which is what
	// makes an anchor checkable against IANA's published value by eye.
	anchorFile := filepath.Join(cfg.WorkDir, "daddybound-anchor.conf")
	content := fmt.Sprintf("trust-anchors {\n  %q static-ds %d %d %d %q;\n};\n",
		cfg.Anchor.Name, cfg.Anchor.KeyTag, cfg.Anchor.Algorithm,
		cfg.Anchor.DigestType, strings.ToUpper(hexOf(cfg.Anchor.Digest)))
	if err := os.WriteFile(anchorFile, []byte(content), 0o600); err != nil {
		return nil, fmt.Errorf("refdelv: writing the anchor file: %w", err)
	}

	return &oracle{host: host, port: port, anchorFile: anchorFile, version: delvVersion()}, nil
}

func (o *oracle) Name() string { return o.version }

// Validate runs delv and maps its verdict.
func (o *oracle) Validate(ctx context.Context, qname string, qtype uint16) (differential.ReferenceResult, error) {
	// Every argument is constrained before it reaches the subprocess.
	//
	// There is no shell here — exec passes the arguments as a slice — so the
	// classic injection is not available. What is available is *argument*
	// injection: a query name beginning with "-" would be read by delv as a
	// flag, and delv has flags that change what validation means. Nothing in
	// this repository supplies such a name, and that is a fact about today's
	// callers rather than a property of the code, so it is checked here.
	typeName, ok := dns.TypeToString[qtype]
	if !ok {
		return differential.ReferenceResult{}, fmt.Errorf("refdelv: no mnemonic for type %d", qtype)
	}
	if err := safeArgument(qname); err != nil {
		return differential.ReferenceResult{}, fmt.Errorf("refdelv: query name: %w", err)
	}
	if _, ok := dns.IsDomainName(qname); !ok {
		return differential.ReferenceResult{}, fmt.Errorf("refdelv: %q is not a domain name", qname)
	}

	// #nosec G204 -- the binary is the fixed literal "delv"; the host and
	// port were parsed by splitHostPort, the type mnemonic comes from a
	// closed map, the anchor path is one this package constructed, and the
	// query name is checked above. Arguments are passed as a slice, so no
	// shell interprets any of them.
	cmd := exec.CommandContext(ctx, "delv",
		"@"+o.host, "-p", o.port,
		"-a", o.anchorFile,
		"+root=.",
		// Ask delv to say what it concluded rather than only to print the
		// answer, and keep it to one transport so a truncation retry does
		// not read as a second opinion.
		"+multiline",
		qname, typeName,
	)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return differential.ReferenceResult{}, ctx.Err()
	}

	res, perr := parseDelv(string(out))
	if perr != nil {
		return differential.ReferenceResult{}, fmt.Errorf("refdelv: %w (exit %v)\n%s", perr, err, out)
	}
	return res, nil
}

// parseDelv maps delv's own words onto the four RFC 4033 states.
//
// delv states its conclusion in a comment line rather than in an exit code,
// and the mapping is deliberately narrow: anything unrecognised is an error
// rather than a guess, because an oracle that quietly reports Insecure when
// it actually failed would flatter every comparison it took part in.
func parseDelv(out string) (differential.ReferenceResult, error) {
	switch {
	case strings.Contains(out, "; fully validated"):
		return differential.ReferenceResult{Status: dnssec.StatusSecure}, nil

	case strings.Contains(out, "; negative response, fully validated"):
		return differential.ReferenceResult{Status: dnssec.StatusSecure, Detail: "negative response"}, nil

	case strings.Contains(out, "; unsigned answer"),
		strings.Contains(out, "; negative response, unsigned answer"):
		// delv reports an unsigned answer without distinguishing RFC 4033's
		// Insecure from its Indeterminate, exactly as libunbound does.
		return differential.ReferenceResult{
			Status: dnssec.StatusInsecure, Unresolved: true, Detail: "unsigned answer",
		}, nil

	case strings.Contains(out, "resolution failed"):
		return differential.ReferenceResult{
			Status: dnssec.StatusBogus, Detail: firstDelvReason(out),
		}, nil
	}
	return differential.ReferenceResult{}, errors.New("delv said nothing this adapter recognises")
}

// firstDelvReason extracts the most specific line delv gave, for a human
// reading a failure. Never parsed for a decision.
func firstDelvReason(out string) string {
	var fallback string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, ";; no valid "),
			strings.HasPrefix(line, ";; validating") && strings.Contains(line, "failed"),
			strings.HasPrefix(line, ";; broken trust chain"),
			strings.HasPrefix(line, ";; got insecure response"):
			return line
		case strings.HasPrefix(line, "; resolution failed:") && fallback == "":
			fallback = line
		}
	}
	return fallback
}

func delvVersion() string {
	out, err := exec.Command("delv", "-v").CombinedOutput()
	if err != nil {
		return "delv (version unknown)"
	}
	return strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
}

func splitHostPort(addr string) (string, string, error) {
	i := strings.LastIndexByte(addr, ':')
	if i < 0 {
		return "", "", fmt.Errorf("refdelv: %q has no port", addr)
	}
	host, port := addr[:i], addr[i+1:]
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", "", fmt.Errorf("refdelv: %q has no valid port", addr)
	}
	if err := safeArgument(host); err != nil {
		return "", "", fmt.Errorf("refdelv: server address: %w", err)
	}
	if net.ParseIP(host) == nil {
		return "", "", fmt.Errorf("refdelv: %q is not an IP address", host)
	}
	return host, port, nil
}

// safeArgument rejects anything that a command-line parser could read as
// something other than a value.
//
// The leading-dash check is the one that matters: an argument starting with
// "-" becomes a flag, and delv's flags include ones that change what
// validation means. The rest keeps whitespace and control characters out of
// an argument list that a human will read in a test failure.
func safeArgument(s string) error {
	if s == "" {
		return errors.New("empty")
	}
	if strings.HasPrefix(s, "-") {
		return fmt.Errorf("%q would be read as a flag", s)
	}
	for _, r := range s {
		if r < 0x21 || r > 0x7E {
			return fmt.Errorf("%q contains a character that is not printable ASCII", s)
		}
	}
	return nil
}

func hexOf(b []byte) string {
	const d = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, d[c>>4], d[c&0xF])
	}
	return string(out)
}
