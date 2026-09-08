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
// delv states its conclusion in comment lines rather than in an exit code, and
// it prints one per RRset it looked at. A CNAME chain therefore produces
// several: the alias may be "; fully validated" while the record it points at
// is "; unsigned answer", or while the resolution as a whole failed.
//
// Taking the first marker found was a defect in this adapter, and a dangerous
// one. delv prints the per-RRset comments before the failure line, so a chain
// whose terminal RRset failed to verify came back as Secure — an oracle
// reporting agreement where the real validator had refused. In the
// FALSE_BOGUS direction that is noise; in the other direction it would have
// let a Daddybound false Secure be recorded as a match, which is the one
// outcome this suite exists to make impossible.
//
// So every marker is collected and the weakest wins, which is the same rule a
// resolver applies to a chain and the same one Daddybound applies in
// dnssec.weakest. The mapping stays narrow: output containing no recognised
// marker is an error rather than a guess.
func parseDelv(out string) (differential.ReferenceResult, error) {
	var (
		found   bool
		result  differential.ReferenceResult
		weakest int
		detail  string
	)
	take := func(rank int, r differential.ReferenceResult, d string) {
		if !found || rank > weakest {
			found, weakest, result, detail = true, rank, r, d
		}
	}

	if strings.Contains(out, "; fully validated") ||
		strings.Contains(out, "; negative response, fully validated") {
		take(0, differential.ReferenceResult{Status: dnssec.StatusSecure}, "")
	}
	if strings.Contains(out, "; unsigned answer") ||
		strings.Contains(out, "; negative response, unsigned answer") {
		// delv reports an unsigned answer without distinguishing RFC 4033's
		// Insecure from its Indeterminate, exactly as libunbound does.
		take(1, differential.ReferenceResult{
			Status: dnssec.StatusInsecure, Unresolved: true,
		}, "unsigned answer")
	}
	if strings.Contains(out, "resolution failed") {
		reason := delvFailureReason(out)
		switch classifyDelvFailure(reason) {
		case delvNegativeAnswer:
			// Not a failure at all. delv reports a name error or a NODATA
			// as "resolution failed: ncache nxdomain" or "ncache nxrrset",
			// and says separately whether the negative answer validated.
			// Reading the word "failed" literally turns every correct
			// NXDOMAIN into a rejection — which is what happened here the
			// first time this function was rewritten.
		case delvGaveUp:
			// delv stopped walking rather than judging the data. That is
			// its equivalent of Indeterminate, and recording it as Bogus
			// would manufacture a disagreement out of two validators
			// choosing different budgets.
			take(2, differential.ReferenceResult{
				Status: dnssec.StatusIndeterminate, Unresolved: true,
			}, reason)
		default:
			// Rejected. The detail is the most specific line delv printed
			// rather than the canonical reason, because this is the string
			// a human reads out of a failing differential test and
			// "broken trust chain resolving 'example/DNSKEY/IN'" localises
			// the problem where "broken trust chain" does not. The verdict
			// above was decided from the canonical reason; only the prose
			// comes from here.
			take(3, differential.ReferenceResult{Status: dnssec.StatusBogus}, firstDelvReason(out))
		}
	}

	if !found {
		return differential.ReferenceResult{}, errors.New("delv said nothing this adapter recognises")
	}
	result.Detail = detail
	return result, nil
}

// How to read a "resolution failed" line from delv.
//
// The word "failed" covers three different things, and telling them apart is
// the difference between an oracle that reports what delv concluded and one
// that reports what it printed.
type delvFailureKind int

const (
	// delvRejected: delv judged the data and refused it.
	delvRejected delvFailureKind = iota
	// delvNegativeAnswer: a name error or NODATA, which delv reports through
	// the same line. Whether it validated is said elsewhere.
	delvNegativeAnswer
	// delvGaveUp: delv stopped walking — a budget, not a verdict.
	delvGaveUp
)

// delvFailureReason returns the text after "resolution failed:".
//
// This is the single reader of that line. Classification below depends on it,
// and so does the human-facing message, because two readers of the same line
// is how one of them drifts: the first version of this adapter had exactly
// that, with classification routed through firstDelvReason, whose prefix
// match expected one semicolon where delv prints two. It returned "", every
// reason fell through to the rejecting default arm, and every authenticated
// NXDOMAIN in the suite was recorded as a disagreement.
func delvFailureReason(out string) string {
	const marker = "resolution failed:"
	for _, line := range strings.Split(out, "\n") {
		if i := strings.Index(line, marker); i >= 0 {
			return strings.TrimSpace(line[i+len(marker):])
		}
	}
	return ""
}

// classifyDelvFailure decides which of the three things delv means by
// "resolution failed".
//
// This is the one place the adapter reads prose to make a decision, and it is
// only tolerable because delv has no exit code that distinguishes these and
// because the strings are delv's own fixed vocabulary rather than free text.
// Nothing downstream of it reaches Daddybound: the result is the *oracle's*
// verdict, never the validator's.
//
// The default arm rejects. An unrecognised reason must not be read as a
// budget, because the comparison layer excuses an oracle that could not
// decide — so a future delv wording landing in delvGaveUp would silently turn
// real rejections into "no opinion", which is the direction that hides a
// Daddybound false Secure.
func classifyDelvFailure(reason string) delvFailureKind {
	switch {
	case strings.Contains(reason, "ncache nxdomain"),
		strings.Contains(reason, "ncache nxrrset"):
		return delvNegativeAnswer
	case strings.Contains(reason, "quota reached"),
		strings.Contains(reason, "timed out"),
		strings.Contains(reason, "too many"),
		strings.Contains(reason, "maximum number"):
		return delvGaveUp
	default:
		return delvRejected
	}
}

// firstDelvReason builds the message a human reads in a test failure. It
// prefers whichever line localises the problem best and falls back to the
// canonical reason. Never parsed for a decision — classifyDelvFailure is.
func firstDelvReason(out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, ";; no valid "),
			strings.HasPrefix(line, ";; validating") && strings.Contains(line, "failed"),
			strings.HasPrefix(line, ";; broken trust chain"),
			strings.HasPrefix(line, ";; got insecure response"):
			return line
		}
	}
	return delvFailureReason(out)
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
