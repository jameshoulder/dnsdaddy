package refdelv

import (
	"strings"
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
)

// parseDelv against real delv output, captured verbatim.
//
// Every fixture below is the exact CombinedOutput of delv 9.18.39 run against
// the offline lab hierarchy, saved rather than written by hand. That matters:
// the defect this test exists for was a wrong belief about delv's output —
// specifically that its verdict is the first marker it prints — and a fixture
// composed from that same belief would have confirmed it. The whitespace,
// the ordering and the doubled semicolons are all delv's own.
//
// Keeping them here also decouples the parser from the tool. TestAgainstDelv
// skips when delv is absent, so on a machine without bind9-dnsutils nothing
// checked this mapping at all; these run everywhere.
func TestParseDelvUsesTheWeakestMarker(t *testing.T) {
	for _, tc := range []struct {
		name   string
		out    string
		status dnssec.ValidationStatus
		// unresolved marks the results the comparison layer treats as
		// "the oracle could not decide", rather than as a verdict.
		unresolved bool
	}{
		{
			// The plain case, and the only one where the first marker is
			// also the last.
			name: "a fully validated answer is Secure",
			out: `; fully validated
www.example.dnsdaddylab.	3600 IN	A 192.0.2.1
www.example.dnsdaddylab.	3600 IN	RRSIG A 15 3 3600 (
				20270409230406 20260409230406 39172 example.dnsdaddylab.
				aBc= )
`,
			status: dnssec.StatusSecure,
		},
		{
			// The regression. A CNAME in a signed zone pointing at a name
			// in an unsigned one: delv prints "; fully validated" for the
			// alias and "; unsigned answer" for the record it leads to,
			// in that order.
			//
			// Reading the first marker reports Secure for an answer whose
			// address records nothing authenticated. That is the shape of
			// a false Secure recorded as agreement, which would defeat the
			// entire point of running an oracle.
			name: "a signed alias into an unsigned zone is Insecure, not Secure",
			out: `;; validating host.unsigned.dnsdaddylab/A: no valid signature found
; fully validated
downgrade.example.dnsdaddylab. 3600 IN CNAME host.unsigned.dnsdaddylab.
downgrade.example.dnsdaddylab. 3600 IN RRSIG CNAME 15 3 3600 (
				20270409230406 20260409230406 39172 example.dnsdaddylab.
				vKGRaTMwYw6CuTiJn4YJs1iCNrowEp1S66lKe/xP33Y8
				qm0/jO62JAd+GmrCQHVN63bn0MGy901SnMvEFJ6oCA== )

; unsigned answer
host.unsigned.dnsdaddylab. 3600	IN A 192.0.2.4
`,
			status:     dnssec.StatusInsecure,
			unresolved: true,
		},
		{
			// The same defect in its worst direction: the terminal RRset
			// of a chain fails to verify, and the alias that led to it is
			// genuinely signed. Bogus must win over Secure.
			name: "a signed alias to a terminal that fails to verify is Bogus",
			out: `;; validating www.example.dnsdaddylab/A: no valid signature found
;; RRSIG failed to verify resolving 'www.example.dnsdaddylab/A/IN': 127.0.0.1#45674
;; resolution failed: RRSIG failed to verify
; fully validated
alias.example.dnsdaddylab. 3600	IN CNAME www.example.dnsdaddylab.
`,
			status: dnssec.StatusBogus,
		},
		{
			// delv reports a name error through the same "resolution
			// failed" line it uses for rejection, and says separately that
			// the negative answer validated. Reading "failed" literally
			// turns every correct NXDOMAIN into a disagreement.
			name: "an authenticated NXDOMAIN is Secure despite the word failed",
			out: `;; resolution failed: ncache nxdomain
; negative response, fully validated
; nope.example.dnsdaddylab. 3600 IN \-ANY	;-$NXDOMAIN
; mail.example.dnsdaddylab. NSEC *.wild.example.dnsdaddylab. MX RRSIG NSEC
; example.dnsdaddylab. NSEC *.aka.example.dnsdaddylab. NS SOA RRSIG NSEC DNSKEY
`,
			status: dnssec.StatusSecure,
		},
		{
			name: "an authenticated NODATA is Secure",
			out: `;; resolution failed: ncache nxrrset
; negative response, fully validated
; www.example.dnsdaddylab. 3600 IN \-TXT ;-$NXRRSET
; www.example.dnsdaddylab. NSEC example.dnsdaddylab. A RRSIG NSEC
`,
			status: dnssec.StatusSecure,
		},
		{
			// A budget, not a verdict. delv walked a CNAME loop until it
			// ran out of allowance; the aliases it did see were properly
			// signed. Recording that as Bogus would manufacture a
			// disagreement out of two validators choosing different caps.
			name: "quota reached on a CNAME loop is Indeterminate",
			out: `;; resolution failed: quota reached
; fully validated
loopa.example.dnsdaddylab. 3600	IN CNAME loopb.example.dnsdaddylab.
loopb.example.dnsdaddylab. 3600	IN CNAME loopa.example.dnsdaddylab.
`,
			status:     dnssec.StatusIndeterminate,
			unresolved: true,
		},
		{
			// Transport, not verdict. delv's canonical reason here is its
			// catch-all "failure" and the diagnosis is on the line above.
			// Reading the catch-all alone records a manufactured Bogus for
			// a query that never got an answer — an oracle blaming a zone
			// for the network, and in a live corpus the shape most likely
			// to drown out a real finding.
			//
			// Captured verbatim from a live run against 1.1.1.1.
			name: "a timeout is Indeterminate, not a rejection",
			out: `;; timed out resolving 'www.github.com/TXT/IN': 1.1.1.1#53
;; resolution failed: failure
`,
			status:     dnssec.StatusIndeterminate,
			unresolved: true,
		},
		{
			// The other half: a named reason is delv's own diagnosis and
			// is taken as given. A transport hiccup further down a long
			// chain must not talk a real rejection down into "no opinion",
			// which is the direction that would hide a Daddybound false
			// Secure.
			name: "a named rejection stands even alongside a timeout",
			out: `;; timed out resolving 'ns2.example.com/AAAA/IN': 1.1.1.1#53
;; validating www.example.com/A: no valid signature found
;; RRSIG failed to verify resolving 'www.example.com/A/IN': 1.1.1.1#53
;; resolution failed: RRSIG failed to verify
`,
			status: dnssec.StatusBogus,
		},
		{
			name: "a broken trust chain is Bogus",
			out: `;; no valid RRSIG resolving 'example.dnsdaddylab/DNSKEY/IN': 127.0.0.1#54377
;; broken trust chain resolving 'www.example.dnsdaddylab/A/IN': 127.0.0.1#54377
;; resolution failed: broken trust chain
`,
			status: dnssec.StatusBogus,
		},
		{
			// An insecure delegation delv could not prove insecure. It is
			// a statement about the data, so Bogus rather than a budget.
			name: "a failed insecurity proof is Bogus",
			out: `;; insecurity proof failed resolving 'www.example.dnsdaddylab/A/IN': 127.0.0.1#59330
;; resolution failed: insecurity proof failed
`,
			status: dnssec.StatusBogus,
		},
		{
			name: "an expired signature is Bogus",
			out: `;; validating www.example.dnsdaddylab/A: verify failed due to bad signature (keyid=39172): RRSIG has expired
;; resolution failed: RRSIG has expired
`,
			status: dnssec.StatusBogus,
		},
		{
			name: "an unsigned delegation answered without signatures is Insecure",
			out: `; unsigned answer
host.unsigned.dnsdaddylab. 3600	IN A 192.0.2.4
`,
			status:     dnssec.StatusInsecure,
			unresolved: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseDelv(tc.out)
			if err != nil {
				t.Fatalf("parseDelv: %v", err)
			}
			if got.Status != tc.status {
				t.Errorf("status = %s, want %s (detail %q)", got.Status, tc.status, got.Detail)
			}
			if got.Unresolved != tc.unresolved {
				t.Errorf("unresolved = %v, want %v", got.Unresolved, tc.unresolved)
			}
		})
	}
}

// Output carrying no marker this adapter understands must be an error rather
// than a guess.
//
// A default would have to be one of the four states, and every choice is
// wrong in a way that matters: defaulting to Secure hides a Daddybound false
// Secure behind an oracle that agrees with everything, and defaulting to
// Bogus buries a real disagreement under noise. An error stops the test and
// shows a human the output, which is the only response that scales to a delv
// release that changes its wording.
func TestParseDelvRefusesToGuess(t *testing.T) {
	for _, out := range []string{
		"",
		";; UDP setup with 127.0.0.1#5353 for 'www.example.com/A' failed: network unreachable\n",
		"www.example.com. 3600 IN A 192.0.2.1\n",
	} {
		if _, err := parseDelv(out); err == nil {
			t.Errorf("parseDelv(%q) succeeded; want an error", out)
		}
	}
}

// The marker order must not decide the verdict.
//
// This is the property the fixtures above sample. delv prints one comment per
// RRset it looked at, and which RRset it reaches first depends on the shape
// of the chain — so an implementation that stops at the first marker gives a
// verdict that is a function of traversal order rather than of what delv
// concluded. Reversing the lines is the cheapest way to state that.
func TestParseDelvIsIndependentOfMarkerOrder(t *testing.T) {
	const forwards = `; fully validated
alias.example.dnsdaddylab. 3600	IN CNAME www.example.dnsdaddylab.
; unsigned answer
www.example.dnsdaddylab. 3600	IN A 192.0.2.1
;; resolution failed: RRSIG failed to verify
`
	lines := strings.Split(strings.TrimSuffix(forwards, "\n"), "\n")
	for i, j := 0, len(lines)-1; i < j; i, j = i+1, j-1 {
		lines[i], lines[j] = lines[j], lines[i]
	}
	backwards := strings.Join(lines, "\n") + "\n"

	a, err := parseDelv(forwards)
	if err != nil {
		t.Fatalf("forwards: %v", err)
	}
	b, err := parseDelv(backwards)
	if err != nil {
		t.Fatalf("backwards: %v", err)
	}
	if a.Status != b.Status {
		t.Fatalf("reordering the markers changed the verdict: %s then %s", a.Status, b.Status)
	}
	if a.Status != dnssec.StatusBogus {
		t.Fatalf("weakest of {secure, insecure, bogus} = %s, want bogus", a.Status)
	}
}

// classifyDelvFailure reads delv's reason text, which is the one place this
// adapter does make a decision from prose. It is delv's own vocabulary rather
// than an English sentence, and the alternative — delv has no exit code that
// distinguishes these — is worse.
func TestClassifyDelvFailure(t *testing.T) {
	for _, tc := range []struct {
		reason string
		want   delvFailureKind
	}{
		{"ncache nxdomain", delvNegativeAnswer},
		{"ncache nxrrset", delvNegativeAnswer},
		{"quota reached", delvGaveUp},
		{"timed out", delvGaveUp},
		{"too many records", delvGaveUp},
		{"maximum number of links exceeded", delvGaveUp},
		{"RRSIG failed to verify", delvRejected},
		{"broken trust chain", delvRejected},
		{"insecurity proof failed", delvRejected},
		{"no valid NSEC", delvRejected},
		{"failure", delvRejected},
		// An unknown reason must land in the rejecting arm. Treating an
		// unrecognised failure as a budget would let a future delv wording
		// silently downgrade real rejections into "could not decide", which
		// the comparison layer excuses.
		{"something nobody has written yet", delvRejected},
		{"", delvRejected},
	} {
		if got := classifyDelvFailure(tc.reason); got != tc.want {
			t.Errorf("classifyDelvFailure(%q) = %v, want %v", tc.reason, got, tc.want)
		}
	}
}

// delvFailureReason must read the doubled-semicolon line delv actually
// prints. It was originally routed through firstDelvReason, whose prefix
// matching expected a single semicolon; it returned "", every reason
// classified as a rejection through the default arm, and every authenticated
// NXDOMAIN in the suite became a disagreement.
func TestDelvFailureReasonReadsTheRealLine(t *testing.T) {
	const out = `;; validating nope.example.dnsdaddylab/A: nonexistence proof(s) found
;; resolution failed: ncache nxdomain
; negative response, fully validated
`
	if got := delvFailureReason(out); got != "ncache nxdomain" {
		t.Fatalf("delvFailureReason = %q, want %q", got, "ncache nxdomain")
	}
	if got := delvFailureReason("nothing here\n"); got != "" {
		t.Fatalf("delvFailureReason with no marker = %q, want empty", got)
	}
}

// safeArgument is the only thing between a query name and delv's flag parser.
func TestSafeArgumentRejectsFlagsAndControlCharacters(t *testing.T) {
	for _, bad := range []string{
		"", "-a", "--anchor", "www.example.com ", "www\texample.com",
		"www.example.com\n", "www.exämple.com", "www.example.com\x00",
	} {
		if err := safeArgument(bad); err == nil {
			t.Errorf("safeArgument(%q) allowed it", bad)
		}
	}
	for _, good := range []string{"www.example.com.", "127.0.0.1", "_25._tcp.mail.example.com."} {
		if err := safeArgument(good); err != nil {
			t.Errorf("safeArgument(%q): %v", good, err)
		}
	}
}
