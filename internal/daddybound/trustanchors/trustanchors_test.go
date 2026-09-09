package trustanchors

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// The IANA root anchors as DNSKEY records, exactly as published in
// root-anchors and shipped by every distribution as root.key.
//
// Present so the DS values in IANARootDS are *derived* here rather than
// trusted: a transposed character in a digest would make the root
// unvalidatable, and the failure would look like every zone being Bogus rather
// than like a typo.
const ksk2017 = `. IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=`

const ksk2024 = `. IN DNSKEY 257 3 8 AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc=`

// TestTheCompiledAnchorsMatchTheIANAKeys recomputes each DS from the DNSKEY it
// is supposed to describe.
func TestTheCompiledAnchorsMatchTheIANAKeys(t *testing.T) {
	want := map[uint16]string{}
	for _, k := range []string{ksk2017, ksk2024} {
		rr, err := dns.NewRR(k)
		if err != nil {
			t.Fatalf("parsing the IANA key: %v", err)
		}
		key, ok := rr.(*dns.DNSKEY)
		if !ok {
			t.Fatal("the IANA key is not a DNSKEY")
		}
		ds := key.ToDS(dns.SHA256)
		want[ds.KeyTag] = strings.ToUpper(ds.Digest)
	}

	if len(IANARootDS) != len(want) {
		t.Fatalf("%d compiled anchors, %d IANA keys", len(IANARootDS), len(want))
	}
	for _, spec := range IANARootDS {
		f := strings.Fields(spec)
		if len(f) != 5 {
			t.Fatalf("anchor %q is not owner/keytag/algorithm/digesttype/digest", spec)
		}
		var tag uint16
		if _, err := fmtSscan(f[1], &tag); err != nil {
			t.Fatalf("keytag in %q: %v", spec, err)
		}
		digest, ok := want[tag]
		if !ok {
			t.Fatalf("compiled anchor %d matches no IANA key", tag)
		}
		if !strings.EqualFold(f[4], digest) {
			t.Errorf("anchor %d digest is\n got %s\nwant %s", tag, f[4], digest)
		}
		if f[2] != "8" || f[3] != "2" {
			t.Errorf("anchor %d is algorithm %s digest type %s, want 8 and 2", tag, f[2], f[3])
		}
	}
}

// TestRootParses is the check that the compiled strings are usable at all,
// rather than only well-formed to the eye.
func TestRootParses(t *testing.T) {
	anchors, err := Root()
	if err != nil {
		t.Fatalf("Root: %v", err)
	}
	if anchors.Empty() {
		t.Fatal("Root returned no anchors")
	}
}

func TestFromFileAcceptsBothCommonForms(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "anchors")
	body := "; a comment\n# another\n\n" +
		IANARootDS[0] + "\n" +
		". IN DS 38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	anchors, err := FromFile(path)
	if err != nil {
		t.Fatalf("FromFile: %v", err)
	}
	if anchors.Empty() {
		t.Fatal("no anchors were read")
	}
}

// TestABadAnchorFileIsAnErrorRatherThanASkippedLine.
//
// Silently skipping a malformed line would configure a validator to trust less
// than the operator wrote, and the symptom — some zones Indeterminate — looks
// nothing like the cause.
func TestABadAnchorFileIsAnErrorRatherThanASkippedLine(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"typo":  ". 20326 8 2 NOTHEXADECIMAL\n",
		"short": ". 20326 8\n",
		"empty": "; only a comment\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := FromFile(path); err == nil {
				t.Fatal("a malformed anchor file was accepted")
			}
		})
	}

	if _, err := FromFile(filepath.Join(dir, "does-not-exist")); err == nil {
		t.Error("a missing anchor file was accepted")
	}
}

func fmtSscan(s string, v *uint16) (int, error) {
	var n uint64
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, errNotANumber
		}
		n = n*10 + uint64(r-'0')
	}
	*v = uint16(n)
	return 1, nil
}

var errNotANumber = errString("not a number")

type errString string

func (e errString) Error() string { return string(e) }
