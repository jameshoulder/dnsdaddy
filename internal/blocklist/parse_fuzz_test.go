package blocklist

import "testing"

// Feed lines are untrusted network input. Parsing must not panic on arbitrary
// bytes, and must not invent a blockable domain from noise.
func FuzzParseLine(f *testing.F) {
	for _, seed := range []string{
		"evil.example",
		"0.0.0.0 evil.example",
		"127.0.0.1 evil.example # comment",
		"||evil.example^",
		"@@||whitelist.example^",
		"",
		"# comment only",
		"not a domain !!!",
		string([]byte{0x00, 0xff, 0xfe}),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, line string) {
		for _, format := range []Format{FormatAuto, FormatHosts, FormatDomains, FormatAdblock} {
			domain, ok := parseLine(line, format)
			if !ok {
				continue
			}
			if domain == "" {
				t.Fatalf("format %s returned ok with empty domain for %q", format, line)
			}
		}
	})
}
