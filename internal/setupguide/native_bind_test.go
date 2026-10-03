package setupguide

import (
	"strings"
	"testing"
)

func TestNativeListenerBoundariesMatchThePreset(t *testing.T) {
	for _, tc := range []struct{ preset, server, clients, listen string }{
		{"lan", "192.168.1.2", "192.168.1.50", "192.168.1.2:53"},
		{"device", "192.168.1.2", "192.168.1.50", "192.168.1.2:53"},
		{"vpn", "fd00::53", "fd00::50", "[fd00::53]:53"},
		{"vps", "203.0.113.53", "198.51.100.9", ":53"},
		{"roaming", "203.0.113.53", "", "127.0.0.1:5353"},
		{"local", "127.0.0.1", "127.0.0.1", "127.0.0.1:5353"},
	} {
		t.Run(tc.preset, func(t *testing.T) {
			p, err := Build(Input{Preset: tc.preset, ServerIP: tc.server, Clients: tc.clients})
			if err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{"listen_udp", "listen_tcp"} {
				if !strings.Contains(p.NativeYAML, key+": \""+tc.listen+"\"") {
					t.Fatalf("%s did not bind %s to %s", tc.preset, key, tc.listen)
				}
			}
		})
	}
}
