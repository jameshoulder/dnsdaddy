package config

import "testing"

func TestAdvertisedDNSIsValidatedAndDisplayOnly(t *testing.T) {
	for _, endpoint := range []string{"192.0.2.53:53", "[2001:db8::53]:5353", "127.0.0.1:5353"} {
		t.Run(endpoint, func(t *testing.T) {
			t.Setenv("DNSDADDY_ADVERTISED_DNS", endpoint)
			cfg, err := Load("")
			if err != nil {
				t.Fatal(err)
			}
			if cfg.DNS.AdvertisedEndpoint != endpoint {
				t.Fatal("advertised endpoint lost")
			}
			if cfg.DNS.ListenUDP != Default().DNS.ListenUDP || cfg.DNS.ListenTCP != Default().DNS.ListenTCP || cfg.DNS.AllowPublicResolver {
				t.Fatal("display setting changed network exposure")
			}
		})
	}
}

func TestAdvertisedDNSRejectsAmbiguousOrNonUnicastEndpoints(t *testing.T) {
	for _, endpoint := range []string{"192.0.2.53", "https://192.0.2.53", "[https://example.test](https://example.test)", "example.test:53", "0.0.0.0:53", "[::]:53", "224.0.0.1:53", "[ff02::1]:53", "[fe80::1%eth0]:53", "192.0.2.53:0", "192.0.2.53:65536"} {
		t.Run(endpoint, func(t *testing.T) {
			t.Setenv("DNSDADDY_ADVERTISED_DNS", endpoint)
			if _, err := Load(""); err == nil {
				t.Fatalf("accepted %q", endpoint)
			}
		})
	}
}
