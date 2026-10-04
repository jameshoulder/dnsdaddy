package resolver

import (
	"crypto/tls"
	"testing"
	"time"
)

// A library migration must not restore environment proxies, HTTP/1 fallback,
// cleartext h2c, compression, permissive certificates or unbounded headers.
// Existing encrypted_security_test fixtures exercise real success, malicious
// responses, certificates, cancellation and bounded connection ownership.
func TestStandardHTTP2TransportRetainsEncryptedBoundary(t *testing.T) {
	client, err := NewEncryptedUpstreams([]EncryptedEndpoint{{Protocol: "doh2", Address: "https://dns.test/dns-query", BootstrapIPs: []string{"127.0.0.1"}}}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	transport := client.endpoints[0].http.h2
	if transport == nil || transport.Protocols == nil || !transport.Protocols.HTTP2() || transport.Protocols.HTTP1() || transport.Protocols.UnencryptedHTTP2() {
		t.Fatal("encrypted transport permits an unintended protocol")
	}
	if transport.Proxy != nil || !transport.DisableCompression || transport.MaxResponseHeaderBytes != int64(maxEncryptedHeaderBytes) {
		t.Fatal("proxy, compression or response-header boundary changed")
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.InsecureSkipVerify || transport.TLSClientConfig.MinVersion < tls.VersionTLS13 {
		t.Fatal("certificate verification or TLS minimum was weakened")
	}
	if transport.HTTP2 == nil || !transport.HTTP2.StrictMaxConcurrentRequests || transport.HTTP2.SendPingTimeout != 15*time.Second || transport.HTTP2.PingTimeout != 5*time.Second || transport.HTTP2.WriteByteTimeout != 5*time.Second {
		t.Fatal("bounded stream admission or stalled-peer timeouts changed")
	}
}
