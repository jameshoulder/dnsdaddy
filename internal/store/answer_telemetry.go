package store

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// AnswerTelemetry is the opt-in, bounded summary of address answers recorded
// beside a query-log row. It stores a hash of A/AAAA addresses, not the
// addresses themselves, plus count and minimum TTL. TXT and other payloads are
// never collected by this path.
type AnswerTelemetry struct {
	// AddrCount is how many unique A/AAAA addresses were in the answer.
	AddrCount int `json:"addrCount,omitempty"`
	// AddrSHA256 is the hex SHA-256 of the sorted unique address strings.
	AddrSHA256 string `json:"addrSha256,omitempty"`
	// MinTTL is the lowest TTL among those address records (seconds).
	MinTTL uint32 `json:"minTtl,omitempty"`
	// Recorded is true when answer telemetry was collected for this row.
	Recorded bool `json:"recorded,omitempty"`
}

// SummarizeAnswerAddresses extracts a privacy-preserving summary of A/AAAA
// answer records. Non-address RRsets are ignored. Returns a zero value when
// there are no address answers.
func SummarizeAnswerAddresses(msg *dns.Msg) AnswerTelemetry {
	if msg == nil {
		return AnswerTelemetry{}
	}
	addrs := make([]string, 0, 4)
	var minTTL uint32
	haveTTL := false
	for _, rr := range msg.Answer {
		var (
			ip  net.IP
			ttl uint32
		)
		switch v := rr.(type) {
		case *dns.A:
			ip, ttl = v.A, v.Hdr.Ttl
		case *dns.AAAA:
			ip, ttl = v.AAAA, v.Hdr.Ttl
		default:
			continue
		}
		if ip == nil {
			continue
		}
		addrs = append(addrs, ip.String())
		if !haveTTL || ttl < minTTL {
			minTTL = ttl
			haveTTL = true
		}
	}
	if len(addrs) == 0 {
		return AnswerTelemetry{}
	}
	sort.Strings(addrs)
	// Deduplicate after sort.
	uniq := addrs[:0]
	var prev string
	for _, a := range addrs {
		if a == prev {
			continue
		}
		uniq = append(uniq, a)
		prev = a
	}
	sum := sha256.Sum256([]byte(strings.Join(uniq, "\n")))
	return AnswerTelemetry{
		AddrCount:  len(uniq),
		AddrSHA256: hex.EncodeToString(sum[:]),
		MinTTL:     minTTL,
		Recorded:   true,
	}
}
