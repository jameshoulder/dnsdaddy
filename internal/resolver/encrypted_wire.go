package resolver

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// Client-specific EDNS options never cross the strict transport boundary. In
// particular ECS, cookies and arbitrary local identifiers would otherwise
// expose clients to a configured forwarding service. DNSSEC request flags are
// preserved; transport authentication does not promote an AD bit to local trust.
func prepareEncryptedQuery(input *dns.Msg) (*dns.Msg, []byte, error) {
	if input == nil || input.Response || input.Opcode != dns.OpcodeQuery || input.Zero || len(input.Question) != 1 || len(input.Answer) != 0 || len(input.Ns) != 0 {
		return nil, nil, fmt.Errorf("%w: require a single standard DNS question", ErrEncryptedResponse)
	}
	question := input.Question[0]
	if question.Qtype == dns.TypeAXFR || question.Qtype == dns.TypeIXFR || question.Qtype == 0 || question.Qclass == 0 {
		return nil, nil, fmt.Errorf("%w: zone transfers and unspecified question types are unsupported", ErrEncryptedResponse)
	}
	question.Name = dns.Fqdn(question.Name)
	if _, ok := dns.IsDomainName(question.Name); !ok {
		return nil, nil, fmt.Errorf("%w: invalid question name", ErrEncryptedResponse)
	}
	var opt *dns.OPT
	for _, additional := range input.Extra {
		candidate, ok := additional.(*dns.OPT)
		if !ok || opt != nil || candidate == nil || candidate.Version() != 0 {
			return nil, nil, fmt.Errorf("%w: only one EDNS version 0 OPT is supported; signed queries are not forwarded", ErrEncryptedResponse)
		}
		opt = candidate
	}
	query := &dns.Msg{
		MsgHdr:   dns.MsgHdr{RecursionDesired: input.RecursionDesired, CheckingDisabled: input.CheckingDisabled, AuthenticatedData: input.AuthenticatedData},
		Question: []dns.Question{question},
	}
	if opt != nil {
		query.SetEdns0(1232, opt.Do())
	}
	wire, err := query.Pack()
	if err != nil || len(wire) < 12 || len(wire) > maxEncryptedMessageBytes {
		return nil, nil, fmt.Errorf("%w: question cannot be encoded within the DNS message limit", ErrEncryptedResponse)
	}
	return query, wire, nil
}

func validateEncryptedReply(wire []byte, query *dns.Msg) (*dns.Msg, error) {
	if len(wire) < 12 || len(wire) > maxEncryptedMessageBytes || binary.BigEndian.Uint16(wire[4:6]) != 1 {
		return nil, fmt.Errorf("%w: invalid message size or question count", ErrEncryptedResponse)
	}
	// Msg.Unpack deliberately tolerates trailing bytes and some inaccurate RR
	// counts. Check complete framing before allowing the parser to normalize it.
	offset := 12
	_, offset, err := dns.UnpackDomainName(wire, offset)
	if err != nil || offset > len(wire)-4 {
		return nil, fmt.Errorf("%w: incomplete question", ErrEncryptedResponse)
	}
	offset += 4
	rrs := int(binary.BigEndian.Uint16(wire[6:8])) + int(binary.BigEndian.Uint16(wire[8:10])) + int(binary.BigEndian.Uint16(wire[10:12]))
	// Even an empty RR needs its root name and ten-byte fixed header.
	if rrs > (len(wire)-offset)/11 {
		return nil, fmt.Errorf("%w: resource count exceeds message bounds", ErrEncryptedResponse)
	}
	for range rrs {
		_, offset, err = dns.UnpackDomainName(wire, offset)
		if err != nil || offset > len(wire)-10 {
			return nil, fmt.Errorf("%w: incomplete resource header", ErrEncryptedResponse)
		}
		rdLength := int(binary.BigEndian.Uint16(wire[offset+8 : offset+10]))
		offset += 10
		if rdLength > len(wire)-offset {
			return nil, fmt.Errorf("%w: incomplete resource data", ErrEncryptedResponse)
		}
		offset += rdLength
	}
	if offset != len(wire) {
		return nil, fmt.Errorf("%w: trailing message data", ErrEncryptedResponse)
	}
	response := new(dns.Msg)
	if err := response.Unpack(wire); err != nil {
		return nil, fmt.Errorf("%w: malformed DNS data", ErrEncryptedResponse)
	}
	if response.Id != 0 || !response.Response || response.Opcode != query.Opcode || response.Zero || len(response.Question) != 1 {
		return nil, fmt.Errorf("%w: header does not match the query", ErrEncryptedResponse)
	}
	expected, actual := query.Question[0], response.Question[0]
	if !strings.EqualFold(dns.Fqdn(expected.Name), dns.Fqdn(actual.Name)) || expected.Qclass != actual.Qclass || expected.Qtype != actual.Qtype {
		return nil, fmt.Errorf("%w: question does not match the query", ErrEncryptedResponse)
	}
	var optSeen bool
	for _, additional := range response.Extra {
		if opt, ok := additional.(*dns.OPT); ok {
			if optSeen {
				return nil, fmt.Errorf("%w: duplicate OPT records", ErrEncryptedResponse)
			}
			optSeen = true
			for _, option := range opt.Option {
				if option.Option() == dns.EDNS0TCPKEEPALIVE {
					return nil, fmt.Errorf("%w: TCP keepalive is not valid on this transport", ErrEncryptedResponse)
				}
			}
		}
	}
	return response, nil
}
