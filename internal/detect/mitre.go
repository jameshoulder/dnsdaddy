package detect

// MITRE ATT&CK mappings for DNS Daddy's behavioural detectors.
//
// House rule: a technique is attached only where the behaviour DNS Daddy
// actually measures is the behaviour the technique describes, and every
// mapping carries a rationale explaining the link. Where a mapping is a
// hypothesis about a true positive rather than something the evidence
// establishes, it is marked Hypothesis and says so in the rationale.
//
// Techniques deliberately NOT attached anywhere in this package:
//
//   - T1041 (Exfiltration Over C2 Channel) — DNS Daddy cannot see whether a
//     tunnel is carrying data out or instructions in, so choosing between
//     T1041 and T1048.003 would be a guess. T1048.003 is attached to
//     tunnelling as a hypothesis and T1041 is left off entirely.
//   - T1090 (Proxy) and T1573 (Encrypted Channel) — plausible for a tunnel,
//     but nothing in the DNS telemetry distinguishes them, so attaching them
//     would inflate apparent coverage without adding information.
//   - Anything at all for resolution-failure findings. A burst of SERVFAIL is
//     an operational signal. Mapping infrastructure breakage to an adversary
//     technique because DNSSEC failures *can* accompany T1584 would be exactly
//     the decoration this rule exists to prevent.
//
// Sources: https://attack.mitre.org/techniques/enterprise/

// Technique catalogue. Names and tactics follow ATT&CK Enterprise.
var (
	// techAppLayerDNS is the canonical C2-over-DNS technique.
	techAppLayerDNS = Technique{
		ID:     "T1071.004",
		Name:   "Application Layer Protocol: DNS",
		Tactic: "Command and Control",
		URL:    "https://attack.mitre.org/techniques/T1071/004/",
	}

	// techExfilNonC2 covers data leaving over a protocol that is not the
	// primary C2 channel, which is what a one-way DNS tunnel looks like.
	techExfilNonC2 = Technique{
		ID:     "T1048.003",
		Name:   "Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol",
		Tactic: "Exfiltration",
		URL:    "https://attack.mitre.org/techniques/T1048/003/",
	}

	// techDGA covers algorithmically generated rendezvous domains.
	techDGA = Technique{
		ID:     "T1568.002",
		Name:   "Dynamic Resolution: Domain Generation Algorithms",
		Tactic: "Command and Control",
		URL:    "https://attack.mitre.org/techniques/T1568/002/",
	}

	// techEncoding covers payloads encoded into a carrier, which is the label
	// encoding a DNS tunnel depends on.
	techEncoding = Technique{
		ID:     "T1132.001",
		Name:   "Data Encoding: Standard Encoding",
		Tactic: "Command and Control",
		URL:    "https://attack.mitre.org/techniques/T1132/001/",
	}
)

// withRationale returns a copy of t carrying the reason it was attached.
func withRationale(t Technique, rationale string) Technique {
	t.Rationale = rationale
	return t
}

// asHypothesis returns a copy of t marked as a hypothesis about a true
// positive rather than an established fact.
func asHypothesis(t Technique, rationale string) Technique {
	t.Rationale = rationale
	t.Hypothesis = true
	return t
}

// tunnelTechniques are the mappings for EventTunnelSuspected.
func tunnelTechniques() []Technique {
	return []Technique{
		withRationale(techAppLayerDNS,
			"The measured behaviour is the mechanism T1071.004 describes: a client is "+
				"using DNS name resolution as a data carrier rather than to look up "+
				"addresses. Large numbers of distinct, high-entropy labels under a single "+
				"parent domain, addressed to that domain's own authoritative server, is "+
				"how DNS is used as an application-layer channel."),
		asHypothesis(techExfilNonC2,
			"If the tunnel is carrying data outbound, the request labels are the payload "+
				"and T1048.003 applies. DNS Daddy sees query volume, label structure and "+
				"entropy; it does not decode the payload, so it cannot establish direction. "+
				"Treat this mapping as the exfiltration hypothesis to test during triage, "+
				"not as a determination."),
		withRationale(techEncoding,
			"Labels scoring as base32/base64/hex under a single parent are the encoding "+
				"step T1132.001 describes. This mapping rests on the encoded_label_ratio "+
				"signal specifically; where that signal did not contribute, the finding "+
				"scored on volume and entropy alone and this mapping is weaker."),
	}
}

// beaconTechniques are the mappings for EventBeaconing.
func beaconTechniques() []Technique {
	return []Technique{
		asHypothesis(techAppLayerDNS,
			"Regular, low-jitter DNS queries for one name are consistent with an implant "+
				"polling for instructions over DNS. They are equally consistent with any "+
				"software that checks in on a timer, and DNS Daddy cannot see the content "+
				"of the exchange. The mapping states what this would be if malicious; the "+
				"finding itself only establishes periodicity."),
	}
}

// dgaTechniques are the mappings for EventDGALike.
func dgaTechniques() []Technique {
	return []Technique{
		withRationale(techDGA,
			"T1568.002 describes a host attempting to reach rendezvous points at "+
				"algorithmically generated domains, most of which are not registered. The "+
				"signals here — many distinct registered domains with random-looking "+
				"second-level labels, mostly resolving NXDOMAIN, from one client in a "+
				"short window — are the direct resolver-side observable of that behaviour."),
	}
}

// nxdomainTechniques are the mappings for EventNXDomainBurst.
func nxdomainTechniques() []Technique {
	return []Technique{
		asHypothesis(techDGA,
			"A burst of failed lookups is the expected resolver-side artefact of a DGA "+
				"walking its domain list. It is also what a misconfigured search suffix, a "+
				"broken internal name, or a captive-portal check produces. This finding "+
				"measures the burst only; the DGA reading is the hypothesis to confirm by "+
				"inspecting the names themselves, and the dga_like_domains detector is what "+
				"tests it."),
	}
}

// txtTechniques are the mappings for EventTXTAnomaly.
func txtTechniques() []Technique {
	return []Technique{
		asHypothesis(techAppLayerDNS,
			"TXT records carry arbitrary text and are the highest-capacity commonly "+
				"permitted response type, which makes them the usual choice for DNS-based "+
				"C2 and staging. This finding establishes that a client's TXT usage is "+
				"anomalous in volume or structure after excluding the standard mail, "+
				"certificate and verification lookups; it does not establish that the "+
				"records carry attacker content."),
	}
}
