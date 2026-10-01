package detect

// ATT&CK mappings describe investigation hypotheses, not proof of an adversary.
// DNS shape, timing and response codes cannot establish endpoint intent, payload
// content or exfiltration. Keep the measured signals separate from this inference.
// Sources: https://attack.mitre.org/techniques/enterprise/
var (
	techAppLayerDNS = Technique{
		ID: "T1071.004", Name: "Application Layer Protocol: DNS",
		Tactic: "Command and Control", URL: "https://attack.mitre.org/techniques/T1071/004/",
	}
	techExfilNonC2 = Technique{
		ID: "T1048.003", Name: "Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol",
		Tactic: "Exfiltration", URL: "https://attack.mitre.org/techniques/T1048/003/",
	}
	techDGA = Technique{
		ID: "T1568.002", Name: "Dynamic Resolution: Domain Generation Algorithms",
		Tactic: "Command and Control", URL: "https://attack.mitre.org/techniques/T1568/002/",
	}
	techEncoding = Technique{
		ID: "T1132.001", Name: "Data Encoding: Standard Encoding",
		Tactic: "Command and Control", URL: "https://attack.mitre.org/techniques/T1132/001/",
	}
)

// withRationale returns a copy; the catalogue must never acquire finding state.
func withRationale(t Technique, rationale string) Technique {
	t.Rationale = rationale
	return t
}

func asHypothesis(t Technique, rationale string) Technique {
	t = withRationale(t, rationale)
	t.Hypothesis = true
	return t
}

func tunnelTechniques() []Technique {
	return []Technique{
		asHypothesis(techAppLayerDNS,
			"Distinct, long, high-entropy names are consistent with DNS carrying a "+
				"command-and-control channel, but DNSBL, CDN and telemetry lookups can "+
				"share this shape. The detector does not establish attacker intent or "+
				"decode a channel. Confirm with endpoint and traffic evidence."),
		asHypothesis(techExfilNonC2,
			"T1048.003 is relevant only if investigation confirms outbound data "+
				"over an unencrypted non-C2 protocol. Query statistics alone do not "+
				"establish payload content, exfiltration or the channel's C2 role; "+
				"transport selection alone cannot decide this mapping."),
		asHypothesis(techEncoding,
			"The encoded_label_ratio signal measures resemblance to encoding "+
				"alphabets, not decoded malicious content. Confirm actual encoding "+
				"and its adversarial use before asserting T1132.001. When that "+
				"signal did not contribute, this is only a triage possibility."),
	}
}

func beaconTechniques() []Technique {
	return []Technique{
		asHypothesis(techAppLayerDNS,
			"Regular, low-jitter queries may indicate DNS C2 polling, but legitimate "+
				"software also checks in on timers. The finding establishes periodicity, "+
				"not a command channel. Correlate with the originating process."),
	}
}

func dgaTechniques() []Technique {
	return []Technique{
		asHypothesis(techDGA,
			"Many random-looking domains and failed lookups are consistent with a "+
				"DGA, but do not prove algorithmic generation, malware or rendezvous "+
				"intent. Inspect the names and originating process; benign generated "+
				"names and configuration faults can produce similar observations."),
	}
}

func nxdomainTechniques() []Technique {
	return []Technique{
		asHypothesis(techDGA,
			"A failed-lookup burst can occur when a DGA tries candidate domains, "+
				"but also with stale search suffixes, broken configuration or captive "+
				"portal checks. The separate DGA-like detector adds evidence, not "+
				"confirmation. Inspect the names and endpoint before escalating."),
	}
}

func txtTechniques() []Technique {
	return []Technique{
		asHypothesis(techAppLayerDNS,
			"Unusual TXT activity can be relevant to DNS C2, but TXT also supports "+
				"legitimate mail, certificate and verification services. The finding "+
				"does not establish attacker-controlled record content or a command "+
				"channel. Confirm with record and endpoint evidence."),
	}
}
