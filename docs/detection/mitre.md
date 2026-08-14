# MITRE ATT&CK mapping

DNS Daddy attaches ATT&CK techniques to findings. This page states the policy
those mappings follow, lists every mapping with its reasoning, and — more
usefully — lists the techniques deliberately *not* attached and why.

[ATT&CK] is a knowledge base of adversary behaviour observed in the wild. Its
value in a detection tool is a shared vocabulary: "T1071.004" means the same
thing to a SOC analyst, a threat intelligence report and a coverage matrix.

That value only holds if the mappings are accurate.

## The policy

**A technique is attached only where the behaviour DNS Daddy actually measures
is the behaviour the technique describes.**

Not "is associated with". Not "could indicate". The mechanism has to match.

**Every mapping carries a rationale**, in the finding itself, not only here. An
ATT&CK ID with no explanation makes a finding look authoritative without making
it more useful, and it pollutes any coverage measurement built on top of it.

**Mappings that are hypotheses are marked as hypotheses.** Some techniques
describe what the behaviour *would* be if the finding is a true positive,
rather than something the evidence establishes. Those carry
`"hypothesis": true`, and the rationale says what would confirm them.

**No mapping is better than a decorative one.** Techniques are cheap to attach
and expensive to attach wrongly: a coverage matrix built from bad mappings
tells you that you are covered when you are not, which is worse than knowing
you are not.

### Why this matters more than it sounds

The commercial incentive runs entirely the other way. Every ATT&CK ID on a
datasheet looks like a capability, and a coverage matrix with more cells filled
in wins more evaluations. That pressure produces mappings where the connection
is "malware sometimes does this and this technique is about malware".

The tell is a mapping with no stated mechanism. If a tool claims a technique
and cannot say which measurement establishes it, it has not detected the
technique — it has detected something and labelled it.

---

## Mappings in use

### T1071.004 — Application Layer Protocol: DNS

*Tactic: Command and Control.* [Technique page][T1071.004]

Attached to `dns_tunnel_suspected` **as established**:

> The measured behaviour is the mechanism T1071.004 describes: a client is
> using DNS name resolution as a data carrier rather than to look up addresses.
> Large numbers of distinct, high-entropy labels under a single parent domain,
> addressed to that domain's own authoritative server, is how DNS is used as an
> application-layer channel.

This is the strongest mapping in the set. The technique describes DNS as a
transport; the detector measures the properties that make DNS work as a
transport. Nothing is inferred beyond what is measured.

Attached to `dns_beaconing_suspected` **as a hypothesis**:

> Regular, low-jitter DNS queries for one name are consistent with an implant
> polling for instructions over DNS. They are equally consistent with any
> software that checks in on a timer, and DNS Daddy cannot see the content of
> the exchange.

Attached to `txt_activity_anomaly` **as a hypothesis**:

> TXT records carry arbitrary text and are the highest-capacity commonly
> permitted response type, which makes them the usual choice for DNS-based C2
> and staging. This finding establishes that a client's TXT usage is anomalous
> after excluding the standard mail, certificate and verification lookups; it
> does not establish that the records carry attacker content.

### T1048.003 — Exfiltration Over Unencrypted Non-C2 Protocol

*Tactic: Exfiltration.* [Technique page][T1048.003]

Attached to `dns_tunnel_suspected` **as a hypothesis**:

> If the tunnel is carrying data outbound, the request labels are the payload
> and T1048.003 applies. DNS Daddy sees query volume, label structure and
> entropy; it does not decode the payload, so it cannot establish direction.
> Treat this mapping as the exfiltration hypothesis to test during triage, not
> as a determination.

Worth dwelling on. A DNS tunnel carrying data *out* is exfiltration; the same
tunnel carrying instructions *in* is command and control. From the resolver
they look identical — the same names, the same volume, the same entropy. The
direction lives in the payload, which is not decoded.

Both are attached, one established and one hypothesised, rather than guessing.

### T1132.001 — Data Encoding: Standard Encoding

*Tactic: Command and Control.* [Technique page][T1132.001]

Attached to `dns_tunnel_suspected` **as established**:

> Labels scoring as base32/base64/hex under a single parent are the encoding
> step T1132.001 describes. This mapping rests on the encoded_label_ratio
> signal specifically; where that signal did not contribute, the finding scored
> on volume and entropy alone and this mapping is weaker.

The second sentence is the point. This mapping is conditional on a specific
signal having fired, and the rationale says which — so an analyst reading a
finding where `encoded_label_ratio` contributed 0.00 knows to weigh it less.

Because names are lowercased before analysis, base64 and base32 collapse into
the same observable. The detector cannot tell them apart and does not claim to.

### T1568.002 — Dynamic Resolution: Domain Generation Algorithms

*Tactic: Command and Control.* [Technique page][T1568.002]

Attached to `dga_like_domains` **as established**:

> T1568.002 describes a host attempting to reach rendezvous points at
> algorithmically generated domains, most of which are not registered. The
> signals here — many distinct registered domains with random-looking
> second-level labels, mostly resolving NXDOMAIN, from one client in a short
> window — are the direct resolver-side observable of that behaviour.

Attached to `nxdomain_burst` **as a hypothesis**:

> A burst of failed lookups is the expected resolver-side artefact of a DGA
> walking its domain list. It is also what a misconfigured search suffix, a
> broken internal name, or a captive-portal check produces. This finding
> measures the burst only; the DGA reading is the hypothesis to confirm by
> inspecting the names themselves, and the dga_like_domains detector is what
> tests it.

Two findings, same technique, different strength — because they measure
different things. `dga_like_domains` looks at whether the names are
algorithmic. `nxdomain_burst` looks only at the failure rate, which has many
innocent causes.

When both fire for the same client in the same window, that is meaningfully
stronger than either alone. That is the argument for several narrow detectors
over one that tries to decide everything.

---

## Techniques deliberately not attached

This list is the more informative half of the page.

### T1041 — Exfiltration Over C2 Channel

Plausible for a tunnel. Not attached, because choosing between T1041 and
T1048.003 requires knowing whether the tunnel is the primary C2 channel or a
secondary path, and DNS Daddy cannot see that. T1048.003 is attached as a
hypothesis and T1041 is left off rather than attaching both and being right by
coincidence.

### T1090 — Proxy, and T1573 — Encrypted Channel

Both plausible for a tunnel. Nothing in the DNS telemetry distinguishes them
from any other tunnel, so attaching them would inflate apparent coverage
without adding information.

### Anything at all for `resolution_failure_burst`

A burst of SERVFAIL is an operational signal. Failed DNSSEC validation *can*
accompany infrastructure hijacking (T1584), so there is a story that gets from
one to the other — and telling that story would be precisely the decoration
this policy exists to prevent.

Far more often it is an expired signature, a nameserver that went away, or the
upstream having a bad afternoon. The finding lists all of those in its evidence
and maps to nothing.

### T1583.001 / T1584.001 — Acquire or Compromise Infrastructure: Domains

These describe what an adversary did *before* the traffic DNS Daddy sees. A
newly registered domain resolving is consistent with them and also with a
business launching a website. Resource-development techniques are not
detectable from resolution behaviour, and claiming them would be claiming
visibility into the adversary's preparation.

### T1557 — Adversary-in-the-Middle: DNS spoofing

DNS Daddy's DoT upstream and cache design *mitigate* aspects of this. Mitigating
a technique is not detecting it, and only detections carry mappings here.
Mitigations live in the [threat model](../threat-model.md).

---

## Using these mappings

They are in every finding, in the API, and in the NDJSON export:

```bash
curl -H "Authorization: Bearer dnsd_…" \
  'https://your-server/api/v1/findings?detail=true' \
| jq -r '.findings[] | .detail
         | "\(.eventType)\t\([.mitre[] | .id + (if .hypothesis then "?" else "" end)] | join(","))"'
```

```
dns_tunnel_suspected      T1071.004,T1048.003?,T1132.001
nxdomain_burst            T1568.002?
dns_beaconing_suspected   T1071.004?
resolution_failure_burst
```

**Filter on `hypothesis` when building coverage metrics.** Counting hypothesised
mappings as coverage is how a matrix ends up claiming detection of exfiltration
on the strength of a client resolving a lot of subdomains.

## Honest coverage assessment

DNS Daddy produces telemetry relevant to a **small** number of ATT&CK
techniques, all in Command and Control and Exfiltration, all from one data
source (DNS resolution). It has nothing to say about initial access, execution,
persistence, privilege escalation, defence evasion, credential access,
discovery, lateral movement or impact.

That is what a DNS resolver can see. A coverage matrix showing DNS Daddy
covering more than the handful of techniques above would be measuring
enthusiasm rather than capability.

[ATT&CK]: https://attack.mitre.org/
[T1071.004]: https://attack.mitre.org/techniques/T1071/004/
[T1048.003]: https://attack.mitre.org/techniques/T1048/003/
[T1132.001]: https://attack.mitre.org/techniques/T1132/001/
[T1568.002]: https://attack.mitre.org/techniques/T1568/002/
