# Compliance applicability and engineering roadmap

Baseline: 1 October 2026; reviewed repository commit
`e397bb503ce8e93cdb419c3e432269a61c7bc181`. This is an initial scoping and
engineering crosswalk, not an exhaustive legal opinion, certification assessment
or claim that every listed control has been tested. Status means documented
implementation, partial, planned or external organisational work; it never means
"compliant worldwide". Licensed standards and an assessor's detailed criteria must
be used for a formal assessment rather than treating this summary as their text.

## 1. Choose the operating model before choosing badges

A project publishing source, an organisation operating a self-hosted resolver,
a managed-service operator and a manufacturer supplying a commercial product have
different obligations. Record who determines purposes, who processes data on whose
behalf, whose data is processed, relevant jurisdictions, commercial/support model,
sector and external recipients. Publishing code alone does not automatically make
the maintainer processor of every installation's DNS logs. Conversely, support
uploads, a hosted resolver or managed telemetry can create additional responsibilities.

Treat requested names, IP addresses, friendly device names, networks, behavioural
inferences and operator notes as potentially personal/sensitive data. Removing an
IP does not necessarily anonymise a domain/network history. A device/IP is not a
reliable one-to-one identity for a person. An operator's sharing acknowledgement is
not automatically consent from the people whose data appears in a query.

## 2. Principal framework crosswalk

| Framework | Engineering contribution and present evidence | Work outside code / remaining evidence |
|---|---|---|
| EU GDPR; UK GDPR / Data Protection Act, taking current UK amendments into account | Existing minimisation switches, retention, protected management, documented recipients, export and encrypted backup support parts of Articles 5, 12-22, 25 and 32. Complete lifecycle and rights handling remain partial. | Determine lawful basis, controller/processor roles, notices, records of processing, retention necessity, DPIA where required, contracts/transfers, rights procedures and breach response. A toggle is not compliance. |
| ISO/IEC 27001:2022 with applicable 2024 amendment; ISO/IEC 27002 guidance | Threat model, access controls, secure development, vulnerability/change records and recovery evidence contribute to an organisation's scoped controls. | Define ISMS scope, accountable owner, risk assessment/treatment, Statement of Applicability, policies, competence, supplier management, internal audits, management reviews and independent certification where sought. Certification is not bestowed on a binary by implementing Annex A-like features. |
| ISO/IEC 27701:2025 | Data inventory, recipient/lifecycle controls and privacy risk evidence can support a privacy information management system. | Establish a scoped PIMS and assess its requirements. It is not an automatic GDPR certification or a checklist of application switches. |
| SOC 2 Trust Services Criteria | Access, monitoring, availability, change/release management, confidentiality and processing-integrity evidence can support a scoped service assessment. | A CPA assurance engagement concerns a defined service organisation/system. Select applicable criteria, describe the system and retain actual operating evidence; do not call an open-source repository "SOC 2 certified". |
| NIST CSF 2.0; SSDF SP 800-218 v1.1 | Organise governance and secure development around ownership, protecting code/builds, safer implementation and responding to vulnerabilities. Existing CI plus the new register/evidence pipeline are partial inputs. | Establish a current/target profile and real operating evidence. SSDF 1.2 was a draft in the sources consulted, not a completed replacement for the final 1.1 baseline. |
| OWASP ASVS 5.0.0; SAMM | Select a risk-appropriate ASVS verification scope for dashboard/API authentication, authorisation, session, input, cryptographic, data and logging controls. Target a documented Level 2 scope rather than claiming attainment. | Track each applicable versioned requirement to a test/result and justified exclusions; use SAMM for lifecycle improvement. No complete ASVS assessment has been performed here. |
| CISA KEV; CVE/CWE; FIRST CVSS and EPSS | Public advisory register, exact KEV correlation, dated scan evidence and triage workflow. Product weaknesses, dependency advisories and malicious-domain intelligence are separate. | Maintain human applicability/reachability review, coordinated disclosure, fix/retest/publication and bounded exceptions. KEV is not a certification and its absence is not evidence of safety. |
| MITRE ATT&CK | Existing detector mappings now label adversarial interpretations as hypotheses, with rationales and regression tests. | Validate representative scenarios/benign traffic and publish limitations; IDs do not prove coverage, prevention or compromise. |
| SLSA; OpenSSF Scorecard; SBOM / provenance practices | Existing dependency automation, pinned actions and CycloneDX CI output help. The supplemental workflow retains candidate inventory evidence. | Verify release-specific binary/image SBOMs, provenance, signing/verification, build isolation, tool pins, branch protection and release recovery. No SLSA level or reproducible-build guarantee is claimed. |
| IETF DNS and privacy standards | Map implemented resolver/transport behaviours to protocol and adversarial tests; publish a deployment-specific recursive operator privacy statement. | RFC 8932 is particularly relevant to a DNS privacy service. Test the actual implementation before claiming conformance, including privacy, DNSSEC and operational requirements. |

Sources: [ICO privacy by design](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/accountability-and-governance/guide-to-accountability-and-governance/data-protection-by-design-and-by-default/),
[ISO 27001](https://www.iso.org/standard/27001),
[ISO 27701](https://www.iso.org/standard/27701),
[AICPA SOC](https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services),
[NIST CSF](https://www.nist.gov/cyberframework),
[NIST SSDF](https://csrc.nist.gov/pubs/sp/800/218/final),
[SSDF publications](https://csrc.nist.gov/projects/ssdf/publications),
[OWASP ASVS](https://owasp.org/projects/asvs),
[SLSA](https://slsa.dev/spec/v1.2/),
[OpenSSF Scorecard](https://scorecard.dev/),
[RFC 8932](https://www.rfc-editor.org/info/rfc8932/).

## 3. Conditional laws and procurement requirements

**EU Cyber Resilience Act:** assess commercial manufacturer and open-source
steward status, not just the licence. The Commission distinguishes non-commercial
open-source distribution from products made available through commercial activity.
Reporting obligations started **11 September 2026** for entities within the relevant
scope; the principal product requirements apply **11 December 2027**. Do not assume
that all open source is exempt, or that this personal project is automatically an
in-scope commercial manufacturer. Reassess monetisation, distribution and support
arrangements before a commercial or hosted offering.
[CRA](https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act),
[open-source scope](https://digital-strategy.ec.europa.eu/en/policies/cra-open-source).

**NIS2 and sector rules:** operating a public DNS service can pose different
questions from distributing software. Assess the actual service definition and
national implementation with qualified advice. Financial customers may add DORA
supplier/operational requirements; payment, healthcare and government deployments
may introduce PCI DSS, HIPAA, FIPS-validated cryptographic-module or other assurance
requirements. These are not interchangeable universal software certifications.
Do not label ordinary AES/TLS use "FIPS validated" or an SBOM "FedRAMP compliant".
[NIS2 overview](https://digital-strategy.ec.europa.eu/en/policies/nis2-directive).

**Other jurisdictions:** build a deployment-specific applicability record for
California CCPA as amended by CPRA and other relevant US state laws; Brazil LGPD;
Canada's applicable federal/provincial privacy rules; Australia; Japan APPI;
Singapore PDPA; China PIPL; and India's applicable DPDP commencement/rules.
This is a screening list, not a determination that each applies. Verify current
commencement, thresholds, territorial reach, transfers, rights and exceptions in
that jurisdiction. Do not copy a GDPR notice and claim it covers every region.
For example, California has distinct sale/sharing and consumer-rights concepts:
[California Attorney General](https://oag.ca.gov/privacy/ccpa).

Assess workplace monitoring, children, electronic communications and marketing /
website cookies separately where relevant. A DNS firewall does not itself need a
marketing-cookie banner to process every query; consent is not a universal lawful
basis. The project website and any hosted service need their own actual data-flow
assessment. ISO 9001, ISO 14001 and Cyber Essentials concern organisational scopes,
not a certification obtained by changing DNS Daddy's application code.

## 4. Larger engineering work, in recommended order

### P1 - Effective privacy controls and a live data-handling view

Add an authenticated privacy view showing effective settings, each stored dataset,
actual last successful prune and oldest records, current upstream/recipient choices,
learning status and remote-copy limitations. Derive it from runtime configuration,
not a hard-coded compliance score. Include a privacy-first onboarding choice;
explain investigation trade-offs without silently changing existing installations.
Keep this view read-only: opening it must not send a domain to an external provider.

Acceptance: tests compare the displayed state to actual behaviour across Forward,
Learn and Live, each transport, policy logging settings, provider modes, queues and
restart. A setting change clearly distinguishes prospective collection from historic
retention. Aggregation, truncation and pseudonymisation are labelled accurately.

### P1 - Complete subject export, restriction and erasure lifecycle

Design a scoped, authenticated job with identity/authority verification, preview,
reauthentication for destructive actions, concurrency control, bounded batching,
failure recovery and a receipt. Cover correlated observations, decisions/captures,
findings/reviews, client presence/names, learned state and queued webhooks, not just
query_log. Shared/domain-only evidence needs an explicit attribution policy.

Acceptance: prevent re-ingestion while deleting; test crashes, retries, backpressure,
concurrent writes and restart. Receipts must not preserve the deleted identifiers
unnecessarily. Handle SQLite/WAL and storage remanence honestly. Define backup expiry,
restore/re-deletion safeguards and legal-retention exceptions. Remote providers,
operator exports and SIEM copies require separate handling; never claim their erasure
because a local SQL deletion succeeded. Do not automatically equate an IP with a person.

### P1 - Retention and at-rest protection across every copy

Implement per-dataset retention for change history and remaining retained state, with
documented minimum audit needs, bounded pruning, testable outcomes and alerts on
pruning failure. Add operator guidance for encrypted volumes, file permissions,
separate key custody, rotation/recovery and backup/export expiry. Field encryption is
not whole-database encryption; pseudonymisation is not anonymisation. Avoid bespoke
cryptography or a new "secure erase" promise that the storage stack cannot provide.

### P1 - Enterprise administration and auditability

Introduce named administrators, least-privilege roles and scoped/expiring API tokens;
MFA/passkeys or a carefully integrated identity provider; session revocation and
reauthentication for risky exports, key changes and deletion. Preserve restricted
local recovery without creating a bypass. Evaluate the existing actor model rather
than asserting that today's single administrator identity provides attribution to
several different people.

Acceptance: test every read/write authorisation boundary, CSRF, proxy identity,
revocation, lockout and recovery path. Add remote tamper-evident audit export with
sequence/integrity verification and explicit delivery gaps. Hash-chaining in the
same writable database is not tamper-proof against an administrator controlling it.

### P1 - Resolver correctness and independent review

Publish a versioned conformance/test map: DNS parsing, question/answer binding,
cache and bailiwick boundaries, TCP/truncation behaviour, DNSSEC chain/denial proofs,
anchor lifecycle, AD/CD semantics, authenticated transports and failover. Include
[RFC 9156](https://www.rfc-editor.org/info/rfc9156/) QNAME minimisation and its work
bounds, and the relevant DNSSEC, DoT, DoH and DoQ specifications for implemented modes.

Acceptance: adversarial/fuzz tests of wire/HTTP/feed inputs, representative
interoperability tests against independent implementations, overload and fault
injection, performance/availability measurements and a scoped independent review.
Test clean installation and recovery on each supported deployment model. Do not
claim a reliable enterprise resolver based only on documentation or synthetic demos.
Keep experimental learning alert-only until measured evidence supports any change.

### P1 - Release evidence and repository controls

Verify protected branches/rulesets, required status checks and meaningful review;
CODEOWNERS alone enforces none of these. Verify private reporting and recovery access.
Pin scanner/build tools with an update process. Scan source, final binary and final
image; correlate relevant inventories with KEV. Retain a release-specific SBOM,
licence inventory, checksums, signed provenance and a tested verification procedure.

Acceptance: another person can identify a release's source, components, build and
verification result without trusting a badge. Document unpatched findings and
exceptions, rollback/upgrade behaviour, support period and security-update process.
A commit signed by GitHub is not an independent review of its contents.

### P2 - Operate the assurance system

Assign accountable humans, review the risk and vulnerability registers, exercise
incident/breach response and restore procedures, assess suppliers and any data
transfers, and keep decision/evidence records. Draft the actual deployment notice
and contracts only after the operating model is known. Commission ISO/SOC assurance
when there is a defined organisation/system and sufficient real operating evidence.

Maintain a detector/model card: purpose, features, sources/licences, validation
split, benign/attack corpora, false positives/negatives, drift/poisoning risk, privacy
and retraining/reset behaviour. AI-assisted coding is not itself a product AI-risk
classification; assess what the deployed learner actually does and what people use
its inferences for. Do not turn anomaly scores into claims about an employee.

## 5. Readiness gate, not a marketing score

Before recommending a release for a consequential deployment: demonstrate working
resolution in supported modes, publish privacy/egress and support boundaries, resolve
or explicitly accept scoped findings, verify release evidence, test restoration and
obtain competent review of the highest-risk paths. Keep unavailable, untested,
experimental and independently verified evidence clearly separated. This roadmap
creates no certification, legal guarantee or human approval.
