# AI assistance and human accountability

DNS Daddy uses AI-assisted development. AI may help generate code, tests,
documentation and review suggestions. Multiple models agreeing is not independent
security assurance. Responsibility for accepting and operating a change remains
with people, not with the models used to produce it.

## Claims the project can make

> DNS Daddy is an AI-assisted open-source DNS security project with documented
> data handling, automated security checks and transparent limitations. It is
> experimental and has not been independently security-audited.

"Practitioner-led" describes governance only when a practitioner actually directs
and accepts the work. "Reviewed by a cybersecurity practitioner" must identify the
reviewer, date, commit/version, scope, methods, findings and limitations in a
[review record](docs/trust/review-template.md). Do not say "verified secure",
"GDPR certified", "SOC 2 certified", "fully compliant worldwide" or "independently
audited" without the appropriate, scoped evidence. AI must not fill in human
sign-off fields or imply that a maintainer's job title verifies every code path.

## Contribution expectations

- Disclose material AI assistance in the PR: what was generated and what was
  reviewed. Do not fabricate a detailed prompt history that was not retained.
- Explain the security-relevant change, rejected alternatives, trust boundaries,
  data flows and failure behaviour. Understand code before accepting it.
- Add tests for misuse and benign cases, not just tests generated from the same
  implementation. Record actual commands, outputs and anything not tested.
- Review dependencies, licence compatibility, provenance and generated snippets;
  AI assistance does not guarantee originality or remove licence obligations.
- Do not send real DNS histories, client identifiers, credentials, private keys,
  embargoed reports or confidential customer material to AI services without a
  documented lawful and authorised basis. Use synthetic fixtures by default.
- Obtain a separate competent reviewer for high-risk authentication, cryptography,
  DNSSEC, parsing, privilege, deletion and release changes where possible. If none
  is available, record that limitation rather than checking an approval box.

Keep operational model behaviour separate from development tooling. The local
Daddybound statistical learner is not a hosted LLM; its retained behavioural
metadata and controls are described in [privacy](docs/privacy.md). This development
policy neither adds runtime telemetry nor enables external AI processing.
