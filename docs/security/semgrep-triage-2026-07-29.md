# Semgrep triage — 2026-07-29

Source: `Semgrep_Code_Combined_Findings_2026_07_29.csv`, 13 findings across
three rules.

## How these were assessed

**A scanner alert is not automatically an exploitable vulnerability.** Each
finding was validated against the actual response type and the data flow
reaching it, not against the rule name. Semgrep's
`no-direct-write-to-responsewriter` rule, for example, exists to catch
unescaped HTML — but three of the four responses it flagged here are binary
DNS wire format, Prometheus exposition format, and a static embedded YAML
document. Passing any of those through `html/template` would corrupt the
protocol rather than protect anyone.

The reverse also holds: **the absence of an alert is not proof of safety.**
The most serious issue fixed in this round — Markdown injection into generated
reports — was found by tracing the data flow behind finding 904618429, not by
the rule itself. Semgrep flagged the write; the actual defect was in what was
being written.

Each finding is classified as one of:

| Classification | Meaning |
|---|---|
| **True positive** | A real weakness; fixed. |
| **Defence in depth** | Not exploitable as written, but the control was missing or weaker than it should be; hardened. |
| **Contextual false positive** | The rule's premise does not hold for this response type; documented and suppressed narrowly. |
| **Accepted risk** | Retained deliberately; documented. *(None in this round.)* |

## Findings

| ID | Rule | File | Original risk | Classification | Remediation | Test evidence | Suppression | Status |
|---|---|---|---|---|---|---|---|---|
| 904618432 | `cookie-missing-secure` | `internal/api/auth.go` (`SetSessionCookie`) | Session cookie could be sent over plain HTTP. `isHTTPS` trusted `X-Forwarded-Proto` from any peer, so a direct client could also assert the wrong scheme. | **True positive** | Trusted-proxy handling moved into `internal/httpx`. `X-Forwarded-Proto` is honoured only from a peer in `http.trusted_proxy_cidrs`; `r.TLS != nil` always counts as HTTPS. New `http.secure_cookies` policy (`auto`/`always`/`never`). | `TestSecureCookieModes`, `TestSecureCookieAutoHonoursTrustedProxyOnly`, `TestIsHTTPS`, `TestIsHTTPSWithTLS` | Narrow, on the assignment only | Resolved |
| 904618431 | `cookie-missing-secure` | `internal/api/auth.go` (`ClearSessionCookie`) | Logout cookie attributes could diverge from login, leaving the original cookie in place. | **True positive** | Both cookies share `secureFlag(r)`; `HttpOnly`, `Path`, `SameSite=Lax` and expiry preserved. | `TestClearSessionCookieMatchesSetAttributes` | Narrow, on the assignment only | Resolved |
| 904618430 | `no-direct-write-to-responsewriter` | `internal/api/handlers_config.go` | Direct write of the OpenAPI document. | **Contextual false positive** | Static `go:embed` asset; no request-controlled content. Confirmed `Content-Type: application/yaml; charset=utf-8`, `nosniff`, `Cache-Control`. | `TestOpenAPIResponseHeaders` (also asserts the body is byte-identical to the embedded spec) | Narrow, one line | Resolved |
| 904618429 | `no-direct-write-to-responsewriter` | `internal/api/handlers_reports.go` | Direct write of a generated Markdown report. | **True positive** — *not* for the reason the rule gives | Markdown injection: feed names, network names, locations, policy names, category labels and blocked domains reached the report unescaped. New `escapeMarkdownCell` / `markdownCode` helpers applied to every non-numeric value. Headers confirmed. | `TestEscapeMarkdownCell`, `TestMarkdownCode`, `TestRenderMarkdownNeutralisesHostileValues`, `TestReportMarkdownResponseHeaders` | Narrow, one line | Resolved |
| 904618428 | `no-direct-write-to-responsewriter` | `internal/api/metrics.go` | Direct write of Prometheus output. | **Contextual false positive** | Prometheus text exposition format. All label values are written with `%q`, which is the correct Prometheus escaping. Confirmed `Content-Type: text/plain; version=0.0.4; charset=utf-8` and `nosniff`. | `TestMetricsResponseHeaders` (validates exposition-format structure) | Narrow, one line | Resolved |
| 904618427 | `no-direct-write-to-responsewriter` | `internal/dnsserver/doh.go` | Direct write of a packed DNS message. | **Contextual false positive** | RFC 8484 binary wire format. `html/template` would corrupt the protocol response. Confirmed `Content-Type: application/dns-message`, `nosniff`, `Content-Length`, `Cache-Control` derived from the response TTL, and no user-controlled header content. | `TestBareDoHPathAllowedWhenOptedIn` (asserts `nosniff` and content type), `TestDoHClientAttributionIgnoresUntrustedXFF` | Narrow, one line | Resolved |
| 904618425 | `github-actions-mutable-action-tag` | `.github/workflows/ci.yml` | Mutable tag: whoever controls the tag controls CI. | **True positive** | Pinned to a verified 40-character commit SHA with a version comment. | `git ls-remote` verification against the official repository | — | Resolved |
| 904618424 | same | `.github/workflows/ci.yml` | same | **True positive** | same | same | — | Resolved |
| 904618423 | same | `.github/workflows/ci.yml` | same | **True positive** | same | same | — | Resolved |
| 904618422 | same | `.github/workflows/ci.yml` | same | **True positive** | same | same | — | Resolved |
| 904618421 | same | `.github/workflows/ci.yml` | same | **True positive** | same | same | — | Resolved |
| 904618420 | same | `.github/workflows/ci.yml` | same | **True positive** | same | same | — | Resolved |
| 904618419 | same | `.github/workflows/ci.yml` | same | **True positive** | same | same | — | Resolved |

## Suppressions used, and why each is safe

Every suppression is a single `// nosemgrep:` line naming the exact rule,
placed on the exact statement, with a comment explaining the reasoning and
naming the tests that prove it. **There are no file-wide or rule-wide
suppressions, and the rules remain enabled repository-wide.**

| File | Statement | Why suppression is safe |
|---|---|---|
| `internal/api/auth.go` | `Secure: a.secureFlag(r)` ×2 | The value is conditional on a validated runtime decision Semgrep cannot follow. Forcing `Secure: true` would break the supported plain-HTTP loopback/private-network mode: the browser would accept the cookie and never send it back, making login impossible. The trusted proxy is validated by CIDR membership in `httpx.TrustedProxies.Trusts`. |
| `internal/dnsserver/doh.go` | `w.Write(packed)` | RFC 8484 binary wire response. Cannot be HTML-escaped without corrupting the DNS protocol. |
| `internal/api/metrics.go` | `w.Write([]byte(b.String()))` | Prometheus exposition format. Label values escaped with `%q`. |
| `internal/api/handlers_config.go` | `w.Write(openAPISpec)` | Static embedded asset; nothing from the request reaches the body. |
| `internal/api/handlers_reports.go` | `w.Write([]byte(renderMarkdown(summary)))` | Markdown, not HTML; served as an attachment with `nosniff`. Every database-controlled value is escaped before it reaches the writer. |

## Corrections made during this review

Two errors from the previous remediation round were found and fixed here.

**The CodeQL action pin was a tag object, not a commit.** `github/codeql-action`
publishes `v3` as an *annotated* tag, so `git ls-remote refs/tags/v3` returns
the tag object SHA (`3b0bd1d1…`) rather than the commit it points at
(`4187e74d…`). GitHub Actions resolves `uses:` against commits, so the CodeQL
job would have failed to start. All references now use the dereferenced commit,
obtained with `refs/tags/v3^{}`. The other four actions publish lightweight
tags, where the plain ref is already the commit.

**The `handlers_reports.go` suppression comment was factually wrong.** It
claimed "the one attacker-influenced field is the domain name, which reaches
here only via `domainutil.Normalize` and so cannot contain markup". That is
untrue on two counts: `dnsserver.Handler` falls back to the raw qname when
normalisation fails, and feed, network, location and policy names are free text
set through the management API. The comment now describes the real data flow,
and the escaping it now claims actually exists.

## Follow-up — 2026-08-15

The tool was re-run locally during an audit of the repository, and the result
changed two of this document's conclusions.

**Three of the suppressions above were not suppressing anything.** Semgrep
honours `// nosemgrep:` only on the matched line or the line immediately above
it. Both annotations in `internal/api/auth.go` sat six lines above their
`http.SetCookie` call, separated from it by the `#nosec` explanation, so
`cookie-missing-secure` was still firing on both. The table said "Narrow, on
the assignment only" and that was true of the intent, not of the effect. Both
are now the last line before the statement, with a comment saying why the
position matters.

**One new finding, in code written after this review.**
`go.lang.security.audit.crypto.math_random.math-random-used` on
`cmd/dnsdaddy-lab`'s `math/rand` import. Classified **contextual false
positive**: the lab exists to generate *reproducible* synthetic traffic, and
`TestScenariosAreDeterministic` asserts that the same seed produces the same
queries. A cryptographic generator would make that impossible, and nothing the
lab generates is a secret. Every generator in the resolver, the API and the
store already uses `crypto/rand`. Suppressed narrowly on the import, with the
reasoning at both the import and the call site in `play()`.

**Semgrep now runs in CI** (`.github/workflows/security.yml`), with `--error`,
against `p/golang`, `p/github-actions` and `p/secrets`. That is the real lesson
of this round: the suppressions and this document described a control that
nothing re-ran, so nothing noticed when three of them stopped working. The tree
is at **0 findings** as of this follow-up.

## Residual risk

The report escape neutralises Markdown table structure and raw HTML. It does
**not** attempt to defeat homograph or right-to-left-override display tricks in
a name — a feed called `paypaI.com` still reads as `paypal.com` to a human.
That is a content-trust problem rather than an injection one, and the mitigation
is that feeds and networks are operator-created.
