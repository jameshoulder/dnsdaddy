# Screenshots and capture guidance

The README uses the current original red, black and off-white identity in both
dark and light themes. Its ten `hacker-*.png` images show the real application
running against an isolated offline lab. The
[image inventory and capture provenance](images/SCREENSHOTS.md) link each view
to its source revision, workflow and machine-readable manifest. Earlier red
and light-theme galleries remain available there as historical evidence.

Screenshots must come from a real instance and its actual API responses.
Synthetic traffic is appropriate when it goes through the real resolver,
logging and detection paths and is labelled as a lab. Do not replace counters,
findings, DOM content or screenshot pixels to make a deployment look healthier
or more mature than it is. Keep observed warning, failure, warming and
unverified states visible.

## Current gallery

| View | File | What it communicates |
| --- | --- | --- |
| Sign-in | [hacker-sign-in.png](images/hacker-sign-in.png) | Approved logo, an empty password field and no instance telemetry before authentication. |
| Dark overview | [hacker-dashboard.png](images/hacker-dashboard.png) | Actual lab activity, resolver setup and selected Forward mode. |
| Light overview | [hacker-dashboard-light.png](images/hacker-dashboard-light.png) | The same application with the operator's light-theme choice. |
| Query explanation | [hacker-queries.png](images/hacker-queries.png) | A stored block with its domain, source and explanation expanded. |
| Findings | [hacker-findings.png](images/hacker-findings.png) | Experimental findings produced by seeded offline scenarios, with evidence visible. |
| Investigation | [hacker-investigate.png](images/hacker-investigate.png) | Stored activity and original decisions for a reserved lab domain. |
| Daddybound | [hacker-daddybound.png](images/hacker-daddybound.png) | Resolver choices and the actual local-validation and learning state. |
| Assurance | [hacker-assurance.png](images/hacker-assurance.png) | Evidence categories, experimental scope and project limitations. |
| Phone overview | [hacker-mobile.png](images/hacker-mobile.png) | The same lab at a 390px phone viewport. |
| Phone navigation | [hacker-mobile-navigation.png](images/hacker-mobile-navigation.png) | The actual menu open with its current route and controls. |

## Refreshing the gallery

The reproducible [brand capture runner](../internal/web/brand.browser.test.cjs)
runs in the deployment-evidence workflow. It uses the built daemon and lab
generator, a temporary database, local DNS fixtures, reserved `.example`
names and a synthetic local threat feed. Forward mode is selected and local
DNSSEC validation is off. The lab's seed, speed and shortened detector
windows are recorded in the manifest; they are demonstration conditions,
not production performance or accuracy evidence.

For an interface change, refresh every affected view under `docs/images/`
and update [the provenance record](images/SCREENSHOTS.md). Preserve the capture
manifest with exact source and head commits, capture times, browser version,
binary hashes, image dimensions and hashes, served frontend hashes, traffic
recipe and completed checks. Link the corresponding workflow run. Retain
historical files with their original provenance rather than overwriting an
old image and keeping its old evidence.

Capture the dark and light themes through the normal theme control. Exercise
mobile navigation through its controls, and check page-level overflow at
390px and 320px. Keep the normal Content Security Policy enabled. The current
runner also checks for browser errors, remote resource loads, empty password
fields and agreement between source and served assets; consult the manifest
and workflow for actual outcomes.

### What to show in additional views

- **Query log:** expand a real recorded decision far enough to show the
  domain, client, source and plain-English reason. Identify synthetic feeds
  explicitly.
- **Findings:** show the measurements and evidence behind an actual finding.
  Label seeded scenarios and accelerated detector settings. Behavioural
  detectors are experimental and alert-only; a demonstration is not an
  accuracy study.
- **Threat feeds:** keep the actual source status, domain count and refresh
  time visible, including any real stale or failed state.
- **Resolver setup:** show the configured listener and address scope. An
  observed loopback address must remain labelled host-only; do not imply LAN
  or internet reachability that was not established.
- **Assurance:** retain the alpha and AI-assistance disclosures and the absence
  of an independent professional security review.
- **`dnsdaddy doctor`:** prefer copyable plain text. Include the real evidence
  and suggested action for a diagnostic failure, and describe any deliberately
  induced misconfiguration.

## Before you publish

Use an isolated lab where possible. Review captures from a real deployment
for private information:

- **Domain names in the query log** can reveal browsing history.
- **Client IPs and hostnames** can identify devices and people.
- **Network CIDRs** appear in network configuration and diagnostics.
- **Server addresses** can appear in diagnostic output and Setup URLs.
- **DoH tokens and admin passwords** are credentials and must not appear in
  published images or logs. An empty password field is required for sign-in
  captures.

If a production capture must be cropped or redacted, say so in its provenance
and preserve the distinction from the unedited lab gallery. Do not retain a
claim that an edited image is a byte-identical raw capture.

For local exploration, the documented offline lab can be started with
`docker compose --profile lab up --build`. Its names are under `.example` or
`.test` and its clients are synthetic. Use the capture runner and its manifest
when producing the reproducible README gallery.
