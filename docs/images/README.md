# Screenshots

Every image whose name starts with `increment-` was captured from a real
`dnsdaddy` process by a Playwright script, not composed by hand. The traffic
behind them is **synthetic laboratory data**: the resolver was pointed at a
local sink instead of a real upstream, every client address is a loopback
address (`127.0.0.2`, `127.0.0.9`, …), every name sits under the reserved
`.example` or `.test` domains, and the two threat feeds were local files named
"Lab malware list" and "Lab ads list". Nothing in them is a real network, a
real device or a real indicator.

| Image | What it shows |
| --- | --- |
| `increment-overview.png` | The overview after the lab scenarios ran: blocked queries split into security and preference, the resolver card with clients seen, networks by state and the windowed failure rate. |
| `increment-investigate.png` | A domain investigation narrowed to one client, after the name had been allow-listed: the stored decisions still say *blocked*, the read-only preview says *allowed*, and the two are labelled as different things. |
| `increment-investigate-390.png` | The same page at 390 px. |
| `increment-findings-review.png` | The findings page with a review recorded against a synthetic beaconing finding. The note is a hostile string, rendered as text. |
| `increment-daddybound-status.png` | The Daddybound runtime card with Learn off: Live unavailable, nothing resolving, no readiness figure. |
| `increment-daddybound-learn.png` | The same card with Learn on inside a container that cannot reach the root servers: native resolution, timeouts and unreachable outcomes counted as operational results, the trust point seeded but never refreshed, and the evidence table still *not quantified*. |

The older images (`dashboard.png`, `assurance.png`, `detections.png`,
`sign-in.png`, `neo-aqua-*.png`) predate this set and are referenced from the
README.
