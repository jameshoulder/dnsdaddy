# Screenshots worth capturing

There are no screenshots in this repository. That is a gap: a protective DNS
tool is largely judged on whether its interface makes a decision
understandable, and nobody can judge that from prose.

**No mock-ups.** A fabricated dashboard would be worse than none at all — it
would misrepresent both what the software looks like and how much data a real
deployment produces. Everything below should come from a real instance with
real traffic, or from the offline lab, which produces genuine findings from
synthetic traffic.

If you run DNS Daddy, capturing any one of these is a genuinely useful
contribution. Open a PR adding the image under `docs/images/` and referencing
it from the README.

## The five that matter

**1 · Dashboard, healthy, with real data.**
The headline view: protection status, 24-hour query and block counts, the
activity chart with actual shape to it, and networks. The point is to show what
a working install looks like once it has been running for a day — not an empty
first-run screen.

**2 · Query log showing a block, with its reason.**
One row expanded far enough to show the domain, the client, the category, the
**feed that caused it**, and the plain-English reason. This is the single most
important screenshot in the set: "explainable decisions" is the project's main
claim, and this is the evidence for it.

**3 · Threat feeds page.**
Each source with its status, domain count and last successful refresh. Worth
capturing a state that includes a feed that has *failed* if you ever see one —
showing that a stale feed is reported honestly rather than hidden behind a
green tick is more persuasive than a page of ticks.

**4 · A finding, with its measurements.**
A detector finding expanded to show the signal table — measured value, band,
weight, contribution, and the score they sum to. The lab's `dns-tunnelling`
scenario produces one in about a minute if you have no real finding to hand.

**5 · `dnsdaddy doctor` in a terminal.**
Plain text, not an image of prose. Two versions are useful: one all-PASS run,
and one showing a real `FAIL` with its evidence and suggested action — a
misconfigured client ACL is the easiest to reproduce deliberately.

## Before you post one

Screenshots of a real deployment leak more than people expect:

- **Domain names in the query log** are browsing history. Use the lab, a test
  VLAN, or crop and redact.
- **Client IPs and hostnames** identify devices and often people.
- **Your network's CIDRs** appear on the Networks page and in `doctor` output.
- **The server's public address** appears in `doctor` and in the Setup page's
  DoH URLs.
- **DoH tokens** are credentials. They are shown in full on the Setup page.
- **The admin password** appears in first-run logs.

The lab (`docker compose --profile lab up --build`) is the safest source for
anything you plan to publish: every name is under `.example` or `.test`, the
clients are synthetic, and nothing in it is real.
