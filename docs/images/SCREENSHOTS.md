# UI screenshot provenance

The canonical README screenshots below were captured directly from the running DNS Daddy application on **29 September 2026, 10:57:45–10:57:46 UTC**. They show the current light interface from [commit `382beb2`](https://github.com/jameshoulder/dnsdaddy/tree/382beb2d0ebaea56659646d23fa6f8bd1106f2fe), which includes the merged workspace redesign.

The pages, data and component states are real application output. No API responses, DOM contents, counters, statuses or DNS evidence were substituted for presentation, and the PNGs have not been recoloured or composited. The names and traffic come from the isolated synthetic lab described below. These images demonstrate the interface and its lab behaviour; they are not evidence of production detection accuracy or an independent security review.

## Image inventory

| File | Output size | Capture | Route | Visible state |
|---|---:|---|---|---|
| [sign-in.png](sign-in.png) | 1440 × 1000 | Viewport | `/` | Signed out; password field empty. |
| [dashboard.png](dashboard.png) | 1440 × 1000 | Viewport | `#/dashboard` | Synthetic lab, current overview; default collapsed connection guide. |
| [detections.png](detections.png) | 1440 × 1200 | Viewport | `#/detections` | Newest synthetic finding expanded using its native disclosure. |
| [assurance.png](assurance.png) | 1440 × 2655 | Full page | `#/assurance` | Full page; Daddybound observation explicitly off in this isolated lab. |
| [queries.png](queries.png) | 1440 × 1000 | Viewport | `#/queries?action=blocked` | Blocked query filter; first synthetic query explanation expanded. |
| [mobile.png](mobile.png) | 390 × 844 | Viewport | `#/dashboard` | Mobile overview; navigation closed. |

All desktop captures use a 1,440 CSS-pixel-wide viewport. Sign-in, overview and query-log viewports are 1,000 pixels high; Findings and Assurance use 1,200 pixels. Assurance is a full-page capture, so its PNG includes the evidence sections and limitations below the initial viewport. The mobile image uses a 390 × 844 CSS-pixel viewport. Device scale is 1, so one CSS pixel produces one output pixel.

The older `neo-aqua-overview.png`, `neo-aqua-query-detail.png` and `neo-aqua-mobile.png` preview assets remain available. The six files in the table are the canonical captures for this README refresh. Banner and icon artwork have separate brand provenance.

## Runtime and capture conditions

| Setting | Value |
|---|---|
| Source revision | `382beb2d0ebaea56659646d23fa6f8bd1106f2fe` |
| Running build label | `dev+382beb2` |
| Go | `go1.25.13 linux/amd64`; `CGO_ENABLED=0` |
| Browser | Chrome for Testing / Headless Shell `151.0.7922.34` |
| Capture driver | Playwright `1.62.1`, Node.js `v24.19.0` |
| Browser locale / timezone | `en-GB` / `UTC` |
| Browser preferences | `colorScheme: 'light'`, `reducedMotion: 'reduce'` |
| Screenshot options | `animations: 'disabled'`; `fullPage` as listed above |
| Application origin | `http://127.0.0.1:18080` |
| DNS listeners | UDP and TCP on `127.0.0.1:15353` |
| Only upstream | Lab responder on `127.0.0.1:15300` |
| Allowed client ranges | `127.0.0.0/8`, `::1/128` |
| External feeds / Observatory | All disabled |
| External API integrations | Disabled; reputation mode `off` |
| Local DNSSEC observation | Explicitly `off` |
| Query / decision records | Enabled, containing synthetic lab data only |
| Detection timing | `window_scale: 0.1`, `eval_interval: 5s`, `cooldown: 2m` |

The sign-in image was taken before entering the temporary lab password. The password input was verified empty again before every authenticated-page capture. No credentials are visible in any screenshot. No production database, hostname, client address or threat infrastructure was used.

## Synthetic data shown

The lab used three local hosts-format files, each containing one reserved example domain. Each was added through the normal management API and loaded through the ordinary feed-refresh path:

| Feed name | Category | File contents |
|---|---|---|
| Synthetic malware fixtures | `malware` | `0.0.0.0 blocked.example` |
| Synthetic phishing fixtures | `phishing` | `0.0.0.0 phishing-check.example` |
| Synthetic cryptomining fixtures | `cryptomining` | `0.0.0.0 miner-check.example` |

A `Synthetic lab` network covers `127.0.0.0/8`, uses `p_standard`, and has resolver access enabled. The local clients have names such as `Lab manual checks`, `Lab ordinary browsing`, `Lab tunnel scenario` and `Lab beacon scenario`.

The manual fixture sent 240 A queries from `127.0.0.1`, repeating this ten-name sequence 24 times:

```text
blocked.example
phishing-check.example
miner-check.example
www.docs.example
api.shop.example
www.bank.example
mail.example
news.example
search.example
gov.example
```

The seven built-in scenarios then ran concurrently, with seed 1 and tenfold time compression. Each used its built-in, distinct loopback client address. The screenshot session began after the beaconing run completed and nine findings had been recorded.

The running API reported **2,772 queries, 72 blocked queries and nine findings** at capture time. The block rate is 2.6% in the API and is rounded to 3% by the overview's existing display logic. Findings comprised one high and eight medium results. The normal-DNS and benign high-entropy scenarios raised no findings. The `hasSeenClients` flag remains false because this lab only uses loopback clients; the overview correctly retains its loopback-only connection notice.

## Commands and capture procedure

The temporary working directory was `../screenshot-runtime` beside the checkout. Its configuration, database, password and helper scripts are local capture scaffolding and are not part of the application or this image commit.

The application and lab responder were built from the pinned checkout using:

```bash
CGO_ENABLED=0 GOTOOLCHAIN=local \
  ../screenshot-runtime/go/bin/go build -trimpath \
  -o ../screenshot-runtime/dnsdaddy ./cmd/dnsdaddy
CGO_ENABLED=0 GOTOOLCHAIN=local \
  ../screenshot-runtime/go/bin/go build -trimpath \
  -o ../screenshot-runtime/dnsdaddy-lab ./cmd/dnsdaddy-lab
```

The isolated runtime was launched with these arguments, from the temporary directory:

```bash
export TZ=UTC
./dnsdaddy-lab -sink 127.0.0.1:15300
./dnsdaddy -config lab.yaml
```

The `lab.yaml` supplied the listener, upstream, disabled integration/DNSSEC, logging and detection settings in the table above. It also set `feeds.refresh_on_start: false`, `feeds.refresh_interval: 24h`, a restricted local fixture directory, and a newly generated lab-only admin password. Before any synthetic queries were sent, the helper used the normal authenticated API to disable every catalog feed, add and refresh the three fixture feeds, create the loopback network, and name the synthetic clients.

Each traffic-generator process used this exact argument pattern:

```bash
./dnsdaddy-lab -server 127.0.0.1:15353 \
  -scenario SCENARIO -speed 10 -seed 1 -quiet
```

`SCENARIO` was, in turn, `normal-dns`, `dns-tunnelling`, `high-entropy-subdomains`, `nxdomain-anomaly`, `suspicious-txt`, `dga-simulation`, and `beaconing`. The processes ran concurrently. Only these bounded generator processes were awaited; the resolver and upstream remained running during capture.

The final helper invocations in that same runtime session were:

```bash
python seed-lab.py
node capture-readme.cjs
```

The Playwright capture used the following browser options and real page operations:

```javascript
const browser = await chromium.launch({
  headless: true,
  executablePath: './chrome/chrome-headless-shell-linux64/chrome-headless-shell',
  args: ['--no-sandbox'], // Isolated ephemeral capture container.
});
const context = await browser.newContext({
  viewport: { width: 1440, height: 1000 },
  deviceScaleFactor: 1,
  colorScheme: 'light',
  reducedMotion: 'reduce',
  locale: 'en-GB',
  timezoneId: 'UTC',
});
```

For each authenticated route it waited for `#view[aria-busy="false"]`, checked the visible page title, and used `page.screenshot({ path, fullPage, animations: 'disabled' })`. It opened the first Findings disclosure with `page.locator('details.finding').first().locator('summary').click()` and the first blocked-query disclosure with `page.locator('details.qrow').first().locator('summary').click()`. Browser state and screenshot dimensions are listed in the inventory. The password was supplied from a private temporary file and was never included in an image or committed file.

Re-running the lab reproduces the traffic scenarios, not identical screenshot bytes: timestamps, generated network IDs and small timing-dependent detector measurements can differ. Keep the synthetic labels and the non-enforcing/experimental statements visible when replacing these images.

## Verification

All six PNGs were opened and visually checked. Each route finished loading, and none of the captured pages overflowed horizontally. The session recorded zero JavaScript errors, zero console/CSP errors, zero failed HTTP resources and zero external resource requests. The running binary served the following files byte-for-byte identically to the pinned checkout:

```text
fb2b630ad68e719aecf56837493fcd59b16ed75d45ea1b1f7a078274d8a575e3  index.html
44326fb2a439b2bb01f8179a65b75c9c832c707646df6344e7be053bc291060f  app.js
ded6b18410a9d362a8b7523081cbcb8208296a795c9f0915a47dbe31d511ef1d  app.css
1442e14df956542de12c6f6fd260492f3ab9b717307463bab984c185e5b6210e  logo.svg
4a7e84aa5b5a6716efd60774e381da069a27acfe394cf049a3a7c7234e804f39  favicon.svg
```

The production Content Security Policy remained in force; no inline-script/style allowance or third-party resource permission was added for capture. This image/documentation refresh did not change Go or frontend code.

The prescribed contribution gates were rerun on 2026-09-29 with Go 1.25.13, `GOMAXPROCS=4` and `GOFLAGS=-p=2`. `make lint` passed (exit 0). `make test-race` completed with 31 passing packages, six packages with no test files and one failing package, `deploy` (make exit 2). All nine failing deployment tests reported `setpriv: setresuid failed: Invalid argument` while attempting to switch UID in the capture container. No race-detector warnings were emitted. The race gate therefore did not pass in this environment; no tests were skipped or modified.

### PNG SHA-256 checksums

Run `sha256sum` from this directory and compare against:

```text
e94e2bcff7fb5a2ef40fa3f5cfe8b9d4cee709d65c1f48d95a21be017288018c  sign-in.png
c126dde2826b3544fbe0d3f9790cd3ca8040567c5a58a491ffeea26240cfc8e9  dashboard.png
18d92d20b13cf9f0017f3e099d05d06c2abb0c198b709687681f8d5f6baa11d1  detections.png
cfb6f9d7675ca6ca4e1e414d0ec3919682cf43da148b1f65078b20b629455133  assurance.png
44ac5456c05dc46bca79745bc9b184604e6dc5d76b92196fdc0901319cee3be9  queries.png
536e08c07077280026ee045f37d5adc87cfd83e5dbc9766d36ffe19be1f6582b  mobile.png
```

---

# Increment captures (29 September 2026, PR #75)

The six `increment-*.png` files were captured from a running `dnsdaddy` built
from this branch, by a Playwright script, after the same isolated lab pattern
as above. They are real application output over **synthetic laboratory data
only**: loopback clients, reserved `.example` / `.test` names, two local feed
files and a local sink as the only upstream. Nothing in them is a real
network, device or indicator, and no credential is visible in any image.

## Image inventory

| File | Output size | Capture | Route | Visible state |
|---|---:|---|---|---|
| [increment-overview.png](increment-overview.png) | 1440 × 2007 | Full page | `#/dashboard` | Blocked queries split into security and preference; resolver card with clients seen, networks by state and the windowed failure rate. The loopback-only connection notice is still shown, as in the canonical captures. |
| [increment-investigate.png](increment-investigate.png) | 1440 × 3013 | Full page | `#/investigate?domain=malware-host.example&client=127.0.0.2` | After the name was allow-listed: stored decisions still read *blocked*, the read-only preview reads *allowed*. |
| [increment-investigate-390.png](increment-investigate-390.png) | 390 × 1500 | Full page, clipped | same | The same page at phone width. |
| [increment-findings-review.png](increment-findings-review.png) | 1440 × 2150 | Full page, clipped | `#/detections?state=all` | First finding expanded; a review recorded with a hostile note rendered as text. |
| [increment-daddybound-status.png](increment-daddybound-status.png) | 1158 × 1292 | Element | `#/assurance` | The Daddybound runtime card with Learn off. |
| [increment-daddybound-learn.png](increment-daddybound-learn.png) | 1158 × 1822 | Element | `#/assurance` | The same card with Learn on in a container that cannot reach the root servers: timeouts and unreachable outcomes counted as operational results, the trust point seeded but never refreshed, evidence still *not quantified*. |

The two element captures hid the sticky top bar through the CSSOM for the
crop only; nothing in the served files changed, and the production Content
Security Policy stayed in force (an attempt to inject a capture-only inline
stylesheet was refused by it).

## Runtime and capture conditions

| Setting | Value |
|---|---|
| Source revision | `12d75b4` plus the working-tree change committed as `7a92ba8` (the rendering fix those captures verified); the build label in the images reads `dev+12d75b4` |
| Go | `go1.25.13 linux/amd64`; `CGO_ENABLED=0` |
| Browser | Chromium `141.0.7390.37` (Playwright build 1194) |
| Capture driver | Playwright `1.56.1`, Node.js `v22.22.2` |
| Viewport | 1440 × 900 desktop, 390 × 844 mobile; device scale 1 |
| Application origin | `http://127.0.0.1:8085` |
| DNS listeners | UDP and TCP on `127.0.0.1:5353` |
| Only upstream | `dnsdaddy-lab -sink 127.0.0.1:5300` |
| Allowed client ranges | `127.0.0.0/8`, `10.0.0.0/8`, `192.168.0.0/16` |
| Catalog feeds / Observatory | All disabled |
| External API integrations | None configured |
| Local DNSSEC observation | `off` for five images; `observe` for `increment-daddybound-learn.png` |
| Query / decision records | Enabled, synthetic data only; retention 7 days |
| Detection timing | `window_scale: 0.1` |

## Synthetic data shown

Two local hosts-format feeds, `Lab malware list` (`malware-host.example`,
`blocked.example`, `c2.example`) and `Lab ads list` (`ads.example`,
`tracker.example`), loaded through the ordinary feed-refresh path. Three
networks reproduce the attribution case from the brief: a broad monitor-only
`127.0.0.0/8` plus an unrelated `192.0.2.123/32`, a narrower blocking
`127.0.0.0/29` on `p_standard` (with `custom-blocked.example` on its block
list and `phish.example` on its allow list), and a guest `127.0.0.8/29` on an
ads-blocking policy. The client `127.0.0.2` is named `laptop-normal`. The
seven built-in `dnsdaddy-lab` scenarios ran at tenfold speed from their own
loopback addresses, followed by manual queries under `.example` and `.test`
names; the API reported about 2,600 queries, 19 blocks and nine findings at
capture time.

## Procedure and verification

The capture script signed in with a lab-only password read from a private
file, waited for `#view[aria-busy="false"]` on every route, and used
`page.screenshot` with `fullPage` where listed. Before the captures, a
51-check Playwright run against the same instance passed in full: production
CSP served; no console errors other than the three non-2xx responses the run
provokes on purpose (a stale review, a routed synthetic 500, a hostile client
parameter); no CSP violations, external requests or failed resource requests;
the attribution scenario reproduced through real queries; a filtered query-log
URL surviving reload and back/forward into the investigation; stored decisions
unchanged and the preview changing after an allow-list rule; a stale review
refused with the other review shown; a false positive changing no rule and no
detector; keyboard order and a visible focus ring; no horizontal scroll on the
overview, investigation, findings and assurance pages at 1440, 1024, 768, 390
and 320 CSS pixels and at 200 % zoom. The rendering defect those checks
exposed (nested notes shown as literal tag text) was fixed and re-captured
before these images were taken.

Re-running the lab reproduces the scenarios, not identical bytes.

### PNG SHA-256 checksums

```text
002caf6393c5c9b63b2bfa23778f32e163264a6840817183ce6ec0bfb7264091  increment-overview.png
999fefcf622b97f2abf7c9bcf43eea92e6f4c487a27c1d8c5699ded24e08a147  increment-investigate.png
db04cf3a960d2999917d6ba7edcbbe5c8c3f3f5f4b638b4cc7dafbb8afa91d52  increment-investigate-390.png
82dfc9846b4382b1904d2f91063633656bcf95f28d0b85a0806a0803c6e70c8e  increment-findings-review.png
b021647e2702f0a269d5777f3cdb7d0ddfb8fb19385680946100cb75dc00679a  increment-daddybound-status.png
93339f4cab56da0062af3d23581aa16a2675a1f1bee0961cbb28ca887552fad6  increment-daddybound-learn.png
```
