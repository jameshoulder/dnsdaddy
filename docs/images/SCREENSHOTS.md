# UI screenshot provenance

The repository contains **two identified capture groups from 29 September 2026**.
The Overview, Daddybound and server-address images were refreshed for encrypted
transport. Other feature images retain their earlier capture and scope. All
images are unedited captures of the running application over synthetic lab
traffic; no API response or DOM content was substituted. They illustrate
implemented controls, not production detection accuracy or field reliability.

## Encrypted transport and server addresses: 23:52 UTC

These five images were captured from **2026-09-29T23:52:05.284Z** through
**2026-09-29T23:52:19.557Z**, from the working tree based on `dc2989bd`. The
binary label is `dev+dc2989b`; its exact hash and the served frontend hashes
are recorded in [transport-capture-manifest.json](transport-capture-manifest.json).
The browser renders its local clock, while manifest timestamps are UTC.

| File | Output size | Capture | Route | Visible state |
| --- | ---: | --- | --- | --- |
| [dashboard.png](dashboard.png) | 1440 × 1000 | Viewport | `#/dashboard` | 30 synthetic queries, six security blocks; inline Host-only IP and real accepted-socket fallback. |
| [features-daddybound.png](features-daddybound.png) | 1440 × 2619 | Full page | `#/daddybound` | Saved encrypted profile, validation pinned Off, deliberate loopback endpoint-test failure and unobserved TLS. |
| [features-daddybound-mobile.png](features-daddybound-mobile.png) | 390 × 4377 | Full page | `#/daddybound` | Same encrypted transport controls and actual failure at phone width. |
| [features-server-addresses.png](features-server-addresses.png) | 1158 × 966 | Address card | `#/setup` | Setup address card only; credential-bearing per-network DoH URLs excluded. |
| [mobile.png](mobile.png) | 390 × 844 | Viewport | `#/dashboard` | 390px overview with mobile navigation closed. |

The real loopback-only lab loaded one local hosts-format threat feed through
the normal management API, with external catalog feeds disabled. It sent
30 queries, recorded six security blocks, and forwarded 24 queries to its
local UDP fixture. The local model had one warming client and zero mature
baselines. Validation was deliberately pinned Off to keep UI capture isolated;
that is an explicit lab pin. The current UI calls this mode Forward (`off`),
which is also the default for new unpinned installations.

The OS denied interface enumeration, exercising the real accepted local socket
fallback. The API returned `127.0.0.1`, `preferredAddress: null`,
`source: connection_local_address` and `partial: true`. The homepage displays
that known address as **Host-only IP**, with Copy IP and the actual configured
DNS ports, while explaining that another device cannot use loopback. No LAN
IP, public IP or reachability was fabricated for the screenshot.

The encrypted endpoint used an unused loopback port. Its explicit test failed
and the UI shows the failure, with no observed TLS connection. Backend local
TLS fixtures establish successful protocol negotiation and rejection behavior;
these browser images do not establish a successful encrypted handshake.
The saved encrypted profile did not change the pinned Off mode.

**30 real-browser checks passed**, including inline fallback IP/copy, actual
API state, no automatic endpoint test, explicit consent, endpoint ordering and
bounds, retained failed drafts, saved transport, native-return acknowledgement,
390px layout and source/served-asset agreement. There were no browser JavaScript
errors or page-level horizontal overflows. The accompanying JavaScript unit
suite passed **266 tests**. The optional reproducible runner is
[transport.browser.test.cjs](../../internal/web/transport.browser.test.cjs);
its header describes the binary, browser and Playwright environment variables.

| Runtime | Value |
| --- | --- |
| Go | 1.27.1, Linux/amd64 |
| Browser | Chrome for Testing Headless Shell 131.0.6778.204 |
| Isolation | Loopback listeners, temporary database, synthetic local file feed |
| Capture | Original browser PNGs; no recolouring, compositing or image editing |
| CSP | Production application CSP |

### Current transport asset SHA-256

```text
4ee778fd9976b5839aef71833ee70215880d59c499b042ebabdf330478641091  app.js
aaa130bb1bd1ba14c9c84edf2999bc1318943da68fb993bc2bff7ac074285b59  app.css
2a27f8afa2f8628654b7279b57710cfb3edc6911dae70b624894f98be5aca6a8  index.html
```

### Current transport PNG SHA-256

```text
de1ee304c7c066dcb166237e97ff6ed10153721d6dc5a3a73a74800d9c335916  dashboard.png
bee6c51986ebe611e701da6dcfa1d92b94607829f3979ee08407be0e2ed06103  features-daddybound.png
31d88c45b56c35e35a1d7823c5d46069faee6dc37e2515fe4d8c57739008eeaa  features-daddybound-mobile.png
1065b8ce30ccf3c56c248e62d82cd5ecbfddbe8cbad7eeaeb54b5f1024e49a51  features-server-addresses.png
25c1d61b438b3c7b3b9bfd714f52a97b1fcbd83873ab4eb2f11b93ec9abeae8a  mobile.png
```

## Retained earlier feature images: 21:11 UTC

The following files retain their original **2026-09-29T21:11:53.053Z–21:11:56.855Z**
capture from the working tree based on `59cc816`. They cover the preceding
feature increment, using the earlier lab described below. They do not show the
new transport form or server-address card. The earlier manifest and hashes
below are historical for any filenames replaced by the 23:52 capture group.

| File | Output size | Route | Visible state |
| --- | ---: | --- | --- |
| [sign-in.png](sign-in.png) | 1440 × 1000 | `/` | Signed out; empty password input. |
| [queries.png](queries.png) | 1440 × 1000 | `#/queries?action=blocked` | Recorded blocked synthetic query and explanation. |
| [detections.png](detections.png) | 1440 × 1200 | `#/detections` | Synthetic detector finding and actual measurements. |
| [assurance.png](assurance.png) | 1440 × 2339 | `#/assurance` | Earlier assurance statements and limitations. |
| [features-external-apis.png](features-external-apis.png) | 1440 × 2278 | `#/integrations` | Disabled synthetic provider and webhook; write-only credentials. |
| [features-protection.png](features-protection.png) | 1440 × 2061 | `#/settings` | Rate limiting, rebinding exceptions and counters. |
| [features-recovery.png](features-recovery.png) | 1440 × 4556 | `#/recovery` | Encrypted backup and real configuration history. |
| [features-exports.png](features-exports.png) | 1440 × 1000 | `#/reports` | Complete NDJSON export controls. |
| [features-investigate.png](features-investigate.png) | 1440 × 6751 | `#/investigate?domain=malware.lab.example&client=127.0.0.21` | Recorded evidence and current read-only policy preview. |

Older `neo-aqua-*.png` and `increment-*.png` files are historical previews;
their original capture notes remain in Git history. Banner and icon artwork
have separate [brand provenance](../brand/README.md).

## Earlier feature lab: 21:11 UTC

All DNS clients and services ran in one isolated network namespace. The management listener used `127.0.0.1:28080`; UDP/TCP DNS used `127.0.0.1:25353`; the only forwarding upstream was a local UDP responder on `127.0.0.1:25300`. No production database, client, credential or threat infrastructure was used.

Three hosts-format files were loaded through the ordinary feed management and refresh APIs from a dedicated `local_feed_dir`:

| Feed | Category | Sole domain |
|---|---|---|
| Synthetic malware fixtures | malware | `malware.lab.example` |
| Synthetic phishing fixtures | phishing | `phishing.lab.example` |
| Synthetic cryptomining fixtures | cryptomining | `miner.lab.example` |

All external catalog feeds were disabled. The network named `Synthetic lab` covered `127.0.0.0/8` with the standard policy. Named clients used loopback addresses `.21` through `.24` and `.99`; the built-in tunnel and TXT scenarios used `.3` and `.6`.

The manual fixture sent A and AAAA lookups for `service0.lab.example` through `service23.lab.example`, the blocked malware fixture and `printer.internal.example`. The last name returned `192.168.20.10` for A queries, so actual DNS rebinding protection refused those answers. The ordinary address responses were fixed public-address values generated by the local responder, without querying those destinations.

The built-in `dns-tunnelling` and `suspicious-txt` scenarios ran with seed 1 and tenfold time compression. Detection used `window_scale: 0.1`, `eval_interval: 5s` and `cooldown: 2m`. Repeated manual traffic across the interactive checks and captures produced **6,337 retained queries**, **240 blocked queries** and **4 stored heuristic findings** at final capture. Existing decisions were retained when the manual policy rule was replaced by the local malware feed, so the investigation shows real historical and current evidence.

**Native mode was explicitly Off in this lab.** This lab pin avoided outbound authoritative DNS queries during UI capture. The current UI calls the same `off` mode Forward, and new unpinned installations also start there. The local learning worker remained enabled and processed **1,450 observations** in the final process. It reported **7 tracked clients**, **0 mature baselines** and **7 warming clients**. The screenshots preserve that cold-start limitation. The stored heuristic findings are not presented as model-learning results.

A synthetic Custom HTTP provider and webhook were saved with throwaway fixture credentials and HTTPS `.invalid` destinations. Both were switched off in the final capture; automatic reputation checks and on-demand enrichment were off. No live provider or webhook test was sent. The UI and management responses returned only write-only credential state. The sign-in screenshot was taken before the lab password was entered, and every screenshot was checked for empty password inputs.

### Earlier runtime and verification

| Setting | Value |
|---|---|
| Go | `go1.25.13 linux/amd64` |
| Browser | Chrome for Testing / Headless Shell `151.0.7922.34` |
| Driver | Playwright 1.62.1, Node.js 24.19.0 |
| Locale / timezone | `en-GB` / `UTC` |
| Preferences | Light colour scheme; reduced motion |
| Device scale | 1 CSS pixel = 1 output pixel |
| Production CSP | Enforced, including `default-src 'none'` and self-hosted scripts/styles |
| Capture options | `animations: 'disabled'`; full-page option as listed above |

The interactive browser run passed **79 checks** against the real app. It covered native-mode acknowledgement, provider save/enable/disable and sharing consent, API settings and latency acknowledgement, a disabled signed webhook, versioned protection updates, an encrypted backup download, redacted change history, and a complete multi-page NDJSON export with unique IDs. Overview, Daddybound, External APIs, Settings, Recovery, Investigate and Findings fit both 390px and 320px widths. A long Settings action that overflowed at 320px was corrected before the passing run.

The final capture pass verified that all five served frontend assets matched this checkout byte-for-byte. It reported zero JavaScript exceptions, console/CSP errors, failed HTTP requests or external browser-resource requests. The UI unit suite passed **246 tests**, including inactive Learn-counter scope, unavailable model handling, explicit sharing boundaries and complete-export failure cases. Native internet resolution, provider accuracy and long-term learning efficacy are not established by these UI checks; those need their own evaluation.

### Earlier frontend asset SHA-256

```text
2a27f8afa2f8628654b7279b57710cfb3edc6911dae70b624894f98be5aca6a8  index.html
1a36e188da01a46a6980017aeeec592b50c1e15c16c2bc312daea48fc2413d40  app.js
71d136813facfeb2c573b04721b902c092919f8ff79980fbe7a4293489cf6e3b  app.css
1442e14df956542de12c6f6fd260492f3ab9b717307463bab984c185e5b6210e  logo.svg
4a7e84aa5b5a6716efd60774e381da069a27acfe394cf049a3a7c7234e804f39  favicon.svg
```

### Earlier PNG SHA-256 (historical where files were replaced)

```text
e94e2bcff7fb5a2ef40fa3f5cfe8b9d4cee709d65c1f48d95a21be017288018c  sign-in.png
b5a9394460cf84dad2b2ec7fc43f982119e305ac1516736408cc161f81d63810  dashboard.png
d592886e86088301c28fbff8ef3c2c54de62b29f5754941e43d2a4322b9f8de4  queries.png
4a463ea74c1620d00ad787744141010e438b50f23aeb0d1f706baa7e63174c1c  detections.png
4a5d8d41791c3b77fffb5b40a6b55dbe71037ed6e09b3b22911cbef080754377  assurance.png
222ab21e3e39df0e660f101337eadeff50153e45982ade435a567c04723d3ca5  features-daddybound.png
ece2ac40cb1df6b9abbf9cb2abdf9f46a393aeaf66fb23df857bcd03f4459586  features-external-apis.png
25ab0684be3f9cd3cdd8daa1569d02351611738a818fdad6d7bf8c17c775c558  features-protection.png
6acfbbc1f353524b5aec2e43f46b6d1ab4916718f373e67cee287b5dd35d8669  features-recovery.png
85b44468c6bb05cd0aacb4cfc0c603910d354e5d6bc682d39171f49a2a646502  features-exports.png
cfd76df48e54d6ffdaf864c5354700322023dda7ba60939496eed75f6057dd9a  features-investigate.png
a5bc248718ac7e165057a663677530a032c4d372b42e22659df598f00719f6ca  mobile.png
e655397d10ae6f134f6d1e558502c63cad3355b43a661399b6819769c74eb66c  features-daddybound-mobile.png
```

The machine-readable [feature-capture-manifest.json](feature-capture-manifest.json) records dimensions, routes, capture times, source asset hashes and bounded fixture counters. Repeating the lab reproduces the scenarios and states, not identical timestamps or image bytes.
