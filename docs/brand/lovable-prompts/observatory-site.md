IMPLEMENT THE APPROVED DNS DADDY IDENTITY ON THREATS.DNSDADDY.DEV

Update this existing Lovable Threat Observatory project with the approved DNS Daddy logo and original red/black/off-white identity. Make public-source research, provenance and collection status clearer. Preserve the working application and data contracts.

1. INSPECT SOURCES, DATA AND ROUTES FIRST

Inspect the current source, navigation, routes, collectors, database/API contracts, source licences, authentication, analytics and consent behaviour before changing anything. Trace each displayed metric and relationship to its actual data field. Consult https://github.com/jameshoulder/dnsdaddy: README.md, docs/capabilities.md, TRUST.md, SECURITY.md, docs/brand/README.md, docs/images/SCREENSHOTS.md and the Observatory retirement note linked from this site's homepage. Record the relevant repository and deployed revisions. Check whether PRs #104 and #106 are merged and released before presenting their features as shipped.

Brand asset revision: feat/hacker-brand-refresh-20261128 in https://github.com/jameshoulder/dnsdaddy (resolve the branch to an exact commit before copying assets). Resolve it to an exact commit and copy the approved files into this project's local asset directory. Missing assets should produce a specific implementation note while the existing valid asset remains; do not invent replacements or silently choose an older identity.

2. USE THE APPROVED LOGO AND SHARED DESIGN SYSTEM

Use docs/brand/logos/dns-daddy-logo-hacker.png: the approved distressed shield/database/circuit artwork and DNS DADDY lettering. Preserve proportions, clear space and legibility. For compact navigation, copy internal/web/static/logo.svg, preserving its 40×40 #mark symbol; use internal/web/static/favicon.svg for favicon sizes. Check the supplied revision's brand guide for theme variants. No generated substitutes, CSS recolouring or rewritten lettering. Keep mutable branches out of production asset URLs.

Shared tokens: ink #0B1014, surface #141B22, ivory #F7F4ED, brand red #E5252A, button red #B91C2B and small-text accent #FF5A52. Retain clearly labelled blue information, green healthy, amber warning and rose blocked/error treatments. Verify contrast in dark and light themes. Use readable local system sans-serif plus monospace for technical identifiers. Use texture around the logo or introduction; keep dense data and controls untextured.

Match the same revision's internal/web/static/app.css and index.html for typography, controls, thin borders, 4–6px corners and status colours. Use a restrained research dashboard: a clear title and freshness summary, source/status cards, then searchable evidence tables. Keep the map secondary to inspectable records. Use the shared navigation and footer treatment, with an ordinary-text “Threat Observatory” label beside the approved brand. On mobile, stack the overview and keep table controls reachable.

Create original DNS-domain, source-record or query-path motifs where useful. Do not copy Darknet Diaries logos, flaming laptops, illustrations, typography or distinctive layouts, or imply endorsement. Avoid constant glitches, flickering scanlines, decorative attack animations and false urgency. Respect reduced motion.

3. MAKE THE OBSERVATORY'S PURPOSE UNAMBIGUOUS

Lead with “Threat-source research and evidence”. Keep a prominent explanation that the built-in Observatory feed integration has been retired: this is a separate research resource, not a dependency for DNS Daddy resolution or filtering. Its records come from third-party/public sources, not private DNS traffic collected from users' installations. Do not restore an integration through marketing copy or imply this site protects visitors' networks.

Preserve and improve the existing overview, sources, research explorer, methodology and status experiences. Use actual route definitions. Give users clear access to source evidence, observation dates, ingestion dates and collection status. Keep existing search, filters, detail views, exports, supported public API links and attribution working. Preserve optional support links without paywalls, fake urgency or forced sign-up.

4. PRESENT ONLY WHAT THE DATA SUPPORTS

Differentiate source-observed time, most recent collection attempt and last successful ingest. Do not use page-load time as freshness. Missing or failed collection is unavailable/stale, not a zero-threat or healthy state. Label real counts with scope and time window. Keep legitimate empty datasets empty. Never populate an empty map, chart or list with fabricated “live” records or synthetic traffic.

Describe records as source-reported indicators rather than independently confirmed malicious infrastructure unless that stronger statement has documented evidence. Preserve distinctions between observed, correlated, inferred and community-reported records only where supported by stored evidence. A relationship needs an inspectable source; an attractive connecting line is not evidence. Absence from a feed does not establish safety. Show uncertainty and attribution without overstating confidence.

If the existing infrastructure map remains, explain that locations describe hosting infrastructure rather than an attacker's location or nationality. Display inferred locations as inferred. Do not invent geolocation, attribution, severity or attack origins to fill visual gaps. Keep provider attribution, licensing and methodology reachable.

5. EVIDENCE, DISCLOSURES AND DELIVERY

Retain alpha/experimental, AI-assisted and no-independent-professional-security-review disclosures. Resolver claims must match docs/capabilities.md: behavioural findings are alert-only; encrypted transport differs from local DNSSEC validation, and local Live validation remains experimental. For relevant product images, use authentic docs/images/hacker-*.png captures listed in docs/images/hacker-brand-capture-manifest.json, with commit/date/theme/lab provenance in docs/images/SCREENSHOTS.md. Do not recolour historical captures or substitute mockups for evidence. Distinguish screenshots containing synthetic lab data from real Observatory source records.

Keep https://threats.dnsdaddy.dev and all existing feed/API endpoints unchanged. Link marketing to https://dnsdaddy.com and the synthetic demo to https://demo.dnsdaddy.dev. Do not globally migrate .dev strings. Preserve APIs, auth, analytics, consent and collector settings; a visual refresh must not start new collection or external tests.

Verify supported routes, filtering, evidence links, exports, loading/empty/stale/error states, theme persistence and keyboard focus. Test 360/390px mobile, tablet and desktop in both themes, 200% text zoom, long indicators, readable tables and no page-level overflow. Run the existing build and relevant checks. Return the implemented preview, change summary, source/asset provenance and exact remaining limitations; claim public deployment only when verified.
