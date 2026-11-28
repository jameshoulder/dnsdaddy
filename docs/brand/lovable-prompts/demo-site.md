IMPLEMENT THE APPROVED DNS DADDY IDENTITY ON DEMO.DNSDADDY.DEV

Update this existing Lovable investigation-demo project with the approved DNS Daddy logo and red/black/off-white hacker print identity. Explain DNS investigation through readable, working interactions and clearly synthetic data.

1. INSPECT THE EXISTING DEMO AND PRODUCT SOURCES

Before editing, inspect the app structure, routes, dataset, filtering, detail panels, state management, APIs, authentication, analytics and consent handling. Preserve working behaviour and current integration contracts. Consult https://github.com/jameshoulder/dnsdaddy: README.md, docs/capabilities.md, TRUST.md, SECURITY.md, docs/encrypted-dns.md, docs/brand/README.md, docs/images/SCREENSHOTS.md and the current app implementation. Establish the product revision represented by the demo. Separate released features, main-branch work, experiments and proposed work; check whether PRs #104 and #106 are merged and released before presenting their features as shipped.

Brand asset revision: feat/hacker-brand-refresh-20261128 in https://github.com/jameshoulder/dnsdaddy (resolve the branch to an exact commit before copying assets). Resolve it to a commit and copy the approved assets into the demo's local asset directory. If the requested files are unavailable, report that specific blocker while preserving the existing valid assets; do not manufacture an alternative logo.

2. APPLY THE ACTUAL APPROVED IDENTITY

Use docs/brand/logos/dns-daddy-logo-hacker.png, the approved distressed shield/database/circuit logo, without redesigning its image or lettering. Preserve proportions, clear space and legibility. For compact navigation, copy internal/web/static/logo.svg, preserving its 40×40 #mark symbol; use internal/web/static/favicon.svg for favicon sizes. Check the same revision's brand guide for theme variants. Do not substitute a generic shield or hotlink mutable branch assets into production.

Use shared tokens: ink #0B1014, surface #141B22, ivory #F7F4ED, brand red #E5252A, button red #B91C2B and small-text accent #FF5A52. Keep blue information, green healthy, amber warning and rose blocked/error treatments distinct and explicitly labelled. Red branding must not make every dataset look compromised. Check contrast in both dark and light themes. Retain legible local system sans-serif and monospace stacks; domains, timestamps and technical values may be monospace.

Use the same revision's internal/web/static/app.css and index.html as the visual reference for the app shell. Match the approved sidebar branding, compact phone emblem, crisp red active-route marker, charcoal panels, thin borders, 4–6px corners and clear heading hierarchy. Keep a stable desktop sidebar and a usable mobile drawer. Give filters, query details and evidence tables consistent spacing and density. Identify this as the demo beside the shared brand without modifying the logo artwork.

Confine distressed print texture to brand artwork and occasional surrounding decoration. Tables, forms, charts and explanatory text need calm, clean surfaces. Use original DNS query-path geometry only where it explains the workflow. Do not copy Darknet Diaries artwork, flaming laptops, distinctive lettering or composition, and do not imply affiliation. Avoid flicker, continuous glitch effects and fabricated terminal activity. Honour reduced-motion preferences.

3. MAKE THE INVESTIGATION WORKFLOW CLEAR

Maintain a persistent “Synthetic demo — no live network traffic” label. Use the existing deterministic fixture data, or documented reserved example domains/IP ranges when fixtures need repair. Keep totals, filters, timestamps and charts internally consistent. Do not show invented live incidents, users protected, adoption figures or benchmark results. Never connect this public demo to a private resolver or mutate production settings.

Preserve and improve the supported sequence: select a query, identify its client/network and query type, inspect the recorded decision and reason, then examine relevant evidence or findings where the current product supports them. Say “A query” or “Query type: A”, not “A record” when describing the request. Clearly distinguish original evidence from a current policy preview. A source field must identify provenance rather than repeat a decision reason. Allowed does not mean proven safe; a feed observation is not independent verification.

Keep existing search, filters, sorting, navigation and detail controls functional. Explain any intentionally disabled production-only action beside the control. Do not create decorative buttons that silently do nothing or imply unsupported backend features. Clearly identify any reset, simulation or local-only state. Preserve empty, loading, error, stale and unavailable states rather than replacing them with reassuring defaults.

4. PRESERVE TECHNICAL AND EVIDENCE ACCURACY

Keep alpha, AI-assisted and no-independent-professional-security-review disclosures accessible. Experimental behavioural detectors generate findings, not automatic heuristic blocks. Keep Forward/Learn/Live, local DNSSEC validation and transport separate. Local Live validation remains experimental. An encrypted endpoint test does not prove a complete locally validated lookup. Optional outbound DoQ/HTTP3 does not imply inbound listeners. Preserve explicit outbound-sharing consent; appearance changes must not trigger tests, provider calls or configuration writes.

Use current authentic app captures listed in docs/images/hacker-brand-capture-manifest.json, with source commit, date, theme and synthetic-lab conditions documented in docs/images/SCREENSHOTS.md. Load the listed docs/images/hacker-*.png files. Do not recolour historical screenshots, replace counters or present a replica as a real app capture. Label older images historical if verified current captures are unavailable.

5. COMPLETE AND VERIFY

Keep this demo at https://demo.dnsdaddy.dev. Link the main project to https://dnsdaddy.com and the separate public-source research resource to https://threats.dnsdaddy.dev. Its built-in resolver feed integration is retired. Do not rewrite other .dev endpoints or change APIs, auth, analytics or consent behaviour. Add no trackers, compulsory registration or dark patterns.

Verify supported interactions with mouse, touch and keyboard; focus after panel changes; filter persistence; clear/reset behaviour; theme persistence; and error/empty states. Check 360/390px mobile, tablet and desktop in both themes, including 200% text zoom, long hostnames and no page-level overflow. Keep operational labels at least 14px and body text at least 16px. Run existing relevant checks and build. Return the implemented preview, change summary, provenance and honest verification limits; do not claim public deployment without evidence.
