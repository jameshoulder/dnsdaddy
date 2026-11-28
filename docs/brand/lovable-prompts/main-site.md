IMPLEMENT THE APPROVED DNS DADDY IDENTITY ON DNSDADDY.COM

Update this existing Lovable project into a coherent, original marketing website for DNS Daddy. Implement the changes; do not stop at a design proposal. Preserve the working project and its infrastructure. The approved direction is bold red, black and off-white hacker print artwork, grounded in DNS Daddy's own shield/database/circuit identity.

1. INSPECT BEFORE CHANGING

Inspect the current source, routes, components, asset pipeline, redirects, integrations, authentication, analytics and consent handling. Record the existing behaviour before editing. Consult https://github.com/jameshoulder/dnsdaddy: README.md, docs/capabilities.md, TRUST.md, SECURITY.md, docs/encrypted-dns.md, docs/brand/README.md and docs/images/SCREENSHOTS.md. Establish which product revision the website describes. Distinguish released functionality, current main, experiments and pending changes. Check whether PRs #104 and #106 are merged and released before using their claims; pending work must not be presented as shipped.

Brand asset revision: feat/hacker-brand-refresh-20261128 in https://github.com/jameshoulder/dnsdaddy (resolve the branch to an exact commit before copying assets). Resolve that supplied revision, record the commit and copy the approved assets into this project's local public assets. If an asset is unavailable, retain the current valid asset and report the exact blocker; do not invent a replacement.

2. USE THE APPROVED LOGO

The approved distressed logo is docs/brand/logos/dns-daddy-logo-hacker.png. Use that actual image, with its original lettering, proportions and artwork. For compact navigation, copy the repository's code-native internal/web/static/logo.svg, preserving its 40×40 #mark symbol; use internal/web/static/favicon.svg for favicon sizes. Inspect the supplied revision's brand guide for theme variants. Do not redraw the logo, generate another concept, stretch it, apply CSS colour filters or substitute a generic shield. Maintain clear space. A contained dark logo panel is acceptable on light backgrounds when it preserves the approved artwork.

Use local design tokens: ink #0B1014, surface #141B22, ivory #F7F4ED, brand red #E5252A, button red #B91C2B and small-text accent #FF5A52. Retain distinct labelled information, healthy, warning and blocked/error states. Check every actual foreground/background pair; the vivid brand red is not the default small-text colour. Support both dark and light themes with theme-appropriate contrast. Retain readable system sans-serif and monospace stacks.

Match the same revision's internal/web/static/app.css and index.html: near-black canvas, charcoal panels, thin neutral borders, 4–6px corner radii, hard red rules and bold tightly spaced headings. Use a roomy page width around 1200px, a clear header, a strong hero with the approved logo, a current product screenshot and a simple next action. Give mobile the same hierarchy in one column. Carry the shared logo, navigation treatment, buttons and footer links through every existing page.

Use large confident headings, generous spacing, restrained rules and subtle screenprint texture around hero artwork. Keep paragraphs, controls and screenshots clean. Original DNS query paths or domain geometry may support the artwork. No copied Darknet Diaries logos, flaming laptops, illustrations, lettering or page compositions; no implied affiliation. Avoid constant glitches, fake terminal output, flashing backgrounds and decorative surveillance theatre. Honour reduced motion.

3. SHAPE THE WEBSITE AROUND UNDERSTANDING AND TRYING THE PRODUCT

Use “Protective DNS. Clearly explained.” as the lead, supported by a concise explanation of self-hosted protective DNS and network visibility. Show a clear primary “Explore the demo” action and a secondary route to verified setup documentation. Explain suitable use cases, how query decisions can be inspected, deployment requirements and the limits of the current software. Keep feature descriptions tied to the capability documentation. Provide routes to GitHub, documentation, trust/security information and the separate Observatory. Preserve existing useful pages and inbound links.

Keep the alpha status, AI-assisted development disclosure and absence of an independent professional security review visible and understandable. Experimental behavioural findings alert and explain; do not imply that they automatically block. Distinguish DNS resolution mode, local DNSSEC validation and outbound transport. Local Live validation remains experimental. Native does not mean every connection is plaintext; encrypted transport does not itself prove DNSSEC validation. Optional outbound DoQ/HTTP3 support must not be described as an inbound listener. Safe Search enforcement is unsupported. Do not invent certification, adoption, performance or protection claims.

4. SHOW AUTHENTIC PRODUCT EVIDENCE

Use current captures of the real running application from the approved revision, with source commit, capture date, theme and synthetic-lab conditions recorded in provenance. Follow docs/images/SCREENSHOTS.md and docs/images/hacker-brand-capture-manifest.json; use the docs/images/hacker-*.png files actually listed there. Refresh outdated captures rather than recolouring or painting over them. Retain real warnings and failures. Caption synthetic traffic clearly; never turn screenshot counters into live website metrics. If current captures cannot be produced, label verified older captures historical and report the gap.

5. PRESERVE ADDRESSES AND VERIFY

Use https://dnsdaddy.com as the marketing canonical. Keep https://demo.dnsdaddy.dev and https://threats.dnsdaddy.dev unchanged. Do not globally replace .dev strings, resolver endpoints, API addresses, installer URLs or feeds. The Observatory is separate public-source research; its built-in resolver feed integration is retired. Preserve APIs, auth, analytics, consent and existing redirects unless a specific correction is required. Add no trackers, sign-up barriers or manipulative prompts.

Verify navigation, CTAs, downloads, theme persistence, keyboard focus, reduced motion and existing interactions. Check 360/390px mobile, tablet and desktop in both themes, including 200% text zoom, long domains and no page-level overflow. Run the existing build and relevant checks. Provide the implemented preview, changed-file summary, asset/capture provenance and any remaining limitations. Do not claim a public deployment or passing checks without evidence.
