# DNS Daddy — Red identity

**Protective DNS. Clearly explained.**

The current identity uses charcoal, ivory and strong red. The shield, database
and network mark connects the software to James Houlder's wider visual identity
while keeping DNS Daddy recognisable as its own project. This is a visual
refresh, not a new software release or a change in the project's alpha status.

## Logo masters

The application uses [`logo.svg`](../../internal/web/static/logo.svg), including
the stable `#mark` symbol. The favicon simplifies the mark for small sizes.
Public SVG masters contain editable geometrical shapes and live lettering;
there are no scripts, external images or remotely loaded fonts. Lettering uses
Arial, Helvetica and the browser's sans-serif fallback. Use the provided PNG
exports when a fixed rendering is needed.

| Variant | Horizontal logo | Standalone mark |
| --- | --- | --- |
| Primary, for light backgrounds | [SVG](logos/dns-daddy-logo-primary.svg) | [SVG](logos/dns-daddy-mark-primary.svg) |
| Reversed, for dark backgrounds | [SVG](logos/dns-daddy-logo-reversed.svg) | [SVG](logos/dns-daddy-mark-reversed.svg) |
| Monochrome ink, on ivory | [SVG](logos/dns-daddy-logo-monochrome-ink.svg) | [SVG](logos/dns-daddy-mark-monochrome-ink.svg) |
| Monochrome white, on ink | [SVG](logos/dns-daddy-logo-monochrome-white.svg) | [SVG](logos/dns-daddy-mark-monochrome-white.svg) |

Stacked lockups: [primary](logos/dns-daddy-logo-stacked-primary.svg) ·
[reversed](logos/dns-daddy-logo-stacked-reversed.svg).

Keep clear space of at least one quarter of the mark's height. Use the standalone
mark when the name would be cramped. Start at 32 px for the full mark and 160 px
for the horizontal logo; use the simplified favicon at smaller sizes. Preserve
the proportions and choose the correct background variant.

## Colour and typography

| Role | Colour | Use |
| --- | --- | --- |
| Ink | `#0B1014` | Main canvas and artwork background |
| Surface | `#141B22` | Cards and panels |
| Elevated surface | `#1B252E` | Layered controls and surfaces |
| Ivory | `#F7F4ED` | Primary text |
| Muted | `#A9B4BE` | Supporting text |
| Brand red | `#E5252A` | Mark, decorative rules and large wordmark lettering |
| Action red | `#B91C2B` | Filled buttons with white labels |
| Text accent | `#FF5A52` | Small red text, links and focus indicators |
| Soft text accent | `#FF8B82` | Supporting accent and hover text |
| Information | `#83BFFF` | Information labels and total-query series |
| Success | `#6DD6A0` | Successful or healthy states |
| Warning | `#F1BF73` | Cautions and incomplete states |
| Danger | `#FF8DA1` | Blocked/error labels and blocked-query series |

Machine-readable brand values are in [palette.json](palette.json) and
[palette.css](palette.css). The application defines its full component and
semantic palette in [`app.css`](../../internal/web/static/app.css).

The vivid brand red does **not** meet the normal-text 4.5:1 contrast threshold
against the ink canvas. Use the lighter text accent for small red text, and
check the foreground/background pair for every new surface. Solid action
buttons use a separate darker fill so white labels remain readable.

Brand colour and operational state are separate. Information stays blue,
success green, warnings amber and blocked/error states rose, with explicit
labels. The total-query and blocked-query chart series retain distinct colours.
Never communicate a status using colour alone.

The application uses local system sans-serif and monospace stacks. It does not
load fonts, scripts, analytics or artwork from a third party. The retained
[Inter licence](Inter-LICENSE.txt) belongs to the previous brand edition;
this refresh adds no font runtime dependency.

## Repository artwork

| Asset | Files | Dimensions |
| --- | --- | --- |
| README banner | [PNG](../images/dnsdaddy-banner.png) · [SVG](github-readme-banner-1600x500.svg) | 1600 × 500 |
| Profile icon | [PNG](../images/dnsdaddy-icon.png) · [SVG](dns-daddy-icon-400x400.svg) | 400 × 400 |
| GitHub social preview | [PNG](github-social-preview-1280x640.png) · [SVG](github-social-preview-1280x640.svg) | 1280 × 640 |

The social-preview file is ready to upload in **Repository Settings → Social
preview**. Committing the artwork does not update that GitHub setting or an
account avatar. See [GitHub's social-preview documentation](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/customizing-your-repositorys-social-media-preview).

## Voice and visual direction

- **Lead:** Protective DNS. Clearly explained.
- **Signature:** Protect. Observe. Respond.
- **Campaign line:** Know what your network is asking for.
- **Descriptor:** Open-source, self-hosted protective DNS.

Use clear explanations of what the resolver observed and what the operator can
inspect. Keep the application dense enough for useful investigation, with calm
reading surfaces and restrained red emphasis. Red sun and brushstroke motifs
belong in public artwork; decorative network lines must never be presented as
live traffic or measured topology.

Preserve the alpha labels, AI-assistance disclosure, experimental scope and
absence of an independent professional security review. Behavioural findings
are alert-only. Keep resolution mode, DNSSEC validation and DNS transport
distinct when describing Daddybound. Technical claims remain governed by the
[capability documentation](../capabilities.md) and [trust statement](../../TRUST.md).

## Website and service addresses

The planned public website is `https://dnsdaddy.com`. The existing `.dev` website
remains linked until the new site and HTTPS redirects are configured and
verified. This visual change does not perform a domain migration.

Keep the existing demo, Observatory feeds, resolver/API endpoints and installer
URLs intact. A website rebrand is not a reason to replace every `.dev` string.

## Screenshot provenance

Brand artwork is separate from application screenshots. Existing application
captures retain their original dates and synthetic-lab scope in
[SCREENSHOTS.md](../images/SCREENSHOTS.md); older light-theme captures are
historical. Do not recolour a screenshot or present a mock-up as live telemetry.

New product captures should use the running application, preserve visible
limitations and record their source revision and capture conditions. The
repository's deployment regression workflow runs the real daemon and browser
and retains its evidence as a workflow artifact.

## Source

Created on 15 November 2026 from the supplied James Houlder / Tech Samurai
visual reference. The mark and artwork are original code-native SVG drawings;
the uploaded composite is a design reference, not a raster logo embedded in
the application. Earlier brand editions remain available in Git history.
