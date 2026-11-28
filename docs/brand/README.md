# DNS Daddy — Hacker print identity

**Protective DNS. Clearly explained.**

The 28 November 2026 identity uses the DNS Daddy logo approved by James Houlder:
an angular red shield, an off-white database, circuit connections and a bold,
lightly distressed wordmark. Charcoal surfaces and readable operational screens
carry the identity into the application. This is a visual refresh; the software
remains alpha and its security and maturity claims have not changed.

## Approved logo and clean adaptations

The authoritative full logo is
[`logos/dns-daddy-logo-hacker.png`](logos/dns-daddy-logo-hacker.png).
It is **2172 × 724, RGBA with a genuinely transparent background**. This is the
exact approved image, preserved byte-for-byte. The application serves an
identical copy as [`/logo-hacker.png`](../../internal/web/static/logo-hacker.png).
Use it for website headers, sign-in branding, the application sidebar and larger
public artwork. Keep its proportions, complete lettering and transparency.

The small mark has been redrawn as original, clean SVG geometry: an angular
shield, three database tiers and four circuit nodes. The application retains
the stable [`/logo.svg#mark`](../../internal/web/static/logo.svg) symbol in a
40 × 40 view box. The [favicon](../../internal/web/static/favicon.svg) omits
the circuit branches for small-size clarity.

| Asset | File | Appropriate use |
| --- | --- | --- |
| Approved textured full logo | [PNG](logos/dns-daddy-logo-hacker.png) | Default brand lockup; exact approved lettering |
| Clean colour mark | [SVG](logos/dns-daddy-mark-reversed.svg) | Mobile chrome, avatar artwork and small illustrations |
| Clean mark, monochrome ink | [SVG](logos/dns-daddy-mark-monochrome-ink.svg) | A single dark ink on a light background |
| Clean mark, monochrome white | [SVG](logos/dns-daddy-mark-monochrome-white.svg) | A single light ink on a dark background |
| Simplified favicon | [SVG](../../internal/web/static/favicon.svg) | Browser tabs and very small icons |

The existing horizontal and stacked SVG filenames now contain **clean utility
adaptations** with the same angular emblem and original geometric block
lettering. They are editable vector alternatives, **not pixel-identical vector
masters of the approved textured PNG**:

- Horizontal: [light](logos/dns-daddy-logo-primary.svg),
  [dark](logos/dns-daddy-logo-reversed.svg),
  [monochrome ink](logos/dns-daddy-logo-monochrome-ink.svg),
  [monochrome white](logos/dns-daddy-logo-monochrome-white.svg).
- Stacked: [light](logos/dns-daddy-logo-stacked-primary.svg),
  [dark](logos/dns-daddy-logo-stacked-reversed.svg).

Keep clear space of at least one quarter of the emblem height. Prefer the full
PNG at 200 px wide or larger; use the standalone mark when space is tighter.
If the small descriptor must be read directly, give the full lockup more space
or repeat that descriptor as ordinary accessible text. Start the full circuit
mark at 32 px and use the simplified favicon below that size. Do not apply
distress to form labels, tables, status messages or evidence values.

## Colour and typography

The established palette remains shared across the app and websites.

| Role | Colour | Use |
| --- | --- | --- |
| Ink | `#0B1014` | Main canvas and artwork background |
| Surface | `#141B22` | Cards and panels |
| Elevated surface | `#1B252E` | Layered controls and surfaces |
| Ivory | `#F7F4ED` | Primary text |
| Muted | `#A9B4BE` | Supporting text |
| Brand red | `#E5252A` | Mark, decorative rules and large graphics |
| Action red | `#B91C2B` | Filled buttons with white labels |
| Text accent | `#FF5A52` | Small red text, links and focus indicators |
| Soft text accent | `#FF8B82` | Supporting accent and hover text |
| Information | `#83BFFF` | Information labels and total-query series |
| Success | `#6DD6A0` | Successful or healthy states |
| Warning | `#F1BF73` | Cautions and incomplete states |
| Danger | `#FF8DA1` | Blocked/error labels and blocked-query series |

Machine-readable values are in [palette.json](palette.json) and
[palette.css](palette.css). The application owns its full semantic and light-mode
palette in [`app.css`](../../internal/web/static/app.css).

Brand red does not meet the normal-text 4.5:1 contrast threshold against the ink
canvas. Use the lighter text accent for small red text. Use the separate darker
action fill for white button labels and check each foreground/background pair.

Brand colour and operational state remain separate. Information is blue,
success green, warning amber and blocked/error states rose, accompanied by
explicit labels. Total queries and blocked queries remain distinguishable.
Never communicate status through colour alone.

The application uses local system sans-serif and monospace stacks. Display
headings can be bold; domains, query types and evidence values can be monospace.
Normal paragraphs remain plain and readable. There are no external font or
artwork requests. The retained [Inter licence](Inter-LICENSE.txt) belongs to a
previous edition; the refresh adds no font runtime dependency.

## Repository and social artwork

| Asset | Public export | Editable source | Dimensions |
| --- | --- | --- | --- |
| README banner | [PNG](github-readme-banner-1600x500.png) | [SVG layout](github-readme-banner-1600x500.svg) | 1600 × 500 |
| Profile icon | [PNG](dns-daddy-icon-400x400.png) | [SVG](dns-daddy-icon-400x400.svg) | 400 × 400 |
| GitHub social preview | [PNG](github-social-preview-1280x640.png) | [SVG layout](github-social-preview-1280x640.svg) | 1280 × 640 |

The README and social SVGs are **layout sources containing a local raster image
reference** to `logos/dns-daddy-logo-hacker.png`. They are not pure-vector logo
masters. Keep the adjacent logo with those source layouts, and use the exported
PNGs for GitHub, social sharing or other standalone web display. This avoids
embedding duplicate copies of the approved image in each SVG. The profile icon
uses only editable vector geometry.

Committing the social-preview file does not change **Repository Settings →
Social preview** or an account avatar. Upload the supplied export to those
settings when required. [GitHub's social-preview documentation](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/customizing-your-repositorys-social-media-preview)
describes the separate setting.

## Reproduce the assets

From the repository root, with Python 3 and Inkscape installed:

```sh
python3 docs/brand/build-assets.py --render
```

The builder verifies the approved PNG's SHA-256, copies it unchanged to the
application, creates the clean SVG adaptations and exports the three artwork
layouts. It uses only local files and does not regenerate the approved logo.
Omit `--render` to update SVG sources without exporting PNGs. PNG rendering was
checked with Inkscape 1.4; different renderer/font versions can change export
bytes. [asset-manifest.json](asset-manifest.json) records the approved input,
dimensions, output hashes, renderer and distinction between raster and vector
assets.

Approved logo SHA-256:

```text
cd53acedeee1f9c572dfb744b4774f5972a186d9b824f0b3daa5a7bbb44638ee
```

## Voice, artwork and site roles

- **Lead:** Protective DNS. Clearly explained.
- **Signature:** Protect. Observe. Respond.
- **Campaign line:** Know what your network is asking for.
- **Descriptor:** Open-source, self-hosted protective DNS.

Use original DNS query paths, policy boundaries and evidence records as the
recurring visual subjects. The red-and-black hacker print atmosphere is a broad
influence; do not copy another project's emblem, illustrations, characters,
wordmark or page composition. Decorative query paths are artwork, never claims
about measured traffic or actual topology.

`https://dnsdaddy.com` is the canonical product website. Keep the established
`https://demo.dnsdaddy.dev` demo and `https://threats.dnsdaddy.dev` Observatory
addresses. Preserve other resolver, API, installer and service URLs; a visual
refresh does not justify replacing every `.dev` string.

The main website can be expressive. The application and demo should prioritise
readable investigation. Demo records must be labelled synthetic. The Observatory
is a separate resource for source-reported research, not telemetry from private
DNS Daddy installations. Do not imply that its retired built-in resolver-feed
integration is an active required product service.

Preserve alpha and AI-assistance disclosures, experimental scope and the absence
of an independent professional security review. Behavioural findings are
alert-only. Keep resolution mode, DNSSEC validation and DNS transport distinct
when describing Daddybound. Technical claims remain governed by the
[capability documentation](../capabilities.md) and [trust statement](../../TRUST.md).

## Screenshot provenance

Brand artwork is separate from application screenshots. Product captures must
come from the running application, preserve visible limitations and record the
source revision, fixture scope and capture time. Do not recolour an old
screenshot or present a mock-up as live telemetry. Current and historical
capture groups are documented in [SCREENSHOTS.md](../images/SCREENSHOTS.md).

## Source

The textured logo was generated with AI and explicitly approved by James
Houlder on 28 November 2026. It evolves his existing shield/database/network
identity. Its original PNG is the immutable visual reference. The simplified
emblem, utility lettering and layout artwork are original code-native
adaptations produced for this repository. Earlier editions remain in Git
history.
