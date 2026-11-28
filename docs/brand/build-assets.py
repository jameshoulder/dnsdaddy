#!/usr/bin/env python3
"""Build DNS Daddy's clean vector adaptations and branded export layouts.

The user-approved PNG is an immutable input, not regenerated or edited here.
Use --render to export the three artwork layouts with a local Inkscape install.
No network access, runtime browser, credentials, or third-party fonts are used.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import xml.etree.ElementTree as ET


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
STATIC = ROOT / "internal" / "web" / "static"
LOGOS = HERE / "logos"
APPROVED = LOGOS / "dns-daddy-logo-hacker.png"
APPROVED_SHA256 = "cd53acedeee1f9c572dfb744b4774f5972a186d9b824f0b3daa5a7bbb44638ee"
INK, IVORY, RED, MUTED = "#0B1014", "#F7F4ED", "#E5252A", "#A9B4BE"


def svg(width: int, height: int, title: str, body: str) -> str:
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
            f'viewBox="0 0 {width} {height}" role="img" aria-labelledby="title">\n'
            f'  <title id="title">{title}</title>\n{body}\n</svg>\n')


def mark(red: str = RED, ink: str = INK, ivory: str = IVORY, circuits: bool = True) -> str:
    """Forty-unit clean adaptation: angular shield, three database tiers, four nodes."""
    branches = f'''  <g fill="none" stroke="{red}" stroke-width="2.7" stroke-linecap="square">
    <path d="M10 16H7.5l-2.2-2.2M10 25H7M30 16h2.5l2.2-2.2M30 25h3"/>
    <circle cx="3.6" cy="11.6" r="2.3" stroke-width="2.3"/><circle cx="3.6" cy="25" r="2.3" stroke-width="2.3"/>
    <circle cx="36.4" cy="11.6" r="2.3" stroke-width="2.3"/><circle cx="36.4" cy="25" r="2.3" stroke-width="2.3"/>
  </g>\n''' if circuits else ""
    return branches + f'''  <path d="M9 8 25.5 2 24 5.2 31.5 8.2 31.2 25.3 20 38 8.8 27.3Z" fill="{red}"/>
  <path d="M12 10.2 21 6.9 28.2 10 28 24 20 33.5 11.9 25.8Z" fill="{ink}"/>
  <g fill="{ivory}">
    <ellipse cx="20" cy="14.2" rx="5.8" ry="2.2"/>
    <path d="M14.2 16.3v3c0 1.3 2.6 2.3 5.8 2.3s5.8-1 5.8-2.3v-3c-1.3 1.2-3.3 1.8-5.8 1.8s-4.5-.6-5.8-1.8Z"/>
    <path d="M14.2 21.6v3c0 1.3 2.6 2.3 5.8 2.3s5.8-1 5.8-2.3v-3c-1.3 1.2-3.3 1.8-5.8 1.8s-4.5-.6-5.8-1.8Z"/>
  </g>'''


# Original geometric letter constructions for the clean utility wordmark.
# These are intentionally untextured adaptations, not tracings of another brand.
GLYPHS = {
    "D": (40, "M0 0H30L40 10V50L30 60H0ZM12 12V48H25L28 45V15L25 12Z"),
    "N": (41, "M0 60V0H12L29 35V0H41V60H29L12 25V60Z"),
    "S": (40, "M8 0H40V12H14V23H30L40 33V51L31 60H0V48H26V37H10L0 27V9Z"),
    "A": (46, "M0 60 16 0H30L46 60H33L30 47H15L12 60ZM18 35H27L22 14Z"),
    "Y": (46, "M0 0H14L23 22 32 0H46L30 36V60H16V36Z"),
}


def wordmark(first: str, second: str) -> str:
    x = 0
    parts = []
    for index, letter in enumerate("DNS DADDY"):
        if letter == " ":
            x += 13
            continue
        width, path = GLYPHS[letter]
        colour = first if index < 3 else second
        parts.append(f'<path transform="translate({x} 0)" fill="{colour}" fill-rule="evenodd" d="{path}"/>')
        x += width + 4
    return '<g>' + "".join(parts) + '</g>'


def label(x: int, y: int, text: str, size: int, fill: str = IVORY, weight: int = 400,
          spacing: float = 0) -> str:
    return (f'<text x="{x}" y="{y}" fill="{fill}" font-family="Arial, Helvetica, sans-serif" '
            f'font-size="{size}" font-weight="{weight}" letter-spacing="{spacing}">{text}</text>')


def write(path: Path, contents: str) -> None:
    ET.fromstring(contents)
    path.write_text(contents, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--render", action="store_true", help="Export the three layouts to PNG with Inkscape")
    args = parser.parse_args()
    if not APPROVED.is_file() or hashlib.sha256(APPROVED.read_bytes()).hexdigest() != APPROVED_SHA256:
        raise SystemExit("The approved logo input is missing or differs from the approved master; refusing to replace it.")
    shutil.copyfile(APPROVED, STATIC / "logo-hacker.png")
    write(STATIC / "logo.svg", svg(40, 40, "DNS Daddy — simplified angular mark",
          '<symbol id="mark" viewBox="0 0 40 40">\n' + mark() + '\n</symbol>\n<use href="#mark"/>'))
    write(STATIC / "favicon.svg", svg(40, 40, "DNS Daddy",
          f'<rect width="40" height="40" rx="3" fill="{INK}"/>\n' + mark(circuits=False)))

    variants = {
        "primary": (RED, INK, IVORY, INK, RED),
        "reversed": (RED, INK, IVORY, IVORY, RED),
        "monochrome-ink": (INK, IVORY, INK, INK, INK),
        "monochrome-white": (IVORY, INK, IVORY, IVORY, IVORY),
    }
    for name, (red, ink, ivory, first, second) in variants.items():
        content = mark(red, ink, ivory)
        if name.startswith("monochrome-"):
            content = (f'<defs><mask id="mono-cut" maskUnits="userSpaceOnUse" x="0" y="0" width="40" height="40">'
                       + mark("#FFFFFF", "#000000", "#FFFFFF")
                       + f'</mask></defs><rect width="40" height="40" fill="{first}" mask="url(#mono-cut)"/>')
        write(LOGOS / f"dns-daddy-mark-{name}.svg", svg(160, 160,
              f"DNS Daddy — simplified {name} mark", f'<g transform="scale(4)">{content}</g>'))
        body = (f'<g transform="translate(12 19) scale(3.5)">{content}</g>'
                f'<g transform="translate(178 56) scale(.98)">{wordmark(first, second)}</g>'
                + label(180, 143, "PROTECTIVE DNS", 17, first, 700, 2.2))
        write(LOGOS / f"dns-daddy-logo-{name}.svg", svg(590, 180,
              f"DNS Daddy — clean utility lockup, {name}", body))
    for name in ("primary", "reversed"):
        red, ink, ivory, first, second = variants[name]
        body = (f'<g transform="translate(160 38) scale(7)">{mark(red, ink, ivory)}</g>'
                f'<g transform="translate(66 390) scale(1.25)">{wordmark(first, second)}</g>'
                + label(175, 512, "PROTECTIVE DNS", 21, first, 700, 2))
        write(LOGOS / f"dns-daddy-logo-stacked-{name}.svg", svg(600, 560,
              f"DNS Daddy — clean utility stacked lockup, {name}", body))

    # Editable layouts link to the one local master. PNG exports are standalone;
    # the SVGs are layout sources and are not pure-vector logo masters.
    logo_image = '<image href="logos/dns-daddy-logo-hacker.png" x="{x}" y="{y}" width="{w}" height="{h}" preserveAspectRatio="xMidYMid meet"/>'
    banner = (f'<rect width="1600" height="500" fill="{INK}"/>'
              f'<path d="M0 0H1600V7H0Z" fill="{RED}"/>'
              + label(64, 55, "OPEN SOURCE / SELF-HOSTED / ALPHA", 18, "#FF5A52", 700, 2)
              + logo_image.format(x=54, y=68, w=1050, h=350)
              + f'''<g fill="none" stroke="{MUTED}" stroke-width="2" opacity=".55">
                <path d="M1238 133h65l24 24h190M1238 230h189M1238 327h65l24-24h190"/>
                <circle cx="1238" cy="133" r="5"/><circle cx="1238" cy="230" r="5"/><circle cx="1238" cy="327" r="5"/>
              </g><path d="M1427 105v232" stroke="{RED}" stroke-width="5"/>
              <path d="M1238 230h189" stroke="{RED}" stroke-width="3"/>
              <rect x="1420" y="222" width="14" height="16" fill="{RED}"/>'''
              + label(1227, 377, "QUERY / POLICY / EVIDENCE", 13, MUTED, 400, 1)
              + f'<path d="M64 430H1536" stroke="{MUTED}" opacity=".3"/>'
              + label(64, 472, "KNOW WHAT YOUR NETWORK IS ASKING FOR.", 20, IVORY, 700, .5)
              + label(1357, 472, "dnsdaddy.com", 20, MUTED))
    write(HERE / "github-readme-banner-1600x500.svg", svg(1600, 500,
          "DNS Daddy — open-source, self-hosted protective DNS", banner))

    social = (f'<rect width="1280" height="640" fill="{INK}"/>'
              f'<path d="M0 0H1280V8H0Z" fill="{RED}"/>'
              + label(80, 69, "OPEN SOURCE / SELF-HOSTED / ALPHA", 19, "#FF5A52", 700, 2)
              + logo_image.format(x=70, y=113, w=1140, h=380)
              + f'<path d="M80 500H1200" stroke="{MUTED}" opacity=".35"/>'
              + label(80, 551, "Protective DNS. Clearly explained.", 35, IVORY, 700)
              + label(82, 604, "PROTECT. OBSERVE. RESPOND.", 16, MUTED, 400, 1.8)
              + label(1031, 604, "dnsdaddy.com", 20, MUTED))
    write(HERE / "github-social-preview-1280x640.svg", svg(1280, 640,
          "DNS Daddy — Protective DNS. Clearly explained.", social))

    profile = (f'<rect width="400" height="400" rx="20" fill="{INK}"/>'
               f'<path d="M32 75V32h43M325 368h43v-43" fill="none" stroke="{RED}" stroke-width="6"/>'
               f'<g transform="translate(52 48) scale(7.4)">{mark()}</g>')
    write(HERE / "dns-daddy-icon-400x400.svg", svg(400, 400,
          "DNS Daddy — angular shield, database and network mark", profile))

    layouts = ["github-readme-banner-1600x500", "github-social-preview-1280x640", "dns-daddy-icon-400x400"]
    renderer = None
    if args.render:
        executable = shutil.which("inkscape")
        if executable is None:
            raise SystemExit("Inkscape is required for --render; SVG sources have been written.")
        renderer = subprocess.check_output([executable, "--version"], text=True).strip()
        for layout in layouts:
            subprocess.run([executable, str(HERE / f"{layout}.svg"), "--export-type=png",
                            f"--export-filename={HERE / (layout + '.png')}"], check=True)

    files = sorted([APPROVED, *LOGOS.glob("*.svg"), *(HERE / f"{p}.svg" for p in layouts),
                    STATIC / "logo-hacker.png", STATIC / "logo.svg", STATIC / "favicon.svg"])
    if args.render:
        files.extend(HERE / f"{p}.png" for p in layouts)
    manifest = {
        "edition": "2026-11-28 hacker print identity",
        "approvedLogo": {"path": str(APPROVED.relative_to(ROOT)), "sha256": APPROVED_SHA256,
                         "width": 2172, "height": 724, "alpha": True,
                         "provenance": "AI-generated logo concept explicitly approved by James Houlder on 28 November 2026; preserved byte-for-byte"},
        "vectorAdaptations": "Original code-native simplified mark and untextured geometric utility lettering; not a pixel-identical vectorisation of the approved raster",
        "layoutSources": "README and social SVG layouts reference the adjacent approved PNG; use PNG exports for standalone web display",
        "renderCommand": "python3 docs/brand/build-assets.py --render",
        "renderer": renderer,
        "files": [{"path": str(p.relative_to(ROOT)), "bytes": p.stat().st_size,
                   "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in files],
    }
    (HERE / "asset-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"Wrote {len(files)} validated brand assets; approved raster preserved unchanged.")


if __name__ == "__main__":
    main()
