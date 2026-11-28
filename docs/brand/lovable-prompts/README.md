# Lovable website refresh prompts

Use each prompt in its matching existing Lovable project. Each brief is complete and includes the shared identity plus site-specific behaviour and verification requirements.

| Project | Prompt | Role |
| --- | --- | --- |
| [dnsdaddy.com](https://dnsdaddy.com) | [Main site](main-site.md) | Explain the product and lead to the demo and setup documentation |
| [demo.dnsdaddy.dev](https://demo.dnsdaddy.dev) | [Demo](demo-site.md) | A usable investigation walkthrough with clearly synthetic data |
| [threats.dnsdaddy.dev](https://threats.dnsdaddy.dev) | [Threat Observatory](observatory-site.md) | Public-source research with inspectable provenance and collection status |

Before running a prompt, resolve its named GitHub branch to a commit. If the branch has been merged or removed, use the merge commit or another verified revision containing this identity and its current screenshot manifest. Copy files into the site's own assets; do not hotlink mutable branch URLs in production.

Use the exact [approved full logo](../logos/dns-daddy-logo-hacker.png), the [brand guide](../README.md), and the real-app captures listed in [the capture manifest](../../images/hacker-brand-capture-manifest.json). Attach the approved PNG to the Lovable conversation if repository asset access is unavailable. Preserve both the exact artwork and the website's current functional contracts.

These are implementation briefs. Adding them to this repository does not modify or deploy any of the websites.
