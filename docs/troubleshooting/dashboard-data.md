# DNS answers, but the dashboard has no data

DNS transport, client authorisation, query-history storage and dashboard API
reads are separate paths. A successful DNS lookup does not establish that the
browser is reading the same instance. A loaded dashboard does not establish that
its API requests succeeded. Keep these checks separate; do not relax DNS ACLs,
TLS verification, session-cookie security or dashboard binding to make a chart move.

## Upgrade the shared code, including installer-managed settings

After updating the checkout to the reviewed release/commit, run:

```sh
./deploy/install-docker.sh --upgrade
```

For an HTTPS deployment whose active `DNSDADDY_BASE_URL` and proxy settings carry
`# managed by install-docker.sh`, upgrade re-discovers the running container's
actual project-network gateway. It replaces obsolete managed proxy subnets with
exact `/32` or `/128` gateway hosts and recreates/waits for the container. The
Docker network named `bridge` is not assumed to be the project's network.

Custom active assignments, including a later unmarked override, are preserved.
A shell environment override is also preserved and reported; it can take precedence
over `.env`. Remove the adjacent managed marker when deliberately adopting a
custom reverse-proxy topology. Unknown/invalid gateway discovery fails the managed
repair instead of guessing or claiming success. `--dry-run` reports the migration
without changing files or restarting a service. Caddy and certificates are not
reconfigured by this upgrade migration.

The installer stamps a clean checked-out source commit into Docker builds. A dirty
tracked working tree is reported and not stamped as that exact commit. Plain
`docker compose` builds can supply `DNSDADDY_COMMIT`; that is builder-supplied
metadata, not independent verification. No rebuild or source update is performed
just because a PR has been merged on GitHub.

## Understand the addresses and ports

A container sees its own interfaces. An internal address such as `172.23.0.2`
is not automatically the host's public address. In the standard Compose profile,
host UDP/TCP port **53** is mapped to container port **5353**. Keep dashboard port
8080 published to **127.0.0.1**, behind HTTPS or an SSH tunnel.

The UI labels detected container addresses separately. To display a known
client-facing ordinary DNS endpoint, configure the optional display-only field:

```dotenv
DNSDADDY_ADVERTISED_DNS=203.0.113.53:53
```

Replace the documentation address with the real host/NAT address and published
port. For IPv6, use `[2001:db8::53]:53` with your real address. In YAML the field is
`dns.advertised_endpoint`. This is **not** a listener setting, access grant, DNS
upstream, proxy trust decision or verified reachability result. It does not call
an external IP-discovery service. A browser Host header is never its source.
`.env` contains plain assignments, not Markdown links, browser paths or API URLs.

## Distinguish a data failure from zero traffic

The Overview shows the exact endpoint and a bounded error when a dashboard read
fails or receives HTML instead of JSON. The browser uses same-origin authenticated
requests with `cache: no-store`; JSON responses are non-cacheable. Embedded HTML
selects content-fingerprinted script/style URLs to avoid mixing a new backend
with old cached assets. Missing assets return an error rather than a successful SPA.

While signed in, the link **Open live measurements on this dashboard connection**
opens `/api/v1/activity/live` on that same origin. It is not an `.env` setting.
Do not share cookies, bearer tokens, passwords or private DNS logs.

Run an explicit UDP/TCP test from an authorised client (use the real server IP):

```sh
nslookup example.com 203.0.113.53
dig @203.0.113.53 -p 53 example.com A +tcp
```

Compare the response with `sinceStart.received` and `sinceStart.completed` in the
live API. These counters include handler refusals and local doctor probes even
when query logging is off. They reset on process restart and do not count messages
rejected before the DNS handler, such as failed DoH authentication. Completion is
not proof that a client received the reply. A 401 is an authentication issue;
HTML/404 suggests routing or an older backend; 5xx needs its server-side cause.

The authenticated diagnostics page also reports whether the **actual peer of
that HTTP request** is trusted when forwarding headers are present. It does not
trust or repeat the contents of those headers, and does not automatically grant
trust to a caller. A mismatch is not proof of the cause of a missing chart.

An automatic history refresh can be discarded when the operator starts editing.
That must leave the existing view's live poller running. The browser regression
covers real DNS traffic before and after that race, with query logging disabled.

## Release evidence boundary

The regression suite and an installer fixture prove specific behaviours, not
arbitrary firewall/NAT arrangements or the maintainer's VPS. Before a release,
record the deployed commit, observed port map, an explicit permitted-client query,
a matching live counter increase, visible dashboard updates through the intended
HTTPS proxy, and rejection of an unpermitted client. Do not publish a release-ready
claim solely because the web health endpoint or CI is green.
