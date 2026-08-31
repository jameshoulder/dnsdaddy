/*
 * Tests for the Threat Observatory card's rendering decisions.
 *
 * Run with `make test-ui`. There is no package.json, no dependency and no build
 * step — this uses node's built-in test runner against the very app.js the
 * binary serves, so it cannot drift from what a browser gets. It lives beside
 * the static directory rather than inside it so that go:embed does not ship
 * the test file to every operator.
 *
 * The behaviour under test is narrow and worth pinning: the card must never
 * describe a feed as Active when nothing has successfully downloaded. An
 * operator who reads "Active" stops looking, and a card that says it over a
 * 404 is worse than no card at all.
 */

'use strict';

const test = require('node:test');
const assert = require('node:assert');

const {
  esc,
  ApiError,
  claimRefresh,
  observatoryState,
  observatoryErrorSummary,
  observatoryEnforcement,
  observatoryCard,
  feedStatusBadge,
  threatIntelPanel,
  diagnosticsBanner,
  firstClientCard,
  accessBadge,
  clientAccessSummary,
  resolverAccessNote,
  emptyState,
  protectionState,
  feedHealth,
  statusHero,
  attentionItems,
  attentionPanel,
  recentlyBlocked,
  protectionBreakdown,
  pages,
  routeName,
} = require('./static/app.js');

const OBSERVATORY_ID = 'dnsdaddy-observatory';

function feed(overrides = {}) {
  return {
    id: OBSERVATORY_ID,
    name: 'DNS Daddy Threat Observatory',
    url: 'https://threats.dnsdaddy.dev/api/v1/feed.json',
    category: 'malware',
    format: 'observatory',
    enabled: false,
    builtin: true,
    indexedDomains: 0,
    loaded: false,
    loadError: '',
    lastRefreshedAt: null,
    lastSuccessAt: null,
    lastStatus: '',
    lastError: '',
    ...overrides,
  };
}

const now = () => new Date().toISOString();
const hoursAgo = (h) => new Date(Date.now() - h * 3600 * 1000).toISOString();

/* ---------- state derivation -------------------------------------------- */

test('a disabled feed offers activation', () => {
  assert.equal(observatoryState(feed(), false), 'off');
});

test('a feed with a validated download is active', () => {
  const f = feed({ enabled: true, loaded: true, lastRefreshedAt: now(), lastSuccessAt: now(), indexedDomains: 34821 });
  assert.equal(observatoryState(f, false), 'active');
});

test('an enabled feed that has never downloaded is not active', () => {
  // The 404 case, which is where the Observatory endpoint stands today.
  const f = feed({
    enabled: true,
    lastRefreshedAt: now(),
    lastSuccessAt: null,
    lastError: 'HTTP 404 from https://threats.dnsdaddy.dev/api/v1/feed.json',
  });
  assert.equal(observatoryState(f, false), 'unavailable');
});

test('an enabled feed with no attempt yet is pending, not active', () => {
  assert.equal(observatoryState(feed({ enabled: true }), false), 'pending');
});

test('a feed erroring after a good download is degraded, not broken', () => {
  const f = feed({
    enabled: true,
    loaded: true,
    lastRefreshedAt: now(),
    lastSuccessAt: hoursAgo(2),
    indexedDomains: 34821,
    lastError: 'HTTP 500 from https://threats.dnsdaddy.dev/api/v1/feed.json',
  });
  assert.equal(observatoryState(f, false), 'stale');
});

test('a refresh in flight shows the connecting state', () => {
  assert.equal(observatoryState(feed({ enabled: true }), true), 'connecting');
});

test('a missing feed row is its own state rather than a false negative', () => {
  assert.equal(observatoryState(undefined, false), 'missing');
});

/* ---------- error wording ------------------------------------------------ */

test('a 404 is explained as the endpoint not being live yet', () => {
  const msg = observatoryErrorSummary('HTTP 404 from https://threats.dnsdaddy.dev/api/v1/feed.json');
  assert.match(msg, /not available yet/);
});

test('a rejected download says the previous copy was kept', () => {
  const msg = observatoryErrorSummary('rejected download, keeping the previous copy: observatory feed ends mid-document: it is truncated');
  assert.match(msg, /previous copy/);
});

test('an unrecognised error still produces a sentence, not a blank', () => {
  assert.notEqual(observatoryErrorSummary('something nobody anticipated'), '');
  assert.equal(observatoryErrorSummary(''), '');
});

/* ---------- the card ----------------------------------------------------- */

test('the disabled card offers one-click activation and states the privacy position', () => {
  const out = observatoryCard(feed(), {});
  assert.match(out, /Enable Threat Observatory/);
  assert.match(out, /id="observatory-enable"/);
  assert.match(out, /No account or API key required/);
  assert.match(out, /threats\.dnsdaddy\.dev/);
  assert.match(out, /DNS query logs are not uploaded/);
  assert.doesNotMatch(out, /Active/);
});

test('the active card reports the real indexed count, not a constant', () => {
  const out = observatoryCard(
    feed({ enabled: true, loaded: true, lastRefreshedAt: now(), lastSuccessAt: now(), indexedDomains: 34821 }),
    {}
  );
  assert.match(out, /badge ok">Active/);
  assert.match(out, /34,821<\/strong> domains indexed/);
  assert.match(out, /id="observatory-disable"/);
  assert.match(out, /href="#\/feeds"/);
});

test('a feed that has never downloaded is never described as active', () => {
  const out = observatoryCard(
    feed({
      enabled: true,
      lastRefreshedAt: now(),
      lastError: 'HTTP 404 from https://threats.dnsdaddy.dev/api/v1/feed.json',
    }),
    {}
  );
  assert.doesNotMatch(out, />Active</);
  assert.match(out, /has not been downloaded yet/);
  assert.match(out, /not available yet/);
  assert.match(out, /Retry connection/);
});

test('a degraded card says what is still being enforced and how old it is', () => {
  const out = observatoryCard(
    feed({
      enabled: true,
      loaded: true,
      lastRefreshedAt: now(),
      lastSuccessAt: hoursAgo(2),
      indexedDomains: 34821,
      lastError: 'HTTP 500 from https://threats.dnsdaddy.dev/api/v1/feed.json',
    }),
    {}
  );
  assert.match(out, /Attention/);
  assert.match(out, /Last successful intelligence/);
  assert.match(out, /2h ago/);
  assert.match(out, /last known good/);
  assert.match(out, /34,821 domains/);
  assert.match(out, /View error/);
  assert.doesNotMatch(out, />Active</);
});

test('the connecting card does not claim protection yet', () => {
  const out = observatoryCard(feed({ enabled: true }), { refreshing: true });
  assert.match(out, /Connecting to the Observatory/);
  assert.match(out, /Downloading threat intelligence/);
  assert.match(out, /Nothing from this feed is enforced until/);
  assert.doesNotMatch(out, />Active</);
});

test('a feed error from a remote server is escaped, not injected', () => {
  // lastError is remote-controlled text: it is built from the response of
  // whatever host the feed URL points at.
  const out = observatoryCard(
    feed({ enabled: true, lastRefreshedAt: now(), lastError: '<img src=x onerror="alert(1)">' }),
    {}
  );
  assert.doesNotMatch(out, /<img/);
  assert.match(out, /&lt;img/);
});

/* ---------- policies are the operator's, not the feed's ------------------ */

test('the card names the categories no policy enforces rather than implying four', () => {
  const out = observatoryEnforcement([{ categories: ['malware', 'phishing'] }]);
  assert.match(out, /Malware, Phishing/);
  assert.match(out, /C2, Cryptomining/);
  assert.match(out, /does not change your policies/);
});

test('the card says nothing about gaps when every category is enforced', () => {
  const out = observatoryEnforcement([{ categories: ['malware', 'phishing', 'c2', 'cryptomining'] }]);
  assert.match(out, /every category/);
});

/* ---------- feed health and the dashboard panel -------------------------- */

test('feed health distinguishes stale intelligence from none at all', () => {
  assert.match(feedStatusBadge(feed()), />Off</);
  assert.match(feedStatusBadge(feed({ enabled: true })), />Pending</);
  assert.match(feedStatusBadge(feed({ enabled: true, loaded: true, lastSuccessAt: now() })), />Active</);
  assert.match(
    feedStatusBadge(feed({ enabled: true, loaded: true, lastSuccessAt: hoursAgo(2), lastError: 'HTTP 500' })),
    />Stale</
  );
  assert.match(feedStatusBadge(feed({ enabled: true, lastError: 'HTTP 404' })), />Unavailable</);
});

test('the dashboard panel offers activation inline and lists the other sources', () => {
  const data = {
    observatoryFeedId: OBSERVATORY_ID,
    totalIndexedDomains: 412345,
    refreshing: false,
    feeds: [
      feed(),
      { ...feed({ enabled: true, loaded: true, lastSuccessAt: now() }), id: 'urlhaus', name: 'abuse.ch URLhaus' },
      { ...feed({ enabled: false }), id: 'stevenblack-ads', name: 'StevenBlack unified hosts' },
    ],
  };
  const out = threatIntelPanel(data);
  assert.match(out, /id="observatory-enable"/);
  assert.match(out, /abuse\.ch URLhaus/);
  assert.match(out, /412,345 domains indexed/);
  // A switched-off third-party feed is summarised, not listed as a live source.
  assert.doesNotMatch(out, /StevenBlack/);
  assert.match(out, /1 further feed available but switched off/);
  // The Observatory is listed first, but with the same badge markup as
  // everything else: prominent, not privileged.
  assert.ok(out.indexOf('DNS Daddy Threat Observatory') < out.indexOf('abuse.ch URLhaus'));
});

test('escaping applies to feed names, which an operator controls', () => {
  assert.equal(esc('<script>'), '&lt;script&gt;');
});

/* ---------- runtime truth, not remembered history ------------------------ */

/*
 * The card's most important job is refusing to say "Active" about a feed that
 * is not blocking anything. A successful download is remembered in the feed
 * row forever; whether the file that download produced is in the index right
 * now is a different question, and only `loaded` answers it.
 */

test('a feed whose cached copy is not in the index is never Active', () => {
  // The restart case: the download succeeded, the cache file has since gone,
  // and the rebuild skipped the feed. Nothing in the timestamps says so.
  const f = feed({
    enabled: true,
    loaded: false,
    loadError: 'its cached copy is missing',
    lastRefreshedAt: hoursAgo(2),
    lastSuccessAt: hoursAgo(2),
    lastStatus: 'ok',
    lastError: '',
  });
  assert.equal(observatoryState(f, false), 'unusable');

  const out = observatoryCard(f, {});
  assert.doesNotMatch(out, />Active</);
  assert.match(out, /not currently blocking anything/);
  assert.match(out, /its cached copy is missing/);
  assert.match(out, /Download again/);
});

test('a loaded feed with a healthy refresh is Active', () => {
  const f = feed({
    enabled: true,
    loaded: true,
    lastRefreshedAt: now(),
    lastSuccessAt: now(),
    indexedDomains: 34821,
  });
  assert.equal(observatoryState(f, false), 'active');
  assert.match(observatoryCard(f, {}), /badge ok">Active/);
});

test('a loaded feed whose latest refresh failed keeps blocking and reports degraded', () => {
  const f = feed({
    enabled: true,
    loaded: true,
    lastRefreshedAt: now(),
    lastSuccessAt: hoursAgo(2),
    indexedDomains: 34821,
    lastError: 'HTTP 500 from https://threats.dnsdaddy.dev/api/v1/feed.json',
  });
  assert.equal(observatoryState(f, false), 'stale');
  const out = observatoryCard(f, {});
  assert.match(out, /still indexed and still blocked/);
  assert.doesNotMatch(out, />Active</);
});

test('the four runtime states are all distinguishable', () => {
  const base = { enabled: true };
  const states = {
    active: { ...base, loaded: true, lastSuccessAt: now() },
    stale: { ...base, loaded: true, lastSuccessAt: hoursAgo(2), lastError: 'HTTP 500' },
    unusable: { ...base, loaded: false, lastSuccessAt: hoursAgo(2) },
    unavailable: { ...base, loaded: false, lastError: 'HTTP 404' },
    pending: { ...base, loaded: false },
  };
  for (const [want, overrides] of Object.entries(states)) {
    assert.equal(observatoryState(feed(overrides), false), want, `expected ${want}`);
  }
});

test('the dashboard panel will not call an unloaded feed Active either', () => {
  const f = feed({ enabled: true, loaded: false, lastSuccessAt: hoursAgo(2) });
  const badge = feedStatusBadge(f);
  assert.doesNotMatch(badge, />Active</);
  assert.match(badge, />Not blocking</);
});

test('a load error from the server is escaped like any other server text', () => {
  const out = observatoryCard(
    feed({
      enabled: true,
      loaded: false,
      lastSuccessAt: hoursAgo(2),
      loadError: '<img src=x onerror="alert(1)">',
    }),
    {}
  );
  assert.doesNotMatch(out, /<img/);
  assert.match(out, /&lt;img/);
  // And escaped exactly once — a double-escaped message is unreadable.
  assert.doesNotMatch(out, /&amp;lt;/);
});

/* ---------- claiming the refresh slot ------------------------------------ */

/*
 * The server serialises refreshes and refuses a second one with 409 rather
 * than queueing it. Treating that as "fine, the running refresh will cover us"
 * is wrong in a way that is invisible: a full refresh reads its feed list
 * before it starts downloading, so one that began before the Observatory was
 * enabled will never fetch it, and neither will a targeted refresh of some
 * other feed. The operator would be left with an enabled feed that was never
 * downloaded, after a card that said it was connecting.
 */

function conflict() {
  return new ApiError(409, 'a feed refresh is already running');
}

test('a busy refresh slot is retried, not shrugged off', async () => {
  const posts = [];
  let waits = 0;
  const result = await claimRefresh('dnsdaddy-observatory', {
    post: async (id) => {
      posts.push(id);
      if (posts.length === 1) throw conflict(); // somebody else holds the slot
    },
    waitIdle: async () => {
      waits += 1;
      return { feeds: [feed({ id: 'dnsdaddy-observatory', enabled: true, loaded: true })] };
    },
    read: async () => null,
    onError: () => assert.fail('a 409 is not an error to report'),
    notify: () => assert.fail('the retry succeeded; nothing to warn about'),
  });

  assert.deepEqual(posts, ['dnsdaddy-observatory', 'dnsdaddy-observatory'],
    'the refresh must be asked for again once the slot frees up');
  assert.equal(waits, 2, 'it must wait for the conflicting refresh before retrying');
  assert.ok(result && result.feeds, 'the settled feed state is returned');
});

test('repeated conflicts give up after a bounded number of attempts', async () => {
  // A busy server must not spin forever, and must not silently pretend the
  // feed was refreshed.
  let posts = 0;
  const warnings = [];
  await claimRefresh('dnsdaddy-observatory', {
    attempts: 3,
    post: async () => {
      posts += 1;
      throw conflict();
    },
    waitIdle: async () => ({ feeds: [] }),
    read: async () => null,
    onError: () => assert.fail('a 409 is not an error to report'),
    notify: (msg) => warnings.push(msg),
  });

  assert.equal(posts, 3, 'it must stop after the attempt budget');
  assert.equal(warnings.length, 1, 'the operator must be told it did not happen');
  assert.match(warnings[0], /busy/);
});

test('a real error is reported once and not retried', async () => {
  let posts = 0;
  const errors = [];
  await claimRefresh('dnsdaddy-observatory', {
    post: async () => {
      posts += 1;
      throw new ApiError(500, 'internal error');
    },
    waitIdle: async () => assert.fail('a 500 is not a busy slot'),
    read: async () => null,
    onError: (err) => errors.push(err),
    notify: () => assert.fail('nothing to warn about; the error was reported'),
  });

  assert.equal(posts, 1, 'a genuine failure must not be retried as though it were a conflict');
  assert.equal(errors.length, 1);
  assert.equal(errors[0].status, 500);
});

test('the connecting state is painted while waiting behind another refresh', async () => {
  let painted = 0;
  let posts = 0;
  await claimRefresh('dnsdaddy-observatory', {
    post: async () => {
      posts += 1;
      if (posts === 1) throw conflict();
    },
    waitIdle: async () => ({ feeds: [] }),
    read: async () => null,
    onRunning: async () => { painted += 1; },
    onError: () => {},
    notify: () => {},
  });
  assert.ok(painted >= 1, 'the card must show work in progress while queued behind another refresh');
});


/*
 * The configuration-problem banner.
 *
 * These exist because of a real deployment failure: the resolver reported
 * itself operational, the dashboard showed the network as protected, and every
 * client on it was answered REFUSED. A green tick above a broken deployment is
 * worse than no tick at all.
 */

function check(overrides = {}) {
  return {
    section: 'CLIENT ACCESS',
    name: 'Network "Home" can resolve',
    status: 'pass',
    summary: 'Network "Home" is permitted to send queries.',
    evidence: [],
    action: '',
    ...overrides,
  };
}

test('the banner is absent when nothing is wrong', () => {
  const out = diagnosticsBanner({ status: 'pass', checks: [check(), check()] });
  assert.strictEqual(out, '', 'a healthy deployment must not carry a banner');
});

test('the banner is absent when diagnostics could not be fetched', () => {
  // An older server, or a failed request. The dashboard must still render.
  assert.strictEqual(diagnosticsBanner(null), '');
  assert.strictEqual(diagnosticsBanner(undefined), '');
  assert.strictEqual(diagnosticsBanner({}), '');
});

test('a failing check is shown with its evidence and its action', () => {
  const out = diagnosticsBanner({
    status: 'fail',
    checks: [
      check(),
      check({
        status: 'fail',
        summary: 'Network "Home" exists in the dashboard, but DNS queries from it are REFUSED.',
        evidence: ['network: 192.168.1.0/24', 'dns.allowed_client_cidrs: 127.0.0.0/8'],
        action: 'Adding a network assigns it a policy; it does not permit it to resolve.',
      }),
    ],
  });

  assert.match(out, /CONFIGURATION PROBLEM/);
  assert.match(out, /REFUSED/);
  assert.match(out, /192\.168\.1\.0\/24/, 'the evidence must be shown so the operator can check our working');
  assert.match(out, /does not permit it to resolve/, 'the action must be shown');
  assert.match(out, /diag-fail/, 'a failure must not be styled as a warning');
});

test('passing checks are not listed alongside problems', () => {
  const out = diagnosticsBanner({
    status: 'fail',
    checks: [
      check({ summary: 'All quiet on the western front.' }),
      check({ status: 'fail', summary: 'Something is broken.' }),
    ],
  });

  assert.match(out, /Something is broken/);
  assert.doesNotMatch(out, /western front/, 'this is an exception report, not a status page');
});

test('a warning is styled and worded as a warning, not a failure', () => {
  const out = diagnosticsBanner({
    status: 'warn',
    checks: [check({ status: 'warn', summary: 'Only part of network "Home" may resolve.' })],
  });

  assert.match(out, /CONFIGURATION WARNING/);
  assert.match(out, /diag-warn/);
  assert.doesNotMatch(out, /diag-fail/);
});

test('server-supplied text is escaped', () => {
  // Network names are operator-supplied and reach this through the API.
  const out = diagnosticsBanner({
    status: 'fail',
    checks: [
      check({
        status: 'fail',
        summary: 'Network "<img src=x onerror=alert(1)>" is REFUSED.',
        evidence: ['<script>alert(2)</script>'],
        action: '<b>do a thing</b>',
      }),
    ],
  });

  assert.doesNotMatch(out, /<img/, 'summary was not escaped');
  assert.doesNotMatch(out, /<script/, 'evidence was not escaped');
  assert.doesNotMatch(out, /<b>/, 'action was not escaped');
  assert.match(out, /&lt;img/);
});


/*
 * The first-client card.
 *
 * A fresh install looks identical whether it is working perfectly with nothing
 * pointed at it, or refusing every client — both produce empty charts. This
 * card says which. It must never invent activity, and must never claim "no
 * devices" when the truth is "we are not recording which devices".
 *
 * It has three states, each backed by something the server actually measured,
 * and getting the branch wrong is worse than the card not existing. It used to
 * branch on "no network carries a permission", which is false on a stock LAN
 * install — that has none, and serves every private range — so it told those
 * operators every client would be REFUSED.
 */

// A working resolver with nothing pointed at it yet. Refusals at zero and the
// ACL serving more than loopback are both measurements, not guesses.
function ready(overrides = {}) {
  return {
    hasSeenClients: false,
    clientAttribution: true,
    permittedNetworks: 0,
    unrestrictedAccess: false,
    servesOnlyLoopback: false,
    refusedClients: 0,
    ...overrides,
  };
}

// window is not defined under node --test; the card reads location.hostname.
function withHostname(host, fn) {
  const had = typeof global.window !== 'undefined';
  const previous = had ? global.window : undefined;
  global.window = { location: { hostname: host } };
  try {
    return fn();
  } finally {
    if (had) global.window = previous;
    else delete global.window;
  }
}

test('the card appears when no client has been seen, naming the dashboard host', () => {
  const out = withHostname('192.168.1.75', () => firstClientCard(ready()));

  assert.match(out, /No devices have used this resolver yet/);
  assert.match(out, /nslookup example\.com 192\.168\.1\.75/,
    'the command must name the address the operator reached the dashboard on');
  assert.match(out, /dnsdaddy doctor/, 'it must say what to do when nothing appears');
});

test('a stock LAN install is not told its clients will be refused', () => {
  // The regression this replaced. No network carries a permission on a fresh
  // install, and the shipped ACL serves every private range perfectly well.
  // Branching on the permission count told that operator the opposite.
  const out = withHostname('192.168.1.75', () =>
    firstClientCard(ready({ permittedNetworks: 0 })));

  assert.match(out, /No devices have used this resolver yet/);
  // A conditional — "if it comes back REFUSED, that address is not permitted
  // yet" — is useful and true. What must not appear is a claim that clients
  // are being refused, or that they will be.
  assert.doesNotMatch(out, /Clients are being refused/);
  assert.doesNotMatch(out, /will be answered <code>REFUSED/);
  assert.doesNotMatch(out, /Only this machine/);
});

test('measured refusals name the ACL as the cause', () => {
  // Queries are arriving and being turned away on their source address. That
  // rules out firewalls, routing and port conflicts in one step, and it is the
  // only evidence that separates a VPS whose clients are refused from a LAN
  // nobody has pointed anything at.
  const out = withHostname('192.168.1.75', () =>
    firstClientCard(ready({ refusedClients: 12 })));

  assert.match(out, /Clients are being refused/);
  assert.match(out, /12 queries have/, 'it must say how many, from the counter');
  assert.match(out, /Allow this network to use DNS Daddy/,
    'it must name the control that fixes it');
  assert.doesNotMatch(out, /No devices have used this resolver yet/,
    'queries did arrive; saying otherwise sends the operator to the wrong problem');
});

test('a loopback-only ACL says so, because then it really is true', () => {
  const out = withHostname('192.168.1.75', () =>
    firstClientCard(ready({ servesOnlyLoopback: true })));

  assert.match(out, /Only this machine may use the resolver/);
  assert.match(out, /Allow this network to use DNS Daddy/);
  assert.match(out, /nothing to restart/,
    'the whole point of the tick-box is that it needs no restart');
});

test('the loopback claim is scoped to clients the ACL actually governs', () => {
  // A DoH or DoT client presenting a network's token bypasses the source ACL
  // entirely — that is what makes a roaming profile roam. Claiming "every
  // other device will be REFUSED" would contradict the resolver and the
  // Networks page, and over-claiming is the fault this card exists to stop.
  const out = withHostname('192.168.1.75', () =>
    firstClientCard(ready({ servesOnlyLoopback: true })));

  assert.doesNotMatch(out, /every other device/);
  assert.match(out, /ordinary DNS/, 'the claim must name the transport it applies to');
  assert.match(out, /DNS-over-HTTPS and DNS-over-TLS clients holding a network.s token/,
    'the exception has to be stated, not left for the operator to discover');
});

test('an unrestricted ACL refuses nothing, and the card must not imply otherwise', () => {
  // An empty dns.allowed_client_cidrs refuses nothing, which config validation
  // only allows for loopback-only listeners or a deliberate public resolver.
  const out = withHostname('192.168.1.75', () =>
    firstClientCard(ready({ unrestrictedAccess: true })));

  assert.match(out, /No devices have used this resolver yet/);
  assert.doesNotMatch(out, /Only this machine/);
});

test('refusals outrank every other state, because they are the strongest evidence', () => {
  const out = withHostname('192.168.1.75', () =>
    firstClientCard(ready({ refusedClients: 3, servesOnlyLoopback: true })));
  assert.match(out, /Clients are being refused/);
});

test('the card disappears as soon as a real client exists', () => {
  const out = withHostname('192.168.1.75', () =>
    firstClientCard(ready({ hasSeenClients: true })));
  assert.strictEqual(out, '', 'onboarding must not outlive its usefulness');
});

test('the card is silent when client addresses are not recorded', () => {
  // log_client_ip false is a deliberate privacy choice. Saying "no devices"
  // there would be a statement about the setting, not about the network — and
  // it would never stop being shown.
  const out = withHostname('192.168.1.75', () =>
    firstClientCard(ready({ clientAttribution: false })));
  assert.strictEqual(out, '');
});

test('no branch claims loopback is the DNS address over an SSH tunnel', () => {
  for (const host of ['127.0.0.1', 'localhost']) {
    for (const state of [{}, { servesOnlyLoopback: true }]) {
      const out = withHostname(host, () => firstClientCard(ready(state)));

      assert.doesNotMatch(out, /example\.com 127\.0\.0\.1/,
        'handing a client 127.0.0.1 as its DNS server would be actively wrong');
      assert.doesNotMatch(out, /example\.com localhost/);
      assert.match(out, /your-server-ip|LAN address/);
    }
  }
});

test('the card tolerates a missing overview', () => {
  assert.strictEqual(withHostname('192.168.1.75', () => firstClientCard(null)), '');
  assert.strictEqual(withHostname('192.168.1.75', () => firstClientCard(undefined)), '');
});

// The Access column says what the resolver is doing, not what the row says.
// Badging the stored intent made three different situations look identical to
// a working one, and each of them is a client being refused while the
// dashboard says otherwise.

function network(overrides = {}) {
  return {
    name: 'HQ',
    cidrs: ['10.0.10.0/24'],
    enabled: true,
    allowResolver: true,
    coverage: 'full',
    publicCidrs: [],
    ...overrides,
  };
}

test('a permitted network the resolver is enforcing reads as allowed', () => {
  const out = accessBadge(network());
  assert.match(out, /badge ok/);
  assert.match(out, />Allowed</);
});

test('a public range is permitted but flagged', () => {
  const out = accessBadge(network({ cidrs: ['203.0.113.0/24'], publicCidrs: ['203.0.113.0/24'] }));
  assert.match(out, /badge warn/);
  assert.match(out, /Allowed \(public\)/);
});

test('a grant the resolver is not enforcing does not read as allowed', () => {
  // A stored permission whose reload failed, or one only partly covered by
  // the ACL. Either way the database says yes and the resolver does not.
  const out = accessBadge(network({ coverage: 'none' }));
  assert.doesNotMatch(out, /badge ok/);
  assert.match(out, /not in force/);
});

test('permitting a catch-all says it grants nothing, because it does', () => {
  // A network with no ranges contributes none to the ACL, so ticking the box
  // on one permits precisely nothing — and the form invites exactly this by
  // defaulting the box on and offering an empty CIDR list as the catch-all.
  const out = accessBadge(network({ cidrs: [] }));
  assert.doesNotMatch(out, /badge ok/);
  assert.doesNotMatch(out, />Allowed</);
  assert.match(out, /Grants nothing/);
});

test('an unpermitted network covered by a wider range says so', () => {
  const out = accessBadge(network({ allowResolver: false, resolvesVia: '10.0.0.0/8' }));
  assert.match(out, /Via wider range/);
});

test('an unpermitted network nothing covers reads as refused', () => {
  // coverage: 'none' is the whole point of the case. Both of these tests said
  // "nothing covers" and passed a fixture whose coverage is full — so they
  // asserted Refused for a network the ACL admits, and passed only because
  // the badge had exactly that bug. A test can encode the defect it was
  // written to prevent.
  const out = accessBadge(network({ allowResolver: false, coverage: 'none' }));
  assert.match(out, /badge bad/);
  assert.match(out, /Refused/);
});

// The "who may use this resolver" card makes two claims, and both were wrong
// in ways the rest of this branch had already fixed elsewhere.

test('the REFUSED claim is scoped to the transport the ACL governs', () => {
  // Round three fixed exactly this over-claim in the onboarding card and left
  // it standing here: a DoH or DoT client holding a network's token is
  // identified by the token, not by where it connects from, so "everything
  // else is REFUSED" is false for them.
  const out = clientAccessSummary({
    unrestricted: false,
    bootstrapCidrs: ['127.0.0.0/8'],
    effectiveCidrs: ['127.0.0.0/8'],
    dashboardCidrs: [],
  });
  assert.match(out, /ordinary DNS/);
  assert.match(out, /DNS-over-HTTPS and DNS-over-TLS/);
  assert.match(out, /rotate its token/);
});

test('a dashboard range that configuration also lists is still shown as permitted here', () => {
  // Subtracting bootstrap from effective loses it, and the operator who has
  // just ticked that network sees an empty column and concludes it did not
  // take. The server sends the grants, so the two lists can overlap.
  const out = clientAccessSummary({
    unrestricted: false,
    bootstrapCidrs: ['10.0.0.0/8'],
    effectiveCidrs: ['10.0.0.0/8'],
    dashboardCidrs: ['10.0.0.0/8'],
  });
  const fromNetworks = out.split('From the networks below')[1];
  assert.match(fromNetworks, /10\.0\.0\.0\/8/);
});

test('an unrestricted ACL says nothing is refused rather than listing ranges', () => {
  const out = clientAccessSummary({ unrestricted: true, allowPublicResolver: false });
  assert.match(out, /nothing is refused/);
});

// The seeded Default network is enabled, has no ranges and is unpermitted, so
// it is the state every fresh install starts in — and it was badged Refused
// while the configured ACL was serving its clients perfectly well. That is the
// dashboard misdiagnosing a working deployment, which is the failure this
// whole branch exists to end.
test('an unpermitted catch-all does not claim its clients are refused', () => {
  const out = accessBadge(network({ cidrs: [], allowResolver: false }));
  assert.doesNotMatch(out, /badge bad/);
  assert.doesNotMatch(out, /Refused/);
  assert.match(out, /Depends on the client/);
});

// A network with ranges, unpermitted and covered by nothing, genuinely is.
test('an unpermitted network with ranges nothing covers still reads as refused', () => {
  const out = accessBadge(network({ allowResolver: false, coverage: 'none' }));
  assert.match(out, /badge bad/);
  assert.match(out, /Refused/);
});

// Disabling a network stops it granting anything and stops its policy applying.
// It does not create a deny rule, so its addresses may still be served — and
// saying Refused there is the dashboard telling an operator a working range is
// being turned away.
test('a disabled network whose addresses are still served says so', () => {
  const out = accessBadge(network({ enabled: false, allowResolver: false, coverage: 'full' }));
  assert.doesNotMatch(out, /badge bad/);
  assert.match(out, /Disabled, still served/);
});

test('a disabled network nothing covers reads as plainly disabled', () => {
  const out = accessBadge(network({ enabled: false, allowResolver: false, coverage: 'none' }));
  assert.match(out, /Disabled/);
  assert.doesNotMatch(out, /still served/);
});

// Partial coverage is its own answer. A 10.0.0.0/8 network against a permitted
// 10.0.0.0/16 has 65k addresses served and the rest refused; calling the whole
// thing Refused hides a working half.
test('a partly covered network is not badged as wholly refused', () => {
  const out = accessBadge(network({ allowResolver: false, coverage: 'partial' }));
  assert.doesNotMatch(out, /badge bad/);
  assert.match(out, /Partly refused/);
});

// The Setup page's whole job is "point your network here". Following it while
// the client ACL does not cover that network gives every device REFUSED — the
// failure this branch exists to end, at the moment the operator acts on it.

test('the setup page names the ranges that may actually query', () => {
  const out = resolverAccessNote({
    unrestricted: false,
    effectiveCidrs: ['10.0.0.0/8', '192.168.0.0/16'],
  });
  assert.match(out, /10\.0\.0\.0\/8/);
  assert.match(out, /192\.168\.0\.0\/16/);
  assert.match(out, /REFUSED/);
  assert.match(out, /Allow this network to use DNS Daddy/);
});

test('the setup page keeps the token exception with the claim it qualifies', () => {
  // The DoH URLs are on the same page, and they are not governed by the ACL.
  const out = resolverAccessNote({ unrestricted: false, effectiveCidrs: ['10.0.0.0/8'] });
  assert.match(out, /DNS-over-HTTPS/);
});

test('an unrestricted ACL says so rather than listing nothing', () => {
  const out = resolverAccessNote({ unrestricted: true });
  assert.match(out, /Every address may query/);
  assert.doesNotMatch(out, /REFUSED/);
});

// The warning lede used to say "DNS Daddy is serving clients". Round 10 made a
// stale client ACL a WARN rather than a FAIL — it means the resolver could not
// re-read its configuration, so what it is enforcing is unconfirmed — and the
// banner then asserted the one thing that had not been established, on the
// strength of there being no FAIL. Downgrading a status without checking what
// consumes it moved the false claim rather than removing it.
test('the warning banner does not assert that clients are being served', () => {
  const out = diagnosticsBanner({
    checks: [
      {
        status: 'warn',
        summary:
          'DNS Daddy could not re-read its configuration after a change, so it cannot ' +
          'confirm that the rules below are the ones being enforced.',
      },
    ],
  });
  assert.match(out, /CONFIGURATION WARNING/);
  assert.doesNotMatch(out, /serving clients/);
  assert.match(out, /could not confirm/);
});

test('the failure banner still says clients are being stopped', () => {
  const out = diagnosticsBanner({
    checks: [{ status: 'fail', summary: 'Queries from network "HQ" are REFUSED.' }],
  });
  assert.match(out, /CONFIGURATION PROBLEM/);
  assert.match(out, /stops clients using it/);
});

// A disabled catch-all has no ranges, so the server's vacuous "full" says
// nothing about it. The badge announced its clients were still being served.
test('a disabled catch-all does not claim its clients are still served', () => {
  const out = accessBadge(network({ enabled: false, cidrs: [], allowResolver: false, coverage: 'full' }));
  assert.doesNotMatch(out, /still served/);
  assert.match(out, /Disabled/);
});

// A disabled network with some of its addresses still permitted is neither
// "still served" nor plainly disabled.
test('a disabled network partly still served says which', () => {
  const out = accessBadge(network({ enabled: false, allowResolver: false, coverage: 'partial' }));
  assert.match(out, /Disabled, partly served/);
});

// With no client ACL configured — a loopback-only deployment, which is what
// DNS Daddy starts as — nothing is refused, but Compute has no grants so
// Shadowed is empty and no row gets a resolvesVia. Every unpermitted network
// fell through to Refused on an install that refuses nobody.
test('an unpermitted network is not badged refused when nothing is refused', () => {
  const out = accessBadge(network({ allowResolver: false, coverage: 'full', resolvesVia: '' }));
  assert.doesNotMatch(out, /badge bad/);
  assert.doesNotMatch(out, /Refused/);
  assert.match(out, /Served, not by this row/);
});

// And where the covering range is known, it is still named — the more useful
// answer, so it has to keep winning.
test('a named covering range still outranks the generic served state', () => {
  const out = accessBadge(network({
    allowResolver: false, coverage: 'full', resolvesVia: '10.0.0.0/8 (dns.allowed_client_cidrs)',
  }));
  assert.match(out, /Via wider range/);
  assert.match(out, /10\.0\.0\.0\/8/);
});

// --- Empty states ---------------------------------------------------------
//
// A fresh install is almost entirely empty states, so they are the product's
// first impression. These pin the two things that make one read as intentional
// rather than broken: it explains what happens next, and it survives being
// called the old two-argument way from the pages that have not been updated.

test('an empty state carries an icon, a title and an explanation', () => {
  const out = emptyState('No queries yet', 'Point a client at this resolver and they appear here.');
  assert.match(out, /empty-ico/);
  assert.match(out, /No queries yet/);
  assert.match(out, /Point a client at this resolver/);
});

test('an empty state renders an action when one is given', () => {
  const out = emptyState('No networks', 'Add one to get started.', {
    action: '<a class="btn btn-primary" href="#/networks">Add a network</a>',
  });
  assert.match(out, /btn-primary/);
  assert.match(out, /Add a network/);
});

test('an empty state without an action renders no empty button row', () => {
  const out = emptyState('Nothing blocked', 'That is the expected state on a quiet network.');
  assert.doesNotMatch(out, /class="row"/);
});

// The title and body are escaped like everything else: an empty state can end
// up carrying a feed name or a hostname that came from configuration.
test('an empty state escapes what it is given', () => {
  const out = emptyState('<script>x</script>', 'body & more');
  assert.doesNotMatch(out, /<script>/);
  assert.match(out, /&amp;/);
});

/* ==========================================================================
 * Dashboard V2
 *
 * The redesign moved every link in the sidebar and replaced the whole of the
 * dashboard's markup. The tests below pin the two things that survive a
 * redesign unchanged — that every route in the shell is reachable, and that no
 * panel claims something the server did not measure — plus the escaping, which
 * a rewrite is exactly the moment to lose.
 * ======================================================================== */

const fs = require('node:fs');
const path = require('node:path');

const indexHtml = fs.readFileSync(path.join(__dirname, 'static', 'index.html'), 'utf8');

/* ---------- the shell and its routes ------------------------------------- */

test('every route the sidebar links to is a page the router will serve', () => {
  const routes = [...indexHtml.matchAll(/data-route="([a-z-]+)"/g)].map((m) => m[1]);
  assert.ok(routes.length >= 11, `expected the full navigation, got ${routes.length}`);
  for (const r of routes) {
    assert.ok(pages[r], `#/${r} is in the sidebar but has no page`);
    assert.equal(routeName(`#/${r}`), r, `#/${r} does not route to itself`);
  }
});

test('the Assurance page is reachable', () => {
  // Called out because it is the one page with no inbound link from anywhere
  // but the sidebar: if the redesign dropped it, nothing else would notice.
  assert.ok(indexHtml.includes('href="#/assurance"'), 'Assurance is missing from the navigation');
  assert.ok(pages.assurance, 'Assurance has no page');
  assert.equal(routeName('#/assurance'), 'assurance');
});

test('an unknown or empty hash falls back to the dashboard', () => {
  assert.equal(routeName(''), 'dashboard');
  assert.equal(routeName('#/'), 'dashboard');
  assert.equal(routeName('#/nonexistent'), 'dashboard');
  assert.equal(routeName('#/queries?domain=x'), 'queries');
});

test('every navigation icon resolves to a symbol defined in the sprite', () => {
  const defined = new Set([...indexHtml.matchAll(/<g id="(i-[a-z]+)"/g)].map((m) => m[1]));
  const used = [...indexHtml.matchAll(/<use href="#(i-[a-z]+)"/g)].map((m) => m[1]);
  assert.ok(used.length >= 13, `expected every nav item to carry an icon, got ${used.length}`);
  for (const id of used) {
    assert.ok(defined.has(id), `${id} is used but never defined`);
  }
});

test('the navigation is grouped with real headings a screen reader can use', () => {
  // Five labelled groups, each a heading with a list that points back at it.
  // The old markup hid the group labels with aria-hidden, which left twelve
  // undifferentiated links for anyone not looking at them.
  const headings = [...indexHtml.matchAll(/<h2 class="nav-group" id="([a-z-]+)">/g)].map((m) => m[1]);
  const labelled = [...indexHtml.matchAll(/<ul class="nav-list" aria-labelledby="([a-z-]+)">/g)].map((m) => m[1]);
  assert.equal(headings.length, 5);
  assert.deepEqual(labelled, headings, 'every nav list must be labelled by its own heading');
  assert.doesNotMatch(indexHtml, /nav-group" aria-hidden/);
});

test('the navigation uses inline SVG rather than the old Unicode glyphs', () => {
  const navBlock = indexHtml.slice(indexHtml.indexOf('<nav class="nav"'), indexHtml.indexOf('</nav>'));
  assert.match(navBlock, /class="nav-ico"/);
  // The redesign's stated aim. A stray emoji or box-drawing glyph in the nav
  // means a link was added without one.
  assert.doesNotMatch(navBlock, /[←-⯿️\u{1F300}-\u{1FAFF}]/u);
});

/* ---------- the status hero ---------------------------------------------- */

function overview(o = {}) {
  return {
    protectionStatus: 'protected',
    resolverStatus: 'operational',
    queries24h: 128491,
    threatsBlocked24h: 327,
    blockRate24h: 0.25,
    protectedNetworks: 2,
    activePolicies: 1,
    blocklistDomains: 412345,
    lastFeedRefresh: now(),
    uptimeSeconds: 90061,
    version: '0.1.0',
    hasSeenClients: true,
    clientAttribution: true,
    servesOnlyLoopback: false,
    refusedClients: 0,
    ...o,
  };
}

const healthyFeeds = {
  observatoryFeedId: OBSERVATORY_ID,
  totalIndexedDomains: 412345,
  refreshing: false,
  feeds: [{ ...feed({ enabled: true, loaded: true, lastSuccessAt: now(), indexedDomains: 412345 }), id: 'urlhaus', name: 'abuse.ch URLhaus' }],
};

test('the three protection states are worded distinctly and none says the process is down', () => {
  const p = protectionState('protected');
  const d = protectionState('degraded');
  const o = protectionState('offline');
  assert.equal(p.tone, 'ok');
  assert.equal(d.tone, 'warn');
  assert.equal(o.tone, 'bad');
  assert.notEqual(p.word, d.word);
  assert.notEqual(d.word, o.word);
  // `offline` means the blocklist is empty, not that the resolver stopped.
  // Saying "offline" about a resolver answering every query sends an operator
  // after the wrong fault.
  assert.doesNotMatch(o.word, /offline/i);
  assert.match(o.line, /no threat intelligence is loaded/i);
});

test('an unrecognised protection status is reported, not silently called healthy', () => {
  const s = protectionState('something-new');
  assert.notEqual(s.tone, 'ok');
  assert.match(s.word, /something-new/);
});

test('the hero states its status in words as well as colour', () => {
  const out = statusHero(overview(), healthyFeeds, { enabled: true, total: 6 });
  assert.match(out, />Protected</);
  assert.match(out, /class="hero is-ok"/);
  // The dot is decorative; removing every class attribute must still leave the
  // status legible.
  assert.match(out.replace(/class="[^"]*"/g, ''), /Protected/);
});

test('the hero reports the numbers the server gave it and invents none', () => {
  const out = statusHero(overview(), healthyFeeds, { enabled: true, total: 6 });
  assert.match(out, /128,491/);
  assert.match(out, /327/);
  assert.match(out, /0\.25%/);
  assert.match(out, />6</);
  assert.match(out, /Last 24 hours/);
});

test('a fresh install with no traffic shows zeroes, not sample data', () => {
  const out = statusHero(
    overview({ queries24h: 0, threatsBlocked24h: 0, blockRate24h: 0, hasSeenClients: false }),
    healthyFeeds,
    { enabled: true, total: 0 }
  );
  assert.match(out, />0</);
  assert.doesNotMatch(out, /128,491/);
});

test('detection switched off reads as off, never as zero detections', () => {
  // A zero would say "nothing suspicious happened". Nobody measured that.
  const out = statusHero(overview(), healthyFeeds, { enabled: false, total: 0 });
  assert.match(out, /Off<\/span><span class="k">Detections/);
  assert.doesNotMatch(out, />0<\/span><span class="k">Detections/);
});

test('a real detection count is rendered as a count', () => {
  const out = statusHero(overview(), healthyFeeds, { enabled: true, total: 6 });
  assert.match(out, /is-detect"><span class="n">6</);
});

test('a detections request that failed does not become a zero either', () => {
  // A zero here would say "nothing suspicious happened in 24 hours". Nothing
  // measured that; the request did not come back.
  const out = statusHero(overview(), healthyFeeds, null);
  assert.match(out, /—<\/span><span class="k">Detections/);
  assert.doesNotMatch(out, />0<\/span><span class="k">Detections/);
});

test('feed health in the hero is stated separately from protection status', () => {
  const stale = {
    ...healthyFeeds,
    feeds: [{ ...healthyFeeds.feeds[0], lastError: 'HTTP 500' }],
  };
  const out = statusHero(overview(), stale, { enabled: true, total: 0 });
  // Protection is still what the server said it was...
  assert.match(out, /class="hero is-ok"/);
  assert.match(out, />Protected</);
  // ...and the feed problem is stated in its own badge rather than folded into
  // the headline, which would produce an amber dot over the word "Protected".
  assert.match(out, /1 of 1 feeds stale/);
});

/* ---------- feed health grading ------------------------------------------ */

test('a switched-off feed is a decision, not a fault', () => {
  const h = feedHealth({ feeds: [feed({ enabled: false }), healthyFeeds.feeds[0]] });
  assert.equal(h.tone, 'ok');
  assert.equal(h.enabled.length, 1);
  assert.equal(h.label, 'Threat intelligence healthy');
});

test('an enabled feed that is not in the index is a fault, whatever its history says', () => {
  const h = feedHealth({ feeds: [feed({ enabled: true, loaded: false, lastSuccessAt: hoursAgo(2) })] });
  assert.equal(h.tone, 'bad');
  assert.equal(h.broken.length, 1);
});

test('a loaded feed whose refresh failed is stale, not broken', () => {
  const h = feedHealth({ feeds: [feed({ enabled: true, loaded: true, lastSuccessAt: hoursAgo(4), lastError: 'HTTP 500' })] });
  assert.equal(h.tone, 'warn');
  assert.equal(h.stale.length, 1);
  assert.equal(h.broken.length, 0);
});

test('no enabled feed at all is a fault, not a healthy empty list', () => {
  const h = feedHealth({ feeds: [feed({ enabled: false })] });
  assert.equal(h.tone, 'bad');
});

/* ---------- needs attention ---------------------------------------------- */

test('a calm install shows an explicit healthy state rather than an absent panel', () => {
  const items = attentionItems({ checks: [{ status: 'ok', name: 'DNS', summary: 'fine' }] }, healthyFeeds);
  assert.equal(items.length, 0);
  const out = attentionPanel(items);
  assert.match(out, /Nothing needs your attention/);
  assert.match(out, /Needs attention/);
});

test('diagnostics that could not be fetched is itself an item, never silence', () => {
  // The worst thing this panel could do is report "nothing needs attention" on
  // the strength of checks it never received.
  const items = attentionItems(null, healthyFeeds);
  assert.equal(items.length, 1);
  assert.equal(items[0].tone, 'warn');
  assert.match(items[0].title, /Configuration checks unavailable/);
  assert.doesNotMatch(attentionPanel(items), /Nothing needs your attention/);
});

test('server-side diagnostics stay authoritative and are passed through verbatim', () => {
  const items = attentionItems(
    {
      checks: [
        { status: 'fail', section: 'Resolver', name: 'Client access', summary: 'Queries from "Home" are REFUSED.', action: 'Permit it on the Networks page.' },
        { status: 'warn', section: 'Feeds', name: 'Refresh age', summary: 'Last refresh was 9 days ago.' },
        { status: 'ok', section: 'Listeners', name: 'Port 53', summary: 'Bound.' },
      ],
    },
    healthyFeeds
  );
  assert.equal(items.length, 2);
  assert.equal(items[0].tone, 'bad');
  assert.equal(items[0].title, 'Client access');
  assert.match(items[0].body, /Queries from "Home" are REFUSED\./);
  assert.match(items[0].body, /Permit it on the Networks page\./);
  assert.equal(items[1].tone, 'warn');
});

test('feed faults reach the attention panel with the reason the server gave', () => {
  const items = attentionItems({ checks: [] }, {
    feeds: [
      { ...feed({ enabled: true, loaded: false, lastSuccessAt: hoursAgo(3), loadError: 'its cached copy is missing' }), name: 'URLhaus' },
      { ...feed({ enabled: true, loaded: true, lastSuccessAt: hoursAgo(3), lastError: 'HTTP 500' }), name: 'StevenBlack' },
    ],
  });
  const titles = items.map((i) => i.title);
  assert.ok(titles.includes('URLhaus is not blocking'), titles.join(' / '));
  assert.ok(titles.includes('StevenBlack is stale'), titles.join(' / '));
  assert.match(items.find((i) => i.title.startsWith('URLhaus')).body, /its cached copy is missing/);
  assert.match(items.find((i) => i.title.startsWith('StevenBlack')).body, /HTTP 500/);
});

test('an install with every feed switched off is told so', () => {
  const items = attentionItems({ checks: [] }, { feeds: [feed({ enabled: false })] });
  assert.equal(items.length, 1);
  assert.equal(items[0].tone, 'bad');
  assert.match(items[0].title, /No threat intelligence is enabled/);
});

test('the attention panel labels severity in words, not only in colour', () => {
  const out = attentionPanel([
    { tone: 'bad', title: 'A', body: 'b' },
    { tone: 'warn', title: 'C', body: 'd' },
  ]);
  assert.match(out, />Fault</);
  assert.match(out, />Warning</);
});

test('attention items escape everything the server put in them', () => {
  const out = attentionPanel(
    attentionItems({ checks: [{ status: 'fail', name: '<img src=x onerror="alert(1)">', summary: '<script>alert(2)</script>' }] }, healthyFeeds)
  );
  assert.doesNotMatch(out, /<img/);
  assert.doesNotMatch(out, /<script>alert/);
  assert.match(out, /&lt;img/);
  assert.doesNotMatch(out, /&amp;lt;/);
});

/* ---------- recently blocked --------------------------------------------- */

function blocked(o = {}) {
  return {
    time: now(),
    domain: 'malware.example',
    qtype: 'A',
    action: 'blocked',
    reason: 'Domain is on a malware distribution list',
    category: 'malware',
    source: 'abuse.ch URLhaus',
    clientIp: '10.0.0.4',
    ...o,
  };
}

test('blocked domains are rendered in monospace so a typosquat is visible as one', () => {
  const out = recentlyBlocked([blocked({ domain: 'paypaI-login.example' })]);
  assert.match(out, /class="dom-name">paypaI-login\.example</);
});

test('a blocked row invents no enrichment it was not given', () => {
  const bare = recentlyBlocked([blocked({ category: '', clientIp: '', clientName: '' })]);
  assert.match(bare, /malware\.example/);
  // No category recorded means no category shown — not a guess at one.
  assert.doesNotMatch(bare, /class="badge/);

  const full = recentlyBlocked([blocked()]);
  assert.match(full, />malware</);
  assert.match(full, /10\.0\.0\.4/);
});

test('an empty query log says which of the two reasons it might be', () => {
  const out = recentlyBlocked([]);
  assert.match(out, /query log is switched off/i);
  assert.doesNotMatch(out, /example\.com|malware\.example/);
});

test('a hostile domain in the log is escaped, not rendered', () => {
  const out = recentlyBlocked([blocked({ domain: '<img src=x onerror="alert(1)">.example', category: '<b>x</b>' })]);
  assert.doesNotMatch(out, /<img/);
  assert.doesNotMatch(out, /<b>x<\/b>/);
  assert.match(out, /&lt;img/);
  assert.doesNotMatch(out, /&amp;lt;/);
});

/* ---------- protection breakdown ----------------------------------------- */

test('the breakdown states counts and shares, not a bar on its own', () => {
  const out = protectionBreakdown([
    { label: 'Malware', count: 60, category: 'malware' },
    { label: 'Phishing', count: 40, category: 'phishing' },
  ]);
  assert.match(out, /Malware/);
  assert.match(out, /60 · 60%/);
  assert.match(out, /40 · 40%/);
  assert.match(out, /class="cat-meter"/);
});

test('no blocks in the period is an explained empty state, not a zeroed chart', () => {
  const out = protectionBreakdown([]);
  assert.match(out, /No blocks in this period/);
  assert.doesNotMatch(out, /cat-meter/);
});

test('a category label from the server is escaped', () => {
  const out = protectionBreakdown([{ label: '<script>alert(1)</script>', count: 1, category: 'malware' }]);
  assert.doesNotMatch(out, /<script>alert/);
  assert.match(out, /&lt;script&gt;/);
});

/* ==========================================================================
 * Query log and threat presentation
 *
 * The query log was seven equal columns; it is now one scannable line per
 * event with the detail behind a disclosure. The tests that matter are the
 * ones a markup change can quietly break: escaping of values an attacker
 * chooses, and the rule that nothing is displayed that the server did not
 * record.
 * ======================================================================== */

const { queryTable, queryRow, repeatOffenders } = require('./static/app.js');

function q(o = {}) {
  return {
    time: now(),
    domain: 'malware.example',
    qtype: 'A',
    action: 'blocked',
    reason: 'Domain is on a malware distribution list',
    category: 'malware',
    source: 'abuse.ch URLhaus',
    clientIp: '10.0.0.4',
    clientName: '',
    cached: false,
    elapsedMs: 3,
    dnssec: 'unvalidated',
    ...o,
  };
}

test('a query row states its outcome in words, not only as a colour', () => {
  assert.match(queryRow(q({ action: 'blocked' })), />Blocked</);
  assert.match(queryRow(q({ action: 'allowed' })), />Allowed</);
  assert.match(queryRow(q({ action: 'error' })), />Error</);

  // Strip every class attribute — the accent rail and the row tint both live
  // there — and the outcome must still be readable.
  const bare = queryRow(q({ action: 'blocked' })).replace(/class="[^"]*"/g, '');
  assert.match(bare, /Blocked/);
});

test('the detail lists only what the server actually recorded', () => {
  const sparse = queryRow(q({
    reason: '', category: '', source: '', clientIp: '', clientName: '',
    dnssec: '', elapsedMs: undefined,
  }));
  // No empty rows reading "—": an absent fact is an accurate statement that
  // nothing was recorded, and a dash is an invitation to wonder.
  assert.doesNotMatch(sparse, /<dt>Reason<\/dt>/);
  assert.doesNotMatch(sparse, /<dt>Category<\/dt>/);
  assert.doesNotMatch(sparse, /<dt>Source<\/dt>/);
  assert.doesNotMatch(sparse, /<dt>DNSSEC<\/dt>/);

  const full = queryRow(q());
  assert.match(full, /<dt>Reason<\/dt>/);
  assert.match(full, /Domain is on a malware distribution list/);
  assert.match(full, /abuse\.ch URLhaus/);
});

test('a badge in the detail is rendered, not stringified', () => {
  // Collecting already-escaped markup and then calling String() on a raw()
  // marker produced "[object Object]" on the page. This is that bug.
  const out = queryRow(q());
  assert.doesNotMatch(out, /\[object Object\]/);
  assert.match(out, /<dt>Category<\/dt>[\s\S]*?malware/);
});

test('the domain is monospace and the row is keyboard reachable', () => {
  const out = queryRow(q({ domain: 'paypaI-secure.example' }));
  assert.match(out, /class="qdomain mono">paypaI-secure\.example</);
  // <details>/<summary> rather than a click handler, so focus, Enter and
  // find-in-page all work without reimplementing them.
  assert.match(out, /<details class="qrow/);
  assert.match(out, /<summary>/);
});

test('every field a hostile server or client could influence is escaped', () => {
  const out = queryRow(q({
    domain: '<img src=x onerror="alert(1)">.example',
    reason: '<script>alert(2)</script>',
    source: '<b>feed</b>',
    clientName: '<svg onload="alert(3)">',
    qtype: '<i>A</i>',
  }));
  assert.doesNotMatch(out, /<img/);
  assert.doesNotMatch(out, /<script>alert/);
  assert.doesNotMatch(out, /<svg onload/);
  assert.doesNotMatch(out, /<b>feed<\/b>/);
  assert.match(out, /&lt;img/);
  // Escaped exactly once — a double-escaped domain is unreadable.
  assert.doesNotMatch(out, /&amp;lt;/);
});

test('an empty query log explains both reasons it could be empty', () => {
  const out = queryTable([]);
  assert.match(out, /query log is switched off/i);
  assert.doesNotMatch(out, /example\.com|malware\.example/);
});

test('repeat offenders describe recurrence rather than printing a count column', () => {
  const out = repeatOffenders([
    { domain: 'a.example', category: 'malware', count: 47, lastSeen: hoursAgo(1) },
    { domain: 'b.example', category: 'phishing', count: 1, lastSeen: hoursAgo(3) },
  ]);
  assert.match(out, /blocked 47 times/);
  // One block is a page that loaded a bad ad; saying "blocked 1 times" would
  // be both wrong and louder than the fact deserves.
  assert.match(out, /blocked once/);
  assert.doesNotMatch(out, /blocked 1 times/);
  assert.match(out, /last 1h ago/);
});

test('repeat offenders escape the domain and the category', () => {
  const out = repeatOffenders([
    { domain: '<img src=x onerror="alert(1)">', category: '<b>x</b>', count: 2, lastSeen: now() },
  ]);
  assert.doesNotMatch(out, /<img/);
  assert.doesNotMatch(out, /<b>x<\/b>/);
  assert.match(out, /&lt;img/);
  assert.doesNotMatch(out, /&amp;lt;/);
});

test('no offenders is an explained empty state', () => {
  const out = repeatOffenders([]);
  assert.match(out, /Nothing has been blocked yet/);
  assert.doesNotMatch(out, /offender-meter/);
});

/* ---------- the login page ----------------------------------------------- */

test('the sign-in page reports no system state', () => {
  const block = indexHtml.slice(indexHtml.indexOf('<div id="login"'), indexHtml.indexOf('<div id="app"'));
  // Comments removed: they are delivered to the browser, but a comment
  // explaining that this page discloses nothing is not itself a disclosure,
  // and matching on it made this test fail on its own rationale.
  const login = block.replace(/<!--[\s\S]*?-->/g, '');

  // The page is reachable from the internet in the HTTPS deployment. It must
  // not say what version this is, how long it has been up, whether a blocklist
  // is loaded, or whether a password has been configured.
  for (const leak of [/version/i, /uptime/i, /blocklist/i, /degraded/i]) {
    assert.doesNotMatch(login, leak, `the login page discloses ${leak}`);
  }
  // And nothing writes into it at runtime either: every id the login markup
  // carries is one the login form itself owns.
  for (const id of ['sidebar-version', 'sidebar-status-text', 'page-title', 'refresh-note']) {
    assert.ok(!login.includes(`id="${id}"`), `the login page carries ${id}, which shows system state`);
  }
  // The password field is a password field, and the browser is told what it is.
  assert.match(login, /type="password"/);
  assert.match(login, /autocomplete="current-password"/);
  assert.match(login, /<label for="password">/);
  // The decorative panel is hidden from assistive technology.
  assert.match(login, /class="login-aside" aria-hidden="true"/);
});

/* ---------- one product, not several generations of one ------------------- */

test('every page title matches the navigation label that leads to it', () => {
  // "Threat feeds" in the header under a "Threat intelligence" nav link made
  // the page look like it belonged to a different product than the link.
  const nav = {};
  for (const m of indexHtml.matchAll(/data-route="([a-z-]+)"[\s\S]*?<span>([^<]+)<\/span>/g)) {
    nav[m[1]] = m[2];
  }
  const src = require('node:fs').readFileSync(
    require('node:path').join(__dirname, 'static', 'app.js'), 'utf8');

  let checked = 0;
  for (const m of src.matchAll(/pages\.([a-z]+) = \{\s*(?:\/\/[^\n]*\n\s*)*title: '([^']+)'/g)) {
    const [, route, title] = m;
    if (!nav[route]) continue;
    checked++;
    assert.equal(title, nav[route],
      `#/${route}: the page header says ${JSON.stringify(title)} but the nav link says ${JSON.stringify(nav[route])}`);
  }
  assert.ok(checked >= 10, `only matched ${checked} pages; the parse is probably wrong`);
});

test('the configuration pages use the shared record row, not their own tables', () => {
  // Networks, feeds and policies were each a bespoke multi-column table. A
  // reader met three different list designs in one product. They now share
  // .rec (and policies the same <details> disclosure as the query log), so
  // there is one list idiom to learn.
  const src = require('node:fs').readFileSync(
    require('node:path').join(__dirname, 'static', 'app.js'), 'utf8');

  const page = (name) => {
    const from = src.indexOf(`pages.${name} = {`);
    const to = src.indexOf('\npages.', from + 1);
    return src.slice(from, to === -1 ? undefined : to);
  };

  for (const name of ['networks', 'feeds']) {
    const body = page(name);
    assert.ok(body.includes('class="rec"'),
      `pages.${name} does not use the shared record row`);
    assert.ok(!body.includes('<thead>'),
      `pages.${name} still renders a bespoke table`);
  }
  assert.ok(page('policies').includes('<details class="card section policy"'),
    'pages.policies no longer collapses each policy');
});

test('no stylesheet rule falls back to a colour literal for a token that does not exist', () => {
  // var(--muted, #a3acba) looked like a themed value and was not: --muted was
  // never defined, so three rules silently used the literal and drifted from
  // --muted-foreground when the palette changed.
  const css = require('node:fs').readFileSync(
    require('node:path').join(__dirname, 'static', 'app.css'), 'utf8');

  const defined = new Set([...css.matchAll(/^\s*(--[a-z0-9-]+):/gm)].map((m) => m[1]));
  for (const m of css.matchAll(/var\((--[a-z0-9-]+),\s*(#[0-9a-fA-F]{3,8}|[a-z]+)\)/g)) {
    assert.ok(defined.has(m[1]),
      `var(${m[1]}, ${m[2]}) falls back to a literal because ${m[1]} is never defined`);
  }
});

test('a feed that has never attempted a download is pending, not a fault', () => {
  // The dashboard opened on a fresh install with six red "is not blocking"
  // faults, beside a panel calling the same six feeds "Pending". Two verdicts
  // on the same state, on the same page. A feed that has not run yet is not
  // broken — that is over-claiming, just pointing the other way.
  const neverRan = {
    feeds: [
      { ...feed({ enabled: true, loaded: false, lastError: '', lastSuccessAt: null }), id: 'a', name: 'A' },
      { ...feed({ enabled: true, loaded: false, lastError: '', lastSuccessAt: null }), id: 'b', name: 'B' },
    ],
  };

  const h = feedHealth(neverRan);
  assert.equal(h.broken.length, 0, 'a feed that never ran was counted as broken');
  assert.equal(h.pending.length, 2);
  assert.equal(h.tone, 'warn', 'never-run feeds should warn, not fault');
  assert.match(h.label, /downloading/);

  // And the two components agree, which is the actual requirement.
  for (const f of neverRan.feeds) {
    assert.match(feedStatusBadge(f), />Pending</);
  }

  const items = attentionItems({ checks: [] }, neverRan);
  assert.equal(items.length, 1, 'one item, not one per feed');
  assert.equal(items[0].tone, 'warn');
  assert.match(items[0].title, /has not downloaded yet/);
  assert.doesNotMatch(items[0].title, /is not blocking/);
});

test('a feed that attempted and failed is still a fault', () => {
  // The distinction has to cut both ways, or it is just a downgrade.
  const failed = {
    feeds: [{ ...feed({ enabled: true, loaded: false, lastError: 'HTTP 404' }), name: 'Broken' }],
  };
  const h = feedHealth(failed);
  assert.equal(h.tone, 'bad');
  assert.equal(h.broken.length, 1);
  assert.equal(h.pending.length, 0);

  const items = attentionItems({ checks: [] }, failed);
  assert.equal(items[0].tone, 'bad');
  assert.match(items[0].title, /Broken is not blocking/);
  assert.match(items[0].body, /HTTP 404/);
});

test('a feed that downloaded once and is not in the index is a fault', () => {
  const unusable = {
    feeds: [{ ...feed({ enabled: true, loaded: false, lastSuccessAt: hoursAgo(3), loadError: 'cache missing' }), name: 'Gone' }],
  };
  const h = feedHealth(unusable);
  assert.equal(h.tone, 'bad');
  assert.equal(h.broken.length, 1);
  assert.equal(h.pending.length, 0);
});
