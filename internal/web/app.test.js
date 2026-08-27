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
 */

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
  const out = withHostname('192.168.1.75', () =>
    firstClientCard({ clientsSeen24h: 0, clientAttribution: true }));

  assert.match(out, /No devices have used this resolver yet/);
  assert.match(out, /nslookup example\.com 192\.168\.1\.75/,
    'the command must name the address the operator reached the dashboard on');
  assert.match(out, /dnsdaddy doctor/, 'it must say what to do when nothing appears');
});

test('the card disappears as soon as a real client exists', () => {
  const out = withHostname('192.168.1.75', () =>
    firstClientCard({ clientsSeen24h: 1, clientAttribution: true }));
  assert.strictEqual(out, '', 'onboarding must not outlive its usefulness');
});

test('the card is silent when client addresses are not recorded', () => {
  // log_client_ip false is a deliberate privacy choice. Saying "no devices"
  // there would be a statement about the setting, not about the network — and
  // it would never stop being shown.
  const out = withHostname('192.168.1.75', () =>
    firstClientCard({ clientsSeen24h: 0, clientAttribution: false }));
  assert.strictEqual(out, '');
});

test('over an SSH tunnel it does not claim loopback is the DNS address', () => {
  for (const host of ['127.0.0.1', 'localhost']) {
    const out = withHostname(host, () =>
      firstClientCard({ clientsSeen24h: 0, clientAttribution: true }));

    assert.doesNotMatch(out, /nslookup example\.com 127\.0\.0\.1/,
      'handing a client 127.0.0.1 as its DNS server would be actively wrong');
    assert.doesNotMatch(out, /nslookup example\.com localhost/);
    assert.match(out, /your-server-ip|LAN address/);
  }
});

test('the card tolerates a missing overview', () => {
  assert.strictEqual(withHostname('192.168.1.75', () => firstClientCard(null)), '');
  assert.strictEqual(withHostname('192.168.1.75', () => firstClientCard(undefined)), '');
});
