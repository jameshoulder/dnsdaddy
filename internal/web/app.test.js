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
  observatoryState,
  observatoryErrorSummary,
  observatoryEnforcement,
  observatoryCard,
  feedStatusBadge,
  threatIntelPanel,
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
  const f = feed({ enabled: true, lastRefreshedAt: now(), lastSuccessAt: now(), indexedDomains: 34821 });
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
    feed({ enabled: true, lastRefreshedAt: now(), lastSuccessAt: now(), indexedDomains: 34821 }),
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
  assert.match(feedStatusBadge(feed({ enabled: true, lastSuccessAt: now() })), />Active</);
  assert.match(
    feedStatusBadge(feed({ enabled: true, lastSuccessAt: hoursAgo(2), lastError: 'HTTP 500' })),
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
      { ...feed({ enabled: true, lastSuccessAt: now() }), id: 'urlhaus', name: 'abuse.ch URLhaus' },
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
