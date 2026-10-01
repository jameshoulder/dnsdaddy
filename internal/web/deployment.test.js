'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { api, ApiError, readDashboardPanel, dashboardReadFailures, serverAddressesCard } = require('./static/app.js');

async function withResponse(response, fn) {
  const before = global.fetch;
  global.fetch = async (url, options) => { assert.equal(options.cache, 'no-store'); return response; };
  try { return await fn(); } finally { global.fetch = before; }
}

test('a proxy HTML success is rejected instead of becoming empty dashboard data', async () => {
  await withResponse(new Response('<html>private proxy error details</html>', { headers: { 'Content-Type': 'text/html' } }), async () => {
    await assert.rejects(api('/overview?domain=private.example'), (error) => {
      assert.ok(error instanceof ApiError); assert.match(error.message, /instead of JSON/); assert.match(error.message, /reverse proxy/);
      assert.doesNotMatch(error.message, /private proxy|private.example/); return true;
    });
  });
});

test('invalid JSON and empty successful bodies cannot impersonate data', async () => {
  for (const body of ['', '{"unfinished":']) await withResponse(new Response(body, { headers: { 'Content-Type': 'application/json' } }), async () => assert.rejects(api('/overview'), /invalid or empty JSON/));
});

test('valid JSON, structured JSON MIME and empty 204 responses keep working', async () => {
  await withResponse(new Response('{"received":2}', { headers: { 'Content-Type': 'application/example+json; charset=utf-8' } }), async () => assert.deepEqual(await api('/activity/live'), { received: 2 }));
  await withResponse(new Response(null, { status: 204 }), async () => assert.equal(await api('/feeds/refresh'), null));
});

test('optional panel failures carry a diagnostic without masquerading as zero', async () => {
  const failures = [];
  assert.equal(await readDashboardPanel('/overview', { read: async () => { throw new ApiError(502, 'Backend unavailable'); }, onError: (path, error) => failures.push({ path, error }) }), null);
  const out = dashboardReadFailures(failures);
  assert.match(out, /Dashboard connection problems/); assert.match(out, /Backend unavailable/); assert.match(out, /not evidence that no DNS queries occurred/);
  assert.match(out, /href="\/api\/v1\/activity\/live"/);
  assert.equal(dashboardReadFailures([]), '');
});

test('diagnostic text is escaped and the endpoint query string is not repeated', () => {
  const out = dashboardReadFailures([{ path: '/overview?domain=private.example', error: new Error('<img src=x>') }]);
  assert.match(out, /&lt;img/); assert.doesNotMatch(out, /<img|private.example/);
});

function addresses(advertised) {
  return { runtime: 'container', source: 'local_interfaces', preferredAddress: '172.23.0.2', addresses: [{ address: '172.23.0.2', family: 'ipv4', type: 'private', interface: 'eth0', dns: [{ transport: 'udp', port: 5353 }] }], listeners: [], advertised };
}

test('a container private IP is not promoted to the client-facing recommendation', () => {
  const out = serverAddressesCard(addresses());
  const featured = out.split('<details')[0];
  assert.match(featured, /internal IP is not the public server IP/); assert.match(featured, /DNSDADDY_ADVERTISED_DNS/);
  assert.doesNotMatch(featured, /172\.23\.0\.2|data-copy=/);
  assert.match(out, /Container-internal IP/);
});

test('configured external addresses and mapped ports remain distinct from internal listeners', () => {
  const out = serverAddressesCard(addresses({ address: '203.0.113.53', port: 53, source: 'configuration', verified: false }));
  const featured = out.split('<details')[0];
  assert.match(featured, /Client-facing DNS address/); assert.match(featured, /data-copy="203.0.113.53"/);
  assert.match(featured, /Port 53/); assert.match(featured, /not a reachability test/); assert.doesNotMatch(featured, /172\.23\.0\.2/);
});
