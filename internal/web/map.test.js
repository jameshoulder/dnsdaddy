'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const {
  esc,
  mapFilters,
  mapHash,
  outcomeTone,
  layoutGraph,
  securityMapPage,
} = (() => {
  // Helpers are exported from map.js; esc comes from app.js in the browser.
  const app = require('./static/app.js');
  const map = require('./static/map.js');
  return { esc: app.esc, ...map };
})();

const fixtureGraph = {
  available: true,
  generatedAt: '2026-11-17T00:00:00.000Z',
  effectiveFrom: '2026-11-16T23:00:00.000Z',
  effectiveTo: '2026-11-17T00:00:00.000Z',
  requestedHours: 1,
  limitations: ['Edges mean DNS queries recorded in the selected window, not visits or connections.'],
  networks: [
    { id: 'net-lan', name: 'LAN', clientsInWindow: 2, queries: 5, blocked: 2, errors: 0, cidrs: ['10.0.0.0/24'] },
    { id: 'net-guest', name: 'Guest', clientsInWindow: 1, queries: 2, blocked: 1, errors: 1, cidrs: ['10.1.0.0/24'] },
  ],
  clients: [
    {
      id: 'client:net-lan/10.0.0.1', clientIp: '10.0.0.1', clientName: 'laptop',
      networkId: 'net-lan', queries: 3, allowed: 1, blocked: 2, errors: 0, distinctDomains: 2,
      firstSeen: '2026-11-16T23:10:00.000Z', lastSeen: '2026-11-16T23:50:00.000Z',
    },
    {
      id: 'client:net-lan/10.0.0.2', clientIp: '10.0.0.2', clientName: 'forwarder',
      networkId: 'net-lan', queries: 2, allowed: 1, blocked: 1, errors: 0, distinctDomains: 2,
    },
    {
      id: 'client:net-guest/10.1.0.5', clientIp: '10.1.0.5', clientName: '<img src=x onerror=alert(1)>',
      networkId: 'net-guest', queries: 2, allowed: 0, blocked: 1, errors: 1, distinctDomains: 2,
    },
  ],
  domains: [
    { id: 'domain:evil.example', domain: 'evil.example', queries: 3, allowed: 1, blocked: 2, errors: 0, distinctClients: 3, category: 'malware' },
    { id: 'domain:news.example', domain: 'news.example', queries: 1, allowed: 1, blocked: 0, errors: 0, distinctClients: 1 },
    { id: 'domain:"><svg/onload=alert(1)>.example', domain: '"><svg/onload=alert(1)>.example', queries: 1, allowed: 1, blocked: 0, errors: 0, distinctClients: 1 },
  ],
  edges: [
    {
      id: 'edge:1', type: 'queried', clientId: 'client:net-lan/10.0.0.1', domainId: 'domain:evil.example',
      queries: 2, allowed: 0, blocked: 2, errors: 0,
    },
    {
      id: 'edge:2', type: 'queried', clientId: 'client:net-lan/10.0.0.1', domainId: 'domain:news.example',
      queries: 1, allowed: 1, blocked: 0, errors: 0,
    },
    {
      id: 'edge:3', type: 'queried', clientId: 'client:net-guest/10.1.0.5',
      domainId: 'domain:"><svg/onload=alert(1)>.example',
      queries: 1, allowed: 1, blocked: 0, errors: 0,
    },
  ],
  findings: [
    {
      id: 'f1', clientId: 'client:net-lan/10.0.0.1', domainId: 'domain:evil.example',
      title: 'Suspicious volume', severity: 'medium', eventType: 'dns.tunnel.suspected', maturity: 'experimental',
    },
  ],
  limits: { truncatedClients: false, truncatedDomains: false, truncatedEdges: false, truncatedSource: false },
  resolverStatus: { note: 'Current runtime context only — not proof of the transport used for every displayed query.', mode: 'off' },
};

test('mapFilters and mapHash round-trip window and focus', () => {
  const hash = mapHash({
    window: '15m', networkId: 'net-lan', action: 'blocked', search: 'evil', focus: 'client:net-lan/10.0.0.1', view: 'table',
  });
  assert.match(hash, /^#\/security-map\?/);
  const f = mapFilters(hash);
  assert.equal(f.window, '15m');
  assert.equal(f.networkId, 'net-lan');
  assert.equal(f.action, 'blocked');
  assert.equal(f.search, 'evil');
  assert.equal(f.focus, 'client:net-lan/10.0.0.1');
  assert.equal(f.view, 'table');
});

test('outcomeTone keeps mixed evidence distinct from a single verdict', () => {
  assert.equal(outcomeTone({ allowed: 2, blocked: 0, errors: 0 }), 'allowed');
  assert.equal(outcomeTone({ allowed: 0, blocked: 2, errors: 0 }), 'blocked');
  assert.equal(outcomeTone({ allowed: 0, blocked: 0, errors: 1 }), 'error');
  assert.equal(outcomeTone({ allowed: 1, blocked: 1, errors: 0 }), 'mixed');
});

test('layoutGraph places clients under networks and domains in a separate column', () => {
  const L = layoutGraph(fixtureGraph, 'client:net-lan/10.0.0.1');
  assert.match(L.clientNodes, /client:net-lan\/10\.0\.0\.1/);
  assert.match(L.domainNodes, /domain:evil\.example/);
  assert.match(L.edgePaths, /map-edge/);
  assert.match(L.netNodes, /LAN/);
});

function loadMapDashboard(fetchImpl, hash = '#/security-map') {
  // Intentionally omit `document` so app.js does not boot timers or navigate.
  const sandbox = {
    module: { exports: {} },
    console, URL, URLSearchParams, Headers, Response, AbortController, AbortSignal, performance,
    setTimeout, clearTimeout,
    window: { location: { hash } },
    fetch: fetchImpl,
  };
  vm.createContext(sandbox);
  const main = fs.readFileSync(path.join(__dirname, 'static/app.js'), 'utf8');
  const setup = fs.readFileSync(path.join(__dirname, 'static/setup.js'), 'utf8');
  const map = fs.readFileSync(path.join(__dirname, 'static/map.js'), 'utf8');
  vm.runInContext(main + '\n;\n' + setup + '\n;\n' + map + '\nmodule.exports.mapPages = pages;', sandbox);
  return sandbox.module.exports.mapPages;
}

test('hostile labels are escaped in map markup', async () => {
  const requests = [];
  const pages = loadMapDashboard(async (raw) => {
    const url = new URL(raw, 'https://fixture.invalid');
    requests.push(url.pathname + url.search);
    if (url.pathname === '/api/v1/networks') {
      return new Response(JSON.stringify({ networks: fixtureGraph.networks }), {
        status: 200, headers: { 'Content-Type': 'application/json' },
      });
    }
    if (url.pathname === '/api/v1/network-map') {
      return new Response(JSON.stringify(fixtureGraph), {
        status: 200, headers: { 'Content-Type': 'application/json' },
      });
    }
    throw new Error('unexpected ' + url.pathname);
  }, '#/security-map?hours=1&focus=client:net-guest/10.1.0.5');
  assert.ok(pages['security-map'], 'security-map page registered in concatenated dashboard');
  const markup = await pages['security-map'].render({
    hash: '#/security-map?hours=1&focus=client:net-guest/10.1.0.5',
    signal: new AbortController().signal,
  });
  assert.doesNotMatch(markup, /<img src=x onerror/);
  assert.doesNotMatch(markup, /<svg\/onload/);
  assert.match(markup, /&lt;img src=x onerror/);
  assert.match(markup, /Investigate client/);
  assert.match(markup, /map-canvas/);
  assert.ok(requests.some((p) => p.startsWith('/api/v1/network-map')));
});

test('API failure does not render an empty fine graph', async () => {
  const pages = loadMapDashboard(async (raw) => {
    const url = new URL(raw, 'https://fixture.invalid');
    if (url.pathname === '/api/v1/networks') {
      return new Response(JSON.stringify({ networks: [] }), {
        status: 200, headers: { 'Content-Type': 'application/json' },
      });
    }
    return new Response(JSON.stringify({ error: 'boom' }), {
      status: 500, headers: { 'Content-Type': 'application/json' },
    });
  });
  const markup = await pages['security-map'].render({
    hash: '#/security-map',
    signal: new AbortController().signal,
  });
  assert.match(markup, /DNS Security Map unavailable|unavailable|failed/i);
  assert.doesNotMatch(markup, /map-canvas/);
});

test('privacy-limited responses stay empty and labelled', async () => {
  const limited = {
    available: false,
    unavailable: 'Client address logging is disabled.',
    limitations: ['Privacy controls omitted client addresses'],
    networks: [], clients: [], domains: [], edges: [], findings: [],
    generatedAt: '2026-11-17T00:00:00.000Z',
    effectiveFrom: '2026-11-16T23:00:00.000Z',
    effectiveTo: '2026-11-17T00:00:00.000Z',
  };
  const pages = loadMapDashboard(async (raw) => {
    const url = new URL(raw, 'https://fixture.invalid');
    if (url.pathname === '/api/v1/networks') {
      return new Response(JSON.stringify({ networks: [] }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    return new Response(JSON.stringify(limited), { status: 200, headers: { 'Content-Type': 'application/json' } });
  });
  const markup = await pages['security-map'].render({
    hash: '#/security-map',
    signal: new AbortController().signal,
  });
  assert.match(markup, /Map limited by privacy/);
  assert.match(markup, /Client address logging is disabled/);
  assert.doesNotMatch(markup, /map-canvas/);
});

test('table view exposes investigation links without graph gestures', async () => {
  const pages = loadMapDashboard(async (raw) => {
    const url = new URL(raw, 'https://fixture.invalid');
    if (url.pathname === '/api/v1/networks') {
      return new Response(JSON.stringify({ networks: fixtureGraph.networks }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    return new Response(JSON.stringify(fixtureGraph), { status: 200, headers: { 'Content-Type': 'application/json' } });
  }, '#/security-map?view=table');
  const markup = await pages['security-map'].render({
    hash: '#/security-map?view=table',
    signal: new AbortController().signal,
  });
  assert.match(markup, /Relationship table/);
  assert.match(markup, /#\/investigate\?/);
  assert.doesNotMatch(markup, /map-canvas/);
});

test('domain details use the query-log domain filter, not exactDomain', async () => {
  const pages = loadMapDashboard(async (raw) => {
    const url = new URL(raw, 'https://fixture.invalid');
    if (url.pathname === '/api/v1/networks') {
      return new Response(JSON.stringify({ networks: fixtureGraph.networks }), {
        status: 200, headers: { 'Content-Type': 'application/json' },
      });
    }
    return new Response(JSON.stringify(fixtureGraph), {
      status: 200, headers: { 'Content-Type': 'application/json' },
    });
  }, '#/security-map?hours=1&focus=domain:evil.example');
  const markup = await pages['security-map'].render({
    hash: '#/security-map?hours=1&focus=domain:evil.example',
    signal: new AbortController().signal,
  });
  assert.match(markup, /#\/queries\?[^"]*domain=evil\.example/);
  assert.doesNotMatch(markup, /exactDomain=/);
});

test('clearSensitive resets viewport state used across refreshes', () => {
  securityMapPage._viewport = { x: 40, y: 12, k: 1.5 };
  securityMapPage.clearSensitive();
  assert.deepEqual(securityMapPage._viewport, { x: 0, y: 0, k: 1 });
});

test('esc still neutralises hostile strings used by map labels', () => {
  assert.equal(esc('<script>'), '&lt;script&gt;');
});
