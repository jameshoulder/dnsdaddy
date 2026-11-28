/* Reproducible brand-gallery captures from the real daemon and offline lab.
 * Run in the deployment-evidence workflow after its existing regressions.
 * No API response, statistic, DOM content or screenshot pixel is substituted.
 */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const dgram = require('node:dgram');
const { spawn, execFileSync } = require('node:child_process');
const { createHash } = require('node:crypto');

const binary = process.env.DNSDADDY_UI_BINARY;
const labBinary = process.env.DNSDADDY_UI_LAB_BINARY;
const executablePath = process.env.DNSDADDY_UI_BROWSER;
if (!binary || !labBinary || !executablePath) {
  console.log('Skipped: set DNSDADDY_UI_BINARY, DNSDADDY_UI_LAB_BINARY and DNSDADDY_UI_BROWSER.');
  process.exit(0);
}
const { chromium } = require(process.env.CODEX_PRIMARY_RUNTIME_NODE_MODULES
  ? path.join(process.env.CODEX_PRIMARY_RUNTIME_NODE_MODULES, 'playwright') : 'playwright');
const hash = (data) => createHash('sha256').update(data).digest('hex');
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const checks = [];
function check(name, value) { assert.ok(value, name); checks.push(name); }
async function freePort() {
  const server = net.createServer();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const selected = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return selected;
}
async function ask(port, domain, id) {
  const socket = dgram.createSocket('udp4');
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0); header.writeUInt16BE(0x0100, 2); header.writeUInt16BE(1, 4);
  const packet = Buffer.concat([header,
    ...domain.split('.').map((label) => Buffer.concat([Buffer.from([label.length]), Buffer.from(label)])),
    Buffer.from([0, 0, 1, 0, 1])]);
  try {
    return await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('Synthetic DNS query timed out')), 3000);
      socket.once('message', (answer) => { clearTimeout(timer); resolve(answer); });
      socket.once('error', (error) => { clearTimeout(timer); reject(error); });
      socket.send(packet, port, '127.0.0.1');
    });
  } finally { socket.close(); }
}
async function expectedAsset(name) {
  const data = await fs.readFile(path.join(__dirname, 'static', name));
  if (name !== 'app.js') return data;
  return Buffer.concat([data, Buffer.from('\n;\n'),
    await fs.readFile(path.join(__dirname, 'static', 'setup.js')), Buffer.from('\n;\n'),
    await fs.readFile(path.join(__dirname, 'static', 'map.js'))]);
}

(async () => {
  const work = await fs.mkdtemp(path.join(os.tmpdir(), 'dnsdaddy-brand-gallery-'));
  const output = process.env.DNSDADDY_UI_CAPTURE_DIR || path.join(work, 'captures');
  await fs.mkdir(output, { recursive: true });
  const ports = new Set();
  while (ports.size < 3) ports.add(await freePort());
  const [httpPort, dnsPort, sinkPort] = [...ports];
  const base = `http://127.0.0.1:${httpPort}`;
  const password = 'isolated-brand-capture-password';
  const config = path.join(work, 'config.yaml');
  await fs.writeFile(path.join(work, 'lab-feed.txt'), '0.0.0.0 blocked.lab.example\n');
  await fs.writeFile(config, [
    `data_dir: ${JSON.stringify(path.join(work, 'data'))}`,
    'dns:', `  listen_udp: "127.0.0.1:${dnsPort}"`, `  listen_tcp: "127.0.0.1:${dnsPort}"`,
    '  allowed_client_cidrs: ["127.0.0.0/8"]',
    `  upstreams: ["udp://127.0.0.1:${sinkPort}"]`, '  local_dnssec_validation: "off"',
    'http:', `  listen: "127.0.0.1:${httpPort}"`, `  admin_password: "${password}"`,
    'feeds:', '  refresh_on_start: false', `  local_feed_dir: ${JSON.stringify(work)}`,
    'log:', '  query_log: true', '  log_client_ip: true', '  decision_records: true',
    'detection:', '  enabled: true', '  window_scale: 0.1', '  eval_interval: 5s', '  cooldown: 2m',
    'protection:', '  rebinding:', '    allow_cidrs: ["203.0.113.0/24", "2001:db8::/32"]', ''
  ].join('\n'));
  const children = [];
  const childLogs = [];
  const childStates = new Map();
  function start(program, args) {
    const child = spawn(program, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let logs = '';
    const state = { startedAt: new Date().toISOString(), finishedAt: null,
      closed: false, exitCode: null, signal: null, error: null, logs: () => logs };
    child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8');
    child.stdout.on('data', (data) => { logs += data; });
    child.stderr.on('data', (data) => { logs += data; });
    child.once('error', (error) => { state.error = error.message; });
    // close follows the final stdout/stderr data, so the completion summary is
    // available before a generator can be recorded as successfully finished.
    child.once('close', (exitCode, signal) => {
      Object.assign(state, { closed: true, exitCode, signal, finishedAt: new Date().toISOString() });
    });
    childStates.set(child, state);
    children.push(child); childLogs.push(() => logs);
    return child;
  }
  start(labBinary, ['-sink', `127.0.0.1:${sinkPort}`]);
  const daemon = start(binary, ['-config', config]);
  let browser;
  try {
    for (let attempt = 0; attempt < 150; attempt++) {
      if (daemon.exitCode !== null) throw new Error(`Capture daemon exited: ${childLogs[1]()}`);
      try { if ((await fetch(`${base}/api/v1/health`)).ok) break; } catch { /* Starting. */ }
      if (attempt === 149) throw new Error('Capture daemon did not become ready');
      await delay(100);
    }
    browser = await chromium.launch({ executablePath, args: ['--no-sandbox'] });
    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, locale: 'en-GB', timezoneId: 'Europe/London' });
    const page = await context.newPage();
    const pageErrors = []; const consoleErrors = []; const externalResources = [];
    page.on('pageerror', (error) => pageErrors.push(error.message));
    page.on('console', (entry) => { if (entry.type() === 'error') consoleErrors.push(entry.text()); });
    page.on('request', (request) => {
      const url = new URL(request.url());
      if (url.protocol.startsWith('http') && url.origin !== base) externalResources.push(url.origin + url.pathname);
    });
    const api = async (route, method = 'GET', body) => {
      const result = await page.evaluate(async ({ route, method, body }) => {
        const response = await fetch('/api/v1' + route, {
          method, headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
          body: body === undefined ? undefined : JSON.stringify(body)
        });
        return { status: response.status, text: await response.text() };
      }, { route, method, body });
      assert.ok(result.status < 400, `${method} ${route}: ${result.status}`);
      return result.text ? JSON.parse(result.text) : null;
    };
    const images = [];
    async function shot(file, route, scope, fullPage = true) {
      await page.waitForFunction(() => document.querySelectorAll('#toasts .toast').length === 0);
      check(`${file}: no entered passwords are captured`, await page.locator('input[type=password]').evaluateAll((inputs) => inputs.every((input) => !input.value)));
      await page.evaluate(() => window.scrollTo(0, 0));
      const target = path.join(output, file);
      await page.screenshot({ path: target, fullPage });
      const bytes = await fs.readFile(target);
      images.push({ file, route, scope, capturedAt: new Date().toISOString(), fullPage,
        viewport: page.viewportSize(), width: bytes.readUInt32BE(16), height: bytes.readUInt32BE(20), sha256: hash(bytes) });
    }
    async function visit(route, selector) {
      await page.goto(base + '/' + route);
      const name = route.slice(2).split('?')[0];
      await page.waitForFunction(({ route, name }) => {
        const view = document.querySelector('#view');
        const active = document.querySelector('.nav a[aria-current="page"]');
        return window.location.hash === route && active && active.dataset.route === name
          && view && view.getAttribute('aria-busy') === 'false';
      }, { route, name });
      await page.locator(selector).first().waitFor();
    }
    await page.goto(base);
    await page.locator('#login').waitFor();
    check('approved logo loads on sign-in', await page.locator('#login img[src^="/logo-hacker.png"]').first().evaluate((img) => img.complete && img.naturalWidth > 0));
    await shot('hacker-sign-in.png', 'sign-in', 'Unauthenticated sign-in; empty password; no instance telemetry.', false);
    await page.locator('#password').fill(password);
    await page.locator('#login-form button[type=submit]').click();
    await page.locator('.server-address-card').waitFor();
    // The product clears its password input on successful sign-in. Assert that
    // invariant before every image, including routes where the form is hidden.
    check('approved logo loads in the workspace', await page.locator('.sidebar img[src^="/logo-hacker.png"]').evaluate((img) => img.complete && img.naturalWidth > 0));
    const feeds = await api('/feeds');
    for (const feed of feeds.feeds.filter((feed) => feed.enabled)) await api(`/feeds/${feed.id}`, 'PATCH', { enabled: false });
    const feed = await api('/feeds', 'POST', { name: 'Synthetic capture feed', url: `file://${path.join(work, 'lab-feed.txt')}`, category: 'malware', format: 'hosts', enabled: true });
    await api(`/feeds/${feed.id}/refresh`, 'POST', {});
    for (let attempt = 0; attempt < 60; attempt++) {
      if ((await api('/feeds')).feeds.find((item) => item.id === feed.id).loaded) break;
      await delay(100);
    }
    check('synthetic local feed is loaded', (await api('/feeds')).feeds.find((item) => item.id === feed.id).loaded);
    for (let id = 1; id <= 48; id++) await ask(dnsPort, id % 4 === 0 ? 'blocked.lab.example' : `workstation${id}.lab.example`, id);
    const generators = [
      { scenario: 'dns-tunnelling', clientIp: '127.0.0.3', eventType: 'dns_tunnel_suspected' },
      { scenario: 'suspicious-txt', clientIp: '127.0.0.6', eventType: 'txt_activity_anomaly' }
    ].map((expected) => ({ ...expected, child: start(labBinary,
      ['-server', `127.0.0.1:${dnsPort}`, '-scenario', expected.scenario, '-speed', '10', '-seed', '1', '-quiet']) }));
    const generatorOutcomes = [];
    const matchingFindings = (generator, rows) => rows.filter((finding) =>
      finding.eventType === generator.eventType && finding.clientIp === generator.clientIp);
    let findings;
    for (let attempt = 0; attempt < 100; attempt++) {
      for (const generator of generators) {
        if (generator.outcome) continue;
        const state = childStates.get(generator.child);
        assert.equal(state.error, null, `${generator.scenario} failed to start: ${state.error}`);
        if (!state.closed) continue;
        assert.equal(state.exitCode, 0, `${generator.scenario} exited unsuccessfully: ${state.logs()}`);
        assert.equal(state.signal, null, `${generator.scenario} ended on signal ${state.signal}`);
        // The lab exits zero even when individual queries fail. Check its real
        // final send summary as well as the process result before claiming a
        // complete scenario in the public capture manifest.
        const planned = state.logs().match(/ — (\d+) queries over /);
        const completed = state.logs().match(/^\s*done: (\d+) sent(?:, (\d+) failed)? in ([^\r\n]+)$/m);
        assert.ok(planned && completed, `${generator.scenario} omitted its completion summary: ${state.logs()}`);
        const plannedQueries = Number(planned[1]);
        const sentQueries = Number(completed[1]);
        const failedQueries = Number(completed[2] || 0);
        check(`${generator.scenario} completed every scheduled lab query without a send failure`,
          plannedQueries > 0 && sentQueries === plannedQueries && failedQueries === 0);
        generator.outcome = { scenario: generator.scenario, clientIp: generator.clientIp,
          expectedEventType: generator.eventType, startedAt: state.startedAt, finishedAt: state.finishedAt,
          exitCode: state.exitCode, signal: state.signal, plannedQueries, sentQueries, failedQueries,
          reportedDuration: completed[3] };
      }
      findings = await api('/findings?limit=100');
      if (generators.every((generator) => generator.outcome && matchingFindings(generator, findings.findings).length)) break;
      await delay(1000);
    }
    for (const generator of generators) {
      check(`${generator.scenario} finished within the lab capture deadline`, Boolean(generator.outcome));
      const matches = matchingFindings(generator, findings.findings);
      check(`${generator.scenario} produced ${generator.eventType} for ${generator.clientIp}`, matches.length > 0);
      generatorOutcomes.push({ ...generator.outcome, findings: matches.map(({ id, time, eventType, clientIp, detector }) =>
        ({ id, time, eventType, clientIp, detector })) });
    }
    check('query logging records the actual synthetic lookups', (await api('/queries?limit=10')).queries.length > 0);
    check('Forward mode remains explicitly selected for the offline capture', (await api('/dnssec/status')).mode.effective === 'off');
    await visit('#/dashboard', '.server-address-card');
    await shot('hacker-dashboard.png', '#/dashboard', 'Real overview over synthetic lab traffic; loopback-only listeners; native validation explicitly off.');
    await page.locator('#theme-toggle').click();
    await page.waitForFunction(() => document.documentElement.dataset.theme === 'light');
    await shot('hacker-dashboard-light.png', '#/dashboard', 'The same running overview in the operator-selected light theme.');
    await page.locator('#theme-toggle').click();
    await page.waitForFunction(() => document.documentElement.dataset.theme === 'dark');
    await visit('#/queries?action=blocked', '.query-row');
    await page.locator('.query-row > summary').first().click();
    check('expanded query explains its actual synthetic feed match', (await page.locator('.query-row[open]').innerText()).includes('blocked.lab.example'));
    await shot('hacker-queries.png', '#/queries?action=blocked', 'Actual stored blocked query expanded; Synthetic capture feed; no fabricated decisions.');
    await visit('#/detections', '[data-finding]');
    await page.locator('[data-finding] > summary').first().click();
    await shot('hacker-findings.png', '#/detections', 'Real experimental heuristic findings from seeded offline tunnelling/TXT scenarios; not a production accuracy claim.');
    await visit('#/investigate?domain=blocked.lab.example', '#inv-decisions');
    await shot('hacker-investigate.png', '#/investigate?domain=blocked.lab.example', 'Stored activity and decision evidence for a reserved synthetic domain.');
    await visit('#/daddybound', '#dns-transport-form');
    await shot('hacker-daddybound.png', '#/daddybound', 'Forward selected; local validation off; the untrained learner and other limitations remain visible.');
    await visit('#/assurance', '.claim-key');
    await shot('hacker-assurance.png', '#/assurance', 'Unedited assurance statements and their limits from the current app.');
    for (const width of [390, 320]) {
      await page.setViewportSize({ width, height: 844 });
      for (const [route, selector] of [['#/dashboard', '.server-address-card'], ['#/queries?action=blocked', '.query-row'], ['#/detections', '[data-finding]'], ['#/assurance', '.claim-key']]) {
        await visit(route, selector);
        check(`${route} fits ${width}px without page-level overflow`, await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
      }
    }
    await page.setViewportSize({ width: 390, height: 844 });
    await visit('#/dashboard', '.server-address-card');
    await shot('hacker-mobile.png', '#/dashboard', '390px phone viewport over the same isolated synthetic lab.', false);
    await page.locator('#menu-btn').click();
    check('mobile navigation opens accessibly', await page.locator('#menu-btn').getAttribute('aria-expanded') === 'true');
    await shot('hacker-mobile-navigation.png', '#/dashboard', 'Actual mobile navigation and approved branding.', false);
    await page.locator('#nav-close').click();
    check('mobile navigation closes accessibly', await page.locator('#menu-btn').getAttribute('aria-expanded') === 'false');
    const assets = {}; const sourceAssets = {};
    for (const asset of ['app.js', 'app.css', 'index.html', 'logo.svg', 'favicon.svg', 'logo-hacker.png', 'theme.js']) {
      let expected = await expectedAsset(asset);
      sourceAssets[asset] = hash(expected);
      if (asset === 'index.html') {
        let template = expected.toString('utf8');
        for (const name of ['app.js', 'app.css']) template = template.replaceAll(`"/${name}"`, `"/${name}?v=${hash(await expectedAsset(name)).slice(0, 16)}"`);
        expected = Buffer.from(template);
      }
      const response = await fetch(base + (asset === 'index.html' ? '/' : '/' + asset));
      assert.equal(response.status, 200, `${asset} is embedded and served`);
      const served = Buffer.from(await response.arrayBuffer());
      assets[asset] = hash(served);
      assert.equal(assets[asset], hash(expected), `${asset} matches this checkout`);
    }
    check('embedded application and branding assets match the captured source', true);
    check('no uncaught browser errors', pageErrors.length === 0);
    check('no console or CSP errors', consoleErrors.length === 0);
    check('the browser loaded no remote resources', externalResources.length === 0);
    const sourceCommit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: path.join(__dirname, '../..'), encoding: 'utf8' }).trim();
    const report = {
      generatedAt: new Date().toISOString(), sourceCommit, headCommit: process.env.DNSDADDY_UI_HEAD_SHA || sourceCommit,
      browser: await browser.version(), binarySha256: hash(await fs.readFile(binary)), labBinarySha256: hash(await fs.readFile(labBinary)),
      checks, images, sourceAssets, servedAssets: assets, pageErrors, consoleErrors, externalResources,
      lab: { synthetic: true, source: 'cmd/dnsdaddy-lab', seed: 1, scenarios: ['dns-tunnelling', 'suspicious-txt'], speed: 10,
        scenarioOutcomes: generatorOutcomes,
        detectionWindowScale: 0.1, detectionEvalInterval: '5s', queries: 'reserved .example names only', listeners: 'loopback only',
        queryLogging: true, localValidationMode: 'off', feed: 'Synthetic capture feed; local file',
        note: 'No API response, DOM content or screenshot pixels were replaced. Counts and timings are observations of this run, not benchmarks. No production data, external provider credentials or live threat infrastructure were used.' },
      observed: { overview: await api('/overview'), findingCount: (await api('/findings?limit=100')).findings.length }
    };
    await fs.writeFile(path.join(output, 'hacker-brand-capture-manifest.json'), JSON.stringify(report, null, 2) + '\n');
    console.log(JSON.stringify({ passed: checks.length, output, images: images.map((image) => image.file), sourceCommit }));
  } finally {
    if (browser) await browser.close();
    for (const child of children.reverse()) {
      if (child.exitCode !== null) continue;
      child.kill('SIGTERM');
      await Promise.race([new Promise((resolve) => child.once('exit', resolve)), delay(1500)]);
      if (child.exitCode === null) child.kill('SIGKILL');
    }
  }
})().catch((error) => { console.error(error); process.exitCode = 1; });
