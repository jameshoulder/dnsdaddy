/* Optional real-browser regression for the served UI and real management API.
 * Build the binary first, then set DNSDADDY_UI_BINARY and DNSDADDY_UI_BROWSER.
 * Playwright must be on NODE_PATH (or CODEX_PRIMARY_RUNTIME_NODE_MODULES).
 * No responses are mocked. All DNS fixtures and deliberate failures use loopback.
 * DNSDADDY_UI_CAPTURE_DIR optionally retains screenshots and a JSON report.
 */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const net = require('node:net');
const dgram = require('node:dgram');
const { spawn } = require('node:child_process');
const { createHash } = require('node:crypto');

const binary = process.env.DNSDADDY_UI_BINARY;
const executablePath = process.env.DNSDADDY_UI_BROWSER;
if (!binary || !executablePath) {
  console.log('Skipped: set DNSDADDY_UI_BINARY and DNSDADDY_UI_BROWSER for the optional real-browser test.');
  process.exit(0);
}
const { chromium } = require(process.env.CODEX_PRIMARY_RUNTIME_NODE_MODULES ? path.join(process.env.CODEX_PRIMARY_RUNTIME_NODE_MODULES, 'playwright') : 'playwright');
const checks = [];
const check = (name, value) => { assert.ok(value, name); checks.push(name); };
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function port() {
  const server = net.createServer();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const value = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return value;
}
function question(name, id) {
  const header = Buffer.alloc(12); header.writeUInt16BE(id, 0); header.writeUInt16BE(0x0100, 2); header.writeUInt16BE(1, 4);
  return Buffer.concat([header, ...name.split('.').map((label) => Buffer.concat([Buffer.from([label.length]), Buffer.from(label)])), Buffer.from([0, 0, 1, 0, 1])]);
}
async function ask(port, name, id) {
  const socket = dgram.createSocket('udp4');
  try {
    return await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('Lab DNS query timed out')), 3000);
      socket.once('message', (answer) => { clearTimeout(timer); resolve(answer); });
      socket.once('error', (error) => { clearTimeout(timer); reject(error); });
      socket.send(question(name, id), port, '127.0.0.1');
    });
  } finally { socket.close(); }
}

(async () => {
  const work = await fs.mkdtemp(path.join(os.tmpdir(), 'dnsdaddy-ui-transport-'));
  const output = process.env.DNSDADDY_UI_CAPTURE_DIR || path.join(work, 'captures');
  await fs.mkdir(output, { recursive: true });
  const upstream = dgram.createSocket('udp4');
  await new Promise((resolve) => upstream.bind(0, '127.0.0.1', resolve));
  let upstreamQueries = 0;
  upstream.on('message', (message, peer) => {
    upstreamQueries++;
    let end = 12;
    while (message[end]) end += message[end] + 1;
    end += 5;
    const header = Buffer.from(message.subarray(0, 12));
    header.writeUInt16BE(0x8180, 2); header.writeUInt16BE(1, 6); header.writeUInt16BE(0, 8); header.writeUInt16BE(0, 10);
    const answer = Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 8, 8, 4, 4]);
    upstream.send(Buffer.concat([header, message.subarray(12, end), answer]), peer.port, peer.address);
  });
  const httpPort = await port(); const dnsPort = await port(); const unusedPort = await port();
  const base = `http://127.0.0.1:${httpPort}`;
  const password = 'isolated-ui-lab-password';
  const config = path.join(work, 'config.yaml');
  await fs.writeFile(path.join(work, 'lab-feed.txt'), '0.0.0.0 blocked.lab.example\n');
  await fs.writeFile(config, `data_dir: ${path.join(work, 'data')}\ndns:\n  listen_udp: "127.0.0.1:${dnsPort}"\n  listen_tcp: "127.0.0.1:${dnsPort}"\n  upstreams: ["127.0.0.1:${upstream.address().port}"]\nhttp:\n  listen: "127.0.0.1:${httpPort}"\n  admin_password: "${password}"\nlog:\n  query_log: false\nfeeds:\n  refresh_on_start: false\n  local_feed_dir: ${work}\n`);
  const app = spawn(binary, ['-config', config], { stdio: ['ignore', 'pipe', 'pipe'] });
  let logs = ''; app.stdout.on('data', (data) => { logs += data; }); app.stderr.on('data', (data) => { logs += data; });
  let browser; let page;
  const images = [];
  try {
    for (let attempt = 0; attempt < 100; attempt++) {
      if (app.exitCode !== null) throw new Error(`Application exited: ${logs}`);
      try { if ((await fetch(`${base}/api/v1/health`)).ok) break; } catch { /* Startup not listening yet. */ }
      if (attempt === 99) throw new Error(`Application did not start: ${logs}`);
      await delay(100);
    }
    browser = await chromium.launch({ executablePath, args: ['--no-sandbox'] });
    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, permissions: ['clipboard-read', 'clipboard-write'] });
    page = await context.newPage(); const errors = []; const requests = []; const liveReads = []; const modeChanges = [];
    page.on('pageerror', (error) => errors.push(error.message));
    page.on('request', (request) => { if (request.url().includes('/dns/transport') && request.method() !== 'GET') requests.push({ method: request.method(), url: request.url(), body: request.postDataJSON() }); });
    page.on('request', (request) => {
      if (request.url().includes('/activity/live')) liveReads.push(Date.now());
      if (request.url().includes('/dnssec/mode') && request.method() === 'PUT') modeChanges.push(request.postDataJSON());
    });
    const api = async (route, method = 'GET', body) => {
      const result = await page.evaluate(async ({ route, method, body }) => {
        const response = await fetch('/api/v1' + route, { method, headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' }, body: body === undefined ? undefined : JSON.stringify(body) });
        return { status: response.status, text: await response.text() };
      }, { route, method, body });
      assert.ok(result.status < 400, `${method} ${route}: ${result.status} ${result.text}`);
      return result.text ? JSON.parse(result.text) : null;
    };
    const shot = async (file, route, fullPage = true) => {
      await page.waitForFunction(() => document.querySelectorAll('#toasts .toast').length === 0);
      await page.evaluate(() => window.scrollTo(0, 0));
      const target = path.join(output, file); await page.screenshot({ path: target, fullPage });
      const bytes = await fs.readFile(target); images.push({ file, route, capturedAt: new Date().toISOString(), fullPage, width: bytes.readUInt32BE(16), height: bytes.readUInt32BE(20), sha256: createHash('sha256').update(bytes).digest('hex') });
    };
    await page.goto(base); await page.locator('#password').fill(password); await page.locator('#login-form button[type=submit]').click();
    await page.locator('.server-address-card').waitFor();
    check('a fresh install exposes selectable Forward mode directly on Overview', await page.locator('#daddybound-mode-form [name=mode][value=off]').isChecked() && await page.locator('#daddybound-mode-form button[type=submit]').isEnabled() && (await api('/dnssec/status')).mode.effective === 'off');
    check('a new instance honestly waits for its first DNS query', await page.locator('#resolver-live').getAttribute('data-live-state') === 'waiting' && (await api('/activity/live')).sinceStart.received === 0);
    await delay(2200);
    check('a timer tick with no traffic does not flash or claim processing', await page.locator('.live-activity-dot.has-activity').count() === 0 && await page.locator('#resolver-live').getAttribute('data-live-state') === 'waiting' && liveReads.length >= 2);
    await page.locator('#daddybound-mode-form [name=mode][value=observe]').check(); await page.locator('#daddybound-mode-form button[type=submit]').click();
    check('native Learn still requires explicit authoritative-DNS acknowledgement', modeChanges.length === 0 && (await page.locator('#native-mode-error').innerText()).includes('Confirm the native DNS transport'));
    await page.locator('#daddybound-mode-form [name=mode][value=off]').check(); await page.locator('#daddybound-mode-form button[type=submit]').click();
    await page.waitForFunction(() => document.querySelector('#daddybound-mode-form button[type=submit]')?.disabled === false);
    check('Forward applies from Overview without native transport consent', modeChanges.length === 1 && modeChanges[0].mode === 'off' && modeChanges[0].acknowledgeNativeTransport === false);
    check('server addresses come from the actual authenticated endpoint', (await api('/server-addresses')).source.length > 0);
    check('loopback-only lab does not claim a usable LAN address', (await page.locator('.server-address-card').innerText()).includes('No LAN or public address'));
    check('the non-preferred host-only IP and copy action are visible without opening details', await page.locator('.server-address-card [data-copy="127.0.0.1"]').isVisible() && (await page.locator('.server-address-card').innerText()).includes('Host-only IP') && !(await page.locator('.server-address-details').evaluate((element) => element.open)));
    const ipCopy = page.locator('.server-address-card [data-copy="127.0.0.1"]'); await ipCopy.click();
    await page.waitForFunction(() => document.querySelector('.server-address-card [data-copy="127.0.0.1"]').textContent === 'Copied');
    check('homepage copy succeeds for the literal loopback IP', true);

    const feeds = await api('/feeds');
    for (const feed of feeds.feeds.filter((feed) => feed.enabled)) await api(`/feeds/${feed.id}`, 'PATCH', { enabled: false });
    const fixtureFeed = await api('/feeds', 'POST', { name: 'Synthetic local lab feed', url: `file://${path.join(work, 'lab-feed.txt')}`, category: 'malware', format: 'hosts', enabled: true });
    await api(`/feeds/${fixtureFeed.id}/refresh`, 'POST', {});
    for (let attempt = 0; attempt < 50; attempt++) {
      if ((await api('/feeds')).feeds.find((feed) => feed.id === fixtureFeed.id).loaded) break;
      await delay(100);
    }
    check('fixture feed loads through the ordinary API without public network traffic', (await api('/feeds')).feeds.find((feed) => feed.id === fixtureFeed.id).loaded);
    const modeForm = await page.locator('#daddybound-mode-form').elementHandle();
    await page.locator('#daddybound-mode-form [name=mode][value=off]').focus();
    for (let id = 1; id <= 30; id++) await ask(dnsPort, id % 5 === 0 ? 'blocked.lab.example' : `service${id}.lab.example`, id);
    await page.waitForFunction(() => Number(document.querySelector('[data-live-count=received]').textContent.replaceAll(',', '')) >= 30);
    check('live activity shows real processing while query logging is disabled', (await api('/settings')).queryLog === false && (await api('/queries?limit=2')).queries.length === 0 && (await page.locator('#resolver-live').innerText()).includes('Processing DNS queries'));
    check('live polling preserves mode-form focus and does not replace the page', await modeForm.evaluate((element) => element.isConnected) && await page.locator('#daddybound-mode-form [name=mode][value=off]').evaluate((element) => element === document.activeElement));
    const receivedBeforePause = await page.locator('[data-live-count=received]').innerText();
    await page.locator('#auto-refresh-btn').click(); await ask(dnsPort, 'paused.lab.example', 31); await delay(2200);
    check('Pause updates freezes the sample and clearly labels it paused', await page.locator('[data-live-count=received]').innerText() === receivedBeforePause && await page.locator('#resolver-live').getAttribute('data-live-state') === 'paused');
    await page.locator('#auto-refresh-btn').click();
    await page.waitForFunction(() => Number(document.querySelector('[data-live-count=received]').textContent.replaceAll(',', '')) >= 31);
    check('Resume updates catches up with actual DNS counters', await page.locator('#resolver-live').getAttribute('data-live-state') === 'active');
    await context.setOffline(true);
    await page.waitForFunction(() => document.querySelector('#resolver-live').dataset.liveState === 'unavailable');
    check('unreachable telemetry keeps the last sample visibly stale', Number((await page.locator('[data-live-count=received]').innerText()).replaceAll(',', '')) >= 31 && (await page.locator('[data-live-summary]').innerText()).includes('current activity is unknown'));
    await context.setOffline(false);
    await page.waitForFunction(() => document.querySelector('#resolver-live').dataset.liveState === 'active');
    check('live telemetry recovers after a real browser connection failure', true);
    await shot('dashboard.png', '#/dashboard', false);

    await page.goto(base + '/#/daddybound'); await page.locator('#dns-transport-form').waitFor();
    const readsAway = liveReads.length; await delay(2200);
    check('leaving Overview stops its independent live polling', liveReads.length === readsAway);
    const form = page.locator('#dns-transport-form');
    check('GET and rendering never perform a transport test', requests.length === 0);
    check('native is initially selected and forwarder fields are not interactive', await form.locator('[name=transport][value=native]').isChecked() && await form.locator('[name=address]').isDisabled());
    await form.locator('[name=transport][value=encrypted]').check();
    check('new encrypted setup does not choose a protocol or provider', await form.locator('[name=protocol]').inputValue() === '' && await form.locator('[name=address]').inputValue() === '');
    await form.locator('[data-transport-example=cloudflare]').click();
    check('explicit example fills a single complete DoH2 endpoint', await form.locator('[data-forwarder]').count() === 1 && await form.locator('[name=protocol]').inputValue() === 'doh2' && await form.locator('[name=address]').inputValue() === 'https://cloudflare-dns.com/dns-query' && await form.locator('[name=serverName]').inputValue() === 'cloudflare-dns.com' && await form.locator('[name=bootstrapIPs]').inputValue() === '1.1.1.1\n1.0.0.1');
    check('adding an example does not consent, test, save or enable Live', requests.length === 0 && !(await form.locator('[name=acknowledgeForwarding]').isChecked()) && (await api('/dns/transport')).transport === 'native' && (await api('/dnssec/status')).mode.effective === 'off');
    await form.locator('[name=address]').fill('https://custom.example/dns-query');
    await form.locator('[name=acknowledgeForwarding]').check();
    await form.locator('[data-transport-example=cloudflare]').click();
    check('adding an example preserves custom entries and revokes old consent', await form.locator('[data-forwarder]').count() === 2 && await form.locator('[name=address]').first().inputValue() === 'https://custom.example/dns-query' && !(await form.locator('[name=acknowledgeForwarding]').isChecked()) && requests.length === 0);
    for (let index = 0; index < 2; index++) await form.locator('[data-forwarder]').last().locator('[data-transport-action=remove]').click();
    await form.locator('#transport-add-endpoint').click();
    for (let index = 1; index < 16; index++) await form.locator('#transport-add-endpoint').click();
    check('the endpoint editor enforces the sixteen-endpoint bound for examples and custom entries', await form.locator('#transport-add-endpoint').isDisabled() && await form.locator('[data-transport-example=cloudflare]').isDisabled() && await form.locator('[data-forwarder]').count() === 16);
    for (let index = 15; index > 0; index--) await form.locator('[data-forwarder]').last().locator('[data-transport-action=remove]').click();
    check('endpoint boundary controls stay correct after removals', await form.locator('[data-transport-action=up]').isDisabled() && await form.locator('[data-transport-action=down]').isDisabled());
    await form.locator('[name=protocol]').selectOption('doq'); await form.locator('[name=address]').fill(`127.0.0.1:${unusedPort}`);
    await form.locator('#transport-test').click();
    check('test requires explicit sharing consent without sending a request', requests.length === 0 && (await form.locator('#dns-transport-error').innerText()).includes('Agree to send'));
    await form.locator('[name=acknowledgeForwarding]').check();
    await form.locator('#transport-add-endpoint').click();
    check('adding an endpoint resets consent', !(await form.locator('[name=acknowledgeForwarding]').isChecked()));
    const second = form.locator('[data-forwarder]').nth(1);
    await second.locator('[name=protocol]').selectOption('doh2'); await second.locator('[name=address]').fill(`https://127.0.0.1:${unusedPort}/dns-query`);
    await second.locator('[data-transport-action=up]').click();
    check('endpoint order can be changed accessibly', await form.locator('[data-forwarder]').first().locator('[name=protocol]').inputValue() === 'doh2');
    await form.locator('[name=acknowledgeForwarding]').check();
    await form.locator('#transport-test').click();
    await page.waitForFunction(() => !document.querySelector('#dns-transport-test-result').hidden);
    check('deliberate local failure is shown rather than claiming connectivity', (await form.locator('#dns-transport-test-result').innerText()).includes('Test query failed'));
    check('test sends the ordered draft and explicit consent', requests.length === 1 && requests[0].body.acknowledgeForwarding === true && requests[0].body.endpoints[0].protocol === 'doh2');
    check('test does not activate or save transport', (await api('/dns/transport')).transport === 'native');
    await form.locator('[data-forwarder]').nth(1).locator('[data-transport-action=remove]').click();
    check('editing the tested draft hides its obsolete test result', await form.locator('#dns-transport-test-result').isHidden());
    await form.locator('[name=address]').fill('https://resolver.example/dns-query'); await form.locator('[name=acknowledgeForwarding]').check();
    await form.locator('button[type=submit]').click();
    await page.waitForFunction(() => !document.querySelector('#dns-transport-error').hidden);
    check('invalid bootstrap configuration is reported and remains unsaved', (await api('/dns/transport')).transport === 'native' && await form.locator('[name=address]').inputValue() === 'https://resolver.example/dns-query');
    await form.locator('[name=address]').fill(`https://127.0.0.1:${unusedPort}/dns-query`); await form.locator('[name=acknowledgeForwarding]').check();
    await form.locator('button[type=submit]').click();
    await page.waitForFunction(() => document.querySelector('#dns-transport-form').dataset.currentTransport === 'encrypted');
    const saved = await api('/dns/transport');
    check('approved encrypted settings persist through the real API', saved.transport === 'encrypted' && saved.endpoints[0].protocol === 'doh2' && saved.plaintextFallback === false);
    check('encrypted transport preserves the separately chosen Forward mode', (await api('/dnssec/status')).mode.effective === 'off');
    await page.locator('#transport-test').click();
    check('a saved endpoint still needs consent before an explicit test', !(await page.locator('[name=acknowledgeForwarding]').isChecked()));
    await page.locator('[name=acknowledgeForwarding]').check(); await page.locator('#transport-test').click();
    await page.waitForFunction(() => !document.querySelector('#dns-transport-test-result').hidden);
    await shot('features-daddybound.png', '#/daddybound');
    await page.setViewportSize({ width: 390, height: 844 });
    check('phone transport form has no page-level horizontal overflow', await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
    await shot('features-daddybound-mobile.png', '#/daddybound');
    await page.setViewportSize({ width: 1440, height: 1000 });

    for (const mode of ['observe', 'enforce', 'off']) {
      await page.locator(`#daddybound-mode-form [name=mode][value=${mode}]`).check();
      check(`encrypted ${mode} never asks for plaintext authoritative consent`, await page.locator('#native-transport-consent').isHidden());
      await page.locator('#daddybound-mode-form button[type=submit]').click();
      await page.waitForFunction((mode) => document.querySelector(`#daddybound-mode-form [name=mode][value=${mode}]`)?.checked && document.querySelector('#daddybound-mode-form button[type=submit]')?.disabled === false, mode);
      check(`the real mode API accepts ${mode} while preserving encrypted transport`, (await api('/dnssec/status')).mode.effective === mode && (await api('/dns/transport')).transport === 'encrypted');
    }
    const upstreamBeforeFailure = upstreamQueries;
    const failedAnswer = await ask(dnsPort, 'unreachable.lab.example', 500);
    check('an unreachable encrypted endpoint produces a real failure without standard-upstream fallback', (failedAnswer.readUInt16BE(2) & 0x000f) === 2 && upstreamQueries === upstreamBeforeFailure);
    await page.goto(base + '/#/dashboard'); await page.locator('#resolver-live').waitFor();
    check('Overview distinguishes measured query failures from idle or successful processing', ['degraded', 'failing'].includes(await page.locator('#resolver-live').getAttribute('data-live-state')) && (await api('/activity/live')).recent.errors > 0);
    await page.goto(base + '/#/daddybound'); await page.locator('#dns-transport-form').waitFor();

    await page.locator('[name=transport][value=native]').check(); const countBefore = requests.length;
    await page.locator('#dns-transport-form button[type=submit]').click();
    check('returning to plaintext native transport needs explicit acknowledgement', requests.length === countBefore && (await page.locator('#dns-transport-error').innerText()).includes('Acknowledge'));
    await page.locator('#dns-transport-form [name=acknowledgeNativeTransport]').check(); await page.locator('#dns-transport-form button[type=submit]').click();
    await page.waitForFunction(() => document.querySelector('#dns-transport-form').dataset.currentTransport === 'native');
    check('switching back keeps the saved endpoint configuration', (await api('/dns/transport')).endpoints.length === 1);
    await page.locator('#dns-transport-form button[type=submit]').click();
    await page.waitForFunction(() => document.querySelector('#dns-transport-form button[type=submit]').disabled === false);
    check('reapplying native does not incorrectly demand a hidden acknowledgement', await page.locator('#dns-transport-error').isHidden());
    await page.goto(base + '/#/setup'); await page.locator('.server-address-card').waitFor();
    check('setup separates client addresses from outbound transport', (await page.locator('#view').innerText()).includes('Upstream transport'));
    // Per-network DoH tokens are credentials. Capture only the address card.
    await page.locator('.server-address-details summary').click();
    await page.waitForFunction(() => document.querySelectorAll('#toasts .toast').length === 0);
    await page.locator('.server-address-card').screenshot({ path: path.join(output, 'server-addresses.png') });
    const addressBytes = await fs.readFile(path.join(output, 'server-addresses.png')); images.push({ file: 'server-addresses.png', route: '#/setup', capturedAt: new Date().toISOString(), capture: 'address card only; credential-bearing DoH URLs excluded', width: addressBytes.readUInt32BE(16), height: addressBytes.readUInt32BE(20), sha256: createHash('sha256').update(addressBytes).digest('hex') });
    await page.goto(base + '/#/dashboard'); await page.locator('.server-address-card').waitFor(); await page.setViewportSize({ width: 390, height: 844 });
    check('phone overview has no page-level horizontal overflow', await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
    await shot('mobile.png', '#/dashboard', false);
    check('no browser JavaScript errors occurred', errors.length === 0);
    check('synthetic traffic reached only the loopback fixture', upstreamQueries > 0);
    const assets = {};
    for (const asset of ['app.js', 'app.css', 'index.html']) {
      const served = Buffer.from(await (await fetch(base + (asset === 'index.html' ? '/' : '/' + asset))).arrayBuffer());
      assets[asset] = createHash('sha256').update(served).digest('hex');
      assert.equal(assets[asset], createHash('sha256').update(await fs.readFile(path.join(__dirname, 'static', asset))).digest('hex'), `Served ${asset} matches current source`);
    }
    check('served assets match the current source', true);
    const report = { generatedAt: new Date().toISOString(), browser: await browser.version(), checks, images, assets, binarySha256: createHash('sha256').update(await fs.readFile(binary)).digest('hex'), serverAddresses: await api('/server-addresses'), overview: await api('/overview'), live: await api('/activity/live'), transport: await api('/dns/transport'), modeChanges, upstreamQueries, note: 'Real isolated app with fresh Forward mode, query logging disabled, external feeds disabled and a synthetic local file feed loaded through the management API. Mode changes exercise encrypted loopback failure targets, and all DNS fixtures use loopback. The browser goes offline briefly to test unavailable telemetry. No API response or DOM content was replaced. Screenshots show actual first-run counters over synthetic .lab.example queries.' };
    await fs.writeFile(path.join(output, 'transport-browser-report.json'), JSON.stringify(report, null, 2) + '\n');
    console.log(JSON.stringify({ passed: checks.length, output, images: images.map((image) => image.file) }));
  } catch (error) {
    if (page) {
      await fs.writeFile(path.join(output, 'failed-dom.html'), await page.content()).catch(() => {});
      await page.screenshot({ path: path.join(output, 'failed-browser.png'), fullPage: true }).catch(() => {});
    }
    throw error;
  } finally {
    if (browser) await browser.close();
    app.kill('SIGTERM'); await Promise.race([new Promise((resolve) => app.once('exit', resolve)), delay(3000)]);
    if (app.exitCode === null) app.kill('SIGKILL');
    upstream.close();
  }
})().catch((error) => { console.error(error); process.exitCode = 1; });
