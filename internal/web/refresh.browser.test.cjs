/* Real daemon regression: discarding an automatic history refresh must not
 * cancel the live poller of the page which remains on screen. All DNS and
 * HTTP traffic is local. The history response is delayed, not fabricated.
 * Required: DNSDADDY_UI_BINARY, DNSDADDY_UI_BROWSER and Playwright on NODE_PATH.
 */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const dgram = require('node:dgram');
const { spawn } = require('node:child_process');
const { chromium } = require('playwright');
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function port() {
  const s = net.createServer(); await new Promise((resolve) => s.listen(0, '127.0.0.1', resolve));
  const p = s.address().port; await new Promise((resolve) => s.close(resolve)); return p;
}
function query(id) {
  const name = `probe${id}.example.test`;
  const head = Buffer.alloc(12); head.writeUInt16BE(id); head.writeUInt16BE(0x0100, 2); head.writeUInt16BE(1, 4);
  return Buffer.concat([head, ...name.split('.').map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l)])), Buffer.from([0, 0, 1, 0, 1])]);
}
async function ask(p, id) {
  const s = dgram.createSocket('udp4'); let timer;
  try {
    return await new Promise((resolve, reject) => {
      timer = setTimeout(() => reject(new Error('DNS test timeout')), 4000);
      s.once('error', reject); s.once('message', (answer) => { assert.equal(answer.readUInt16BE(2) & 15, 0); resolve(answer); });
      s.send(query(id), p, '127.0.0.1');
    });
  } finally { clearTimeout(timer); s.close(); }
}
(async () => {
  assert.ok(process.env.DNSDADDY_UI_BINARY && process.env.DNSDADDY_UI_BROWSER, 'binary and browser must be supplied; this gate must not silently skip');
  const work = await fs.mkdtemp(path.join(os.tmpdir(), 'dnsdaddy-refresh-'));
  const upstream = dgram.createSocket('udp4');
  await new Promise((resolve) => upstream.bind(0, '127.0.0.1', resolve));
  upstream.on('message', (message, peer) => {
    let end = 12; while (message[end]) end += message[end] + 1; end += 5;
    const head = Buffer.from(message.subarray(0, 12)); head.writeUInt16BE(0x8180, 2); head.writeUInt16BE(1, 6); head.writeUInt32BE(0, 8);
    upstream.send(Buffer.concat([head, message.subarray(12, end), Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 8, 8, 4, 4])]), peer.port, peer.address);
  });
  const httpPort = await port(), dnsPort = await port();
  const base = `http://127.0.0.1:${httpPort}`, password = 'local-refresh-regression-password';
  const config = path.join(work, 'config.yaml');
  await fs.writeFile(config, `data_dir: ${work}/data\ndns:\n  listen_udp: "127.0.0.1:${dnsPort}"\n  listen_tcp: "127.0.0.1:${dnsPort}"\n  upstreams: ["127.0.0.1:${upstream.address().port}"]\nhttp:\n  listen: "127.0.0.1:${httpPort}"\n  admin_password: "${password}"\nfeeds:\n  refresh_on_start: false\nlog:\n  query_log: false\n`);
  const app = spawn(process.env.DNSDADDY_UI_BINARY, ['-config', config], { stdio: ['ignore', 'pipe', 'pipe'] });
  let logs = '', browser;
  app.stdout.on('data', (b) => { logs += b; }); app.stderr.on('data', (b) => { logs += b; });
  try {
    for (let n = 0; n < 100; n++) {
      if (app.exitCode !== null) throw new Error(logs);
      try { if ((await fetch(base + '/api/v1/health')).ok) break; } catch { /* not listening yet */ }
      if (n === 99) throw new Error('Daemon did not start: ' + logs); await delay(100);
    }
    browser = await chromium.launch({ executablePath: process.env.DNSDADDY_UI_BROWSER, args: ['--no-sandbox'] });
    const context = await browser.newContext(); const page = await context.newPage();
    const errors = []; page.on('pageerror', (e) => errors.push(e.message));
    await page.goto(base); await page.locator('#password').fill(password); await page.locator('#login-form button[type=submit]').click();
    await page.locator('#resolver-live').waitFor(); await ask(dnsPort, 1);
    await page.waitForFunction(() => Number(document.querySelector('[data-live-count=received]').textContent.replaceAll(',', '')) >= 1);
    const original = await page.locator('#daddybound-mode-form').elementHandle();
    let release, arrived;
    const held = new Promise((resolve) => { release = resolve; });
    const requestSeen = new Promise((resolve) => { arrived = resolve; });
    await page.route(base + '/api/v1/overview', async (route) => { arrived(); await held; await route.continue(); });
    await page.evaluate(() => { document.activeElement.blur(); window.pendingRefresh = router.reload({ automatic: true }); });
    await requestSeen;
    await page.locator('#daddybound-mode-form [value=off]').focus();
    release();
    assert.equal(await page.evaluate(() => window.pendingRefresh), false, 'history replacement is abandoned to preserve input');
    await page.unroute(base + '/api/v1/overview');
    assert.ok(await original.evaluate((e) => e.isConnected), 'focused form must not be replaced');
    await ask(dnsPort, 2);
    await page.waitForFunction(() => Number(document.querySelector('[data-live-count=received]').textContent.replaceAll(',', '')) >= 2, null, { timeout: 6000 });
    assert.ok(await page.locator('#daddybound-mode-form [value=off]').evaluate((e) => e === document.activeElement), 'polling preserves focus');
    assert.deepEqual(errors, []);
    console.log('PASS: real DNS counters continue after an automatic refresh is discarded; form and focus survive.');
  } finally {
    if (browser) await browser.close();
    app.kill('SIGTERM'); await Promise.race([new Promise((resolve) => app.once('exit', resolve)), delay(3000)]);
    if (app.exitCode === null) app.kill('SIGKILL');
    upstream.close(); await fs.rm(work, { recursive: true, force: true });
  }
})().catch((e) => { console.error(e); process.exitCode = 1; });
