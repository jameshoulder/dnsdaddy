/*
 * DNS Daddy dashboard.
 *
 * No framework and no build step: the whole UI is this file, served from the
 * binary. Interpolated values go through the `html` tagged template, which
 * escapes everything by default — domain names in the query log come from
 * whatever a device on the network asked for, so they are untrusted input.
 */

'use strict';

/* ---------- tiny helpers ------------------------------------------------ */

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

function esc(value) {
  if (value === null || value === undefined) return '';
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Tagged template that escapes every interpolation. Use `raw()` to opt out. */
function html(strings, ...values) {
  return strings.reduce((out, str, i) => {
    if (i === 0) return str;
    const v = values[i - 1];
    const rendered = v && v.__raw ? v.value : esc(v);
    return out + rendered + str;
  }, '');
}

const raw = (value) => ({ __raw: true, value });

const CATEGORY_COLOURS = {
  malware: '#bfed6d',
  phishing: '#7ec4ff',
  c2: '#ffb45a',
  cryptomining: '#f97583',
  'newly-registered': '#c792ea',
  ads: '#5eead4',
  adult: '#fda4af',
  gambling: '#fbbf24',
  custom: '#94a3b8',
};

const colourFor = (cat) => CATEGORY_COLOURS[cat] || '#94a3b8';

function sanitize(htmlString) {
  const doc = new DOMParser().parseFromString(htmlString, 'text/html');
  for (const el of doc.querySelectorAll('script, iframe, object, embed')) {
    el.remove();
  }
  for (const el of doc.querySelectorAll('*')) {
    for (const attr of [...el.attributes]) {
      if (attr.name.startsWith('on')) {
        el.removeAttribute(attr.name);
      }
      if (['href', 'src', 'action', 'formaction'].includes(attr.name) &&
          /^\s*javascript:/i.test(attr.value)) {
        el.removeAttribute(attr.name);
      }
    }
  }
  return doc.body.innerHTML;
}

function num(n) {
  if (n === null || n === undefined) return '—';
  return Number(n).toLocaleString('en-GB');
}

function compact(n) {
  if (n === null || n === undefined) return '—';
  n = Number(n);
  if (n < 1000) return String(n);
  if (n < 1e6) return (n / 1e3).toFixed(n < 1e4 ? 1 : 0) + 'k';
  return (n / 1e6).toFixed(1) + 'M';
}

function relTime(iso) {
  if (!iso) return 'never';
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return '—';
  const secs = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (secs < 10) return 'just now';
  if (secs < 60) return `${secs}s ago`;
  const mins = Math.round(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.round(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

function clockTime(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function duration(seconds) {
  seconds = Math.max(0, Math.floor(seconds || 0));
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  return `${m}m`;
}

/* ---------- API --------------------------------------------------------- */

class ApiError extends Error {
  constructor(status, message, body) {
    super(message);
    this.status = status;
    // The parsed response, so a caller can act on structured detail rather
    // than parsing prose. The public-address confirmation needs the exact
    // ranges the server objected to, and inventing them here would mean two
    // implementations of a security rule that must have one.
    this.body = body || null;
  }
}

async function api(path, options = {}) {
  const res = await fetch(`/api/v1${path}`, {
    credentials: 'same-origin',
    headers: options.body ? { 'Content-Type': 'application/json' } : {},
    ...options,
  });

  if (res.status === 401) {
    showLogin();
    throw new ApiError(401, 'Not signed in');
  }
  if (res.status === 204) return null;

  const text = await res.text();
  let body = null;
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = { error: text };
    }
  }
  if (!res.ok) {
    throw new ApiError(res.status, (body && body.error) || `Request failed (${res.status})`, body);
  }
  return body;
}

const apiGet = (path) => api(path);
const apiSend = (method, path, body) =>
  api(path, { method, body: body === undefined ? undefined : JSON.stringify(body) });

/* ---------- toasts ------------------------------------------------------ */

function toast(message, kind = 'info') {
  const el = document.createElement('div');
  el.className = `toast${kind === 'error' ? ' error' : ''}`;
  el.textContent = message;
  $('#toasts').append(el);
  setTimeout(() => el.remove(), kind === 'error' ? 7000 : 4000);
}

function reportError(err) {
  if (err instanceof ApiError && err.status === 401) return;
  console.error(err);
  toast(err.message || 'Something went wrong', 'error');
}

/* ---------- charts ------------------------------------------------------ */

/**
 * Area chart of total vs blocked queries. Drawn as raw SVG rather than pulling
 * in a charting library — two series over 24 points does not justify 200 kB.
 */
function areaChart(buckets) {
  if (!buckets || !buckets.length) {
    return html`<div class="empty">No query activity recorded yet.</div>`;
  }

  const W = 720;
  const H = 180;
  const padX = 8;
  const padTop = 12;
  const padBottom = 26;
  const max = Math.max(1, ...buckets.map((b) => b.total));
  const stepX = (W - padX * 2) / Math.max(1, buckets.length - 1);
  const plotH = H - padTop - padBottom;

  const pointsFor = (key) =>
    buckets.map((b, i) => {
      const x = padX + i * stepX;
      const y = padTop + plotH - (b[key] / max) * plotH;
      return [x, y];
    });

  const line = (pts) => pts.map(([x, y], i) => `${i ? 'L' : 'M'}${x.toFixed(1)} ${y.toFixed(1)}`).join(' ');
  const area = (pts) => `${line(pts)} L${(padX + (buckets.length - 1) * stepX).toFixed(1)} ${padTop + plotH} L${padX} ${padTop + plotH} Z`;

  const totalPts = pointsFor('total');
  const blockedPts = pointsFor('blocked');

  // Label roughly every 4 hours so the axis stays legible on a phone. The
  // first and last labels anchor inward, otherwise a centred label at x=0 is
  // half-clipped by the viewBox.
  const labelEvery = Math.max(1, Math.round(buckets.length / 6));
  const labels = buckets
    .map((b, i) => ({ b, i }))
    .filter(({ i }) => i % labelEvery === 0)
    .map(({ b, i }) => {
      const x = padX + i * stepX;
      const anchor = i === 0 ? 'start' : i >= buckets.length - 1 ? 'end' : 'middle';
      return `<text x="${x.toFixed(1)}" y="${H - 8}" fill="#a3acba" font-size="10" text-anchor="${anchor}">${esc(b.label)}</text>`;
    })
    .join('');

  const gridlines = [0.25, 0.5, 0.75]
    .map((f) => {
      const y = padTop + plotH * f;
      return `<line x1="${padX}" y1="${y}" x2="${W - padX}" y2="${y}" stroke="#2a313b" stroke-width="1" stroke-dasharray="3 4"/>`;
    })
    .join('');

  return html`
    <svg class="chart" viewBox="0 0 ${raw(W)} ${raw(H)}" preserveAspectRatio="none" role="img"
         aria-label="DNS queries and blocks over time">
      <defs>
        <linearGradient id="areaFill" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="#bfed6d" stop-opacity="0.28"/>
          <stop offset="100%" stop-color="#bfed6d" stop-opacity="0"/>
        </linearGradient>
      </defs>
      ${raw(gridlines)}
      <path d="${raw(area(totalPts))}" fill="url(#areaFill)"/>
      <path d="${raw(line(totalPts))}" fill="none" stroke="#bfed6d" stroke-width="2"
            stroke-linejoin="round" stroke-linecap="round" vector-effect="non-scaling-stroke"/>
      <path d="${raw(line(blockedPts))}" fill="none" stroke="#f97583" stroke-width="1.75"
            stroke-linejoin="round" stroke-linecap="round" vector-effect="non-scaling-stroke"/>
      ${raw(labels)}
    </svg>
    <div class="chart-legend">
      <span><i class="swatch" data-bg="#bfed6d"></i>Total queries · peak ${compact(max)}/h</span>
      <span><i class="swatch" data-bg="#f97583"></i>Blocked</span>
    </div>
  `;
}

/** Horizontal bar list, used for category breakdowns. */
function barList(rows, { colour } = {}) {
  if (!rows || !rows.length) {
    return html`<div class="empty">Nothing blocked in this period.</div>`;
  }
  const max = Math.max(...rows.map((r) => r.count));
  return rows
    .map(
      (r) => html`
        <div class="bar-row">
          <span class="nowrap">${r.label}</span>
          <span class="bar-track">
            <span class="bar-fill" data-width="${raw(Math.max(2, (r.count / max) * 100).toFixed(1))}"
                  data-bg="${colour ? colour(r) : colourFor(r.category)}"></span>
          </span>
          <span class="num muted">${num(r.count)}</span>
        </div>
      `
    )
    .join('');
}

/* ---------- reusable fragments ------------------------------------------ */

function metricCard({ label, value, sub, tone }) {
  return html`
    <div class="card metric ${tone || ''}">
      <div class="label">${label}</div>
      <div class="value">${value}</div>
      ${raw(sub ? html`<div class="sub">${sub}</div>` : '')}
    </div>
  `;
}

function statusBadge(status) {
  const map = {
    protected: ['ok', 'Protected'],
    operational: ['ok', 'Operational'],
    healthy: ['ok', 'Healthy'],
    ok: ['ok', 'OK'],
    degraded: ['warn', 'Degraded'],
    'no-traffic': ['warn', 'No traffic yet'],
    disabled: ['', 'Disabled'],
    offline: ['bad', 'Offline'],
    down: ['bad', 'Down'],
  };
  const [cls, text] = map[status] || ['', status || 'Unknown'];
  return html`<span class="badge ${cls}">${text}</span>`;
}

/**
 * Renders configuration problems that stop the resolver serving clients.
 *
 * This is the dashboard's answer to a resolver that reports itself
 * operational while refusing every real query. A green tick above a broken
 * deployment is worse than no tick at all, so anything the server reports as
 * warn or fail is shown here, above everything else, with the evidence it was
 * reached from and what to do about it.
 *
 * Passing checks are deliberately not listed: this is an exception report, not
 * a status page.
 */
function diagnosticsBanner(diagnostics) {
  if (!diagnostics || !Array.isArray(diagnostics.checks)) return '';

  const problems = diagnostics.checks.filter((c) => c.status === 'fail' || c.status === 'warn');
  if (problems.length === 0) return '';

  const failed = problems.some((c) => c.status === 'fail');
  const items = problems
    .map(
      (c) => html`
        <li class="diag-item">
          <span class="badge ${c.status === 'fail' ? 'bad' : 'warn'}">${c.status.toUpperCase()}</span>
          <div>
            <div class="diag-summary">${c.summary}</div>
            ${raw((c.evidence || []).map((e) => html`<div class="diag-evidence">${e}</div>`).join(''))}
            ${raw(c.action ? html`<div class="diag-action">${c.action}</div>` : '')}
          </div>
        </li>`,
    )
    .join('');

  return html`
    <div class="card diag-banner ${failed ? 'diag-fail' : 'diag-warn'}">
      <div class="diag-title">
        ${failed ? 'CONFIGURATION PROBLEM' : 'CONFIGURATION WARNING'}
      </div>
      <p class="muted small diag-lede">
        ${failed
          ? 'DNS Daddy is running, but part of this configuration stops clients using it.'
          : 'DNS Daddy is running and nothing here is a definite fault — but each of these is worth knowing about, including anything it could not confirm.'}
      </p>
      <ul class="diag-list">${raw(items)}</ul>
      <p class="muted small">Run <code>dnsdaddy doctor</code> on the server for the full report.</p>
    </div>`;
}

/**
 * Shown until a device on the network has actually used the resolver.
 *
 * A fresh install looks identical whether it is working perfectly with nothing
 * pointed at it, or refusing every client — both produce empty charts. This
 * says which, and it says it from measurements rather than from guesses.
 *
 * The guess it used to make was "no network carries a permission, so every
 * client will be REFUSED". That is false on a stock LAN install, which has no
 * permissions at all and serves every private range perfectly well, and being
 * confidently wrong about why DNS is not working is the exact failure this
 * product exists to stop producing. What is left is three states, each backed
 * by something the server actually knows:
 *
 *   queries are arriving and being refused  → the ACL is the problem, say so
 *   nothing but loopback may resolve        → nothing can reach it, say so
 *   otherwise                               → nothing has tried yet, test it
 */
function firstClientCard(overview) {
  if (typeof window === 'undefined') return '';
  if (!overview || overview.hasSeenClients) return '';

  // Client addresses are not recorded, so "no clients" would be a statement
  // about the privacy setting rather than about the network.
  if (!overview.clientAttribution) return '';

  // The address the browser reached the dashboard on is almost always the
  // right one to hand a test client — unless it is loopback, which means an
  // SSH tunnel or a proxy, and the DNS address is something this page cannot
  // know.
  const host = window.location.hostname;
  const isLoopback = host === 'localhost' || host === '127.0.0.1' || host === '[::1]' || host === '::1';
  const target = isLoopback ? '<your-server-ip>' : host;

  const footer = html`
    <p class="muted small">
      Run <code>dnsdaddy doctor</code> on the server for the full picture — it
      reports exactly which ranges may resolve, and from which setting.
    </p>`;

  // Measured, not inferred: queries are reaching DNS Daddy and being turned
  // away on their source address. That rules out firewalls, routing and port
  // conflicts in one step.
  if (overview.refusedClients > 0) {
    return html`
      <div class="card first-client">
        <div class="first-client-title">Clients are being refused</div>
        <p class="muted small">
          ${num(overview.refusedClients)} quer${overview.refusedClients === 1 ? 'y has' : 'ies have'}
          reached DNS Daddy and been answered <code>REFUSED</code>, because the
          address they came from is not permitted to use this resolver. Nothing
          is broken — DNS Daddy is declining on purpose.
        </p>
        <ol class="small first-client-steps">
          <li>Open <a href="#/networks">Networks</a> and add the client or network.</li>
          <li>Tick <strong>Allow this network to use DNS Daddy</strong>.</li>
          <li>Try again — it takes effect on the next query.</li>
        </ol>
        <p class="muted small">
          Refused addresses are deliberately not logged, so compare the address
          your client actually has against the permitted ranges on the Networks
          page.
        </p>
        ${raw(footer)}
      </div>`;
  }

  // Also measured: the effective ACL admits nothing but this machine.
  //
  // Scoped to clients identified by their source address, which is what the
  // ACL governs. A DoH or DoT client presenting a network's token is
  // identified by the token and resolves regardless — saying "every other
  // device" would contradict both the resolver and the Networks page, and
  // over-claiming is the fault this card exists to stop making.
  if (overview.servesOnlyLoopback) {
    return html`
      <div class="card first-client">
        <div class="first-client-title">Only this machine may use the resolver</div>
        <p class="muted small">
          The client ACL permits loopback and nothing else, so a device asking
          over ordinary DNS from any other address is answered
          <code>REFUSED</code>. Testing before you change that will fail, and
          the failure will not tell you why.
        </p>
        <p class="muted small">
          DNS-over-HTTPS and DNS-over-TLS clients holding a network's token are
          identified by that token rather than by where they connect from, so
          they are unaffected by this.
        </p>
        <ol class="small first-client-steps">
          <li>Open <a href="#/networks">Networks</a> and add your client or network.</li>
          <li>Tick <strong>Allow this network to use DNS Daddy</strong>.</li>
          <li>Point the device at <code>${target}</code> for DNS.</li>
          <li>Test it: <code>nslookup example.com ${target}</code></li>
        </ol>
        <p class="muted small">
          It takes effect immediately — there is nothing to restart and no file
          to edit.
        </p>
        ${raw(footer)}
      </div>`;
  }

  return html`
    <div class="card first-client">
      <div class="first-client-title">No devices have used this resolver yet</div>
      <p class="muted small">
        DNS Daddy is running and nothing has sent it a query, which is expected
        until you point something at it.
      </p>
      <p class="small">Try this from a machine you expect it to serve:</p>
      <pre class="first-client-cmd">nslookup example.com ${target}</pre>
      <p class="muted small">
        ${raw(isLoopback
          ? 'You are viewing this over loopback, so this page cannot tell which address your clients should use — substitute the server\'s LAN address.'
          : 'Then reload this page: the query should appear in the Query log, attributed to that machine.')}
      </p>
      <p class="muted small">
        If it comes back <code>REFUSED</code>, that address is not permitted
        yet — add it under <a href="#/networks">Networks</a> and tick
        <strong>Allow this network to use DNS Daddy</strong>.
      </p>
      ${raw(footer)}
    </div>`;
}

function categoryBadge(category, label) {
  if (!category) return html`<span class="muted">—</span>`;
  return html`<span class="badge" data-fg="${colourFor(category)}">${label || category}</span>`;
}

// emptyState is what most of a fresh install looks like, so it is written to
// read as "nothing has happened yet, and here is what happens next" rather
// than as a feature that failed to load. icon and action are optional; the
// two-argument calls that predate them still work.
function emptyState(title, body, opts = {}) {
  const icon = opts.icon || '○';
  const action = opts.action ? html`<div class="row">${raw(opts.action)}</div>` : '';
  return html`<div class="empty">
    <span class="empty-ico" aria-hidden="true">${icon}</span>
    <strong>${title}</strong>
    <p>${body}</p>
    ${raw(action)}
  </div>`;
}

function copyBlock(text) {
  return html`
    <div class="copy-row">
      <div class="code">${text}</div>
      <button class="btn btn-ghost btn-sm" data-copy="${text}">Copy</button>
    </div>
  `;
}

/* ---------- DNS Daddy Threat Observatory --------------------------------- */

/*
 * The Observatory is an ordinary built-in feed: the same row in the same
 * table, refreshed, cached, validated and indexed by the same machinery as
 * URLhaus. What it gets that the others do not is this card, because it is the
 * one source an operator has to opt into, and burying that behind the advanced
 * feeds page means most installs never get it.
 *
 * Everything below reads the state the feeds endpoint already reports. There
 * is no Observatory-specific state anywhere, on the server or here, and no
 * separate blocking mode — enabling it is a PATCH on a feed row followed by a
 * refresh of that row.
 */

const OBSERVATORY_CATEGORIES = 'Malware · Phishing · C2 · Cryptomining';

// The categories Observatory indicators are filed under, for the note about
// which of them the operator's policies actually enforce.
const OBSERVATORY_CATEGORY_IDS = ['malware', 'phishing', 'c2', 'cryptomining'];

/**
 * Which state the card is in, derived from the feed row.
 *
 * "Active" is decided by `loaded` — whether this feed is in the index that is
 * answering queries right now — and never by the download history alone. That
 * distinction is the whole job of this function. A feed that downloaded
 * successfully last week and whose cached file has since gone missing has a
 * healthy lastSuccessAt, no lastError, and is blocking precisely nothing: the
 * rebuild at the last restart skipped it. Reporting that as Active is the most
 * misleading thing this card could do, so the two failure modes are kept
 * apart:
 *
 *   loaded                     → the index has it; the card may say Active
 *   !loaded && lastSuccessAt   → downloaded once, unusable now  ("unusable")
 *   !loaded && lastError       → never downloaded, and we know why ("unavailable")
 *   !loaded && neither         → enabled, nothing attempted yet  ("pending")
 *
 * A feed that is loaded but whose most recent refresh failed is "stale": the
 * last known good copy is in the index and still blocking, and only the
 * refresh is broken.
 */
function observatoryState(feed, refreshing) {
  if (!feed) return 'missing';
  if (!feed.enabled) return 'off';
  if (refreshing) return 'connecting';
  if (!feed.loaded) {
    if (feed.lastSuccessAt) return 'unusable';
    return feed.lastError ? 'unavailable' : 'pending';
  }
  return feed.lastError ? 'stale' : 'active';
}

/**
 * A plain-English summary of a feed error, with the raw text still available
 * behind "View error".
 *
 * The 404 case is called out by name because it is the expected answer until
 * the Observatory's JSON API ships: an operator who enables this today should
 * be told the endpoint is not live yet, not left reading an HTTP status.
 */
function observatoryErrorSummary(error) {
  if (!error) return '';
  if (/HTTP 404/.test(error)) return 'The Observatory feed endpoint is not available yet.';
  if (/HTTP 401|HTTP 403/.test(error)) return 'The Observatory refused the request.';
  if (/HTTP 5\d\d/.test(error)) return 'The Observatory is having server trouble.';
  if (/rejected download/.test(error)) return 'The Observatory served a feed DNS Daddy could not trust, so the previous copy was kept.';
  if (/timeout|deadline|no such host|connection refused/i.test(error)) return 'The Observatory could not be reached from this server.';
  return 'The Observatory could not be refreshed.';
}

function observatoryErrorDetails(error) {
  if (!error) return '';
  return html`
    <details class="finding obs-error">
      <summary>View error</summary>
      <div class="code obs-error-text">${error}</div>
    </details>
  `;
}

/** The privacy statement. Shown wherever the card offers to turn this on. */
function observatoryPrivacyNote() {
  return html`
    <p class="muted small obs-privacy">
      DNS Daddy periodically downloads the public threat feed from
      <span class="mono">threats.dnsdaddy.dev</span>. DNS query logs are not uploaded.
    </p>
  `;
}

/**
 * Which Observatory categories the operator's policies actually enforce.
 *
 * Activation supplies intelligence; it does not tick a single category box.
 * If somebody has deliberately turned cryptomining off, enabling this feed
 * must not quietly turn it back on — so the card says plainly what is and is
 * not being enforced rather than implying four categories of protection it
 * does not control.
 */
function observatoryEnforcement(policies) {
  if (!policies || !policies.length) return '';
  const enforced = new Set();
  for (const p of policies) {
    for (const c of p.categories || []) enforced.add(c);
  }
  const on = OBSERVATORY_CATEGORY_IDS.filter((c) => enforced.has(c));
  const off = OBSERVATORY_CATEGORY_IDS.filter((c) => !enforced.has(c));
  const label = (c) => (c === 'c2' ? 'C2' : c.charAt(0).toUpperCase() + c.slice(1));

  if (!off.length) {
    return html`<p class="muted small">Your policies enforce every category the Observatory files indicators under.</p>`;
  }
  return html`
    <p class="muted small">
      Your policies enforce ${on.length ? on.map(label).join(', ') : 'none of these categories'}.
      Indicators tagged ${off.map(label).join(', ')} are indexed but not blocked, because no policy
      enables ${off.length === 1 ? 'that category' : 'those categories'} —
      turning this feed on does not change your policies.
    </p>
  `;
}

/**
 * The activation card. `feed` is the Observatory row from GET /feeds.
 */
function observatoryCard(feed, { refreshing = false, policies = null } = {}) {
  const state = observatoryState(feed, refreshing);

  if (state === 'missing') {
    return html`
      <div class="card observatory" id="observatory-card">
        <div class="card-head"><div><h2>DNS Daddy Threat Observatory</h2></div></div>
        <p class="muted">
          The built-in Observatory feed is not in this install's feed list. It is seeded on
          first run; if it is missing, restart DNS Daddy or add it as a custom feed.
        </p>
      </div>
    `;
  }

  const badge = {
    active: html`<span class="badge ok">Active</span>`,
    connecting: html`<span class="badge info">Connecting…</span>`,
    stale: html`<span class="badge warn">Attention</span>`,
    unusable: html`<span class="badge bad">Not blocking</span>`,
    unavailable: html`<span class="badge warn">Attention</span>`,
    pending: html`<span class="badge warn">Pending</span>`,
    off: '',
  }[state];

  const bodies = {
    off: () => html`
      <p>Use live DNS threat intelligence published by the DNS Daddy Threat Observatory.</p>
      <p class="obs-cats">${OBSERVATORY_CATEGORIES}</p>
      <p class="muted small">No account or API key required.</p>
      <div class="row obs-actions">
        <button class="btn btn-primary" id="observatory-enable">Enable Threat Observatory</button>
      </div>
      ${raw(observatoryPrivacyNote())}
    `,

    connecting: () => html`
      <p class="obs-progress-lead">Connecting to the Observatory…<br>Downloading threat intelligence…</p>
      <div class="obs-progress" role="progressbar" aria-label="Downloading threat intelligence"><span></span></div>
      <p class="muted small">
        Nothing from this feed is enforced until the first download has been validated.
      </p>
    `,

    active: () => html`
      <p class="obs-count"><strong>${num(feed.indexedDomains)}</strong> domains indexed</p>
      <p class="muted small">Updated ${relTime(feed.lastRefreshedAt)}</p>
      <p class="obs-cats">${OBSERVATORY_CATEGORIES}</p>
      <p class="muted small">Threat intelligence is refreshed automatically with your other feeds.</p>
      ${raw(observatoryEnforcement(policies))}
      <div class="row obs-actions">
        <a class="btn btn-ghost" href="#/feeds">View details</a>
        <button class="btn btn-ghost" id="observatory-disable">Disable</button>
      </div>
    `,

    stale: () => html`
      <p>${observatoryErrorSummary(feed.lastError)}</p>
      <p class="obs-count small">Last successful intelligence: <strong>${relTime(feed.lastSuccessAt)}</strong></p>
      <p class="muted small">
        DNS Daddy is continuing to use the last known good feed —
        ${num(feed.indexedDomains)} domains from it are still indexed and still blocked.
      </p>
      ${raw(observatoryErrorDetails(feed.lastError))}
      <div class="row obs-actions">
        <button class="btn btn-primary" id="observatory-retry">Retry</button>
        <a class="btn btn-ghost" href="#/feeds">View details</a>
        <button class="btn btn-ghost" id="observatory-disable">Disable</button>
      </div>
    `,

    unavailable: () => html`
      <p>Enabled, but threat intelligence has not been downloaded yet.</p>
      <p class="muted small">${observatoryErrorSummary(feed.lastError)}</p>
      ${raw(observatoryErrorDetails(feed.lastError))}
      <div class="row obs-actions">
        <button class="btn btn-primary" id="observatory-retry">Retry connection</button>
        <button class="btn btn-ghost" id="observatory-disable">Disable</button>
      </div>
    `,

    // Downloaded successfully at some point, but the cached file is not in
    // the index now — it went missing, or it would not parse on the way in.
    // The feed row looks healthy and the resolver is blocking nothing from it,
    // which is the one situation where trusting the timestamps would tell an
    // operator the opposite of the truth.
    unusable: () => html`
      <p>The Observatory is enabled but is <strong>not currently blocking anything</strong>.</p>
      <p class="muted small">
        It downloaded successfully ${relTime(feed.lastSuccessAt)}, but that copy could not be
        loaded into the running blocklist${feed.loadError ? ` — ${feed.loadError}` : ''}.
        Downloading it again will fix it.
      </p>
      ${raw(observatoryErrorDetails(feed.lastError))}
      <div class="row obs-actions">
        <button class="btn btn-primary" id="observatory-retry">Download again</button>
        <a class="btn btn-ghost" href="#/feeds">View details</a>
        <button class="btn btn-ghost" id="observatory-disable">Disable</button>
      </div>
    `,

    pending: () => html`
      <p>Enabled, but threat intelligence has not been downloaded yet.</p>
      <div class="row obs-actions">
        <button class="btn btn-primary" id="observatory-retry">Retry connection</button>
        <button class="btn btn-ghost" id="observatory-disable">Disable</button>
      </div>
    `,
  };

  return html`
    <div class="card observatory" id="observatory-card" data-state="${state}">
      <div class="card-head">
        <div>
          <h2>DNS Daddy Threat Observatory</h2>
          <p>Live DNS threat intelligence from DNS Daddy.</p>
        </div>
        <div class="row-end">${raw(badge)}</div>
      </div>
      ${raw(bodies[state]())}
    </div>
  `;
}

/**
 * Wire the card's buttons. Safe to call on a page that has no card.
 *
 * Every button is a call to an endpoint that already existed for feeds, or —
 * in the case of the single-feed refresh — the narrow version of one. None of
 * it touches policies, categories, or any other feed.
 */
function mountObservatoryCard(feedId) {
  const enable = $('#observatory-enable');
  if (enable) {
    enable.addEventListener('click', async () => {
      enable.disabled = true;
      enable.textContent = 'Connecting…';
      try {
        await apiSend('PATCH', `/feeds/${feedId}`, { enabled: true });
      } catch (err) {
        reportError(err);
        enable.disabled = false;
        enable.textContent = 'Enable Threat Observatory';
        return;
      }
      await runObservatoryRefresh(feedId);
    });
  }

  const retry = $('#observatory-retry');
  if (retry) {
    retry.addEventListener('click', async () => {
      retry.disabled = true;
      retry.textContent = 'Connecting…';
      await runObservatoryRefresh(feedId);
    });
  }

  const disable = $('#observatory-disable');
  if (disable) {
    disable.addEventListener('click', async () => {
      disable.disabled = true;
      try {
        // Only this feed. Every other feed, and every policy, is untouched;
        // the server rebuilds the index so its domains stop being blocked
        // without waiting for the next scheduled refresh.
        await apiSend('PATCH', `/feeds/${feedId}`, { enabled: false });
        toast('Threat Observatory disabled — your other feeds are unchanged');
      } catch (err) {
        reportError(err);
      }
      await router.reload();
    });
  }
}

/**
 * Refresh the Observatory feed now and follow it to a result.
 *
 * This is the second half of one-click activation: enabling a feed that then
 * sits untouched until the next scheduled refresh — up to twelve hours later —
 * is not an activated feed, it is a promise. So the row is refreshed
 * immediately through the ordinary feed machinery, the card shows the download
 * happening, and the operator is told what actually came back.
 */
async function runObservatoryRefresh(feedId) {
  const route = router.current;
  // Paint the connecting state as soon as a refresh is actually in flight —
  // ours, or the one we are queued behind — and not before.
  let painted = false;
  const data = await claimRefresh(feedId, {
    onRunning: async () => {
      if (painted) return;
      painted = true;
      await router.reload();
    },
  });
  await router.reload(); // the outcome

  const feed = data && (data.feeds || []).find((f) => f.id === feedId);
  if (feed) {
    if (feed.lastError) {
      toast(observatoryErrorSummary(feed.lastError), 'error');
    } else if (feed.loaded) {
      toast(`Threat Observatory active — ${num(feed.indexedDomains)} domains indexed`);
    }
  }

  // Only repaint if the operator is still on the page they clicked from.
  if (router.current === route) await router.reload();
}

/**
 * Refresh one feed, waiting for the refresh slot if something else holds it.
 *
 * The server serialises refreshes: a second one is refused with 409 rather
 * than queued. Treating that 409 as "fine, the running refresh will cover us"
 * is wrong, and quietly so. A full refresh reads its feed list before it starts
 * downloading, so one that began before this feed was enabled will never fetch
 * it; nor will a targeted refresh of some other feed. The operator would be
 * left with an enabled feed, no download, and a card that had claimed to be
 * connecting.
 *
 * So a 409 means wait for the slot and ask again, up to a bounded number of
 * attempts. Nothing here starts a concurrent refresh — the server owns that
 * decision and this only ever asks.
 */
async function claimRefresh(feedId, opts = {}) {
  const {
    attempts = 4,
    onRunning = null,
    // Injected so the retry sequence can be tested without a server. The
    // defaults are the only thing the dashboard ever uses.
    post = (id) => apiSend('POST', `/feeds/${id}/refresh`),
    waitIdle = waitForFeedRefresh,
    read = () => apiGet('/feeds').catch(() => null),
    onError = reportError,
    notify = toast,
  } = opts;

  let data = null;
  for (let i = 0; i < attempts; i++) {
    try {
      await post(feedId);
      if (onRunning) await onRunning();
      return await waitIdle();
    } catch (err) {
      if (!(err instanceof ApiError && err.status === 409)) {
        onError(err);
        return await read();
      }
      // Somebody else holds the slot. Wait for them to finish, then ask again.
      if (onRunning) await onRunning();
      data = await waitIdle();
    }
  }
  notify('Another feed refresh kept the queue busy — try again in a moment', 'error');
  return data;
}

/** Poll the feeds endpoint until no refresh is running, then return it. */
function waitForFeedRefresh({ intervalMs = 2000, timeoutMs = 180000 } = {}) {
  return new Promise((resolve) => {
    const started = Date.now();
    const poll = setInterval(async () => {
      let data = null;
      try {
        data = await apiGet('/feeds');
      } catch {
        clearInterval(poll);
        resolve(null);
        return;
      }
      if (!data.refreshing || Date.now() - started > timeoutMs) {
        clearInterval(poll);
        resolve(data);
      }
    }, intervalMs);
  });
}

/**
 * One row per feed, for the dashboard's threat-intelligence panel.
 *
 * Reuses the feed rows the feeds page already renders rather than keeping a
 * second notion of feed health anywhere.
 */
function feedStatusBadge(feed) {
  if (!feed.enabled) return html`<span class="badge">Off</span>`;
  // Same rule as the Observatory card: "Active" means this feed is in the
  // index answering queries, not that a download once succeeded.
  if (!feed.loaded) {
    if (feed.lastSuccessAt) return html`<span class="badge bad">Not blocking</span>`;
    return feed.lastError
      ? html`<span class="badge bad">Unavailable</span>`
      : html`<span class="badge warn">Pending</span>`;
  }
  return feed.lastError
    ? html`<span class="badge warn">Stale</span>`
    : html`<span class="badge ok">Active</span>`;
}

/**
 * Compact threat-intelligence health panel for the dashboard.
 *
 * The Observatory sits at the top because it is the one feed that needs a
 * decision from the operator, and it carries an inline Enable button so the
 * decision can be made from the page everybody lands on. It is not presented
 * as better intelligence than the independent sources under it — it is one row
 * in the same list, with the same badge, from the same endpoint.
 */
function threatIntelPanel(data) {
  const feeds = data.feeds || [];
  const observatory = feeds.find((f) => f.id === data.observatoryFeedId);
  const others = feeds.filter((f) => f.id !== data.observatoryFeedId && f.enabled);
  const offCount = feeds.filter((f) => f.id !== data.observatoryFeedId && !f.enabled).length;

  const row = (feed, extra) => html`
    <div class="intel-row">
      <span class="intel-name">${feed.name}</span>
      <span class="intel-status">${raw(extra || feedStatusBadge(feed))}</span>
    </div>
  `;

  const observatoryRow = !observatory
    ? ''
    : observatory.enabled
      ? row(observatory)
      : row(
          observatory,
          html`<button class="btn btn-primary btn-sm" id="observatory-enable">Enable</button>`
        );

  return html`
    <div class="card">
      <div class="card-head">
        <div>
          <h2>Threat intelligence</h2>
          <p>${num(data.totalIndexedDomains)} domains indexed across enabled feeds.</p>
        </div>
        <div class="row-end"><a class="btn btn-ghost btn-sm" href="#/feeds">Manage</a></div>
      </div>
      <div class="intel-list">
        ${raw(observatoryRow)}
        ${raw(others.map((f) => row(f)).join(''))}
      </div>
      ${raw(
        offCount
          ? html`<p class="muted small mt-3">${offCount} further feed${offCount === 1 ? '' : 's'} available but switched off.</p>`
          : ''
      )}
    </div>
  `;
}

/* ---------- pages ------------------------------------------------------- */

const pages = {};

pages.dashboard = {
  title: 'Dashboard',
  subtitle: 'What your network asked for, and what was stopped.',
  async render() {
    const [overview, activity, categories, top, feeds, diagnostics] = await Promise.all([
      apiGet('/overview'),
      apiGet('/activity/queries?hours=24'),
      apiGet('/threats/categories?hours=24'),
      apiGet('/threats/top-domains?days=7&limit=8'),
      apiGet('/feeds'),
      // Tolerate failure: a dashboard that will not load because the
      // diagnostics endpoint is unavailable is a worse outcome than a
      // dashboard without a banner.
      apiGet('/diagnostics').catch(() => null),
    ]);
    this.feeds = feeds;

    const catRows = categories.categories.map((c) => ({
      label: c.label,
      count: c.count,
      category: c.category,
    }));

    return html`
      ${raw(diagnosticsBanner(diagnostics))}
      ${raw(firstClientCard(overview))}
      <div class="section grid grid-4">
        ${raw(metricCard({
          label: 'Protection',
          value: raw(statusBadge(overview.protectionStatus)),
          sub: `${num(overview.blocklistDomains)} domains indexed`,
        }))}
        ${raw(metricCard({
          label: 'Queries (24h)',
          value: compact(overview.queries24h),
          sub: `${num(overview.queries24h)} total`,
        }))}
        ${raw(metricCard({
          label: 'Threats blocked (24h)',
          value: compact(overview.threatsBlocked24h),
          sub: `${overview.blockRate24h}% of all queries`,
          tone: 'accent',
        }))}
        ${raw(metricCard({
          label: 'Networks',
          value: overview.protectedNetworks,
          sub: `${overview.activePolicies} polic${overview.activePolicies === 1 ? 'y' : 'ies'}`,
        }))}
      </div>

      <div class="section card">
        <div class="card-head">
          <div>
            <h2>Query activity</h2>
            <p>Last 24 hours, hourly buckets.</p>
          </div>
        </div>
        ${raw(areaChart(activity.buckets))}
      </div>

      <div class="section grid grid-2">
        <div class="card">
          <div class="card-head"><div><h2>Threats by category</h2><p>Last 24 hours.</p></div></div>
          ${raw(barList(catRows))}
        </div>
        <div class="card">
          <div class="card-head"><div><h2>Most blocked domains</h2><p>Last 7 days.</p></div></div>
          ${raw(
            top.domains.length
              ? html`<div class="table-wrap"><table>
                  <thead><tr><th>Domain</th><th>Category</th><th class="num">Blocks</th></tr></thead>
                  <tbody>${raw(
                    top.domains
                      .map(
                        (d) => html`<tr>
                          <td class="mono">${d.domain}</td>
                          <td>${raw(categoryBadge(d.category))}</td>
                          <td class="num">${num(d.count)}</td>
                        </tr>`
                      )
                      .join('')
                  )}</tbody></table></div>`
              : emptyState('Nothing blocked yet', 'Blocked domains appear here once devices resolve through DNS Daddy.', { icon: '⚠' })
          )}
        </div>
      </div>

      <div class="section grid grid-2">
        ${raw(threatIntelPanel(feeds))}
        <div class="card">
          <div class="card-head"><div><h2>Resolver</h2><p>Uptime and feed freshness.</p></div></div>
          <div class="grid grid-3">
            <div><div class="label muted small">STATUS</div><div>${raw(statusBadge(overview.resolverStatus))}</div></div>
            <div><div class="label muted small">UPTIME</div><div>${duration(overview.uptimeSeconds)}</div></div>
            <div><div class="label muted small">FEEDS REFRESHED</div><div>${relTime(overview.lastFeedRefresh)}</div></div>
          </div>
        </div>
      </div>
    `;
  },
  async mounted() {
    // The panel's inline Enable button runs exactly the same activation as the
    // full card on the Threats page.
    mountObservatoryCard(this.feeds ? this.feeds.observatoryFeedId : '');
  },
};

pages.threats = {
  title: 'Threats',
  subtitle: 'Everything blocked, and why.',
  async render() {
    const [categories, top, recent, feeds, policies] = await Promise.all([
      apiGet('/threats/categories?hours=168'),
      apiGet('/threats/top-domains?days=7&limit=25'),
      apiGet('/queries?action=blocked&limit=50'),
      apiGet('/feeds'),
      apiGet('/policies'),
    ]);
    this.feeds = feeds;

    const catRows = categories.categories.map((c) => ({ label: c.label, count: c.count, category: c.category }));
    const total = catRows.reduce((sum, r) => sum + r.count, 0);
    const observatory = (feeds.feeds || []).find((f) => f.id === feeds.observatoryFeedId);

    return html`
      <div class="section">
        ${raw(observatoryCard(observatory, {
          refreshing: feeds.refreshing,
          policies: policies.policies,
        }))}
      </div>

      <div class="section grid grid-2">
        <div class="card">
          <div class="card-head"><div><h2>By category</h2><p>Last 7 days · ${num(total)} blocked.</p></div></div>
          ${raw(barList(catRows))}
        </div>
        <div class="card">
          <div class="card-head"><div><h2>Repeat offenders</h2><p>Domains blocked most often in 7 days.</p></div></div>
          ${raw(
            top.domains.length
              ? html`<div class="table-wrap"><table>
                  <thead><tr><th>Domain</th><th>Category</th><th class="num">Blocks</th><th>Last seen</th></tr></thead>
                  <tbody>${raw(
                    top.domains
                      .map(
                        (d) => html`<tr>
                          <td class="mono">${d.domain}</td>
                          <td>${raw(categoryBadge(d.category))}</td>
                          <td class="num">${num(d.count)}</td>
                          <td class="muted nowrap">${relTime(d.lastSeen)}</td>
                        </tr>`
                      )
                      .join('')
                  )}</tbody></table></div>`
              : emptyState('No threats blocked yet', 'Either nothing malicious has been requested, or no client is using the resolver yet.', { icon: '⚠', action: '<a class="btn btn-ghost btn-sm" href="#/setup">Check Setup</a>' })
          )}
        </div>
      </div>

      <div class="card">
        <div class="card-head"><div><h2>Recent blocks</h2><p>The last 50 blocked queries, newest first.</p></div></div>
        ${raw(queryTable(recent.queries))}
      </div>
    `;
  },
  async mounted() {
    mountObservatoryCard(this.feeds ? this.feeds.observatoryFeedId : '');
  },
};

/*
 * DNSSEC status as reported by the upstream resolver.
 *
 * Deliberately cautious wording. DNS Daddy forwards rather than validating
 * locally, so "validated" means the upstream said so, and "unvalidated" covers
 * both an unsigned zone and an upstream that does not validate — a forwarder
 * cannot tell those apart. See docs/dnssec.md.
 */
function dnssecBadge(status) {
  const map = {
    validated: ['ok', 'validated', 'The upstream resolver validated this answer against the DNSSEC chain of trust.'],
    unvalidated: ['', 'unvalidated', 'No AD bit came back: either the zone is unsigned or the upstream does not validate.'],
    servfail: ['bad', 'servfail', 'The upstream could not answer. A failed DNSSEC validation is one possible cause among several.'],
  };
  const entry = map[status];
  if (!entry) return html`<span class="muted">—</span>`;
  const [cls, text, title] = entry;
  return html`<span class="badge ${cls}" title="${title}">${text}</span>`;
}

function queryTable(queries) {
  if (!queries || !queries.length) {
    return emptyState('No queries recorded', 'Either query logging is off, or nothing has resolved through DNS Daddy yet.', { icon: '≡', action: '<a class="btn btn-ghost btn-sm" href="#/settings">Check settings</a>' });
  }
  return html`
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Time</th><th>Domain</th><th>Type</th><th>Client</th>
            <th>Action</th><th>DNSSEC</th><th>Reason</th>
          </tr>
        </thead>
        <tbody>
          ${raw(
            queries
              .map(
                (q) => html`
                  <tr>
                    <td class="muted nowrap">${clockTime(q.time)}</td>
                    <td class="mono">${q.domain}</td>
                    <td class="muted">${q.qtype}</td>
                    <td class="mono muted">${q.clientName || q.clientIp || '—'}</td>
                    <td>${raw(
                      q.action === 'blocked'
                        ? html`<span class="badge bad">Blocked</span>`
                        : q.action === 'error'
                          ? html`<span class="badge warn">Error</span>`
                          : html`<span class="badge ok">Allowed</span>`
                    )}</td>
                    <td>${raw(dnssecBadge(q.dnssec))}</td>
                    <td class="muted">${q.reason || '—'}${raw(q.cached ? ' <span class="badge info">cached</span>' : '')}</td>
                  </tr>
                `
              )
              .join('')
          )}
        </tbody>
      </table>
    </div>
  `;
}

pages.queries = {
  title: 'Query log',
  subtitle: 'Every lookup, with a plain-English reason.',
  state: { cursor: 0, rows: [] },
  async render() {
    const [networks] = await Promise.all([apiGet('/networks')]);
    this.state = { cursor: 0, rows: [] };

    return html`
      <div class="card section">
        <div class="row" id="q-filters">
          <input id="q-domain" class="w-260" placeholder="Filter by domain…">
          <select id="q-action" class="w-150">
            <option value="">All actions</option>
            <option value="blocked">Blocked</option>
            <option value="allowed">Allowed</option>
            <option value="error">Errors</option>
          </select>
          <select id="q-network" class="w-200">
            <option value="">All networks</option>
            ${raw(networks.networks.map((n) => html`<option value="${n.id}">${n.name}</option>`).join(''))}
          </select>
          <button class="btn btn-primary" id="q-apply">Apply</button>
          <span class="row-end muted small" id="q-count"></span>
        </div>
      </div>
      <div id="q-results">${raw(emptyState('Loading…', 'Fetching matching queries.', { icon: '·' }))}</div>
      <div class="row mt-4">
        <button class="btn btn-ghost" id="q-more" hidden>Load more</button>
      </div>
    `;
  },
  async mounted() {
    const load = async (append) => {
      const params = new URLSearchParams({ limit: '100' });
      const domain = $('#q-domain').value.trim();
      const action = $('#q-action').value;
      const network = $('#q-network').value;
      if (domain) params.set('domain', domain);
      if (action) params.set('action', action);
      if (network) params.set('networkId', network);
      if (append && this.state.cursor) params.set('cursor', String(this.state.cursor));

      try {
        const data = await apiGet(`/queries?${params}`);
        this.state.cursor = data.nextCursor;
        this.state.rows = append ? this.state.rows.concat(data.queries) : data.queries;
        $('#q-results').innerHTML = queryTable(this.state.rows);
        $('#q-count').textContent = `${this.state.rows.length} row${this.state.rows.length === 1 ? '' : 's'}`;
        $('#q-more').hidden = !data.nextCursor;
      } catch (err) {
        reportError(err);
      }
    };

    $('#q-apply').addEventListener('click', () => {
      this.state.cursor = 0;
      load(false);
    });
    $('#q-domain').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        this.state.cursor = 0;
        load(false);
      }
    });
    $('#q-more').addEventListener('click', () => load(true));
    await load(false);
  },
};

/* ---------- detections -------------------------------------------------- */

const SEVERITY_CLASS = { high: 'bad', medium: 'warn', low: 'info', info: '' };

function severityBadge(sev) {
  const cls = SEVERITY_CLASS[sev] !== undefined ? SEVERITY_CLASS[sev] : '';
  return html`<span class="badge ${cls}">${sev || 'unknown'}</span>`;
}

/**
 * Signal table for one finding.
 *
 * The point of showing floor, ceiling and contribution rather than just a
 * score is that an analyst can check the arithmetic. A number nobody can
 * reproduce is a number nobody should act on.
 */
function signalTable(signals) {
  if (!signals || !signals.length) return '';
  return html`
    <div class="table-wrap">
      <table>
        <thead>
          <tr><th>Signal</th><th class="num">Measured</th><th class="num">Band</th><th class="num">Weight</th><th class="num">Contributed</th></tr>
        </thead>
        <tbody>
          ${raw(
            signals
              .map(
                (s) => html`<tr>
                  <td><span class="mono">${s.name}</span><div class="muted small">${s.description}</div></td>
                  <td class="num mono">${s.value}</td>
                  <td class="num muted mono nowrap">${s.floor} – ${s.ceiling}</td>
                  <td class="num muted mono">${s.weight}</td>
                  <td class="num mono">${s.contribution}</td>
                </tr>`
              )
              .join('')
          )}
        </tbody>
      </table>
    </div>
  `;
}

function evidenceList(evidence) {
  if (!evidence) return '';
  return html`
    <dl class="kv">
      ${raw(
        Object.entries(evidence)
          .map(([k, v]) => {
            const rendered = Array.isArray(v) ? v.join(', ') : v === null ? '—' : typeof v === 'object' ? JSON.stringify(v) : v;
            return html`<div><dt class="mono">${k}</dt><dd class="mono">${rendered}</dd></div>`;
          })
          .join('')
      )}
    </dl>
  `;
}

function mitreList(techniques) {
  if (!techniques || !techniques.length) {
    return html`<p class="muted small">No ATT&amp;CK mapping. Not every finding describes adversary
      behaviour, and attaching a technique anyway would be decoration.</p>`;
  }
  return html`
    <ul class="stack">
      ${raw(
        techniques
          .map(
            (t) => html`<li>
              <a href="${t.url}" target="_blank" rel="noopener noreferrer"><span class="mono">${t.id}</span></a>
              ${t.name} · <span class="muted">${t.tactic}</span>
              ${raw(t.hypothesis ? html`<span class="badge warn">hypothesis</span>` : '')}
              <div class="muted small">${t.rationale}</div>
            </li>`
          )
          .join('')
      )}
    </ul>
  `;
}

function bulletList(items) {
  if (!items || !items.length) return '';
  return html`<ul class="stack small muted">${raw(items.map((i) => html`<li>${i}</li>`).join(''))}</ul>`;
}

function findingDetail(detail) {
  if (!detail) return html`<p class="muted">No detail stored for this finding.</p>`;
  return html`
    <div class="stack">
      <div>
        <h4>Why this was raised</h4>
        ${raw(signalTable(detail.signals))}
      </div>
      <div>
        <h4>Evidence</h4>
        ${raw(evidenceList(detail.evidence))}
      </div>
      <div>
        <h4>MITRE ATT&amp;CK</h4>
        ${raw(mitreList(detail.mitre))}
      </div>
      <div>
        <h4>Before you escalate — benign causes that look like this</h4>
        ${raw(bulletList(detail.falsePositives))}
      </div>
      <div>
        <h4>How to investigate</h4>
        ${raw(bulletList(detail.nextSteps))}
      </div>
    </div>
  `;
}

pages.detections = {
  title: 'Detections',
  subtitle: 'Behavioural findings. Observed and explained, never blocked.',
  async render() {
    const [catalogue, findings, summary] = await Promise.all([
      apiGet('/detectors'),
      apiGet('/findings?limit=100&detail=true'),
      apiGet('/findings/summary?days=7'),
    ]);

    if (!catalogue.enabled) {
      return html`
        <div class="card">
          <div class="card-head"><div><h2>Behavioural detection is switched off</h2></div></div>
          <p class="muted">Set <code>detection.enabled: true</code> in the configuration file, or
            <code>DNSDADDY_DETECTION_ENABLED=true</code>, and restart.</p>
        </div>
      `;
    }

    const bySeverity = { high: 0, medium: 0, low: 0, info: 0 };
    for (const row of summary.byType || []) {
      if (bySeverity[row.severity] !== undefined) bySeverity[row.severity] += row.count;
    }

    return html`
      <div class="card notice">
        <p><strong>These findings do not block anything.</strong> They are behavioural
          heuristics: they score traffic, explain the score, and alert. Blocking is done by the
          policy and threat-feed engine, from curated intelligence rather than inference. Every
          detector below is <strong>experimental</strong> — the thresholds are calibrated against
          synthetic traffic, not a production network.</p>
      </div>

      <div class="section grid grid-4">
        ${raw(metricCard({ label: 'High', value: num(bySeverity.high), sub: 'Last 7 days', tone: bySeverity.high ? 'bad' : '' }))}
        ${raw(metricCard({ label: 'Medium', value: num(bySeverity.medium), sub: 'Last 7 days' }))}
        ${raw(metricCard({ label: 'Low', value: num(bySeverity.low), sub: 'Last 7 days' }))}
        ${raw(metricCard({ label: 'Detectors', value: num(catalogue.detectors.length), sub: 'All alert-only' }))}
      </div>

      <div class="card">
        <div class="card-head"><div><h2>Recent findings</h2><p>Newest first. Expand one to see the
          measurements behind it.</p></div></div>
        ${raw(
          findings.findings.length
            ? findings.findings
                .map(
                  (f) => html`
                    <details class="finding">
                      <summary>
                        ${raw(severityBadge(f.severity))}
                        <span class="mono">${f.eventType}</span>
                        <span>${f.domain || f.clientName || f.clientIp || '—'}</span>
                        <span class="muted small nowrap">confidence ${f.confidence}</span>
                        <span class="muted small nowrap">${relTime(f.time)}</span>
                      </summary>
                      <div class="finding-body">
                        <p>${f.summary}</p>
                        <p class="muted small">
                          Client: <span class="mono">${f.clientName || f.clientIp || 'not attributed'}</span> ·
                          Detector: <span class="mono">${f.detector}</span> ·
                          Score: <span class="mono">${f.score}</span>
                        </p>
                        ${raw(findingDetail(f.detail))}
                      </div>
                    </details>
                  `
                )
                .join('')
            : emptyState(
                'No findings yet',
                'Either nothing has behaved unusually, or not enough traffic has passed through yet. ' +
                  'The lab in labs/ generates traffic that will trigger these detectors safely.'
              )
        )}
      </div>

      <div class="card">
        <div class="card-head"><div><h2>What is being looked for</h2><p>Straight from the running
          detectors, so this cannot drift from what the code does.</p></div></div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Detector</th><th>Maturity</th><th>Window</th><th>Max severity</th><th>Blocks?</th></tr></thead>
            <tbody>
              ${raw(
                catalogue.detectors
                  .map(
                    (d) => html`<tr>
                      <td>
                        <span class="mono">${d.name}</span>
                        <div class="muted small">${d.description}</div>
                      </td>
                      <td><span class="badge warn">${d.maturity}</span></td>
                      <td class="muted mono nowrap">${d.window}</td>
                      <td>${raw(severityBadge(d.maxSeverity))}</td>
                      <td class="muted">${d.enforces ? 'yes' : 'no'}</td>
                    </tr>`
                  )
                  .join('')
              )}
            </tbody>
          </table>
        </div>
      </div>
    `;
  },
};

/**
 * The one sentence the product has to get across on this page.
 *
 * A Network has always decided what happens to a client's queries. Whether
 * DNS Daddy accepts them at all was a separate setting in an environment
 * variable, and the gap between the two is what made a correctly configured
 * resolver look broken: the network was listed, and every client was REFUSED.
 * Both are set here now, and the distinction is stated where the choice is
 * made rather than left in the documentation.
 */
function accessExplainer() {
  return html`
    <div class="access-explainer">
      <p class="small">
        <strong>Policy</strong> decides what DNS Daddy does with this network's
        queries — what it blocks, what it logs.
      </p>
      <p class="small">
        <strong>Access</strong> decides whether DNS Daddy accepts queries
        arriving <em>from this network's addresses</em> at all. Without it this
        network grants nothing, and its clients are answered <code>REFUSED</code>
        unless another permitted range covers them — permissions add up, and
        nothing here subtracts, so unticking a narrower network does not close a
        range a wider one opens.
      </p>
      <p class="small muted">
        DNS-over-HTTPS and DNS-over-TLS clients holding this network's token are
        identified by that token rather than by where they connect from, so they
        keep working either way — that is what makes a roaming profile roam. To
        cut one off, disable the network or rotate its token.
      </p>
    </div>`;
}

/** A short account of who may currently use the resolver, and from where. */
function clientAccessSummary(access) {
  if (!access) return '';

  if (access.unrestricted) {
    return html`
      <div class="card section">
        <div class="card-head"><div><h2>Who may use this resolver</h2></div></div>
        <p class="small">
          ${access.allowPublicResolver
            ? 'Every address on the internet. dns.allow_public_resolver is set and no client ACL is configured.'
            : 'Every address. No client ACL is configured, which DNS Daddy only starts with when the DNS listeners are loopback-only.'}
        </p>
        <p class="muted small">
          Permissions set below are recorded and take effect if a client ACL is
          ever configured. While nothing is configured, nothing is refused.
        </p>
      </div>`;
  }

  const bootstrap = access.bootstrapCidrs || [];
  // From the server, not from subtracting one list from another here: a range
  // permitted in the dashboard *and* present in configuration survives that
  // subtraction as nothing, so a network the operator had just ticked would be
  // shown as contributing no ranges.
  const fromDashboard = access.dashboardCidrs || [];

  return html`
    <div class="card section">
      <div class="card-head">
        <div>
          <h2>Who may use this resolver</h2>
          <p>Any other address asking over <strong>ordinary DNS</strong> is answered
            REFUSED before any lookup happens. DNS-over-HTTPS and DNS-over-TLS clients
            holding a network's token are identified by that token rather than by where
            they connect from, so this does not apply to them — disable the network, or
            rotate its token, to cut one off.</p>
        </div>
      </div>
      <div class="grid grid-2">
        <div>
          <div class="muted small">From configuration</div>
          <div class="mono small">${bootstrap.length ? bootstrap.join(', ') : '—'}</div>
          <p class="muted small">
            DNSDADDY_ALLOWED_CLIENT_CIDRS, or dns.allowed_client_cidrs. Changing
            it needs a restart, so it is the right place for a headless or
            automated deployment and the wrong place for day-to-day admin.
          </p>
        </div>
        <div>
          <div class="muted small">From the networks below</div>
          <div class="mono small">${fromDashboard.length ? fromDashboard.join(', ') : '—'}</div>
          <p class="muted small">
            Added and removed here, in force on the next query. No restart.
          </p>
        </div>
      </div>
    </div>`;
}

/**
 * Confirms a permission that would accept DNS from the public internet.
 *
 * Driven entirely by the server's own refusal: the ranges named are the ones
 * it objected to. Classifying addresses here as well would be a second
 * implementation of a security rule, free to drift from the one that is
 * actually enforced.
 */
function confirmPublicAccess(cidrs) {
  const list = (cidrs || []).join(', ');
  return confirm(
    `${list} is a public internet address.\n\n` +
      'Allowing it means DNS Daddy will accept DNS requests from that source.\n\n' +
      'Make sure your VPS or cloud firewall restricts TCP and UDP port 53 to ' +
      'addresses you trust. DNS Daddy will not open or close your provider ' +
      'firewall, and cannot see it.\n\n' +
      'Allow this network to use DNS Daddy?'
  );
}

/**
 * Sends a network write, and retries once with the acknowledgement if the
 * server asks for one and the operator agrees.
 */
async function sendNetwork(method, path, payload) {
  try {
    return await apiSend(method, path, payload);
  } catch (err) {
    const needsAck = err instanceof ApiError && err.body && err.body.publicAckRequired;
    if (!needsAck) throw err;
    if (!confirmPublicAccess(err.body.publicCidrs)) return null;
    return apiSend(method, path, { ...payload, publicAck: true });
  }
}

// The Access column reports what the resolver is doing, not what the row says.
//
// allowResolver is the stored intent; coverage is computed from the ACL the
// resolver is actually enforcing. They come apart in several ways, and every
// one of them was reaching a branch that read better than the truth:
//
//   disabled          the row grants nothing and its policy does not apply,
//                     but disabling creates no deny rule, so its addresses may
//                     still be served by configuration or a wider network
//   catch-all         has no ranges of its own, so it neither grants nor is
//                     refused; the answer depends on each client's address
//   partial coverage  some of the range is served and the rest refused, which
//                     is the state that looks like intermittent breakage
//   stored, unloaded  a grant the resolver has not published
//
// Collapsing any of these into "Allowed" or "Refused" is how the dashboard
// ends up misdiagnosing a working deployment, which is the failure this whole
// line of work exists to remove.
// The Setup page tells an operator to point a whole network at DNS Daddy. It
// has to say whether that network may use it, because the answer is the
// difference between a rollout and every device on the LAN getting REFUSED —
// which is the failure this branch exists to end, and the Setup page is where
// an operator acts on it. Measured from the ACL in force, not from a count of
// permissions.
function resolverAccessNote(access) {
  if (!access) return '';
  if (access.unrestricted) {
    return html`<p class="muted small note-tight">
      Every address may query this resolver: no client ACL is configured. Anything you
      point here will be answered.</p>`;
  }
  const effective = access.effectiveCidrs || [];
  if (!effective.length) {
    return '';
  }
  return html`<p class="muted small note-tight">
    <strong>Before you point anything here:</strong> only these ranges may query over
    ordinary DNS — <span class="mono">${effective.join(', ')}</span>. A client outside
    them is answered <code>REFUSED</code> however you configure it. Add its network under
    <em>Networks</em> and tick <em>Allow this network to use DNS Daddy</em>. The
    DNS-over-HTTPS URLs below are identified by token instead, so they work from
    anywhere.</p>`;
}

function accessBadge(n) {
  const catchAll = !(n.cidrs || []).length;
  const coverage = n.coverage || 'none';
  const disabled = n.enabled === false;

  // The catch-all is settled before anything reads coverage, because coverage
  // is a statement about a network's ranges and a catch-all has none. The
  // server answers "full" for it, which is true of the empty set and useless
  // here — and every branch that read it without checking got the wrong
  // answer, including the disabled one, which announced that a catch-all's
  // clients were still being served when that depends on each client.
  if (catchAll) {
    if (disabled) {
      return html`<span class="badge"
        title="This network is disabled, so it applies no policy and grants nothing. It has no ranges of its own either, so whether a client it would have matched is served depends on that client's own address.">Disabled</span>`;
    }
    if (n.allowResolver) {
      return html`<span class="badge warn"
        title="A catch-all has no ranges of its own, so permitting it grants nothing. Give it CIDRs, or permit the network the clients actually match.">Grants nothing</span>`;
    }
    return html`<span class="badge"
      title="A catch-all has no ranges of its own. Whether a client it matches is served depends on that client's own address — see who may use this resolver, above.">Depends on the client</span>`;
  }

  // Disabling stops this row granting anything and stops its policy applying.
  // It creates no deny rule, so the addresses may still be served — and an
  // operator who disabled the network to cut a client off needs to be told
  // when that did not happen.
  if (disabled) {
    if (coverage === 'full') {
      return html`<span class="badge"
        title="Disabled, so this row grants nothing and applies no policy — but disabling creates no deny rule, and configuration or another network still permits these addresses.">Disabled, still served</span>`;
    }
    if (coverage === 'partial') {
      return html`<span class="badge"
        title="Disabled, so this row grants nothing — but some of these addresses are still permitted by configuration or another network.">Disabled, partly served</span>`;
    }
    return html`<span class="badge">Disabled</span>`;
  }

  if (n.allowResolver && coverage !== 'full') {
    return html`<span class="badge warn"
      title="Stored, but the resolver is not enforcing all of it — see the client access summary above.">Allowed, not in force</span>`;
  }
  if (n.allowResolver) {
    const tone = (n.publicCidrs || []).length ? 'warn' : 'ok';
    const label = (n.publicCidrs || []).length ? 'Allowed (public)' : 'Allowed';
    return html`<span class="badge ${tone}">${label}</span>`;
  }
  if (n.resolvesVia) {
    return html`<span class="badge warn" title="Covered by ${n.resolvesVia}">Via wider range</span>`;
  }
  // Fully covered with nothing to name. The case that matters is an
  // unrestricted ACL: Compute returns before populating Shadowed, because
  // there are no grants for a range to be shadowed *by*, so every unpermitted
  // row arrived here with coverage full and no resolvesVia — and fell through
  // to Refused, on a deployment that refuses nobody. That is the dashboard
  // misdiagnosing a working install, which is what this column exists to stop.
  if (coverage === 'full') {
    return html`<span class="badge"
      title="These addresses are admitted by the client ACL rather than by a permission on this row — see who may use this resolver, above.">Served, not by this row</span>`;
  }
  if (coverage === 'partial') {
    return html`<span class="badge warn"
      title="Some of this network's addresses are permitted and the rest are refused, which looks like intermittent breakage from the client side. Permit the whole range, or split the network.">Partly refused</span>`;
  }
  return html`<span class="badge bad">Refused</span>`;
}

pages.networks = {
  title: 'Networks',
  subtitle: 'Sites, VLANs, and roaming profiles.',
  async render() {
    const [networks, policies] = await Promise.all([apiGet('/networks'), apiGet('/policies')]);
    const policyOptions = policies.policies
      .map((p) => html`<option value="${p.id}">${p.name}</option>`)
      .join('');

    return html`
      ${raw(clientAccessSummary(networks.clientAccess))}

      <div class="card section">
        <div class="card-head">
          <div>
            <h2>Add a network</h2>
            <p>Give each site or VLAN its own policy. Leave the CIDR list empty to make it the catch-all.</p>
          </div>
        </div>
        <form id="network-form">
          <div class="grid grid-3">
            <label class="field"><span>Name</span><input name="name" required placeholder="HQ — London"></label>
            <label class="field"><span>Location</span><input name="location" placeholder="London, UK"></label>
            <label class="field"><span>Policy</span><select name="policyId">${raw(policyOptions)}</select></label>
          </div>
          <label class="field">
            <span>Client networks (CIDR, comma separated)</span>
            <input name="cidrs" placeholder="10.0.10.0/24, 192.168.4.0/24">
            <span class="hint muted">A single IP works too — 203.0.113.25 means just that machine.</span>
          </label>
          <label class="checkline access-toggle">
            <input type="checkbox" name="allowResolver" checked>
            <span><strong>Allow this network to use DNS Daddy</strong>
              <span class="cat-desc">Permits DNS queries from these addresses. Leave it off and
                this network grants nothing — its clients are answered REFUSED unless some
                other permitted range covers them, since the ACL is a union with no deny
                rules.</span>
              <span class="cat-desc" id="access-needs-cidrs" hidden>This permits nothing while
                the CIDR list is empty: a catch-all has no addresses of its own to permit.
                Add a range above, or permit the network your clients actually match.</span></span>
          </label>
          ${raw(accessExplainer())}
          <button class="btn btn-primary" type="submit">Add network</button>
        </form>
      </div>

      <div class="card">
        <div class="card-head"><div><h2>Networks</h2><p>Traffic over the last 24 hours.</p></div></div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr><th>Network</th><th>Client ranges</th><th>Policy</th><th>Access</th>
                  <th class="num">Queries 24h</th><th class="num">Blocked</th><th>Status</th><th></th></tr>
            </thead>
            <tbody>
              ${raw(
                networks.networks
                  .map((n) => {
                    const policy = policies.policies.find((p) => p.id === n.policyId);
                    const publicRanges = n.publicCidrs || [];
                    return html`<tr>
                      <td><strong>${n.name}</strong><div class="muted small">${n.location || '—'}</div></td>
                      <td class="mono">${n.cidrs.length ? n.cidrs.join(', ') : 'catch-all'}
                        ${raw(publicRanges.length
                          ? html`<div class="muted small">public: ${publicRanges.join(', ')}</div>`
                          : '')}
                      </td>
                      <td>${policy ? policy.name : n.policyId}</td>
                      <td>
                        <label class="checkline access-cell" title="Allow this network to use DNS Daddy">
                          <input type="checkbox" data-access="${n.id}" data-name="${n.name}"
                                 ${raw(n.allowResolver ? 'checked' : '')}>
                          <span>${raw(accessBadge(n))}</span>
                        </label>
                        ${raw(!n.allowResolver && n.resolvesVia
                          ? html`<div class="muted small">Reachable anyway, inside ${n.resolvesVia}.
                                 Access has no deny rules.</div>`
                          : '')}
                      </td>
                      <td class="num">${num(n.queries24h)}</td>
                      <td class="num">${num(n.blocked24h)}</td>
                      <td>${raw(statusBadge(n.status))}</td>
                      <td><button class="btn btn-danger btn-sm" data-delete-network="${n.id}"
                            data-name="${n.name}">Delete</button></td>
                    </tr>`;
                  })
                  .join('')
              )}
            </tbody>
          </table>
        </div>
      </div>
    `;
  },
  async mounted() {
    // The tick box defaults on, and the field above invites an empty CIDR list
    // to make a catch-all. Following both leaves a network that reads as
    // permitted and grants nothing, because a network with no ranges
    // contributes none to the ACL. The note appears exactly when that is the
    // state being built, rather than after the row exists.
    const cidrsField = $('#network-form [name="cidrs"]');
    const needsCIDRs = $('#access-needs-cidrs');
    const allowBox = $('#network-form [name="allowResolver"]');
    const syncAccessNote = () => {
      needsCIDRs.hidden = !(allowBox.checked && !cidrsField.value.trim());
    };
    cidrsField.addEventListener('input', syncAccessNote);
    allowBox.addEventListener('change', syncAccessNote);
    syncAccessNote();

    $('#network-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const form = new FormData(e.target);
      const cidrs = String(form.get('cidrs') || '')
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
      try {
        const created = await sendNetwork('POST', '/networks', {
          name: form.get('name'),
          location: form.get('location') || '',
          policyId: form.get('policyId'),
          cidrs,
          allowResolver: form.get('allowResolver') === 'on',
        });
        if (!created) {
          toast('Network not added — the public address was not confirmed', 'error');
          return;
        }
        if (created.warning) {
          toast(created.warning, 'error');
        } else {
          toast('Network added');
        }
        router.reload();
      } catch (err) {
        reportError(err);
      }
    });

    $$('[data-access]').forEach((box) =>
      box.addEventListener('change', async () => {
        const wanted = box.checked;
        try {
          const updated = await sendNetwork('PATCH', `/networks/${box.dataset.access}`, {
            allowResolver: wanted,
          });
          if (!updated) {
            // The operator declined the public-address confirmation. Put the
            // control back where it was rather than leaving it showing a
            // permission that was never granted.
            box.checked = !wanted;
            return;
          }
          // Only claim the change is in force when it is. A stored-but-not-
          // reloaded revocation still has the old permission being honoured,
          // and "can no longer use DNS Daddy" over the top of that warning is
          // a false success about the security-relevant direction.
          if (updated.warning) {
            toast(updated.warning, 'error');
          } else {
            toast(wanted
              ? `"${box.dataset.name}" may now use DNS Daddy`
              : `"${box.dataset.name}" can no longer use DNS Daddy`);
          }
          router.reload();
        } catch (err) {
          box.checked = !wanted;
          reportError(err);
        }
      })
    );

    $$('[data-delete-network]').forEach((btn) =>
      btn.addEventListener('click', async () => {
        if (!confirm(`Delete network "${btn.dataset.name}"? Query history is kept.`)) return;
        try {
          // A delete answers 204 on success and 200 with a warning when the
          // resolver could not be reloaded — where whether the deleted
          // network's clients are still being served is exactly what could
          // not be confirmed.
          const result = await apiSend('DELETE', `/networks/${btn.dataset.deleteNetwork}`);
          if (result && result.warning) {
            toast(result.warning, 'error');
          } else {
            toast('Network deleted');
          }
          router.reload();
        } catch (err) {
          reportError(err);
        }
      })
    );
  },
};

pages.policies = {
  title: 'Policies',
  subtitle: 'What gets blocked, and for whom.',
  async render() {
    const [policies, categories] = await Promise.all([apiGet('/policies'), apiGet('/categories')]);

    const cards = policies.policies
      .map((p) => {
        const checks = categories.categories
          .map(
            (c) => html`
              <label class="checkline">
                <input type="checkbox" data-policy="${p.id}" data-category="${c.id}"
                       ${raw(p.categories.includes(c.id) ? 'checked' : '')}>
                <span>
                  ${c.label}
                  <span class="cat-desc">${c.description} · ${num(c.indexedDomains)} domains indexed</span>
                </span>
              </label>
            `
          )
          .join('');

        return html`
          <div class="card section">
            <div class="card-head">
              <div>
                <h2>${p.name} ${raw(p.isDefault ? '<span class="badge ok">default</span>' : '')}</h2>
                <p>${p.description || 'No description.'} · ${p.assigned} network${p.assigned === 1 ? '' : 's'}</p>
              </div>
              <div class="row-end row">
                <button class="btn btn-ghost btn-sm" data-save-policy="${p.id}">Save changes</button>
                ${raw(
                  p.isDefault
                    ? ''
                    : html`<button class="btn btn-danger btn-sm" data-delete-policy="${p.id}" data-name="${p.name}">Delete</button>`
                )}
              </div>
            </div>

            <div class="grid grid-2">
              <div>
                <h3 class="small muted mb-2">BLOCKED CATEGORIES</h3>
                ${raw(checks)}
                <label class="field mt-4">
                  <span>When blocking, answer with</span>
                  <select data-blockmode="${p.id}">
                    <option value="nxdomain" ${raw(p.blockMode === 'nxdomain' ? 'selected' : '')}>NXDOMAIN (recommended)</option>
                    <option value="zeroip" ${raw(p.blockMode === 'zeroip' ? 'selected' : '')}>0.0.0.0 / ::</option>
                    <option value="refused" ${raw(p.blockMode === 'refused' ? 'selected' : '')}>REFUSED</option>
                  </select>
                </label>
                <label class="checkline">
                  <input type="checkbox" data-logqueries="${p.id}" ${raw(p.logQueries ? 'checked' : '')}>
                  <span>Log individual queries
                    <span class="cat-desc">Off keeps dashboard counts but stores no per-query rows.</span>
                  </span>
                </label>
              </div>

              <div>
                <label class="field">
                  <span>Always allow (one domain per line)</span>
                  <textarea data-allow="${p.id}">${p.allowDomains.join('\n')}</textarea>
                  <span class="hint muted">Beats every blocklist. Use this to clear a false positive immediately.</span>
                </label>
                <label class="field">
                  <span>Always block (one domain per line)</span>
                  <textarea data-block="${p.id}">${p.blockDomains.join('\n')}</textarea>
                  <span class="hint muted">Subdomains are included automatically.</span>
                </label>
              </div>
            </div>
          </div>
        `;
      })
      .join('');

    return html`
      ${raw(cards)}
      <div class="card">
        <div class="card-head"><div><h2>New policy</h2><p>Start from the default categories and adjust.</p></div></div>
        <form id="policy-form" class="row">
          <input name="name" class="w-260" placeholder="Policy name" required>
          <input name="description" class="w-340" placeholder="Description">
          <button class="btn btn-primary" type="submit">Create policy</button>
        </form>
      </div>
    `;
  },
  async mounted() {
    $$('[data-save-policy]').forEach((btn) =>
      btn.addEventListener('click', async () => {
        const id = btn.dataset.savePolicy;
        const categories = $$(`[data-policy="${id}"]`)
          .filter((cb) => cb.checked)
          .map((cb) => cb.dataset.category);
        const lines = (sel) =>
          $(sel)
            .value.split('\n')
            .map((s) => s.trim())
            .filter(Boolean);

        try {
          await apiSend('PATCH', `/policies/${id}`, {
            categories,
            blockMode: $(`[data-blockmode="${id}"]`).value,
            logQueries: $(`[data-logqueries="${id}"]`).checked,
            allowDomains: lines(`[data-allow="${id}"]`),
            blockDomains: lines(`[data-block="${id}"]`),
          });
          toast('Policy saved — takes effect immediately');
        } catch (err) {
          reportError(err);
        }
      })
    );

    $$('[data-delete-policy]').forEach((btn) =>
      btn.addEventListener('click', async () => {
        if (!confirm(`Delete policy "${btn.dataset.name}"?`)) return;
        try {
          await apiSend('DELETE', `/policies/${btn.dataset.deletePolicy}`);
          toast('Policy deleted');
          router.reload();
        } catch (err) {
          reportError(err);
        }
      })
    );

    $('#policy-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const form = new FormData(e.target);
      try {
        await apiSend('POST', '/policies', {
          name: form.get('name'),
          description: form.get('description') || '',
          categories: ['malware', 'phishing', 'c2', 'cryptomining'],
        });
        toast('Policy created');
        router.reload();
      } catch (err) {
        reportError(err);
      }
    });
  },
};

pages.feeds = {
  title: 'Threat feeds',
  subtitle: 'Where the blocking decisions come from.',
  async render() {
    const data = await apiGet('/feeds');
    return html`
      <div class="card section">
        <div class="card-head">
          <div>
            <h2>Sources</h2>
            <p>${num(data.totalIndexedDomains)} domains indexed across enabled feeds.
               Disabled feeds cost nothing.</p>
          </div>
          <div class="row-end">
            <button class="btn btn-primary" id="refresh-feeds" ${raw(data.refreshing ? 'disabled' : '')}>
              ${data.refreshing ? 'Refreshing…' : 'Refresh now'}
            </button>
          </div>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr><th>Feed</th><th>Category</th><th class="num">Domains</th>
                  <th>Last refreshed</th><th>Status</th><th>Enabled</th></tr>
            </thead>
            <tbody>
              ${raw(
                data.feeds
                  .map(
                    (f) => html`<tr>
                      <td>
                        <strong>${f.name}</strong>
                        <div class="muted small mono">${f.url}</div>
                        ${raw(f.lastError ? html`<div class="small feed-error">${f.lastError}</div>` : '')}
                        ${raw(
                          f.enabled && !f.loaded && f.lastSuccessAt
                            ? html`<div class="small feed-error">Not in the running blocklist${f.loadError ? ` — ${f.loadError}` : ''}</div>`
                            : ''
                        )}
                      </td>
                      <td>${raw(categoryBadge(f.category))}
                        ${raw(
                          f.format === 'observatory'
                            ? html`<div class="muted small">plus each indicator's own category</div>`
                            : ''
                        )}
                      </td>
                      <td class="num">${f.enabled ? num(f.indexedDomains) : '—'}</td>
                      <td class="muted nowrap">${relTime(f.lastRefreshedAt)}
                        ${raw(
                          f.enabled && f.lastError && f.lastSuccessAt
                            ? html`<div class="small">last good ${relTime(f.lastSuccessAt)}</div>`
                            : ''
                        )}
                      </td>
                      <td>${raw(feedStatusBadge(f))}</td>
                      <td>
                        <input type="checkbox" data-feed="${f.id}" ${raw(f.enabled ? 'checked' : '')}
                               aria-label="Enable ${f.name}">
                      </td>
                    </tr>`
                  )
                  .join('')
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div class="card">
        <div class="card-head">
          <div><h2>Add a custom feed</h2>
          <p>Any URL serving a hosts file, a plain domain list, or Adblock-style rules.
             The format is sniffed per line.</p></div>
        </div>
        <form id="feed-form">
          <div class="grid grid-3">
            <label class="field"><span>Name</span><input name="name" required placeholder="Internal deny list"></label>
            <label class="field"><span>URL</span><input name="url" required placeholder="https://example.org/list.txt"></label>
            <label class="field"><span>Category</span>
              <select name="category">
                ${raw(
                  ['malware', 'phishing', 'c2', 'cryptomining', 'newly-registered', 'ads', 'adult', 'gambling']
                    .map((c) => html`<option value="${c}">${c}</option>`)
                    .join('')
                )}
              </select>
            </label>
          </div>
          <button class="btn btn-primary" type="submit">Add feed</button>
        </form>
      </div>
    `;
  },
  async mounted() {
    $('#refresh-feeds').addEventListener('click', async (e) => {
      e.target.disabled = true;
      e.target.textContent = 'Refreshing…';
      try {
        await apiSend('POST', '/feeds/refresh');
        toast('Refresh started — this can take a minute or two');
        // Poll until the manager reports it has finished.
        const poll = setInterval(async () => {
          try {
            const data = await apiGet('/feeds');
            if (!data.refreshing) {
              clearInterval(poll);
              toast('Feeds refreshed');
              router.reload();
            }
          } catch {
            clearInterval(poll);
          }
        }, 3000);
      } catch (err) {
        reportError(err);
        e.target.disabled = false;
        e.target.textContent = 'Refresh now';
      }
    });

    $$('[data-feed]').forEach((cb) =>
      cb.addEventListener('change', async () => {
        try {
          await apiSend('PATCH', `/feeds/${cb.dataset.feed}`, { enabled: cb.checked });
          toast(
            cb.checked
              ? 'Feed enabled — refresh to download it'
              : 'Feed disabled — its domains are being dropped from the index'
          );
        } catch (err) {
          reportError(err);
          cb.checked = !cb.checked;
        }
      })
    );

    $('#feed-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const form = new FormData(e.target);
      try {
        await apiSend('POST', '/feeds', {
          name: form.get('name'),
          url: form.get('url'),
          category: form.get('category'),
        });
        toast('Feed added — refresh to index it');
        router.reload();
      } catch (err) {
        reportError(err);
      }
    });
  },
};

pages.setup = {
  title: 'Setup',
  subtitle: 'Point your network here.',
  async render() {
    const [info, networks] = await Promise.all([apiGet('/resolvers'), apiGet('/networks')]);
    const port = (listen) => (listen || '').split(':').pop() || '53';

    return html`
      <div class="card section">
        <div class="card-head">
          <div><h2>Resolver addresses</h2>
          <p>Set these as the DNS servers on your firewall, DHCP scope, or router.
             Replace the host with this server's LAN or public IP.</p></div>
        </div>
        ${raw(copyBlock(`Plain DNS (UDP/TCP), port ${port(info.listenUdp)}`))}
        ${raw(resolverAccessNote(networks.clientAccess))}
        <p class="muted small note-tight">
          On pfSense: <em>System → General Setup → DNS Servers</em>.
          On UniFi: <em>Settings → Networks → your LAN → DHCP Name Server</em>.
          Then block outbound port 53 to everything else so devices cannot skip past it.
        </p>
        ${raw(info.listenDot ? html`<div class="note-loose">${raw(copyBlock(`DNS-over-TLS: port ${port(info.listenDot)}`))}</div>` : '')}
      </div>

      <div class="card section">
        <div class="card-head">
          <div><h2>DNS-over-HTTPS</h2>
          <p>Per-network URLs. A roaming laptop configured with its network's URL keeps that
             network's policy from any internet connection.</p></div>
        </div>
        <div class="stack">
          ${raw(copyBlock(info.dohUrl))}
          ${raw(
            info.networks && info.networks.length
              ? info.networks
                  .map(
                    (n) => html`<div>
                      <div class="small muted mb-1">${n.name}</div>
                      ${raw(copyBlock(n.dohUrl))}
                    </div>`
                  )
                  .join('')
              : ''
          )}
        </div>
        <p class="muted small note-loose">
          These URLs are credentials — anyone holding one resolves under that network's policy.
          Rotate a token from the API if it leaks.
        </p>
      </div>

      <div class="card">
        <div class="card-head"><div><h2>Upstream resolvers</h2><p>Where DNS Daddy forwards what it does not block.</p></div></div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Upstream</th><th>Protocol</th><th class="num">Queries</th>
                       <th class="num">Errors</th><th class="num">Avg latency</th></tr></thead>
            <tbody>
              ${raw(
                (info.upstreams || [])
                  .map(
                    (u) => html`<tr>
                      <td class="mono">${u.spec}</td>
                      <td>${raw(u.protocol === 'tls' || u.protocol === 'https'
                        ? html`<span class="badge ok">${u.protocol} · encrypted</span>`
                        : html`<span class="badge warn">${u.protocol} · plaintext</span>`)}</td>
                      <td class="num">${num(u.queries)}</td>
                      <td class="num">${num(u.errors)}</td>
                      <td class="num">${u.avgLatencyMs} ms</td>
                    </tr>`
                  )
                  .join('')
              )}
            </tbody>
          </table>
        </div>
      </div>
    `;
  },
};

pages.reports = {
  title: 'Reports',
  subtitle: 'Evidence you can forward.',
  async render() {
    const summary = await apiGet('/reports/summary?days=7');
    return html`
      <div class="card section">
        <div class="card-head">
          <div>
            <h2>Last 7 days</h2>
            <p>${num(summary.totals.queries)} queries · ${num(summary.totals.blocked)} blocked
               (${summary.blockRate}%) across ${summary.networks.length} network(s).</p>
          </div>
          <div class="row-end row">
            <select id="report-days" class="w-150">
              <option value="7">Last 7 days</option>
              <option value="30">Last 30 days</option>
              <option value="90">Last 90 days</option>
            </select>
            <button class="btn btn-primary" id="download-report">Download Markdown</button>
          </div>
        </div>
        <p class="muted small">
          The Markdown report is written for someone who does not run the network — a director,
          an insurer, or a Cyber Essentials assessor. It lists what was blocked, on which site,
          and which intelligence sources were in force.
        </p>
      </div>

      <div class="grid grid-2">
        <div class="card">
          <div class="card-head"><div><h2>By category</h2></div></div>
          ${raw(barList(summary.categories.map((c) => ({ label: c.label, count: c.count, category: c.category }))))}
        </div>
        <div class="card">
          <div class="card-head"><div><h2>By network</h2></div></div>
          <div class="table-wrap">
            <table>
              <thead><tr><th>Network</th><th>Policy</th><th class="num">Queries</th><th class="num">Blocked</th></tr></thead>
              <tbody>
                ${raw(
                  summary.networks
                    .map(
                      (n) => html`<tr>
                        <td>${n.name}</td><td class="muted">${n.policy || '—'}</td>
                        <td class="num">${num(n.queries)}</td><td class="num">${num(n.blocked)}</td>
                      </tr>`
                    )
                    .join('')
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    `;
  },
  async mounted() {
    $('#download-report').addEventListener('click', () => {
      const days = $('#report-days').value;
      // A plain navigation keeps the session cookie and lets the browser
      // handle the download; no blob juggling required.
      window.location.href = `/api/v1/reports/summary?days=${encodeURIComponent(days)}&format=markdown`;
    });
  },
};

// The Assurance page exists because "is this trustworthy?" is a fair question
// about an AI-assisted project, and the useful answer is evidence rather than
// reassurance. Everything here is a pointer to something a reader can check:
// a workflow file, a document, a test. Nothing on this page asserts a security
// property that has not been tested, and the limitations are given the same
// prominence as the evidence — a page that only listed the good news would be
// the marketing it is meant to replace.
//
// It is deliberately static. A trust page that needs a backend is a trust page
// that can fail to load, and it would cost memory on a $5 VPS to tell the
// reader things the repository already states.
const REPO = 'https://github.com/jameshoulder/dnsdaddy/blob/main';

function evidenceRow(what, where, detail) {
  return html`<tr>
    <td>${what}</td>
    <td class="mono small">${where}</td>
    <td class="muted">${detail}</td>
  </tr>`;
}

pages.assurance = {
  title: 'Assurance',
  subtitle: 'What is checked, by what, and what that does not prove.',
  async render() {
    const settings = await apiGet('/settings').catch(() => ({ version: 'unknown' }));

    return html`
      <div class="card lead section">
        <div class="card-eyebrow">Position</div>
        <h2>AI-assisted, transparently built, test-backed</h2>
        <p class="muted note-tight">
          DNS Daddy is an open-source project built with AI assistance. That is disclosed
          rather than hidden, because the useful response to "was this written with an LLM?"
          is evidence you can check, not a reassurance you have to accept.
        </p>
        <p class="muted">
          You are running <span class="mono">${settings.version}</span>. Every document linked
          below ships in the repository, so you can read the version you are actually running
          rather than a page about it.
        </p>
        <div class="row note-loose">
          <a class="btn btn-primary" href="${REPO}/docs/assurance.md" target="_blank" rel="noopener noreferrer">Engineering assurance</a>
          <a class="btn btn-ghost" href="${REPO}/docs/threat-model.md" target="_blank" rel="noopener noreferrer">Threat model</a>
          <a class="btn btn-ghost" href="${REPO}/docs/security-testing.md" target="_blank" rel="noopener noreferrer">Security testing</a>
        </div>
      </div>

      <div class="card section">
        <div class="card-head">
          <div>
            <div class="card-eyebrow">Automated</div>
            <h2>What runs on every change</h2>
            <p>These run in CI on every push and pull request. They are not a substitute for
               review by a person; they are the floor beneath it.</p>
          </div>
        </div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Check</th><th>Where</th><th>What it covers</th></tr></thead>
            <tbody>
              ${raw(evidenceRow('Build, vet, unit and integration tests', '.github/workflows/ci.yml', 'Every push and pull request'))}
              ${raw(evidenceRow('Race detector', 'go test -race', 'Concurrent resolver and ACL paths'))}
              ${raw(evidenceRow('staticcheck', '.github/workflows/security.yml', 'Correctness and dead code'))}
              ${raw(evidenceRow('gosec', 'security workflow', 'Common Go security mistakes'))}
              ${raw(evidenceRow('govulncheck', 'security workflow', 'Known CVEs in dependencies actually reached'))}
              ${raw(evidenceRow('CodeQL and Semgrep', 'security workflow', 'Static analysis for injection and data flow'))}
              ${raw(evidenceRow('Container and filesystem scan', 'security workflow', 'The published image'))}
              ${raw(evidenceRow('End-to-end resolver test', 'CI', 'Grant, query, revoke, restart — against a real binary over UDP'))}
            </tbody>
          </table>
        </div>
      </div>

      <div class="card section">
        <div class="card-head">
          <div>
            <div class="card-eyebrow">Testing</div>
            <h2>Vulnerability scanning</h2>
            <p>Scanning was performed with Tenable Vulnerability Management / Nessus across
               several scan types, before and after deployment. Methodology and findings are
               documented in full.</p>
          </div>
        </div>
        <p class="muted">
          The one Medium finding in those scans was
          <strong>the scanner's own certificate</strong> on its management port, present on the
          host before DNS Daddy was installed. It is recorded because omitting it would make the
          results look cleaner than they were — not because it is a DNS Daddy defect.
        </p>
        <p class="muted note-tight">
          Vulnerability scanning is one layer. It looks for known issues in exposed services;
          it does not read the source, reason about the design, or attempt exploitation.
        </p>
        <div class="row note-loose">
          <a class="btn btn-ghost" href="${REPO}/docs/security-testing.md" target="_blank" rel="noopener noreferrer">Read the methodology and findings</a>
        </div>
      </div>

      <div class="card section diag-banner">
        <div class="diag-title">Limitations</div>
        <p class="diag-lede">Stated here rather than in a footnote, because they are the part
           most worth knowing.</p>
        <ul class="first-client-steps">
          <li><strong>No independent professional security review.</strong> No third-party
              penetration test, code audit or certification has been carried out. Nothing on
              this page should be read as one.</li>
          <li><strong>Scanners are not proof.</strong> A clean scan means known checks found
              nothing on the surfaces they examined, not that the software is secure.</li>
          <li><strong>Early software.</strong> Interfaces and storage formats may still change
              between releases.</li>
          <li><strong>Self-hosted responsibility.</strong> Exposure of the dashboard, firewall
              rules and TLS termination are decided by your deployment, and DNS Daddy can only
              report what it can actually observe.</li>
        </ul>
      </div>

      <div class="card section">
        <div class="card-head">
          <div>
            <div class="card-eyebrow">Inspectable</div>
            <h2>Design and privacy</h2>
            <p>The reasoning behind the parts most worth disagreeing with.</p>
          </div>
        </div>
        <div class="row">
          <a class="btn btn-ghost" href="${REPO}/docs/architecture.md" target="_blank" rel="noopener noreferrer">Architecture</a>
          <a class="btn btn-ghost" href="${REPO}/docs/privacy.md" target="_blank" rel="noopener noreferrer">Privacy</a>
          <a class="btn btn-ghost" href="${REPO}/docs/audit-2026-08.md" target="_blank" rel="noopener noreferrer">Audit notes</a>
          <a class="btn btn-ghost" href="${REPO}/docs/roadmap.md" target="_blank" rel="noopener noreferrer">Roadmap</a>
        </div>
      </div>
    `;
  },
};

pages.settings = {
  title: 'Settings',
  subtitle: 'Runtime configuration and access.',
  async render() {
    const [settings, tokens] = await Promise.all([apiGet('/settings'), apiGet('/tokens')]);

    return html`
      <div class="section grid grid-4">
        ${raw(metricCard({ label: 'Version', value: settings.version }))}
        ${raw(metricCard({ label: 'Uptime', value: duration(settings.uptimeSeconds) }))}
        ${raw(metricCard({ label: 'Memory', value: `${settings.memoryMb} MB`, sub: `${settings.goroutines} goroutines` }))}
        ${raw(metricCard({ label: 'Cache hit rate', value: `${settings.cacheHitRate}%`, sub: `${num(settings.cacheEntries)} entries` }))}
      </div>

      <div class="card section">
        <div class="card-head">
          <div><h2>Effective configuration</h2>
          <p>Read-only. Configuration lives in your YAML file and environment, so a
             deployment is reproducible from its config rather than from database state.</p></div>
        </div>
        <div class="table-wrap">
          <table>
            <tbody>
              <tr><td>Data directory</td><td class="mono">${settings.dataDir}</td></tr>
              <tr><td>Query logging</td><td>${settings.queryLog ? 'Enabled' : 'Disabled'}</td></tr>
              <tr><td>Log client IPs</td><td>${settings.logClientIp ? 'Yes' : 'No'}</td></tr>
              <tr><td>Query-log retention</td><td>${settings.retentionDays} days
                  <span class="muted">(${num(settings.queryLogRows)} rows stored)</span></td></tr>
              <tr><td>Statistics retention</td><td>${settings.rollupDays} days</td></tr>
              <tr><td>Answer cache</td><td>${settings.cacheEnabled ? `Enabled, max ${num(settings.cacheMaxEntries)} entries` : 'Disabled'}</td></tr>
              <tr><td>Feed refresh interval</td><td>${settings.feedRefreshInterval}</td></tr>
              <tr><td>Upstream mode</td><td>${settings.upstreamMode}</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <div class="card section">
        <div class="card-head"><div><h2>Change admin password</h2></div></div>
        <form id="password-form" class="grid grid-3">
          <label class="field"><span>Current password</span>
            <input type="password" name="current" autocomplete="current-password" required></label>
          <label class="field"><span>New password</span>
            <input type="password" name="next" autocomplete="new-password" minlength="12" required></label>
          <label class="field"><span>&nbsp;</span><button class="btn btn-primary" type="submit">Update password</button></label>
        </form>
      </div>

      <div class="card">
        <div class="card-head">
          <div><h2>API tokens</h2>
          <p>For automation, or for a hosted control centre reading this resolver.
             The secret is shown once.</p></div>
        </div>
        <form id="token-form" class="row mb-4">
          <input name="name" class="w-280" placeholder="Token name (e.g. control-centre)" required>
          <button class="btn btn-primary" type="submit">Create token</button>
        </form>
        <div id="token-secret"></div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Name</th><th>Prefix</th><th>Created</th><th>Last used</th><th></th></tr></thead>
            <tbody>
              ${raw(
                tokens.tokens.length
                  ? tokens.tokens
                      .map(
                        (t) => html`<tr>
                          <td>${t.name}</td>
                          <td class="mono">${t.prefix}…</td>
                          <td class="muted">${relTime(t.createdAt)}</td>
                          <td class="muted">${relTime(t.lastUsedAt)}</td>
                          <td><button class="btn btn-danger btn-sm" data-delete-token="${t.id}"
                                data-name="${t.name}">Revoke</button></td>
                        </tr>`
                      )
                      .join('')
                  : html`<tr><td colspan="5" class="muted">No tokens yet.</td></tr>`
              )}
            </tbody>
          </table>
        </div>
      </div>
    `;
  },
  async mounted() {
    $('#password-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const form = new FormData(e.target);
      try {
        await apiSend('POST', '/auth/password', {
          currentPassword: form.get('current'),
          newPassword: form.get('next'),
        });
        toast('Password updated');
        e.target.reset();
      } catch (err) {
        reportError(err);
      }
    });

    $('#token-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const form = new FormData(e.target);
      try {
        const token = await apiSend('POST', '/tokens', { name: form.get('name') });
        $('#token-secret').innerHTML = html`
          <div class="card token-reveal">
            <p class="small reveal-lead"><strong>Copy this now — it is not shown again.</strong></p>
            ${raw(copyBlock(token.secret))}
          </div>
        `;
        paintDynamic($('#token-secret'));
        bindCopyButtons();
        e.target.reset();
      } catch (err) {
        reportError(err);
      }
    });

    $$('[data-delete-token]').forEach((btn) =>
      btn.addEventListener('click', async () => {
        if (!confirm(`Revoke token "${btn.dataset.name}"? Anything using it stops working immediately.`)) return;
        try {
          await apiSend('DELETE', `/tokens/${btn.dataset.deleteToken}`);
          toast('Token revoked');
          router.reload();
        } catch (err) {
          reportError(err);
        }
      })
    );
  },
};

/* ---------- dynamic styling --------------------------------------------- */

/**
 * Apply values that genuinely vary at runtime — bar widths, category colours.
 *
 * These cannot be `style="…"` attributes: the dashboard ships a strict CSP with
 * no 'unsafe-inline' for styles, and the browser refuses them. Assigning through
 * the CSSOM after insertion is allowed, and keeps the policy tight.
 */
function paintDynamic(root = document) {
  $$('[data-bg]', root).forEach((el) => {
    el.style.background = el.dataset.bg;
  });
  $$('[data-width]', root).forEach((el) => {
    el.style.width = `${el.dataset.width}%`;
  });
  $$('[data-fg]', root).forEach((el) => {
    el.style.color = el.dataset.fg;
    el.style.borderColor = `${el.dataset.fg}55`;
  });
}

/* ---------- copy buttons ------------------------------------------------ */

function bindCopyButtons() {
  $$('[data-copy]').forEach((btn) => {
    if (btn.dataset.bound) return;
    btn.dataset.bound = '1';
    btn.addEventListener('click', async () => {
      const text = btn.dataset.copy;
      try {
        // The clipboard API needs a secure context; fall back to a hidden
        // textarea so copy still works over plain HTTP on a LAN.
        if (navigator.clipboard && window.isSecureContext) {
          await navigator.clipboard.writeText(text);
        } else {
          const ta = document.createElement('textarea');
          ta.value = text;
          ta.style.position = 'fixed';
          ta.style.opacity = '0';
          document.body.append(ta);
          ta.select();
          document.execCommand('copy');
          ta.remove();
        }
        btn.textContent = 'Copied';
        setTimeout(() => (btn.textContent = 'Copy'), 1500);
      } catch {
        toast('Could not copy — select the text manually', 'error');
      }
    });
  });
}

/* ---------- router ------------------------------------------------------ */

const router = {
  current: 'dashboard',

  route() {
    const hash = window.location.hash.replace(/^#\/?/, '') || 'dashboard';
    return pages[hash] ? hash : 'dashboard';
  },

  async navigate() {
    const name = this.route();
    this.current = name;
    const page = pages[name];

    $$('.nav a').forEach((a) => a.classList.toggle('active', a.dataset.route === name));
    $('#page-title').textContent = page.title;
    $('#page-subtitle').textContent = page.subtitle || '';
    $('#sidebar').classList.remove('open');

    const view = $('#view');
    view.setAttribute('aria-busy', 'true');

    try {
      view.innerHTML = sanitize(await page.render());
      if (page.mounted) await page.mounted();
      paintDynamic(view);
      bindCopyButtons();
      $('#refresh-note').textContent = `Updated ${new Date().toLocaleTimeString('en-GB')}`;
    } catch (err) {
      if (!(err instanceof ApiError && err.status === 401)) {
        view.innerHTML = emptyState('Could not load this page', esc(err.message || 'The request failed.'), { icon: '!' });
        reportError(err);
      }
    } finally {
      view.setAttribute('aria-busy', 'false');
    }
  },

  reload() {
    return this.navigate();
  },
};

/* ---------- auth & bootstrap -------------------------------------------- */

function showLogin() {
  $('#app').hidden = true;
  $('#login').hidden = false;
  $('#password').focus();
}

function showApp() {
  $('#login').hidden = true;
  $('#app').hidden = false;
}

async function refreshSidebarStatus() {
  try {
    const overview = await apiGet('/overview');
    const chip = $('#sidebar-status');
    const map = { protected: 'ok', degraded: 'warn', offline: 'bad' };
    chip.className = `status-chip ${map[overview.protectionStatus] || ''}`;
    $('#sidebar-status-text').textContent =
      overview.protectionStatus === 'protected'
        ? 'Resolver online'
        : overview.protectionStatus === 'degraded'
          ? 'Not enforcing'
          : 'No blocklist loaded';
    $('#sidebar-version').textContent = `v${overview.version}`;
  } catch {
    /* the page render will surface the real error */
  }
}

async function boot() {
  $('#login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const err = $('#login-error');
    err.hidden = true;
    try {
      await apiSend('POST', '/auth/login', { password: $('#password').value });
      $('#password').value = '';
      showApp();
      await router.navigate();
      await refreshSidebarStatus();
    } catch (ex) {
      err.textContent = ex.message || 'Sign in failed';
      err.hidden = false;
    }
  });

  $('#logout-btn').addEventListener('click', async () => {
    try {
      await apiSend('POST', '/auth/logout');
    } catch {
      /* logging out locally is what matters */
    }
    showLogin();
  });

  $('#refresh-btn').addEventListener('click', () => {
    router.reload();
    refreshSidebarStatus();
  });

  $('#menu-btn').addEventListener('click', () => $('#sidebar').classList.toggle('open'));

  window.addEventListener('hashchange', () => router.navigate());

  // Keep the dashboard fresh without hammering a single-vCPU box.
  setInterval(() => {
    if (document.hidden || $('#app').hidden) return;
    if (router.current === 'dashboard' || router.current === 'threats') router.reload();
    refreshSidebarStatus();
  }, 30000);

  let session;
  try {
    session = await apiGet('/auth/session');
  } catch {
    showLogin();
    return;
  }

  if (session && session.authenticated) {
    showApp();
    await router.navigate();
    await refreshSidebarStatus();
  } else {
    showLogin();
  }
}

// In a browser this is the entry point. Under `node --test` there is no
// document to boot against, and the point of loading the file there is to
// exercise the pure rendering functions below, so the dashboard stays asleep.
if (typeof document !== 'undefined') {
  boot();
}

/*
 * Test surface.
 *
 * The dashboard is a plain script with no build step, and it stays that way:
 * this is not a module system, it is four lines that let `node --test` require
 * the file. `module` is undefined in a browser, so the block is inert there.
 *
 * Only pure functions are exported — the ones that decide what the Threat
 * Observatory card claims. That decision is the one place in the UI where
 * being wrong means telling somebody they are protected when they are not.
 */
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
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
  };
}
