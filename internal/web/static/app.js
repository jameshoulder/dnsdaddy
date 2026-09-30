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

// Threat and policy categories, as a categorical palette.
//
// Not one of these is green, and that is the point. Every value here labels
// something that was BLOCKED, and green in this product means protected,
// healthy, or the affirmative action — so rendering `malware` in the brand
// lime, as V2 did, put the safest colour in the interface on the most
// dangerous word in it.
//
// Severity descends roughly through the list: red for outright malicious,
// amber and violet for suspicious, cooler hues for the policy categories that
// are choices rather than threats. They stay far enough apart in hue to be
// told apart in the breakdown meter, where they appear side by side.
const CATEGORY_COLOURS = {
  malware: '#AD2843',            // danger — outright malicious
  phishing: '#99430B',           // credential theft
  c2: '#A02772',                 // command-and-control
  cryptomining: '#805400',       // resource abuse
  'newly-registered': '#7046AC', // suspicion, not proof
  ads: '#006E76',                // policy, not a threat
  adult: '#9F375C',              // policy
  gambling: '#726000',           // policy
  custom: '#526578',             // operator's own list
};

const colourFor = (cat) => CATEGORY_COLOURS[cat] || '#526578';

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
  if (!iso || String(iso).startsWith('0001-01-01')) return 'never';
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

/*
 * Tidy a Go duration string for display.
 *
 * The detector catalogue reports its window exactly as the runtime formats it,
 * which is how "5m0s" and "30m0s" reached a product surface: correct, and
 * plainly machine output. This drops the zero components and nothing else. An
 * input it does not recognise is returned untouched rather than guessed at —
 * a window nobody can parse should be shown as the server stated it, not
 * replaced by a plausible-looking number.
 */
function goDuration(text) {
  if (typeof text !== 'string' || !/^\d+(\.\d+)?(ns|us|µs|ms|s|m|h)([\d.]+(ns|us|µs|ms|s|m|h))*$/.test(text)) {
    return text == null ? '' : String(text);
  }
  const parts = text.match(/\d+(?:\.\d+)?(?:ns|us|µs|ms|s|m|h)/g) || [];
  const kept = parts.filter((part) => parseFloat(part) !== 0);
  return kept.length ? kept.join(' ') : parts[parts.length - 1];
}

/*
 * A percentage sized for a headline.
 *
 * The server reports two decimal places, which is the right amount for an API
 * and two too many for a number set at forty-eight pixels: "28.46%" reads as a
 * measurement taken to the hundredth of a percent by a resolver that counted
 * 246 queries. Rounded to a whole number — except below one per cent, where
 * the server's own figure is passed through untouched, because rounding a real
 * 0.25% down to "0%" would make a small but genuine block rate look like the
 * absence of one.
 */
function rate(value) {
  const n = Number(value);
  if (!isFinite(n)) return '—';
  if (n > 0 && n < 1) return String(value);
  return String(Math.round(n));
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

const apiGet = (path, options) => api(path, options);
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
  // The axis moved out of the SVG, so the plot gets the height that used to be
  // reserved for it.
  const padBottom = 8;
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

  // The axis is HTML beside the SVG rather than <text> inside it. The plot
  // stretches to the card with preserveAspectRatio="none", which squashes any
  // glyph it contains — at phone width the labels were unreadable. Sampling is
  // uniform, and the last bucket is always included, so spacing them evenly
  // across the same box puts each label under the point it belongs to.
  const labelEvery = Math.max(1, Math.round(buckets.length / 6));
  const labelIdx = [];
  for (let i = 0; i < buckets.length; i += labelEvery) labelIdx.push(i);
  if (labelIdx[labelIdx.length - 1] !== buckets.length - 1) labelIdx.push(buckets.length - 1);
  const axis = labelIdx.map((i) => html`<span>${buckets[i].label}</span>`).join('');

  const gridlines = [0.25, 0.5, 0.75]
    .map((f) => {
      const y = padTop + plotH * f;
      return `<line x1="${padX}" y1="${y}" x2="${W - padX}" y2="${y}" stroke="var(--border)" stroke-width="1" stroke-dasharray="3 4"/>`;
    })
    .join('');

  return html`
    <svg class="chart" viewBox="0 0 ${raw(W)} ${raw(H)}" preserveAspectRatio="none" role="img"
         aria-label="DNS queries and blocks over time">
      <defs>
        <linearGradient id="areaFill" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="var(--brand-cyan)" stop-opacity="0.18"/>
          <stop offset="100%" stop-color="var(--brand-cyan)" stop-opacity="0"/>
        </linearGradient>
      </defs>
      ${raw(gridlines)}
      <path d="${raw(area(totalPts))}" fill="url(#areaFill)"/>
      <path d="${raw(line(totalPts))}" fill="none" stroke="var(--brand-cyan)" stroke-width="2"
            stroke-linejoin="round" stroke-linecap="round" vector-effect="non-scaling-stroke"/>
      <path d="${raw(line(blockedPts))}" fill="none" stroke="var(--danger)" stroke-width="1.75"
            stroke-linejoin="round" stroke-linecap="round" vector-effect="non-scaling-stroke"/>
    </svg>
    <div class="chart-axis">${raw(axis)}</div>
    <div class="chart-legend">
      <span><i class="swatch" data-bg="var(--brand-cyan)"></i>Total queries · peak ${num(max)}/h</span>
      <span><i class="swatch" data-bg="var(--danger)"></i>Blocked queries</span>
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
    protected: ['ok', 'Filtering configured'],
    operational: ['ok', 'Operational'],
    healthy: ['ok', 'Healthy'],
    ok: ['ok', 'OK'],
    degraded: ['warn', 'Degraded'],
    // Cyan, not amber. Nothing has been measured here yet; that is an
    // observation, and it sat beside genuine cautions wearing their colour.
    'no-traffic': ['info', 'No traffic yet'],
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

  // A dashboard hostname can point at a reverse proxy, not at the DNS
  // listener. Its HTTP port also says nothing about a published DNS port.
  const target = '<your-server-ip>';

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
        <details class="first-client-guide"><summary>Connection steps</summary>
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
        </details>
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
        <details class="first-client-guide"><summary>Connection steps</summary>
        <p class="muted small">
          DNS-over-HTTPS and DNS-over-TLS clients holding a network's token are
          identified by that token rather than by where they connect from, so
          they are unaffected by this.
        </p>
        <ol class="small first-client-steps">
          <li>Open <a href="#/networks">Networks</a> and add your client or network.</li>
          <li>Tick <strong>Allow this network to use DNS Daddy</strong>.</li>
          <li>Open <a href="#/setup">Setup</a> and check the server’s LAN address and published DNS port.</li>
          <li>Test it: <code>dig @${target} -p &lt;host-dns-port&gt; example.com A</code></li>
        </ol>
        <p class="muted small">
          It takes effect immediately — there is nothing to restart and no file
          to edit.
        </p>
        ${raw(footer)}
        </details>
      </div>`;
  }

  return html`
    <div class="card first-client">
      <div class="first-client-title">No devices have used this resolver yet</div>
      <p class="muted small">
        No device outside this server has been recorded using DNS Daddy yet.
        Test one permitted device before changing your whole network.
      </p>
      <details class="first-client-guide"><summary>Connection steps</summary>
      <p class="small">Try this from a machine you expect it to serve:</p>
      <pre class="first-client-cmd">dig @${target} -p &lt;host-dns-port&gt; example.com A</pre>
      <p class="muted small">
        Use the server’s LAN or VPN address and published DNS port from <a href="#/setup">Setup</a>.
        The dashboard address may be a proxy or SSH tunnel. Then look for the query in the Query log.
      </p>
      <p class="muted small">
        If it comes back <code>REFUSED</code>, that address is not permitted
        yet — add it under <a href="#/networks">Networks</a> and tick
        <strong>Allow this network to use DNS Daddy</strong>.
      </p>
      ${raw(footer)}
      </details>
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

function unavailableState(title, body) {
  return emptyState(title, body, {
    icon: '!',
    action: '<button type="button" class="btn btn-ghost btn-sm" data-page-retry>Retry</button>',
  });
}

function copyBlock(text) {
  return html`
    <div class="copy-row">
      <div class="code">${text}</div>
      <button class="btn btn-ghost btn-sm" data-copy="${text}">Copy</button>
    </div>
  `;
}

function serverAddressRow(address, { featured = false, label = '' } = {}) {
  const labels = { private: 'Private network', public: 'Public address', loopback: 'This machine only', link_local: 'Link-local' };
  const endpoints = Array.isArray(address.dns) ? address.dns : [];
  const portable = endpoints.length > 0 && address.type !== 'link_local';
  const ports = endpoints.map((endpoint) => `${String(endpoint.transport || '').toUpperCase()} ${endpoint.port}`).join(' · ');
  return html`<div class="server-address ${featured ? 'server-address-featured' : ''}">
    <div class="server-address-main">${raw(label ? html`<p class="small muted">${label}</p>` : '')}<div class="server-address-value"><span class="mono">${address.address}</span>
      <span class="badge">${address.family === 'ipv6' ? 'IPv6' : address.family === 'ipv4' ? 'IPv4' : 'IP'}</span></div>
      <p class="small muted">${labels[address.type] || 'Unknown address scope'}${address.interface ? ` · ${address.interface}` : ''}${ports ? ` · ${ports}` : ''}</p>
      ${raw(address.type === 'loopback' ? html`<p class="small rec-note is-warn">Other devices cannot use this loopback address.</p>` : '')}
      ${raw(!portable ? html`<p class="small muted">${address.type === 'link_local' ? 'A link-local address needs the client’s network-interface scope. No portable endpoint is offered.' : 'No configured DNS listener matches this address.'}</p>` : '')}
    </div>
    ${raw(portable ? html`<button type="button" class="btn ${featured ? 'btn-primary' : 'btn-ghost'} btn-sm" data-copy="${address.address}" aria-label="Copy IP address ${address.address}">Copy IP</button>` : '')}
  </div>`;
}

function serverAddressesCard(data) {
  if (!data) return html`<section class="card section server-address-card" aria-labelledby="server-address-title"><div class="card-head"><div><h2 id="server-address-title">Server IP addresses</h2><p>Addresses for configuring your DNS clients.</p></div><a class="btn btn-ghost btn-sm" href="#/setup">Connection setup</a></div>
    ${raw(unavailableState('Server addresses unavailable', 'The server could not report its local interface addresses. No address is inferred from this browser’s location.'))}</section>`;
  const addresses = Array.isArray(data.addresses) ? data.addresses : [];
  const preferred = addresses.find((address) => address.address === data.preferredAddress && ['private', 'public'].includes(address.type) && (address.dns || []).length);
  // Show a known local address even when none can be recommended to another
  // device. Visibility must not promote loopback or an unmatched interface
  // into a preferred LAN destination.
  const displayed = preferred || addresses.find((address) => address.type !== 'link_local' && (address.dns || []).length) || addresses[0];
  const displayedLabel = preferred ? '' : displayed && displayed.type === 'loopback' ? 'Host-only IP' : data.source === 'connection_local_address' ? 'Local connection IP' : 'Detected IP';
  const others = addresses.filter((address) => address !== displayed);
  const listeners = Array.isArray(data.listeners) ? data.listeners : [];
  const hasNonstandardDNSPort = displayed && (displayed.dns || []).some((endpoint) => ['udp', 'tcp'].includes(endpoint.transport) && endpoint.port !== 53);
  return html`<section class="card section server-address-card" aria-labelledby="server-address-title"><div class="card-head"><div><div class="card-eyebrow">Connect your devices</div><h2 id="server-address-title">Server IP addresses</h2></div><a class="btn btn-ghost btn-sm" href="#/setup">Connection setup</a></div>
    ${raw(displayed ? serverAddressRow(displayed, { featured: true, label: displayedLabel }) : '')}
    ${raw(!preferred ? html`<p class="notice-inline">No LAN or public address matching a DNS listener was identified. Review the available interfaces and configured listeners below.</p>` : '')}
    <p class="small muted server-address-note">${data.source === 'connection_local_address' ? 'Reported by this dashboard connection’s local socket; other interfaces could not be enumerated.' : 'Detected on this server’s interfaces; reachability has not been tested.'} Containers, NAT and port mappings may require a different host address.</p>
    ${raw(hasNonstandardDNSPort ? html`<p class="small rec-note is-warn">DNS is using a non-standard port. Copy IP copies the address only; configure the displayed port separately on clients that support it.</p>` : '')}
    ${raw(data.partial || data.truncated ? html`<p class="small rec-note is-warn">${data.partial ? 'Some interfaces could not be read. ' : ''}${data.truncated ? `The address list is limited to ${data.limit || 32} entries. ` : ''}This list may be incomplete.</p>` : '')}
    <details class="server-address-details"><summary>All addresses, listeners and connection notes</summary>
      ${raw(others.length ? html`<div class="server-address-list">${raw(others.map((address) => serverAddressRow(address)).join(''))}</div>` : !displayed ? html`<p class="small muted">No local interface address was returned.</p>` : '')}
      ${raw(listeners.length ? html`<div class="table-wrap note-tight"><table><thead><tr><th>Client transport</th><th>Configured listener</th><th>Binding</th></tr></thead><tbody>${raw(listeners.map((listener) => html`<tr>
        <td>${listener.transport === 'dot' ? 'DNS-over-TLS' : String(listener.transport || '').toUpperCase()}</td><td class="mono small">${listener.listen || 'Not configured'}</td><td>${listener.enabled ? listener.binding : 'Disabled'}</td></tr>`).join(''))}</tbody></table></div>` : '')}
      ${(data.notes || []).length ? raw(html`<ul class="compact-list">${raw(data.notes.map((note) => html`<li>${note}</li>`).join(''))}</ul>`) : ''}
      <p class="small muted">These are listener-compatible candidates, not reachability probes. Client permission, firewall rules and TLS hostname checks still apply.</p>
    </details>
  </section>`;
}

/* ---------- Feed refresh and health ------------------------------------- */

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
  // "Active" means this feed is in the
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

// Feed health and an explicit route to operator-owned external APIs.
function threatIntelPanel(data) {
  if (!data) return html`<div class="card"><div class="card-head"><h2>Threat intelligence</h2></div>
    ${raw(unavailableState('Threat intelligence unavailable', 'Feed health could not be retrieved. Retry to check the current state.'))}</div>`;
  const feeds = data.feeds || [];
  const enabled = feeds.filter((feed) => feed.enabled);
  const offCount = feeds.length - enabled.length;
  return html`<div class="card"><div class="card-head"><div><h2>Threat intelligence</h2>
      <p>${num(data.totalIndexedDomains)} domains indexed across enabled feeds.</p></div>
      <a class="btn btn-observe btn-sm" href="#/feeds">Manage feeds</a></div>
    <div class="intel-list">${raw(enabled.map((feed) => html`<div class="feed-row"><span class="feed-name">${feed.name}</span>
      ${raw(feed.loaded && feed.indexedDomains ? html`<span class="feed-meta">${compact(feed.indexedDomains)}</span>` : '')}
      <span class="intel-status">${raw(feedStatusBadge(feed))}</span></div>`).join(''))}</div>
    ${raw(offCount ? html`<p class="muted small mt-3">${offCount} further feed${offCount === 1 ? '' : 's'} available but switched off.</p>` : '')}
    <p class="small note-tight"><a href="#/integrations">Connect your own external APIs →</a></p>
  </div>`;
}

/* ---------- overview ---------------------------------------------------- */

// Configuration, observed activity and faults are separate claims. The
// overview uses existing endpoints and never substitutes a zero for a failed
// read: an empty result and an unavailable result require different actions.

/**
 * The hero's wording, taken from the server's protection status and nothing
 * else.
 *
 * The three states are the server's, with its own definitions restated in
 * plain English: `offline` means the blocklist is empty, `degraded` means it
 * is loaded but no policy enforces a category or a domain. Neither means the
 * process is down, so neither is worded that way — an operator reading
 * "Offline" about a resolver that is answering every query learns the wrong
 * thing and goes looking for the wrong fault.
 */
const PROTECTION_STATES = {
  protected: {
    tone: 'ok',
    word: 'Filtering configured',
    line: 'Threat intelligence is loaded and blocking rules are configured. Each query follows its matched policy.',
  },
  degraded: {
    tone: 'warn',
    word: 'Not enforcing',
    line: 'Threat intelligence is loaded, but no configured policy has category or domain blocking rules.',
  },
  offline: {
    tone: 'bad',
    word: 'No intelligence loaded',
    line: 'No threat intelligence is loaded. Configured domain rules may still apply.',
  },
};

function protectionState(status) {
  return (
    PROTECTION_STATES[status] || {
      tone: 'warn',
      word: String(status || 'Unknown'),
      line: 'The server reported a protection status this dashboard does not recognise. Run dnsdaddy doctor for the authoritative report.',
    }
  );
}

/**
 * Feed health across every enabled feed, graded by exactly the rule
 * feedStatusBadge uses for a single row: `loaded` decides whether a feed is
 * blocking, and the download history never does.
 *
 * Disabled feeds are excluded on purpose. A feed the operator switched off is
 * a decision, not a fault, and counting it as unhealthy would put a permanent
 * warning on a deliberately minimal install.
 */
function feedHealth(data) {
  if (!data || !Array.isArray(data.feeds)) {
    return { tone: 'warn', label: 'Threat intelligence unavailable', unavailable: true,
      enabled: [], broken: [], pending: [], stale: [] };
  }
  const all = (data && data.feeds) || [];
  const enabled = all.filter((f) => f.enabled);

  // Three states, not two. A feed that has never attempted a download is not
  // broken — it is a feed on an install that has not finished starting, and
  // calling that a Fault is the same over-claiming this product avoids
  // everywhere else, just pointing the other way. On a fresh install every
  // feed is in that state for the first minute, and the dashboard used to
  // open with six red faults beside a panel calling the same feeds "Pending".
  //
  // This matches feedStatusBadge exactly, which is the point: two components
  // describing the same feed on the same page must not disagree.
  //
  //   loaded                        blocking now
  //   !loaded && (error || success) attempted and unusable  -> broken
  //   !loaded && neither            nothing attempted yet   -> pending
  const broken = enabled.filter((f) => !f.loaded && (f.lastError || f.lastSuccessAt));
  const pending = enabled.filter((f) => !f.loaded && !f.lastError && !f.lastSuccessAt);
  const stale = enabled.filter((f) => f.loaded && f.lastError);

  if (!enabled.length) {
    return { tone: 'bad', label: 'No threat intelligence enabled', enabled, broken, pending, stale };
  }
  if (broken.length) {
    return {
      tone: 'bad',
      label: `${broken.length} of ${enabled.length} feeds not blocking`,
      enabled, broken, pending, stale,
    };
  }
  if (stale.length) {
    return {
      tone: 'warn',
      label: `${stale.length} of ${enabled.length} feeds stale`,
      enabled, broken, pending, stale,
    };
  }
  if (pending.length) {
    return {
      tone: 'warn',
      label: pending.length === enabled.length
        ? 'Threat intelligence not loaded yet'
        : `${pending.length} of ${enabled.length} feeds not loaded yet`,
      enabled, broken, pending, stale,
    };
  }
  return { tone: 'ok', label: 'Threat intelligence healthy', enabled, broken, pending, stale };
}

function toneBadgeClass(tone) {
  return tone === 'bad' ? 'bad' : tone === 'warn' ? 'warn' : 'ok';
}

/**
 * The status block the page opens with.
 *
 * The headline describes the server's configuration heuristic; feed health
 * has its own labelled badge. A configured rule and a fresh feed are separate
 * facts, and neither alone establishes coverage of every network.
 *
 * Nothing here relies on colour: every state that has a colour also has a word
 * beside it, and the dot's shape changes with severity.
 */
/**
 * The class split under "Blocked queries".
 *
 * A blocked query is an outcome, not proof that the name was malicious: an
 * ads block and a C2 block are both blocks. The server splits the total by
 * the category recorded on each query, and this line states the security
 * share on its own so the headline total is never read as a threat count.
 * Rendered only from a measured split the server actually sent — an older
 * server sends none, and nothing is inferred from the total.
 */
function blockedSplit(measured) {
  const by = measured && measured.outcomes && measured.outcomes.blockedByClass;
  if (!by || typeof by.security !== 'number') return '';
  const other = ['precaution', 'preference', 'custom', 'unclassified']
    .reduce((sum, k) => sum + (typeof by[k] === 'number' ? by[k] : 0), 0);
  return html`<span class="hero-split">${num(by.security)} security · ${num(other)} other</span>`;
}

/**
 * The resolver card's facts, from the measured block where the server sent
 * one and from the legacy fields where it did not.
 *
 * Each cell is one measurement with its scope in the label. "Unmeasured" and
 * "Unavailable" are rendered as words rather than as a zero, because a zero
 * says something happened and was counted, and these say nobody counted.
 */
function measuredFacts(overview) {
  const m = overview && overview.measured;
  // `value` is already-escaped markup and `note` is plain text. The note's
  // own span is built with html`` — which escapes the text once — and then
  // marked raw, because interpolating one html`` result into another escapes
  // it a second time and the reader sees the markup as text.
  const cell = (label, value, note) => html`<div><div class="label muted small">${label}</div><div>${raw(value)}${raw(note ? html` <span class="muted small">${note}</span>` : '')}</div></div>`;
  if (!m) {
    return html`
      ${raw(cell('Configured networks', html`${num(overview.protectedNetworks)}`))}
      ${raw(cell('Policies', html`${num(overview.activePolicies)}`))}`;
  }
  const n = m.networks || {};
  const c = m.clients || {};
  const f = m.filtering || {};
  const feeds = m.feeds || {};
  const rate = (m.resolver && m.resolver.errorRate) || {};
  const errors = (m.outcomes && m.outcomes.errors) || {};
  const hours = m.window && m.window.hours ? `${m.window.hours}h` : 'window';

  const clients = c.attribution && typeof c.observedInWindow === 'number'
    ? html`${num(c.observedInWindow)}`
    : html`<span class="muted is-unavailable">Not recorded</span>`;
  const rateText = rate.available
    ? html`${rate.ratio >= 0.0005 || rate.ratio === 0 ? rate.ratio === 0 ? '0%' : `${(rate.ratio * 100).toFixed(1)}%` : '<0.1%'}`
    : html`<span class="muted is-unavailable">Unmeasured</span>`;
  const rateNote = rate.available
    ? `${num(rate.numerator)} of ${num(rate.denominator)}`
    : (rate.unavailable || '');
  const errorNote = errors.complete === false && errors.measuredSince
    ? `counted since ${new Date(errors.measuredSince).toLocaleString('en-GB')}`
    : '';

  return html`
    ${raw(cell('Networks', html`${num(n.configured)} configured`, `${num(n.enabled)} enabled · ${num(n.resolverPermitted)} permitted · ${num(n.withTrafficInWindow)} with traffic (${hours})`))}
    ${raw(cell(`Clients seen (${hours})`, clients, c.attribution ? '' : (c.unavailable || 'client addresses are not recorded')))}
    ${raw(cell('Blocking policies in use', html`${num(f.blockingPoliciesAssigned)} of ${num(f.blockingPolicies)}`, `${num(n.monitorOnly)} enabled network${n.monitorOnly === 1 ? '' : 's'} monitor-only`))}
    ${raw(cell('Feeds', html`${num(feeds.loaded)} of ${num(feeds.enabled)} loaded`, `${num(feeds.failing)} failing · ${num(feeds.neverDownloaded)} never downloaded${f.categoryBlockingAvailable ? '' : ' · index empty'}`))}
    ${raw(cell(`Resolution failures (${hours})`, rateText, rateNote))}
    ${raw(cell('Failed queries', html`${num(errors.count)}`, errorNote || `in the last ${hours}`))}`;
}

function statusHero(overview, feedsData, detections) {
  const state = protectionState(overview.protectionStatus);
  const intel = feedHealth(feedsData);
  const indexed = feedsData ? feedsData.totalIndexedDomains : null;

  // Behavioural detection has three answers and they are not interchangeable.
  // A zero says "nothing suspicious happened"; nobody measured that when the
  // detector is switched off, and nobody measured it when the request failed
  // either. Only a count that came back gets rendered as a count.
  let detectionStat;
  if (!detections) {
    detectionStat = html`<div class="hero-stat"><span class="n muted is-unavailable">Unavailable</span><span class="k">Findings</span></div>`;
  } else if (detections.enabled === false) {
    detectionStat = html`<div class="hero-stat"><span class="n muted">Off</span><span class="k">Findings</span></div>`;
  } else {
    detectionStat = html`<div class="hero-stat is-detect"><span class="n">${num(detections.total)}</span><span class="k">Findings</span></div>`;
  }

  return html`
    <section class="hero is-${state.tone}" aria-label="Filtering configuration and activity">
      <div class="hero-top">
        <div class="hero-state">
          <span class="hero-dot" aria-hidden="true"></span>
          <div>
            <h2 class="hero-word">${state.word}</h2>
            <p class="hero-sub">${state.line}</p>
            <p class="hero-sub hero-intel">
              <span class="badge ${toneBadgeClass(intel.tone)}">${intel.label}</span>
              ${raw(intel.unavailable ? '' : html`<span>${num(indexed)} domains indexed${intel.enabled.length ? ` across ${intel.enabled.length} enabled feed${intel.enabled.length === 1 ? '' : 's'}` : ''}</span>`)}
            </p>
          </div>
        </div>
        <div class="hero-period"><span class="badge">Last 24 hours</span></div>
      </div>
      <div class="hero-stats">
        <div class="hero-stat"><span class="n">${num(overview.queries24h)}</span><span class="k">DNS queries</span></div>
        <div class="hero-stat is-blocked"><span class="n">${num(overview.threatsBlocked24h)}</span><span class="k">Blocked queries</span>${raw(blockedSplit(overview.measured))}</div>
        <!-- No queries in the period means no rate to state. Zero per cent is
             a measurement; this is the absence of one. -->
        <div class="hero-stat">
          <span class="n">${overview.queries24h ? `${rate(overview.blockRate24h)}%` : '—'}</span>
          <span class="k">Of all queries</span>
        </div>
        ${raw(detectionStat)}
      </div>
    </section>
  `;
}

/**
 * Everything the server currently reports as wrong, in one list.
 *
 * The two sources are the diagnostics endpoint — which is authoritative for
 * configuration and stays so; nothing here second-guesses it — and feed health
 * graded by the same rule the feed badges use. An operator should not have to
 * decide which of two panels is the real one, so there is only one.
 *
 * A diagnostics request that failed is itself an item. The alternative is a
 * page that quietly reports "nothing needs attention" on the strength of
 * checks it never received, which is the single most misleading thing this
 * panel could do.
 */
function attentionItems(diagnostics, feedsData, unavailable = []) {
  const items = [];

  if (!diagnostics || !Array.isArray(diagnostics.checks)) {
    items.push({
      tone: 'warn',
      title: 'Configuration checks unavailable',
      body: 'The diagnostics endpoint did not answer, so this page cannot confirm the configuration is sound. Run dnsdaddy doctor on the server.',
    });
  } else if (Array.isArray(diagnostics.checks)) {
    for (const c of diagnostics.checks) {
      if (c.status !== 'fail' && c.status !== 'warn') continue;
      items.push({
        tone: c.status === 'fail' ? 'bad' : 'warn',
        title: c.name || c.section || 'Configuration',
        body: [c.summary, c.action].filter(Boolean).join(' '),
        evidence: c.evidence || [],
      });
    }
  }

  const health = feedHealth(feedsData);
  if (health.unavailable) {
    items.push({
      tone: 'warn',
      title: 'Threat intelligence unavailable',
      body: 'Feed health could not be retrieved. Retry to check which sources are loaded.',
    });
  } else if (!health.enabled.length) {
    items.push({
      tone: 'bad',
      title: 'No threat intelligence is enabled',
      body: 'Every feed is switched off, so no domain is being blocked from intelligence. Enable at least one source on the Threat intelligence page.',
    });
  }
  for (const f of health.broken) {
    items.push({
      tone: 'bad',
      title: `${f.name} is not blocking`,
      body: f.lastSuccessAt
        ? `This feed downloaded successfully before, but its contents are not in the index answering queries right now. ${f.loadError || ''}`.trim()
        : `This feed has never produced a usable download. ${f.lastError || ''}`.trim(),
    });
  }
  // Pending is one item, not one per feed: on a fresh install every feed is
  // pending at once, and six identical rows saying "still downloading" is
  // noise rather than information.
  if (health.pending.length && !health.broken.length) {
    items.push({
      tone: 'warn',
      title: health.pending.length === health.enabled.length
        ? 'Threat intelligence has not downloaded yet'
        : `${health.pending.length} feeds have not downloaded yet`,
      body: 'Nothing is being blocked from these sources until the first download finishes. On a new install that takes a minute or two; if it persists, check that this machine can reach them over HTTPS.',
    });
  }
  for (const f of health.stale) {
    items.push({
      tone: 'warn',
      title: `${f.name} is stale`,
      body: `The last known good copy is still indexed and still blocking, but the most recent refresh failed. ${f.lastError || ''}`.trim(),
    });
  }

  return items.concat(unavailable.map((title) => ({
    tone: 'warn', title, body: 'This endpoint could not be retrieved. Retry to check its current state.',
  })));
}

function attentionPanel(items) {
  const bad = items.filter((i) => i.tone === 'bad').length;

  const body = items.length
    ? items
        .map(
          (i) => html`
            <div class="attn-item ${i.tone === 'bad' ? 'is-bad' : ''}">
              <span class="badge ${toneBadgeClass(i.tone)} attn-badge">${i.tone === 'bad' ? 'Fault' : 'Warning'}</span>
              <div class="attn-body">
                <strong>${i.title}</strong>
                ${raw((i.body || '').length > 140 || (i.evidence || []).length
                  ? html`<details class="attn-details"><summary>Details and next step</summary>
                      <p>${i.body}</p>
                      ${raw((i.evidence || []).length ? html`<ul>${raw(i.evidence.map((e) => html`<li>${e}</li>`).join(''))}</ul>` : '')}
                    </details>`
                  : html`<p>${i.body}</p>`)}
              </div>
            </div>`
        )
        .join('')
    : html`
        <div class="attn-clear">
          <span class="hero-dot" aria-hidden="true"></span>
          <div class="attn-body">
            <strong>Nothing needs your attention</strong>
            <p>No warnings or faults were returned by configuration checks or feed health.</p>
          </div>
        </div>`;

  const lede = items.length
    ? `${items.length} item${items.length === 1 ? '' : 's'}${bad ? ` · ${bad} fault${bad === 1 ? '' : 's'}` : ''}`
    : 'Configuration checks and feed health.';

  return html`
    <div class="card">
      <div class="card-head">
        <div><h2>Needs attention</h2><p>${lede}</p></div>
        <div class="row-end"><a class="btn btn-ghost btn-sm" href="#/setup">Setup</a></div>
      </div>
      ${raw(body)}
    </div>
  `;
}

/**
 * The most recent blocked queries, exactly as logged.
 *
 * Domains are monospace so a typosquat is visible as one, and nothing beside
 * them is invented: the category is the category the resolver filed the block
 * under, the client is the client it attributed, and a query with neither
 * shows neither. The full prose reason and the feed it came from are a click
 * away in the query log rather than guessed at here.
 */
function recentlyBlocked(rows) {
  if (!rows) {
    return unavailableState('Recent blocks unavailable', 'The query log could not be retrieved. Retry to see the latest recorded blocks.');
  }
  if (!rows.length) {
    return emptyState(
      'Nothing blocked in the log yet',
      'Either the query log is switched off, or nothing resolving through DNS Daddy has asked for a blocked domain yet.',
      { icon: '⃠', action: '<a class="btn btn-observe btn-sm" href="#/queries?action=blocked">Open query log</a>' }
    );
  }
  return rows
    .map(
      (q) => html`
        <div class="dom-row">
          <a class="dom-name" href="${queryHash({ domain: q.domain, action: 'blocked' })}">${q.domain}</a>
          <span class="dom-meta">
            ${raw(q.category ? categoryBadge(q.category) : '')}
            ${raw(q.clientName || q.clientIp ? html`<span class="mono">${q.clientName || q.clientIp}</span>` : '')}
            <span>${relTime(q.time)}</span>
          </span>
        </div>`
    )
    .join('');
}

/**
 * Domains blocked more than once, presented as recurrence rather than as a
 * count in a column.
 *
 * A number in a table cell is a fact; "47 times, most recently 3 minutes ago"
 * is the same fact answering the question somebody actually has, which is
 * whether this is still happening. A single block is a page that loaded a bad
 * ad once; forty-seven is something on the network retrying, and that is worth
 * opening the query log for.
 *
 * No enrichment beyond what the server recorded: the category is the category
 * it filed the block under, and the count and timestamp are its own.
 */
function repeatOffenders(domains) {
  if (!domains || !domains.length) {
    return emptyState(
      'Nothing has been blocked yet',
      'Either nothing malicious has been requested, or no device is using the resolver yet.',
      { icon: '⌾', action: '<a class="btn btn-ghost btn-sm" href="#/setup">Check Setup</a>' }
    );
  }
  const max = Math.max(...domains.map((d) => d.count));
  return domains
    .map((d) => {
      const recurring = d.count > 1;
      return html`
        <div class="offender">
          <div class="offender-body">
            <span class="offender-name mono">${d.domain}</span>
            <span class="offender-meta">
              ${raw(d.category ? categoryBadge(d.category) : '')}
              <span>${recurring ? `blocked ${num(d.count)} times` : 'blocked once'}</span>
              ${raw(d.lastSeen ? html`<span>last ${relTime(d.lastSeen)}</span>` : '')}
            </span>
            <span class="offender-meter" aria-hidden="true">
              <span data-width="${raw(Math.max(3, (d.count / max) * 100).toFixed(1))}"
                    data-bg="${colourFor(d.category)}"></span>
            </span>
          </div>
          <a class="btn btn-ghost btn-sm offender-go" href="${queryHash({ domain: d.domain })}"
             data-investigate="${d.domain}">Investigate</a>
        </div>`;
    })
    .join('');
}

/**
 * Which kinds of threat were blocked, as a share of the blocks in the period.
 *
 * Deliberately not a progress bar: the meter is a proportion of the largest
 * category, and the count that produced it is stated beside it, because a bar
 * on its own invites the reading that something is filling up.
 */
function protectionBreakdown(rows) {
  if (!rows || !rows.length) {
    return emptyState(
      'No blocks in this period',
      'When DNS Daddy blocks something, the category it was blocked under appears here.',
      { icon: '◔' }
    );
  }
  const max = Math.max(...rows.map((r) => r.count));
  const total = rows.reduce((sum, r) => sum + r.count, 0);
  return rows
    .map((r) => {
      const share = total ? Math.round((r.count / total) * 100) : 0;
      const width = Math.max(2, (r.count / max) * 100).toFixed(1);
      return html`
        <div class="cat-row">
          <span class="cat-name">${r.label}</span>
          <span class="cat-n">${num(r.count)} · ${raw(String(share))}%</span>
          <span class="cat-meter"><span data-width="${raw(width)}" data-bg="${colourFor(r.category)}"></span></span>
        </div>`;
    })
    .join('');
}

/* ---------- pages ------------------------------------------------------- */

const pages = {};

pages.dashboard = {
  title: 'Overview',
  subtitle: 'Resolver activity, filtering configuration and the next thing to check.',
  async render(context = {}) {
    const read = (path) => apiGet(path, { signal: context.signal });
    const optional = (path) => read(path).catch((err) => {
      if (err.status === 401 || err.name === 'AbortError') throw err;
      return null;
    });
    const [overview, activity, categories, recent, feeds, diagnostics, detections, native, learning, addresses] = await Promise.all([
      read('/overview'),
      optional('/activity/queries?hours=24'),
      optional('/threats/categories?hours=24'),
      optional('/queries?action=blocked&limit=8'),
      optional('/feeds'),
      optional('/diagnostics'),
      optional('/findings/summary?days=1'),
      optional('/dnssec/status?hours=24'),
      optional('/learning/status'),
      optional('/server-addresses'),
    ]);
    if (!context.isCurrent || context.isCurrent()) this.feeds = feeds;

    const catRows = categories ? (categories.categories || []).map((c) => ({
      label: c.label, count: c.count, category: c.category,
    })) : null;
    const buckets = activity ? activity.buckets || [] : [];
    const hadTraffic = buckets.some((b) => b.total > 0);
    const unavailable = [
      !activity && 'Query activity unavailable',
      !categories && 'Block categories unavailable',
      !recent && 'Recent blocks unavailable',
      !detections && 'Findings unavailable',
    ].filter(Boolean);

    return html`
      <div class="overview-workspace">
        ${raw(statusHero(overview, feeds, detections))}
        ${raw(serverAddressesCard(addresses))}
        ${raw(nativeOverview(native, learning))}
        <div class="overview-primary">
          <section class="card overview-activity">
            <div class="card-head">
              <div><h2>DNS activity</h2><p>Queries and blocks over the last 24 hours.</p></div>
              <div class="row-end"><a class="btn btn-observe btn-sm" href="#/queries?hours=24">Query log</a></div>
            </div>
            ${raw(!activity
              ? unavailableState('Query activity unavailable', 'Hourly query counts could not be retrieved. Retry to see the current activity.')
              : hadTraffic
                ? html`<div class="chart-wrap">${raw(areaChart(buckets))}</div>
                    <details class="chart-data"><summary>View hourly values</summary>
                      <div class="table-wrap"><table><thead><tr><th>Hour</th><th>Queries</th><th>Blocked</th></tr></thead>
                      <tbody>${raw(buckets.map((b) => html`<tr><td>${b.label}</td><td>${num(b.total)}</td><td>${num(b.blocked)}</td></tr>`).join(''))}</tbody></table></div>
                    </details>`
                : emptyState('No DNS activity recorded',
                    'No query activity is recorded for the last 24 hours. Check client configuration and query logging if you expected traffic.',
                    { icon: '∿', action: '<a class="btn btn-ghost btn-sm" href="#/setup">Setup guide</a>' }))}
          </section>
          <div class="overview-attention">${raw(attentionPanel(attentionItems(diagnostics, feeds, unavailable)))}</div>
        </div>

        ${raw(firstClientCard(overview))}

        <div class="section grid grid-2">
          <div class="card">
            <div class="card-head">
              <div><h2>Recently blocked</h2><p>Newest first, as recorded in the query log.</p></div>
              <div class="row-end"><a class="btn btn-observe btn-sm" href="#/queries?action=blocked">View log</a></div>
            </div>
            ${raw(recentlyBlocked(recent ? recent.queries : null))}
          </div>
          <div class="card">
            <div class="card-head"><div><h2>Blocked by category</h2><p>Recorded blocks in the last 24 hours.</p></div></div>
            ${raw(catRows
              ? protectionBreakdown(catRows)
              : unavailableState('Block categories unavailable', 'The category breakdown could not be retrieved. Retry to check the recorded blocks.'))}
          </div>
        </div>

        <div class="section grid grid-2">
          ${raw(threatIntelPanel(feeds))}
          <div class="card">
            <div class="card-head"><div><h2>Resolver</h2><p>This instance, its configured scope and what was measured. Each figure names its own window.</p></div></div>
            <div class="grid grid-3">
              <div><div class="label muted small">Status</div><div>${raw(statusBadge(overview.resolverStatus))}</div></div>
              <div><div class="label muted small">Uptime</div><div>${duration(overview.uptimeSeconds)}</div></div>
              <div><div class="label muted small">Feeds refreshed</div><div>${relTime(overview.lastFeedRefresh)}</div></div>
              ${raw(measuredFacts(overview))}
              <div><div class="label muted small">Policies</div><div>${num(overview.activePolicies)}</div></div>
              <div><div class="label muted small">Version</div><div class="mono small">${overview.version}</div></div>
            </div>
          </div>
        </div>
      </div>
    `;
  },
  async mounted() {
  },
};

/* ---------- decision records: "why was this blocked?" -------------------- */

/*
 * The read path for a decision record. Everything rendered here came from
 * storage as it was when the decision was made — the explanation is a stored
 * sentence, not one this file composes. That is deliberate: a dashboard that
 * rewrote explanations from current data would quietly change why something
 * was blocked whenever a feed refreshed.
 *
 * Nothing here invents a reason. A decision with no evidence renders as a
 * decision with no evidence, which is information rather than an embarrassment
 * to be papered over.
 */

const CONFIDENCE_LABEL = { low: 'Low', medium: 'Medium', high: 'High' };

// A source's claim, as that source made it. The kind is shown because "a feed
// listed this" and "a heuristic inferred this" are different claims and an
// operator has to be able to tell them apart at a glance.
//
// Named decisionEvidenceRow rather than evidenceRow because the assurance page
// already has an evidenceRow with a different signature. Two functions of the
// same name in one file is not an error in JavaScript — the later definition
// simply wins — so this collided silently and the decision evidence rendered
// through the assurance page's renderer. Caught by a dashboard test.
function decisionEvidenceRow(cited) {
  const e = cited.evidence || cited;
  const kind = e.kind || 'unknown';
  const conf = CONFIDENCE_LABEL[e.confidence] || e.confidence || '';
  return html`
    <div class="ev-row">
      <div class="ev-main">
        <div class="ev-title">
          <strong>${e.sourceName || e.source}</strong>
          <span class="badge">${kind}</span>
          ${raw(conf ? html`<span class="badge">${conf} confidence</span>` : '')}
          ${raw(cited.contributed ? html`<span class="badge ok">decided this</span>` : '')}
        </div>
        <div class="ev-claim">${e.claim}</div>
        <div class="rec-meta">
          ${raw(e.category ? html`<span>${e.category}</span>` : '')}
          <span>observed ${relTime(e.observedAt)}</span>
          ${raw(e.expiresAt ? html`<span>expires ${relTime(e.expiresAt)}</span>` : '')}
        </div>
      </div>
    </div>`;
}

// One decision, collapsed. The evidence is fetched when it is opened rather
// than with the list: fifty decisions each carrying six evidence rows is a
// payload nobody reads.
function decisionRow(d) {
  return html`
    <details class="decision" data-decision="${d.id}">
      <summary class="decision-head">
        <span class="policy-caret" aria-hidden="true"></span>
        <span class="decision-title">
          <strong class="mono">${d.subject && d.subject.value}</strong>
          <span class="badge ${d.action === 'blocked' ? 'bad' : 'ok'}">${d.action}</span>
        </span>
        <span class="decision-when">${relTime(d.time)}</span>
      </summary>
      <div class="decision-body">
        <p class="decision-why">${d.explanation || 'No explanation was recorded for this decision.'}</p>
        <div class="rec-meta">
          ${raw(d.clientName || d.clientIp ? html`<span>asked by ${d.clientName || d.clientIp}</span>` : '')}
          ${raw(d.qtype ? html`<span>${d.qtype}</span>` : '')}
        </div>
        ${raw(d.policyPath ? html`<div class="decision-path mono">${d.policyPath}</div>` : '')}
        <div class="decision-evidence" data-evidence-for="${d.id}">
          <p class="small muted">Loading the evidence…</p>
        </div>
      </div>
    </details>`;
}

function decisionsCard(data) {
  const rows = data.decisions || [];
  if (!data.recording) {
    return html`
      <div class="card">
        <div class="card-head">
          <div>
            <h2>Why was this blocked?</h2>
            <p>Decision records are switched off.</p>
          </div>
        </div>
        ${raw(
          emptyState(
            'Not recording decisions',
            'Set log.decision_records in dnsdaddy.yaml and restart to keep a record of what ' +
              'decided each block, with the evidence that was true at the time.',
            { icon: '○' }
          )
        )}
      </div>`;
  }
  return html`
    <div class="card">
      <div class="card-head">
        <div>
          <h2>Why was this blocked?</h2>
          <p>Recorded decisions and their evidence. Older decisions without an original snapshot are labelled when expanded.</p>
        </div>
      </div>
      ${raw(
        rows.length
          ? rows.map(decisionRow).join('')
          : emptyState('Nothing decided yet', 'Blocks will appear here as they happen.', { icon: '○' })
      )}
    </div>`;
}

function decisionEvidenceContent(full) {
  const cited = full.evidence || [];
  const provenance = full.evidenceNote || (full.evidenceSource === 'legacy_current_reference' ? 'Legacy decision: these are current references, not an original evidence snapshot.' : '');
  return html`${raw(provenance ? html`<p class="notice-inline ${full.evidenceSource === 'legacy_current_reference' ? 'is-warn' : ''}">${provenance}</p>` : '')}
    ${raw(cited.length ? cited.map(decisionEvidenceRow).join('') : html`<p class="small muted">The evidence behind this decision is no longer on file. The explanation above is what was recorded at the time.</p>`)}`;
}

// mountDecisionCards fetches a decision's evidence the first time it is opened.
function mountDecisionCards() {
  $$('[data-decision]').forEach((el) => {
    el.addEventListener('toggle', async () => {
      if (!el.open || el.dataset.loaded) return;
      el.dataset.loaded = '1';
      const host = $(`[data-evidence-for="${el.dataset.decision}"]`, el);
      try {
        const full = await apiGet(`/decisions/${el.dataset.decision}`);
        host.innerHTML = sanitize(decisionEvidenceContent(full));
        paintDynamic(host);
      } catch (err) {
        host.innerHTML = sanitize(html`<p class="rec-note is-warn">${err.message}</p>`);
      }
    });
  });
}


pages.threats = {
  title: 'Blocked domains',
  subtitle: 'Recorded DNS blocks and the evidence behind them.',
  async render() {
    const [categories, top, recent, decisions] = await Promise.all([
      apiGet('/threats/categories?hours=168'),
      apiGet('/threats/top-domains?days=7&limit=25'),
      apiGet('/queries?action=blocked&limit=50'),
      apiGet('/decisions?limit=25'),
    ]);
    const catRows = categories.categories.map((c) => ({ label: c.label, count: c.count, category: c.category }));
    const total = catRows.reduce((sum, r) => sum + r.count, 0);

    return html`
      ${raw(externalAPICard())}

      <div class="section grid grid-side">
        <div class="card">
          <div class="card-head"><div><h2>By category</h2><p>Last 7 days · ${num(total)} blocked.</p></div></div>
          ${raw(barList(catRows))}
        </div>
        <div class="card">
          <div class="card-head"><div><h2>Repeat offenders</h2><p>Something on your network keeps asking for these.</p></div></div>
          ${raw(repeatOffenders(top.domains))}
        </div>
      </div>

      <div class="section">${raw(decisionsCard(decisions))}</div>

      <div class="card">
        <div class="card-head"><div><h2>Recent blocks</h2><p>The last 50 blocked queries, newest first.</p></div></div>
        ${raw(queryTable(recent.queries))}
      </div>
    `;
  },
  async mounted() {
    mountDecisionCards();


  },
};

/*
 * The answer's recorded authenticated-data status and validation source.
 * Historical records must never inherit the currently selected transport.
 * Legacy records without a source can report AD, but cannot attribute it.
 */
function dnssecBadge(status, source = 'unknown') {
  const locallyValidated = source === 'native' || source === 'encrypted_forwarded';
  const origin = source === 'native' ? 'Daddybound' : source === 'encrypted_forwarded' ? 'Daddybound over encrypted forwarding' : source === 'upstream' ? 'The upstream resolver' : 'The recorded answer';
  const map = {
    validated: [source === 'unknown' ? 'info' : 'ok', source === 'unknown' ? 'AD reported' : 'validated', source === 'unknown' ? 'The answer carried an authenticated-data flag, but its validation source was not recorded.' : `${origin} reported a DNSSEC-validated answer.`],
    unvalidated: ['', 'unvalidated', locallyValidated ? 'No authenticated-data flag: the answer may be unsigned, or the client may have requested checking disabled.' : source === 'upstream' ? 'No AD bit came back: either the zone is unsigned or the upstream did not validate.' : 'No authenticated-data flag was recorded. The validation source is unknown.'],
    servfail: ['bad', 'servfail', `${origin} could not answer. Check the recorded reason: failed or inconclusive validation is one possible cause.`],
  };
  const entry = map[status];
  if (!entry) return html`<span class="muted">—</span>`;
  return html`<span class="badge ${entry[0]}" title="${entry[2]}">${entry[1]}</span>`;
}

/*
 * Daddybound's recorded verdict. Only explicit Live provenance establishes
 * answer-path validation; sampled Learn records never claim enforcement.
 */
function localDnssecBadge(v) {
  const live = v.resolution === 'native_live' || v.resolution === 'encrypted_live';
  const pathLabel = v.resolution === 'encrypted_live' ? 'Encrypted Live validation' : v.resolution === 'native_live' ? 'Native Live validation' : v.resolution === 'encrypted_forwarded' ? 'Encrypted Learn observation, nothing blocked' : 'Learn mode, nothing blocked';
  const map = {
    secure: ['ok', 'secure', 'Daddybound authenticated this answer against the DNSSEC chain of trust.'],
    insecure: ['', 'insecure', 'Daddybound proved this name lies in an unsigned part of the DNS.'],
    bogus: ['bad', 'bogus', live ? 'Daddybound local DNSSEC validation rejected this answer.' : 'Daddybound could not authenticate this answer. Nothing was blocked: Learn mode records verdicts only.'],
    indeterminate: ['', 'indeterminate', 'Daddybound could not decide.'],
    timeout: ['', 'timeout', 'Validation ran out of time. This says nothing about the answer.'],
    resource_limit: ['', 'limit reached', 'Validation hit an internal bound. This says nothing about the answer.'],
    unsupported: ['', 'unsupported', 'This build cannot evaluate the algorithm or shape used here.'],
    internal_error: ['bad', 'error', 'The validator failed. This is a defect, not a property of the zone.'],
  };
  const entry = map[v.status];
  if (!entry) return html`<span class="muted">—</span>`;
  const [cls, text, title] = entry;

  const note = !live && v.disagreement
    ? html` <span class="badge warn" title="The local verdict and the upstream's assertion differ. Recorded, not acted on.">differs from upstream</span>`
    : '';
  const stale = v.cached
    ? html` <span class="muted" title="The answer came from the cache, so it may be older than this observation.">(answer was cached)</span>`
    : '';

  // "Learn" is the product name, and "nothing blocked" is the part that must
  // survive any rewording: this badge sits next to a bogus verdict, and a
  // reader who takes it as evidence the answer was refused has been misled
  // about what their resolver did.
  return html`<span class="badge ${cls}" title="${title}">${text}</span>`
    + html`<span class="muted"> · ${pathLabel}</span>`
    + note + stale;
}

/**
 * The query log, as a telemetry stream rather than a spreadsheet.
 *
 * Seven columns of equal weight made every row cost the same to read, which on
 * a page whose whole job is "find the interesting one" is the wrong trade. Each
 * entry is now one scannable line — outcome, domain, client, time — with the
 * technical detail behind a disclosure that only the rows worth investigating
 * pay for.
 *
 * <details>/<summary> rather than a click handler: keyboard navigation, screen
 * reader semantics and browser find-in-page all work without any of it being
 * reimplemented, and a row stays open across a re-render of its neighbours.
 */
function queryTable(queries, { filtered = false, filters = {} } = {}) {
  if (!queries || !queries.length) {
    if (filtered) {
      return emptyState('No matching queries',
        'Try a broader filter or time range. Only queries retained in the log can appear here.',
        { icon: '≡', action: '<a class="btn btn-ghost btn-sm" href="#/queries">Clear filters</a>' });
    }
    return emptyState(
      'No queries recorded',
      'Either the query log is switched off, or nothing has resolved through DNS Daddy yet.',
      { icon: '≡', action: '<a class="btn btn-ghost btn-sm" href="#/setup">How to point a device at it</a>' }
    );
  }

  return html`<div class="qlog">
    <div class="query-log-head query-grid" aria-hidden="true"><span></span><span>Domain</span><span>Outcome</span><span>Category</span><span>Client</span><span>Time</span></div>
    ${raw(queries.map((q) => queryRow(q, filters)).join(''))}</div>`;
}

// One entry. The action decides the row's accent, and the accent is never the
// only signal: the word is there too, in a badge.
function queryRow(q, filters = {}) {
  const action = ['blocked', 'error', 'allowed'].includes(q.action) ? q.action : 'unknown';
  const who = q.clientName || q.clientIp || '';
  const context = normaliseQueryFilters(filters);

  // Detail rows, each omitted when the server did not record it. An empty row
  // reading "—" is noise; an absent one is an accurate statement that nothing
  // was recorded.
  // Each value is already-escaped HTML: html`` escapes its interpolations,
  // and categoryBadge/dnssecBadge return escaped markup. They are collected as
  // strings and marked raw once, at the point of insertion — wrapping them in
  // raw() here and stringifying later turned the marker object itself into the
  // output, which is how "[object Object]" reached the page.
  const facts = [
    ['Type', q.qtype ? html`<span class="mono">${q.qtype}</span>` : ''],
    ['Client', who ? html`<span class="mono">${who}</span>` : ''],
    ['Client address', q.clientName && q.clientIp ? html`<span class="mono">${q.clientIp}</span>` : ''],
    ['Network ID', q.networkId ? html`<span class="mono">${q.networkId}</span>` : ''],
    ['Protocol', q.proto ? html`${q.proto}` : ''],
    ['Reason', q.reason ? html`${q.reason}` : ''],
    ['Category', q.category ? categoryBadge(q.category) : ''],
    ['Source', q.source ? html`${q.source}` : ''],
    [q.dnssecSource === 'native' ? 'DNSSEC (native — Daddybound)' : q.dnssecSource === 'encrypted_forwarded' ? 'DNSSEC (encrypted forwarding — Daddybound)' : q.dnssecSource === 'upstream' ? 'DNSSEC (upstream)' : 'DNSSEC (source unrecorded)', q.dnssec ? dnssecBadge(q.dnssec, q.dnssecSource || 'unknown') : ''],
    [q.dnssecValidation && q.dnssecValidation.resolution === 'native_live' ? 'Native validation outcome' : q.dnssecValidation && q.dnssecValidation.resolution === 'encrypted_live' ? 'Encrypted validation outcome' : 'DNSSEC (local — Daddybound)', q.dnssecValidation ? localDnssecBadge(q.dnssecValidation) : ''],
    ['Cache hit', typeof q.cached === 'boolean' ? (q.cached ? 'Yes' : 'No') : ''],
    ['Took', typeof q.elapsedMs === 'number' ? html`${q.elapsedMs} ms` : ''],
    ['Time', q.time ? html`${new Date(q.time).toLocaleString('en-GB')}` : ''],
  ]
    .filter(([, v]) => typeof v === 'string' && v !== '')
    .map(([k, v]) => html`<div class="qfact"><dt>${k}</dt><dd>${raw(v)}</dd></div>`)
    .join('');

  return html`
    <details class="qrow query-row is-${raw(action)}">
      <summary class="query-grid">
        <span class="qmark" aria-hidden="true"></span>
        <span class="qdomain mono">${q.domain}</span>
        ${raw(
          action === 'blocked'
            ? html`<span class="badge bad qact">Blocked</span>`
            : action === 'error'
              ? html`<span class="badge warn qact">Error</span>`
              : action === 'allowed'
                ? html`<span class="badge qact qact-allowed">Allowed</span>`
                : html`<span class="badge warn qact">Unknown</span>`
        )}
        <span class="qcat">${q.category || '—'}</span>
        <span class="qclient mono"><span class="sr-only">Client: </span>${who || '—'}</span>
        <span class="qtime"><span class="sr-only">Time: </span>${clockTime(q.time)}</span>
      </summary>
      <dl class="qfacts">${raw(facts)}</dl>
      <div class="qactions">
        <a class="btn btn-observe btn-sm" href="${investigateHash({ domain: q.domain, client: q.clientIp, hours: context.hours })}" data-investigate-domain="${q.domain}">Investigate this domain</a>
        <a class="btn btn-ghost btn-sm" href="${queryHash({ ...context, domain: q.domain })}" data-filter-domain="${q.domain}">Filter this domain</a>
        ${raw(q.clientIp ? html`<a class="btn btn-ghost btn-sm" href="${investigateHash({ client: q.clientIp, hours: context.hours })}" data-investigate-client="${q.clientIp}">Investigate this client</a>` : '')}
        ${raw(q.clientIp ? html`<a class="btn btn-ghost btn-sm" href="${queryHash({ ...context, clientIp: q.clientIp })}">Filter this client</a>` : '')}
      </div>
    </details>`;
}

// The HTTP endpoint accepts relative hours; storage's since/until fields are
// not exposed by this API. Keep bookmarks limited to filters we can apply.
function normaliseQueryFilters(input = {}) {
  return {
    domain: String(input.domain || '').trim(),
    clientIp: String(input.clientIp || '').trim(),
    action: ['blocked', 'allowed', 'error'].includes(input.action) ? input.action : '',
    networkId: String(input.networkId || '').trim(),
    hours: ['1', '24', '168'].includes(String(input.hours)) ? String(input.hours) : '',
  };
}

function queryFilters(hash) {
  const params = new URLSearchParams(String(hash || '').split('?')[1] || '');
  return normaliseQueryFilters(Object.fromEntries(params));
}

function queryParameters(filters) {
  return new URLSearchParams(Object.entries(normaliseQueryFilters(filters)).filter(([, value]) => value));
}

function queryHash(filters) {
  const query = queryParameters(filters).toString();
  return `#/queries${query ? `?${query}` : ''}`;
}

function setQueryFilters(filters) {
  const next = queryHash(filters);
  if (window.location.hash === next) return router.reload();
  window.location.hash = next;
}

function queryFilterForm(networks, filters) {
  const choices = networks || [];
  const missing = filters.networkId && !choices.some((n) => n.id === filters.networkId);
  const option = (value, label, selected) => html`<option value="${value}"${raw(value === selected ? ' selected' : '')}>${label}</option>`;
  return html`
    <div class="card section query-filter-card">
      <form class="query-filters" id="q-filters">
        <div class="query-filter"><label for="q-domain">Domain contains</label>
          <input id="q-domain" name="domain" type="search" placeholder="example.com" autocomplete="off" spellcheck="false" value="${filters.domain}"></div>
        <div class="query-filter"><label for="q-client">Client IP</label>
          <input id="q-client" name="clientIp" type="search" placeholder="Exact IP address" autocomplete="off" spellcheck="false" value="${filters.clientIp}"></div>
        <div class="query-filter"><label for="q-action">Outcome</label>
          <select id="q-action" name="action">
            ${raw([['', 'All outcomes'], ['blocked', 'Blocked'], ['allowed', 'Allowed'], ['error', 'Errors']].map(([v, l]) => option(v, l, filters.action)).join(''))}
          </select></div>
        <div class="query-filter"><label for="q-network">Network</label>
          <select id="q-network" name="networkId">
            ${raw(option('', 'All networks', filters.networkId))}
            ${raw(choices.map((n) => option(n.id, n.name, filters.networkId)).join(''))}
            ${raw(missing ? option(filters.networkId, `${filters.networkId} (not in current list)`, filters.networkId) : '')}
          </select></div>
        <div class="query-filter"><label for="q-hours">Time range</label>
          <select id="q-hours" name="hours">
            ${raw([['', 'All retained'], ['1', 'Last hour'], ['24', 'Last 24 hours'], ['168', 'Last 7 days']].map(([v, l]) => option(v, l, filters.hours)).join(''))}
          </select></div>
        <div class="query-filter-actions">
          <button type="submit" class="btn btn-observe" id="q-apply">Apply filters</button>
          <button type="button" class="btn btn-ghost" id="q-clear">Clear filters</button>
        </div>
      </form>
      <div class="query-filter-note query-filter-summary row">
        <p class="muted small">Domain uses a substring match. Client IP must match exactly. Times are local to this browser.</p>
        <span class="row-end muted small" id="q-count" role="status" aria-live="polite"></span>
      </div>
      ${raw(networks ? '' : html`<p class="form-error" role="status">Network names unavailable. Existing network filters still apply. <button type="button" class="btn btn-ghost btn-sm" data-page-retry>Retry</button></p>`)}
    </div>`;
}

// A request owns its rows until the route changes. Both the initial request
// and pagination use the same guard, so a late page cannot replace a new filter
// and repeated clicks cannot append the same cursor twice.
function createQueryLoader({ read, filters, isCurrent, onLoading, onData, onError }) {
  const state = { cursor: 0, rows: [], loading: false };
  return {
    state,
    async load(append = false) {
      if (state.loading || !isCurrent() || (append && !state.cursor)) return false;
      state.loading = true;
      onLoading(true, append);
      const params = queryParameters(filters);
      params.set('limit', '100');
      if (append) params.set('cursor', String(state.cursor));
      try {
        const data = await read(`/queries?${params}`);
        if (!isCurrent()) return false;
        if (!data || !Array.isArray(data.queries)) throw new Error('The query log returned an unreadable response.');
        state.cursor = data.nextCursor || 0;
        state.rows = append ? state.rows.concat(data.queries) : data.queries;
        onData(state, append);
        return true;
      } catch (err) {
        if (isCurrent() && err.name !== 'AbortError') onError(err, append);
        return false;
      } finally {
        state.loading = false;
        if (isCurrent()) onLoading(false, append);
      }
    },
  };
}

pages.queries = {
  title: 'Query log',
  subtitle: 'Inspect recorded lookups, then open a row for its explanation.',
  async render(context = {}) {
    const hash = context.hash === undefined ? window.location.hash : context.hash;
    const filters = queryFilters(hash);
    const networks = await apiGet('/networks', { signal: context.signal }).catch((err) => {
      if (err.status === 401 || err.name === 'AbortError') throw err;
      return null;
    });
    return html`
      ${raw(queryFilterForm(networks ? networks.networks || [] : null, filters))}
      <div id="q-results" aria-busy="true">${raw(emptyState('Loading queries…', 'Fetching matching queries.', { icon: '·' }))}</div>
      <p class="form-error" id="q-error" role="alert" hidden></p>
      <div class="row mt-4"><button type="button" class="btn btn-ghost" id="q-more" hidden>Load more</button></div>
    `;
  },
  async mounted(context = {}) {
    const host = $('#q-results');
    const form = $('#q-filters');
    const apply = $('#q-apply');
    const more = $('#q-more');
    const count = $('#q-count');
    const error = $('#q-error');
    const hash = context.hash === undefined ? window.location.hash : context.hash;
    const filters = queryFilters(hash);
    const isCurrent = () => host.isConnected && window.location.hash === hash &&
      (!context.isCurrent || context.isCurrent());
    const loader = createQueryLoader({
      filters,
      isCurrent,
      read: (path) => apiGet(path, { signal: context.signal }),
      onLoading: (loading, append) => {
        host.setAttribute('aria-busy', String(loading));
        apply.disabled = loading;
        more.disabled = loading;
        more.textContent = loading && append ? 'Loading more…' : 'Load more';
        if (loading) {
          error.hidden = true;
          count.textContent = append ? `${num(loader.state.rows.length)} shown · Loading more…` : 'Loading…';
        }
      },
      onData: (state) => {
        host.innerHTML = sanitize(queryTable(state.rows, { filtered: Object.values(filters).some(Boolean), filters }));
        paintDynamic(host);
        count.textContent = `${num(state.rows.length)} quer${state.rows.length === 1 ? 'y' : 'ies'} shown`;
        more.hidden = !state.cursor;
      },
      onError: (err, append) => {
        if (append) {
          error.textContent = `Could not load more queries. ${err.message || 'Try again.'}`;
          error.hidden = false;
          count.textContent = `${num(loader.state.rows.length)} shown · More rows unavailable`;
        } else {
          host.innerHTML = sanitize(unavailableState('Query log unavailable', err.message || 'The query log could not be retrieved. Try again.'));
          count.textContent = 'Results unavailable';
          more.hidden = true;
        }
      },
    });
    this.state = loader.state;
    form.addEventListener('submit', (event) => {
      event.preventDefault();
      if (loader.state.loading) return;
      setQueryFilters(Object.fromEntries(new FormData(form)));
    });
    $('#q-clear').addEventListener('click', () => setQueryFilters({}));
    more.addEventListener('click', () => loader.load(true));
    await loader.load();
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
            const rendered = Array.isArray(v) ? v.map((item) => typeof item === 'object' && item !== null ? JSON.stringify(item) : item).join(', ') : v === null ? '—' : typeof v === 'object' ? JSON.stringify(v) : v;
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

/* ---------- finding review ------------------------------------------------ */

/*
 * An operator's disposition of a finding sits beside the finding, never
 * inside it: the measurements, severity, confidence and evidence are what the
 * detector produced and stay as they were. Marking a finding a false positive
 * records that assessment and does nothing else — no detector is disabled, no
 * policy relaxed, no domain allowed — and the form says so.
 *
 * Writes carry the version that was read. A 409 means somebody else reviewed
 * the finding in the meantime, and the form shows what they wrote instead of
 * overwriting it.
 */

const REVIEW_STATES = [
  ['new', 'New', ''],
  ['acknowledged', 'Acknowledged', 'info'],
  ['resolved', 'Resolved', 'ok'],
  ['false_positive', 'False positive', 'warn'],
];

const REVIEW_LABEL = Object.fromEntries(REVIEW_STATES.map(([v, l]) => [v, l]));

function reviewBadge(review) {
  const state = review && review.state ? review.state : 'new';
  const entry = REVIEW_STATES.find(([v]) => v === state);
  const cls = entry ? entry[2] : 'warn';
  const label = entry ? entry[1] : String(state);
  return html`<span class="badge ${cls} review-badge" data-review-badge>${label}</span>`;
}

// The moves the server allows from each state, mirrored here so the form
// offers only what will be accepted. The server remains the authority.
const REVIEW_MOVES = {
  new: ['acknowledged', 'resolved', 'false_positive'],
  acknowledged: ['new', 'resolved', 'false_positive'],
  resolved: ['acknowledged', 'false_positive'],
  false_positive: ['acknowledged', 'resolved'],
};

// The version line under a review form. Each html`` result is marked raw
// exactly once where it is inserted: nesting one html`` inside another
// without raw() escapes it a second time and shows the markup as text.
function reviewMetaLine(review) {
  if (!review || !review.version) return 'Not yet reviewed';
  const by = review.actor ? html`by <span class="mono">${review.actor}</span> · ` : '';
  return html`Version ${review.version} · ${raw(by)}updated ${relTime(review.updatedAt)}`;
}

function reviewForm(finding) {
  const review = finding.review || { state: 'new', version: 0, note: '' };
  const state = REVIEW_LABEL[review.state] ? review.state : 'new';
  const options = [state, ...(REVIEW_MOVES[state] || [])];
  const id = finding.id;
  return html`
    <form class="review-form" data-review-form="${id}" data-version="${review.version || 0}">
      <h4>Review</h4>
      <p class="muted small">Records your assessment. It does not disable a detector, relax a policy, delete evidence or allow a domain.</p>
      <div class="review-fields">
        <label class="field"><span>Disposition</span>
          <select name="state">
            ${raw(options.map((v) => html`<option value="${v}"${raw(v === state ? ' selected' : '')}>${REVIEW_LABEL[v]}</option>`).join(''))}
          </select></label>
        <label class="field review-note"><span>Note</span>
          <textarea name="note" maxlength="2000" rows="2" placeholder="What you found, a ticket reference, why it is benign…">${review.note || ''}</textarea></label>
        <div class="field"><span>&nbsp;</span><button type="submit" class="btn btn-observe btn-sm">Save review</button></div>
      </div>
      <p class="muted small review-meta">
        ${raw(reviewMetaLine(review))}
        · <a href="#" data-review-history="${id}">History</a>
      </p>
      <p class="form-error" role="alert" hidden data-review-error></p>
      <div class="review-history" data-review-history-for="${id}" hidden></div>
    </form>`;
}

function findingConfidence(f) {
  if (f.eventType === 'local_behavior_anomaly' || f.detector === 'robust-ewma-v1' || (f.detail && f.detail.evidence && f.detail.evidence.confidenceAvailable === false)) {
    return html`<span class="badge tier">Uncalibrated anomaly</span>`;
  }
  return html`<span class="muted small nowrap">confidence ${f.confidence}</span>`;
}

function findingScore(f) {
  if (f.eventType === 'local_behavior_anomaly') {
    const distance = f.detail && f.detail.evidence && f.detail.evidence.anomalyDistance;
    return typeof distance === 'number' ? html`Anomaly distance: <span class="mono">${Number(distance.toFixed(3))}</span> <span class="muted">(not a threat probability)</span>`
      : html`Normalised anomaly score: <span class="mono">${f.score}</span> <span class="muted">(not a threat probability)</span>`;
  }
  return html`Score: <span class="mono">${f.score}</span>`;
}

function findingRow(f) {
  return html`
    <details class="finding" data-finding="${f.id}">
      <summary>
        ${raw(severityBadge(f.severity))}
        ${raw(reviewBadge(f.review))}
        <span class="mono">${f.eventType}</span>
        <span>${f.domain || f.clientName || f.clientIp || '—'}</span>
        ${raw(findingConfidence(f))}
        <span class="muted small nowrap">${relTime(f.time)}</span>
      </summary>
      <div class="finding-body">
        <p>${f.summary}</p>
        <p class="muted small">
          Client: <span class="mono">${f.clientName || f.clientIp || 'not attributed'}</span> ·
          Detector: <span class="mono">${f.detector}</span> ·
          ${raw(findingScore(f))}
        </p>
        ${raw(findingLinks(f))}
        ${raw(reviewForm(f))}
        ${raw(findingDetail(f.detail))}
      </div>
    </details>`;
}

function normaliseFindingFilters(input = {}) {
  return {
    state: REVIEW_LABEL[input.state] ? String(input.state) : '',
    severity: ['high', 'medium', 'low', 'info'].includes(input.severity) ? String(input.severity) : '',
    days: ['1', '7', '30', '90'].includes(String(input.days)) ? String(input.days) : '7',
  };
}

function findingFilters(hash) {
  const params = new URLSearchParams(String(hash || '').split('?')[1] || '');
  return normaliseFindingFilters(Object.fromEntries(params));
}

function findingHash(filters) {
  const f = normaliseFindingFilters(filters);
  const query = new URLSearchParams(Object.entries(f).filter(([k, v]) => v && !(k === 'days' && v === '7'))).toString();
  return `#/detections${query ? `?${query}` : ''}`;
}

function findingFilterForm(filters, byState) {
  const option = (value, label, selected) => html`<option value="${value}"${raw(value === selected ? ' selected' : '')}>${label}</option>`;
  const count = (state) => (byState && typeof byState[state] === 'number' ? ` (${num(byState[state])})` : '');
  return html`
    <div class="card section query-filter-card">
      <form class="query-filters" id="f-filters">
        <div class="query-filter"><label for="f-state">Review state</label>
          <select id="f-state" name="state">
            ${raw(option('', 'All states', filters.state))}
            ${raw(REVIEW_STATES.map(([v, l]) => option(v, l + count(v), filters.state)).join(''))}
          </select></div>
        <div class="query-filter"><label for="f-severity">Severity</label>
          <select id="f-severity" name="severity">
            ${raw([['', 'All severities'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low'], ['info', 'Info']].map(([v, l]) => option(v, l, filters.severity)).join(''))}
          </select></div>
        <div class="query-filter"><label for="f-days">Period</label>
          <select id="f-days" name="days">
            ${raw([['1', 'Last 24 hours'], ['7', 'Last 7 days'], ['30', 'Last 30 days'], ['90', 'Last 90 days']].map(([v, l]) => option(v, l, filters.days)).join(''))}
          </select></div>
        <div class="query-filter-actions">
          <button type="submit" class="btn btn-observe" id="f-apply">Apply</button>
          <button type="button" class="btn btn-ghost" id="f-clear">Clear</button>
        </div>
      </form>
      <div class="query-filter-note query-filter-summary row">
        <p class="muted small">Counts are for the selected period. A finding nobody has reviewed is New.</p>
        <span class="row-end muted small" id="f-count" role="status" aria-live="polite"></span>
      </div>
    </div>`;
}

pages.detections = {
  title: 'Findings',
  subtitle: 'Behavioural findings. Observed and explained, never blocked.',
  async render(context = {}) {
    const hash = context.hash === undefined ? window.location.hash : context.hash;
    const filters = findingFilters(hash);
    const read = (path) => apiGet(path, { signal: context.signal });
    const [catalogue, summary] = await Promise.all([
      read('/detectors'),
      read(`/findings/summary?days=${encodeURIComponent(filters.days)}`),
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
    const byState = summary.byState || null;
    const period = `Last ${filters.days} day${filters.days === '1' ? '' : 's'}`;

    return html`
      <div class="card notice">
        <p><strong>These findings do not block anything.</strong> They are behavioural
          signals for investigation, with the measurements retained for review. The local traffic
          model also compares each client against its own baseline. These detectors are <strong>experimental</strong>;
          sample maturity is not proof of accuracy. Reviewing a finding records your assessment
          without changing policy or automatically retraining the model.</p>
      </div>

      <div class="section grid grid-4">
        ${raw(metricCard({ label: 'High', value: num(bySeverity.high), sub: period, tone: bySeverity.high ? 'bad' : '' }))}
        ${raw(metricCard({ label: 'Medium', value: num(bySeverity.medium), sub: period }))}
        ${raw(metricCard({ label: 'Awaiting review', value: byState ? num(byState.new) : '—', sub: byState ? `${num(byState.acknowledged)} acknowledged · ${num(byState.resolved)} resolved · ${num(byState.false_positive)} false positive` : 'Review counts unavailable', tone: byState && byState.new ? 'warn' : '' }))}
        ${raw(metricCard({ label: 'Detectors', value: num(catalogue.detectors.length), sub: 'All alert-only', tone: 'detect' }))}
      </div>

      ${raw(findingFilterForm(filters, byState))}

      <div class="card">
        <div class="card-head"><div><h2>Findings</h2><p>Newest first. Expand one to see the
          measurements behind it and to record a review.</p></div></div>
        <div id="f-results" aria-busy="true">${raw(emptyState('Loading findings…', 'Fetching matching findings.', { icon: '·' }))}</div>
        <p class="form-error" id="f-error" role="alert" hidden></p>
        <div class="row mt-4"><button type="button" class="btn btn-ghost" id="f-more" hidden>Load more</button></div>
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
                      <td><span class="badge tier">${d.maturity}</span></td>
                      <td class="muted mono nowrap">${goDuration(d.window)}</td>
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
  async mounted(context = {}) {
    const host = $('#f-results');
    if (!host) return; // detection off
    const form = $('#f-filters');
    const more = $('#f-more');
    const count = $('#f-count');
    const error = $('#f-error');
    const hash = context.hash === undefined ? window.location.hash : context.hash;
    const filters = findingFilters(hash);
    const isCurrent = () => host.isConnected && window.location.hash === hash &&
      (!context.isCurrent || context.isCurrent());

    const loader = createFindingLoader({
      filters,
      isCurrent,
      read: (path) => apiGet(path, { signal: context.signal }),
      onLoading: (loading, append) => {
        host.setAttribute('aria-busy', String(loading));
        more.disabled = loading;
        more.textContent = loading && append ? 'Loading more…' : 'Load more';
        if (loading) {
          error.hidden = true;
          count.textContent = append ? `${num(loader.state.rows.length)} shown · Loading more…` : 'Loading…';
        }
      },
      onData: (state, append) => {
        if (append) {
          // Append rather than re-render, so open findings and half-written
          // reviews above stay exactly as they were.
          const fragment = document.createElement('div');
          fragment.innerHTML = sanitize(state.added.map(findingRow).join(''));
          while (fragment.firstChild) host.appendChild(fragment.firstChild);
        } else {
          host.innerHTML = sanitize(state.rows.length
            ? state.rows.map(findingRow).join('')
            : emptyState(
                filters.state || filters.severity ? 'No matching findings' : 'No findings yet',
                filters.state || filters.severity
                  ? 'Nothing matches these filters in the selected period.'
                  : 'Either nothing has behaved unusually, or not enough traffic has passed through yet. ' +
                    'This is not a statement that the network is clean: it is a statement that these ' +
                    'detectors have not raised anything.'
              ));
        }
        paintDynamic(host);
        bindReviewForms(host);
        count.textContent = `${num(state.rows.length)} finding${state.rows.length === 1 ? '' : 's'} shown`;
        more.hidden = !state.cursor;
      },
      onError: (err, append) => {
        if (append) {
          error.textContent = `Could not load more findings. ${err.message || 'Try again.'}`;
          error.hidden = false;
        } else {
          host.innerHTML = sanitize(unavailableState('Findings unavailable', err.message || 'The findings could not be retrieved. Try again.'));
          count.textContent = 'Results unavailable';
          more.hidden = true;
        }
      },
    });
    this.state = loader.state;
    form.addEventListener('submit', (event) => {
      event.preventDefault();
      const next = findingHash(Object.fromEntries(new FormData(form)));
      if (window.location.hash === next) router.reload();
      else window.location.hash = next;
    });
    $('#f-clear').addEventListener('click', () => { window.location.hash = findingHash({}); });
    more.addEventListener('click', () => loader.load(true));
    await loader.load();
  },
};

// The findings list pages by keyset cursor; the same ownership rule as the
// query log applies, so a late page cannot land on a different filter.
function createFindingLoader({ read, filters, isCurrent, onLoading, onData, onError }) {
  const state = { cursor: '', rows: [], added: [], loading: false };
  return {
    state,
    async load(append = false) {
      if (state.loading || !isCurrent() || (append && !state.cursor)) return false;
      state.loading = true;
      onLoading(true, append);
      const params = new URLSearchParams({ limit: '50', detail: 'true' });
      if (filters.state) params.set('state', filters.state);
      if (filters.severity) params.set('severity', filters.severity);
      params.set('hours', String(Number(filters.days || '7') * 24));
      if (append) params.set('cursor', state.cursor);
      try {
        const data = await read(`/findings?${params}`);
        if (!isCurrent()) return false;
        if (!data || !Array.isArray(data.findings)) throw new Error('The findings list returned an unreadable response.');
        state.cursor = data.nextCursor || '';
        state.added = data.findings;
        state.rows = append ? state.rows.concat(data.findings) : data.findings;
        onData(state, append);
        return true;
      } catch (err) {
        if (isCurrent() && err.name !== 'AbortError') onError(err, append);
        return false;
      } finally {
        state.loading = false;
        if (isCurrent()) onLoading(false, append);
      }
    },
  };
}

// applyReviewResult updates one finding's row in place after a write or a
// conflict, so the rest of the list is untouched.
function applyReviewResult(form, review) {
  const row = form.closest('[data-finding]');
  form.dataset.version = String(review.version || 0);
  const select = $('select[name="state"]', form);
  const state = REVIEW_LABEL[review.state] ? review.state : 'new';
  const options = [state, ...(REVIEW_MOVES[state] || [])];
  select.innerHTML = sanitize(options.map((v) => html`<option value="${v}"${raw(v === state ? ' selected' : '')}>${REVIEW_LABEL[v]}</option>`).join(''));
  $('textarea[name="note"]', form).value = review.note || '';
  const meta = $('.review-meta', form);
  if (meta) {
    meta.innerHTML = sanitize(html`${raw(reviewMetaLine(review))}
      · <a href="#" data-review-history="${form.dataset.reviewForm}">History</a>`);
  }
  if (row) {
    const badge = $('[data-review-badge]', row);
    if (badge) badge.outerHTML = sanitize(reviewBadge(review));
  }
}

function reviewHistoryList(events) {
  if (!events || !events.length) return html`<p class="muted small">No review recorded yet.</p>`;
  return html`<ol class="review-history-list">${raw(events.map((e) => html`<li>
      <span class="muted small">${new Date(e.at).toLocaleString('en-GB')}</span>
      ${REVIEW_LABEL[e.fromState] || e.fromState} → <strong>${REVIEW_LABEL[e.toState] || e.toState}</strong>
      ${raw(e.actor ? html` <span class="muted small">by <span class="mono">${e.actor}</span></span>` : '')}
      ${raw(e.note ? html`<div class="small review-history-note">${e.note}</div>` : '')}
    </li>`).join(''))}</ol>
    <p class="muted small">Application history, in write order. It explains what an operator did; it is not tamper-evident.</p>`;
}

function bindReviewForms(root) {
  $$('[data-review-form]', root).forEach((form) => {
    if (form.dataset.bound) return;
    form.dataset.bound = '1';
    const id = form.dataset.reviewForm;
    const errorEl = $('[data-review-error]', form);
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const button = $('button[type="submit"]', form);
      button.disabled = true;
      errorEl.hidden = true;
      try {
        const review = await apiSend('PUT', `/findings/${encodeURIComponent(id)}/review`, {
          state: $('select[name="state"]', form).value,
          note: $('textarea[name="note"]', form).value,
          version: Number(form.dataset.version || 0),
        });
        applyReviewResult(form, review);
        toast('Review saved');
      } catch (err) {
        if (err && err.status === 409 && err.body && err.body.current) {
          applyReviewResult(form, err.body.current);
          errorEl.textContent = 'Somebody else reviewed this finding first. The form now shows their review; check it and save again if you still want to change it.';
        } else {
          errorEl.textContent = err && err.message ? err.message : 'The review could not be saved.';
        }
        errorEl.hidden = false;
      } finally {
        button.disabled = false;
      }
    });
    form.addEventListener('click', async (event) => {
      const link = event.target.closest('[data-review-history]');
      if (!link) return;
      event.preventDefault();
      const host = $('[data-review-history-for]', form);
      host.hidden = !host.hidden;
      if (host.hidden || host.dataset.loaded) return;
      host.dataset.loaded = '1';
      host.innerHTML = sanitize(html`<p class="muted small">Loading…</p>`);
      try {
        const data = await apiGet(`/findings/${encodeURIComponent(id)}/review/history`);
        host.innerHTML = sanitize(reviewHistoryList(data.history));
      } catch (err) {
        host.innerHTML = sanitize(html`<p class="rec-note is-warn">${err.message}</p>`);
      }
    });
  });
}

/* ---------- investigation ------------------------------------------------ */

/*
 * One name or one address, everything already recorded about it, in sections
 * that never blur into each other. The order is the operator's question in
 * order: what happened, why it was decided then, what would be decided now,
 * what is on file, what the detectors think. The first screen answers the
 * first two; everything raw lives in labelled disclosures at the end.
 *
 * Nothing on this page is written by this page. The preview is the server's
 * evaluation of current configuration and is labelled as such, next to the
 * stored decisions it must never be confused with.
 */

// Links from a finding to the subjects it concerns.
function findingLinks(f) {
  const links = [];
  if (f.domain) links.push(html`<a class="btn btn-ghost btn-sm" href="${investigateHash({ domain: f.domain })}" data-investigate-domain="${f.domain}">Investigate domain</a>`);
  if (f.clientIp) links.push(html`<a class="btn btn-ghost btn-sm" href="${investigateHash({ client: f.clientIp })}" data-investigate-client="${f.clientIp}">Investigate client</a>`);
  return links.length ? html`<div class="row finding-links">${raw(links.join(''))}</div>` : '';
}

function normaliseInvestigateFilters(input = {}) {
  return {
    domain: String(input.domain || '').trim(),
    client: String(input.client || '').trim(),
    hours: ['1', '24', '168', '720'].includes(String(input.hours)) ? String(input.hours) : '',
  };
}

function investigateFilters(hash) {
  const params = new URLSearchParams(String(hash || '').split('?')[1] || '');
  return normaliseInvestigateFilters(Object.fromEntries(params));
}

function investigateHash(filters) {
  const f = normaliseInvestigateFilters(filters);
  const query = new URLSearchParams(Object.entries(f).filter(([, v]) => v)).toString();
  return `#/investigate${query ? `?${query}` : ''}`;
}

function investigateForm(filters) {
  const option = (value, label, selected) => html`<option value="${value}"${raw(value === selected ? ' selected' : '')}>${label}</option>`;
  return html`
    <div class="card section">
      <form class="query-filters" id="inv-form">
        <div class="query-filter"><label for="inv-domain">Domain</label>
          <input id="inv-domain" name="domain" type="search" placeholder="exact name, e.g. evil.example" autocomplete="off" spellcheck="false" value="${filters.domain}"></div>
        <div class="query-filter"><label for="inv-client">Client IP</label>
          <input id="inv-client" name="client" type="search" placeholder="optional, exact address" autocomplete="off" spellcheck="false" value="${filters.client}"></div>
        <div class="query-filter"><label for="inv-hours">Retained data window</label>
          <select id="inv-hours" name="hours">
            ${raw([['', 'Retention window'], ['1', 'Last hour'], ['24', 'Last 24 hours'], ['168', 'Last 7 days'], ['720', 'Last 30 days']].map(([v, l]) => option(v, l, filters.hours)).join(''))}
          </select></div>
        <div class="query-filter-actions">
          <button type="submit" class="btn btn-observe" id="inv-apply">Investigate</button>
          <button type="button" class="btn btn-ghost" id="inv-clear">Clear</button>
        </div>
      </form>
      <p class="muted small query-filter-note">Exact names only, as this resolver recorded them. A domain alone investigates the name;
        a client alone investigates the address; both together narrow the name to that client. This is not a passive-DNS history,
        an IP-reputation source or a device discovery tool — it reads what this resolver kept.</p>
    </div>`;
}

function windowLine(w) {
  if (!w) return '';
  return html`<span class="badge">Last ${w.hours}h</span>
    <span class="muted small">Per-query rows are retained for ${w.retentionDays} day${w.retentionDays === 1 ? '' : 's'}${w.queryLog ? '' : ' · query log off'}${w.clientAttribution ? '' : ' · client addresses not recorded'}</span>`;
}

const OUTCOME_BADGE = {
  blocked: ['bad', 'Blocked'],
  allowed: ['qact-allowed', 'Allowed'],
  not_evaluated: ['warn', 'Not evaluated'],
};

function outcomeBadge(outcome) {
  const [cls, label] = OUTCOME_BADGE[outcome] || ['warn', String(outcome || 'unknown')];
  return html`<span class="badge ${cls}">${label}</span>`;
}

// 1. What happened.
function activitySection(act, { client = false } = {}) {
  if (!act || !act.available) {
    return html`
      <div class="card section" id="inv-activity">
        <div class="card-head"><div><h2>Recorded activity</h2><p>What the query log holds for this subject.</p></div></div>
        ${raw(emptyState('Not recorded', (act && act.unavailable) || 'No per-query rows exist for this subject by configuration.', { icon: '○' }))}
      </div>`;
  }
  const s = act.summary || {};
  const qtypes = Object.entries(s.qtypes || {}).sort((a, b) => b[1] - a[1]);
  const stat = (label, value, note) => html`<div class="qfact"><dt>${label}</dt><dd>${raw(value)}${raw(note ? html` <span class="muted small">${note}</span>` : '')}</dd></div>`;
  const clients = (act.clients || []).length
    ? html`<h4>Clients that asked</h4>
        <div class="table-wrap"><table>
          <thead><tr><th>Client</th><th>Network</th><th class="num">Queries</th><th class="num">Blocked</th><th>Last seen</th><th></th></tr></thead>
          <tbody>${raw(act.clients.map((c) => html`<tr>
            <td class="mono">${c.clientName || c.clientIp}${raw(c.clientName ? html` <span class="muted small">${c.clientIp}</span>` : '')}</td>
            <td class="mono small">${c.networkId || '—'}</td>
            <td class="num">${num(c.queries)}</td><td class="num">${num(c.blocked)}</td>
            <td class="muted">${relTime(c.lastSeen)}</td>
            <td><a class="btn btn-ghost btn-sm" href="${investigateHash({ client: c.clientIp })}">Investigate client</a></td></tr>`).join(''))}
          </tbody></table></div>`
    : '';
  const domains = (act.domains || []).length
    ? html`<h4>Names this client asked for</h4>
        <div class="table-wrap"><table>
          <thead><tr><th>Domain</th><th class="num">Queries</th><th class="num">Blocked</th><th>Category</th><th>Last seen</th><th></th></tr></thead>
          <tbody>${raw(act.domains.map((d) => html`<tr>
            <td class="mono">${d.domain}</td>
            <td class="num">${num(d.queries)}</td><td class="num">${num(d.blocked)}</td>
            <td>${raw(d.category ? categoryBadge(d.category) : '—')}</td>
            <td class="muted">${relTime(d.lastSeen)}</td>
            <td><a class="btn btn-ghost btn-sm" href="${investigateHash({ domain: d.domain })}">Investigate domain</a></td></tr>`).join(''))}
          </tbody></table></div>`
    : '';
  return html`
    <div class="card section" id="inv-activity">
      <div class="card-head"><div><h2>Recorded activity</h2><p>${act.note}</p></div></div>
      ${raw(s.queries
        ? html`<dl class="claim-key">
            ${raw(stat('Queries', html`<span class="mono">${num(s.queries)}</span>`, `${num(s.allowed)} allowed · ${num(s.blocked)} blocked · ${num(s.errors)} failed`))}
            ${raw(stat('Seen', html`${relTime(s.firstSeen)} → ${relTime(s.lastSeen)}`))}
            ${raw(stat('Record types', html`<span class="mono">${qtypes.map(([t, n]) => `${t} ${num(n)}`).join(' · ')}</span>`))}
            ${raw(stat('Answer cache', html`<span class="mono">${num(s.cached)}</span>`, 'allowed answers served from cache'))}
            ${raw(stat('Latency', html`<span class="mono">${(s.avgElapsedMs || 0).toFixed(1)} ms</span>`, `average · max ${num(s.maxElapsedMs)} ms`))}
          </dl>`
        : emptyState('Nothing recorded in this window', 'No query-log row matches this exact subject in the selected window. Widen the window, or check the name is spelt as clients ask for it.', { icon: '○' }))}
      ${raw(client ? domains : clients)}
      ${raw((act.recent || []).length
        ? html`<h4>Newest rows${act.recentCursor ? ` (first ${act.recentLimit})` : ''}</h4>
            <div class="qlog">${raw(act.recent.map((q) => queryRow(q)).join(''))}</div>
            ${raw(act.recentCursor ? html`<p class="muted small">More rows exist. <a href="${queryHash(client ? { clientIp: act.recent[0].clientIp } : { domain: act.recent[0].domain })}">Open the query log</a> to page through them.</p>` : '')}`
        : '')}
    </div>`;
}

// 2. What was decided at the time.
function decisionSection(dec) {
  const rows = (dec && dec.items) || [];
  return html`
    <div class="card section" id="inv-decisions">
      <div class="card-head"><div><h2>Historical decisions</h2><p>${(dec && dec.note) || 'Stored when each decision was made.'}</p></div></div>
      ${raw(!dec || !dec.recording
        ? emptyState('Not recording decisions', 'Decision records are switched off (log.decision_records), so no stored explanation exists. The current policy preview below is not a substitute: it says what would be decided now, not why anything was decided then.', { icon: '○' })
        : rows.length
          ? rows.map(decisionRow).join('') + (dec.truncated ? html`<p class="muted small">Only the newest decisions are shown.</p>` : '')
          : emptyState('No decision recorded', 'No stored decision matches this subject. An allowed query records no decision; a block before decision records were enabled has none either.', { icon: '○' }))}
    </div>`;
}

function previewDecisionLine(d) {
  return html`${raw(outcomeBadge(d.outcome))}
    ${raw(d.rule ? html`<span class="badge">${d.rule}</span>` : '')}
    ${raw(d.category ? categoryBadge(d.category) : '')}
    ${raw(d.reason ? html`<span class="muted small">${d.reason}</span>` : '')}
    ${raw(d.source ? html`<span class="muted small">source: ${d.source}</span>` : '')}`;
}

// 3. What would be decided now. Labelled as a preview everywhere it appears.
function previewSection(pv) {
  if (!pv) return '';
  const c = pv.context || {};
  const ext = pv.external || {};
  return html`
    <div class="card section" id="inv-preview">
      <div class="card-head"><div>
        <div class="card-eyebrow">Preview · current configuration · read-only</div>
        <h2>Current policy preview</h2>
        <p>${pv.note}</p>
      </div></div>
      <dl class="claim-key">
        <div class="qfact"><dt>Context</dt><dd>
          ${raw(c.client ? html`client <span class="mono">${c.client}</span> · ` : html`no client supplied · `)}
          ${raw(c.attribution === 'catch_all' ? 'catch-all network' : c.attribution === 'network_prefix' ? 'matched by network prefix' : 'no network')}
          ${raw(c.networkName ? html` · <span class="mono">${c.networkName}</span>` : '')}
          ${raw(c.policyName ? html` · policy <span class="mono">${c.policyName}</span>` : '')}
        </dd></div>
        <div class="qfact"><dt>Would be</dt><dd>${raw(previewDecisionLine(pv.decision || {}))}</dd></div>
        <div class="qfact"><dt>External providers</dt><dd>
          ${raw(!ext.configured
            ? html`<span class="badge">none configured</span>`
            : html`<span class="badge ${ext.evaluated ? 'ok' : ext.reached ? 'warn' : ''}">${ext.evaluated ? 'cached verdict used' : ext.reached ? 'lookup not performed' : 'not reached'}</span>`)}
          ${raw(ext.mode ? html` <span class="muted small">mode ${ext.mode}</span>` : '')}
          ${raw(ext.provider ? html` <span class="muted small">${ext.provider}</span>` : '')}
          ${raw(ext.note ? html`<div class="muted small">${ext.note}</div>` : '')}
          ${raw(ext.configured && ext.reached && !ext.evaluated ? html`<div class="note-tight"><label class="checkline"><input type="checkbox" id="inv-enrich-consent"><span>I agree to share this domain with the configured providers.</span></label><div class="row note-tight"><button type="button" class="btn btn-ghost btn-sm" id="inv-enrich">Ask the configured providers now</button> <span class="muted small">A deliberate lookup within the configured mode and budget.</span></div><p id="inv-enrich-error" class="form-error" role="alert" hidden></p></div>` : '')}
        </dd></div>
      </dl>
      <details class="chart-data"><summary>Under every policy</summary>
        <div class="table-wrap"><table>
          <thead><tr><th>Policy</th><th class="num">Enabled networks</th><th>Would be</th></tr></thead>
          <tbody>${raw((pv.byPolicy || []).map((p) => html`<tr>
            <td>${p.policyName} <span class="muted small mono">${p.policyId}</span></td>
            <td class="num">${num(p.assignedNetworks)}</td>
            <td>${raw(previewDecisionLine(p.decision || {}))}</td></tr>`).join(''))}
          </tbody></table></div>
        <p class="muted small">A comparison, not a change: nothing is assigned or edited from this page.</p>
      </details>
    </div>`;
}

// 4. What is on file now.
function evidenceSection(ev) {
  if (!ev) return '';
  const a = ev.assessment || {};
  const items = ev.items || [];
  const row = (e) => html`
    <div class="ev-row${e.expired ? ' is-expired' : ''}">
      <div class="ev-main">
        <div class="ev-title">
          <strong>${e.sourceName || e.source}</strong>
          <span class="badge">${e.kind || 'unknown'}</span>
          ${raw(e.confidence ? html`<span class="badge">${CONFIDENCE_LABEL[e.confidence] || e.confidence} confidence</span>` : '')}
          ${raw(e.expired ? html`<span class="badge warn">expired</span>` : '')}
          ${raw(e.contributedTo ? html`<span class="badge ok">decided ${num(e.contributedTo)} quer${e.contributedTo === 1 ? 'y' : 'ies'}</span>` : html`<span class="badge">on file only</span>`)}
        </div>
        <div class="ev-claim">${e.claim}</div>
        <div class="rec-meta">
          ${raw(e.category ? html`<span>${e.category}</span>` : '')}
          <span>observed ${relTime(e.observedAt)}</span>
          ${raw(e.expiresAt ? html`<span>${e.expired ? 'expired' : 'expires'} ${relTime(e.expiresAt)}</span>` : html`<span>does not expire</span>`)}
        </div>
      </div>
    </div>`;
  return html`
    <div class="card section" id="inv-evidence">
      <div class="card-head"><div><h2>Current evidence</h2><p>${ev.note}</p></div></div>
      <p><strong>${a.summary || 'Nothing on file for this subject.'}</strong>
        ${raw(a.verdict ? html` <span class="badge ${a.verdict === 'malicious' ? 'bad' : a.verdict === 'suspicious' ? 'warn' : a.verdict === 'benign' ? 'ok' : ''}">${a.verdict}</span>` : '')}
        ${raw(a.inferenceOnly ? html` <span class="badge warn">inference only</span>` : '')}
        ${raw(a.corroborated ? html` <span class="badge">corroborated</span>` : '')}</p>
      ${raw(items.length ? items.map(row).join('') : '')}
    </div>`;
}

// 5. What the detectors inferred, and what Daddybound concluded.
function relatedFindingsSection(fd) {
  if (!fd) return '';
  const items = fd.items || [];
  return html`
    <div class="card section" id="inv-findings">
      <div class="card-head"><div>
        <div class="card-eyebrow">Experimental · alert-only</div>
        <h2>Related findings</h2>
        <p>${fd.note}</p>
      </div></div>
      ${raw(!fd.enabled
        ? emptyState('Behavioural detection is switched off', 'No active finding source was reported. Retained findings depend on this installation’s history and retention.', { icon: '○' })
        : items.length
          ? items.map((f) => html`
              <details class="finding">
                <summary>
                  ${raw(severityBadge(f.severity))}
                  <span class="mono">${f.eventType}</span>
                  <span>${f.domain || f.clientName || f.clientIp || '—'}</span>
                  ${raw(findingConfidence(f))}
                  <span class="muted small nowrap">${relTime(f.time)}</span>
                </summary>
                <div class="finding-body">
                  <p>${f.summary}</p>
                  <p class="muted small">Client: <span class="mono">${f.clientName || f.clientIp || 'not attributed'}</span> · Detector: <span class="mono">${f.detector}</span> · ${raw(findingScore(f))}</p>
                  ${raw(findingDetail(f.detail))}
                </div>
              </details>`).join('') + (fd.truncated ? html`<p class="muted small">Only the newest findings are shown.</p>` : '')
          : emptyState('No related finding', 'No detector raised anything about this subject in the window. That is not evidence that it is clean.', { icon: '○' }))}
    </div>`;
}

function observationsSection(ob) {
  if (!ob) return '';
  const items = ob.items || [];
  return html`
    <div class="card section" id="inv-observations">
      <div class="card-head"><div>
        <div class="card-eyebrow">Experimental · recorded Daddybound outcomes</div>
        <h2>Local DNSSEC observations</h2>
        <p>${ob.note}</p>
      </div></div>
      ${raw(!ob.available
        ? emptyState('No local DNSSEC records available', 'This response contains no retained local validation data. Check Daddybound for the current operating mode.', { icon: '○' })
        : items.length
          ? html`<div class="table-wrap"><table>
              <thead><tr><th>When</th><th>Type</th><th>Recorded path</th><th>Upstream said</th><th>Daddybound concluded</th><th>Differs</th><th>Reason</th></tr></thead>
              <tbody>${raw(items.map((o) => html`<tr>
                <td class="muted">${relTime(o.time)}${o.cached ? ' (cached answer)' : ''}</td>
                <td class="mono">${o.qtype}</td>
                <td>${o.resolution === 'native_live' ? 'Native Live' : o.resolution === 'encrypted_live' ? 'Encrypted Live' : o.resolution === 'encrypted_forwarded' ? 'Encrypted Learn observation' : 'Learn observation'}</td>
                <td>${raw(o.resolution === 'native_live' || o.resolution === 'encrypted_live' ? 'Not applicable' : o.upstream ? dnssecBadge(o.upstream, 'upstream') : '—')}</td>
                <td>${raw(localDnssecBadge(o))}</td>
                <td>${o.resolution === 'native_live' || o.resolution === 'encrypted_live' ? 'Not applicable' : o.disagreement || '—'}</td>
                <td class="muted small">${o.reason || ''}</td></tr>`).join(''))}
              </tbody></table></div>${raw(ob.truncated ? html`<p class="muted small">Only the newest observations are shown.</p>` : '')}`
          : emptyState('No observation for this name', 'No retained local validation record matches this name and window. Missing records do not establish a validation result.', { icon: '○' }))}
    </div>`;
}

function rawJsonSection(data) {
  let text;
  try {
    text = JSON.stringify(data, null, 2);
  } catch {
    text = 'unavailable';
  }
  return html`<details class="chart-data section"><summary>Raw response</summary><pre class="mono small inv-raw">${text}</pre></details>`;
}

function investigationHeader(subject, w) {
  return html`
    <div class="card section">
      <div class="card-head inv-head"><div class="inv-subject">
        <div class="card-eyebrow">${subject.kind}</div>
        <h2 class="mono">${subject.title}</h2>
        ${raw(subject.sub ? html`<p>${subject.sub}</p>` : '')}
      </div><div class="row-end hero-intel">${raw(windowLine(w))}</div></div>
    </div>`;
}

function investigationLearning(data) {
  if (!data) return '';
  const client = data.client;
  return html`<div class="card section" id="inv-learning"><div class="card-head"><div><h2>Local learning baseline</h2><p>${data.note || 'Current local model state for this client.'}</p></div><span class="badge ${data.enabled && data.available === false ? 'warn' : 'tier'}">${data.enabled && data.available === false ? 'Unavailable' : 'Learning only'}</span></div>
    ${raw(!data.enabled ? html`<p class="muted">Local traffic learning is off.</p>` : data.available === false ? html`<p class="rec-note is-warn">The learning model could not be read. A baseline result is unavailable.</p>` : !data.found || !client ? html`<p class="muted">No retained baseline for this client. This is not a benign verdict.</p>` : html`
      <dl class="claim-key"><div class="qfact"><dt>Maturity</dt><dd><span class="badge ${client.ready ? 'info' : ''}">${client.ready ? 'Baseline ready' : 'Building baseline'}</span> <span class="muted small">sample maturity, not detection accuracy</span></dd></div>
        <div class="qfact"><dt>History</dt><dd>${num(client.baselineWindows)} trained windows · ${num(client.baselineQueries)} baseline queries</dd></div>
        <div class="qfact"><dt>Last seen</dt><dd>${relTime(client.lastSeenAt)}</dd></div></dl>
      <details class="chart-data"><summary>Baseline features</summary><div class="table-wrap"><table><thead><tr><th>Feature</th><th>Mean</th><th>Standard deviation</th></tr></thead><tbody>
        ${raw((client.features || []).map((feature) => html`<tr><td class="mono small">${feature.name}</td><td>${feature.baselineMean === null ? '—' : num(feature.baselineMean)}</td><td>${feature.baselineStd === null ? '—' : num(feature.baselineStd)}</td></tr>`).join(''))}</tbody></table></div></details>`)}
    <p class="small note-tight"><a href="#/daddybound">View learning health and recent windows →</a></p>
  </div>`;
}

pages.investigate = {
  title: 'Investigate',
  subtitle: 'One name or one address: what happened, why, and what would happen now.',
  async render(context = {}) {
    const hash = context.hash === undefined ? window.location.hash : context.hash;
    const filters = investigateFilters(hash);
    const read = (path) => apiGet(path, { signal: context.signal });
    const form = investigateForm(filters);

    if (!filters.domain && !filters.client) {
      return html`${raw(form)}
        ${raw(emptyState('Enter a domain or a client address', 'Query-log rows and findings link here. The page reads what this resolver kept: recorded activity, stored decisions, a read-only preview of current policy, evidence on file, and related findings.', { icon: '⌕' }))}`;
    }

    const hours = filters.hours ? `hours=${encodeURIComponent(filters.hours)}` : '';
    if (!filters.domain) {
      let data;
      try {
        data = await read(`/investigate/client/${encodeURIComponent(filters.client)}${hours ? `?${hours}` : ''}`);
      } catch (err) {
        if (err.status === 401 || err.name === 'AbortError') throw err;
        return html`${raw(form)}${raw(unavailableState('Could not investigate this client', err.message || 'The request failed.'))}`;
      }
      const sub = data.subject || {};
      const att = sub.attribution || {};
      return html`${raw(form)}
        ${raw(investigationHeader({
          kind: 'Client', title: sub.name ? `${sub.name} · ${sub.client}` : sub.client,
          sub: `Current attribution: ${att.attribution === 'catch_all' ? 'catch-all network' : att.attribution === 'network_prefix' ? 'matched by network prefix' : 'none'}${att.networkName ? ` · ${att.networkName}` : ''}${att.policyName ? ` · policy ${att.policyName}` : ''} — as configured now, not as recorded then.`,
        }, data.window))}
        ${raw(activitySection(data.activity, { client: true }))}
        ${raw(decisionSection(data.decisions))}
        ${raw(relatedFindingsSection(data.findings))}
        ${raw(investigationLearning(data.learning))}
        ${raw(rawJsonSection(data))}`;
    }

    const params = [filters.client ? `client=${encodeURIComponent(filters.client)}` : '', hours].filter(Boolean).join('&');
    let data;
    try {
      data = await read(`/investigate/domain/${encodeURIComponent(filters.domain)}${params ? `?${params}` : ''}`);
    } catch (err) {
      if (err.status === 401 || err.name === 'AbortError') throw err;
      return html`${raw(form)}${raw(unavailableState('Could not investigate this domain', err.message || 'The request failed.'))}`;
    }
    const sub = data.subject || {};
    this.enrich = { domain: sub.domain, client: sub.client };
    return html`${raw(form)}
      ${raw(investigationHeader({
        kind: sub.client ? 'Domain · one client' : 'Domain',
        title: sub.domain,
        sub: `${sub.input && sub.input !== sub.domain ? `Entered as ${sub.input}. ` : ''}${sub.client ? `Narrowed to client ${sub.client}.` : ''}`,
      }, data.window))}
      ${raw(activitySection(data.activity))}
      ${raw(decisionSection(data.decisions))}
      ${raw(previewSection(data.preview))}
      ${raw(evidenceSection(data.evidence))}
      ${raw(relatedFindingsSection(data.findings))}
      ${raw(observationsSection(data.observations))}
      ${raw(rawJsonSection(data))}`;
  },
  async mounted() {
    const form = $('#inv-form');
    if (form) {
      form.addEventListener('submit', (event) => {
        event.preventDefault();
        const next = investigateHash(Object.fromEntries(new FormData(form)));
        if (window.location.hash === next) router.reload();
        else window.location.hash = next;
      });
      $('#inv-clear').addEventListener('click', () => { window.location.hash = '#/investigate'; });
    }
    mountDecisionCards();
    const enrich = $('#inv-enrich');
    if (enrich && this.enrich) {
      enrich.addEventListener('click', async () => {
        const consent = $('#inv-enrich-consent'); const error = $('#inv-enrich-error');
        if (!consent || !consent.checked) { if (error) { error.textContent = 'Agree to share this domain before requesting external evidence.'; error.hidden = false; } if (consent) consent.focus(); return; }
        if (error) error.hidden = true;
        enrich.disabled = true;
        try {
          const q = this.enrich.client ? `?client=${encodeURIComponent(this.enrich.client)}` : '';
          const res = await apiSend('POST', `/investigate/domain/${encodeURIComponent(this.enrich.domain)}/enrich${q}`, { consent: true });
          toast(res && res.note ? res.note : `Lookup ${res && res.lookup ? res.lookup : 'requested'}`);
          router.reload();
        } catch (err) {
          reportError(err);
          enrich.disabled = false;
        }
      });
    }
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
// resolverAccessNote tells someone about to point a device here whether it
// will actually be answered.
//
// Two settings decide that and they are deliberately described separately.
// dns.allowed_client_cidrs says which addresses are *eligible*; ad-hoc access
// on the Default network says whether an eligible client that matches no
// Network may actually resolve. Collapsing them into one sentence — "these
// ranges work" — is wrong in the case that matters most: ad-hoc access off,
// which is what a fresh install ships with, where an address inside the
// configured pool is still answered REFUSED until a Network covers it.
function resolverAccessNote(access) {
  if (!access) return '';
  if (access.unrestricted) {
    return html`<p class="muted small note-tight">
      Every address may query this resolver: no client ACL is configured. Anything you
      point here will be answered.</p>`;
  }

  const dohNote = html` The DNS-over-HTTPS and DNS-over-TLS URLs below are identified by
    their network token instead of by address, so they work from anywhere regardless of
    this setting.`;

  // Gated off: the eligible pool is not what will be served, and saying it is
  // sends the reader to check the wrong thing.
  if (access.adHocAccessGated && !access.adHocAccess) {
    const eligible = access.bootstrapCidrs || [];
    const granted = access.dashboardCidrs || [];
    return html`<p class="muted small note-tight">
      <strong>Before you point anything here:</strong> ad-hoc access is off, so a client is
      answered over ordinary DNS only if a Network you added covers its address —
      currently ${raw(granted.length
        ? html`<span class="mono">${granted.join(', ')}</span>`
        : html`<strong>none</strong>`)}. Everything else is answered <code>REFUSED</code>,
      including addresses inside <span class="mono">${eligible.join(', ')}</span>, which are
      eligible to be served but not currently being served. Add the client's network under
      <em>Networks</em> and tick <em>Allow this network to use DNS Daddy</em>, or turn on
      <em>Ad-hoc DNS access</em> on the Default row to serve every eligible address without
      naming each one.${raw(dohNote)}</p>`;
  }

  const effective = access.effectiveCidrs || [];
  if (!effective.length) {
    return '';
  }
  return html`<p class="muted small note-tight">
    <strong>Before you point anything here:</strong> only these ranges may query over
    ordinary DNS — <span class="mono">${effective.join(', ')}</span>. A client outside
    them is answered <code>REFUSED</code> however you configure it. Add its network under
    <em>Networks</em> and tick <em>Allow this network to use DNS Daddy</em>.${raw(dohNote)}</p>`;
}

// The seeded catch-all. It is the only network whose access control means
// something other than "permit these ranges", so it is the only one the
// dashboard has to render differently.
const DEFAULT_NETWORK_ID = 'n_default';

function isDefaultNetwork(n) {
  return !!n && n.id === DEFAULT_NETWORK_ID;
}

// adHocBadge describes the Default row's ad-hoc access state.
//
// Kept apart from accessBadge's catch-all branch because the two say different
// things. A user-created catch-all really does grant nothing when permitted —
// it has no ranges — and "Grants nothing" is the honest answer there. The
// Default row's bit is not a grant at all: it decides whether unmatched
// clients inside the configured ACL may resolve, which is a real effect and
// was being reported as a no-op.
function adHocBadge(n) {
  if (n.enabled === false) {
    return html`<span class="badge"
      title="The Default network is disabled, so it applies no policy and admits no unmatched clients.">Disabled</span>`;
  }
  if (n.allowResolver) {
    return html`<span class="badge ok"
      title="Unmatched clients whose address is already inside the configured resolver ACL may use DNS Daddy and receive the Default policy. This does not widen that ACL and does not expose DNS Daddy to arbitrary internet clients.">Ad-hoc access on</span>`;
  }
  return html`<span class="badge"
    title="Unmatched clients are refused. Networks you have added and permitted are unaffected, and the resolver stays usable from this machine.">Ad-hoc access off</span>`;
}

// networkRow renders one row of the Networks list.
//
// A network is a record, not a spreadsheet row: name and ranges are what you
// scan for, access is the decision, and the traffic figures are context. The
// eight-column table this replaced gave all of them equal weight and pushed
// the access tick-box — the only control on the page — into a narrow middle
// column.
//
// The Default row takes the same shape and different words. It has no CIDRs of
// its own, so a control labelled "Allow" alongside a range list reading
// "catch-all" invited the reading that permitting it would permit something,
// which is what produced the old "Grants nothing" badge. What its bit actually
// does is admit unmatched clients that are already inside the configured
// resolver ACL, and the row now says that instead.
function networkRow(n, policy) {
  const isDefault = isDefaultNetwork(n);
  const publicRanges = n.publicCidrs || [];

  const ranges = isDefault
    ? html`<span>every client that matches no other network</span>`
    : html`<span class="mono">${n.cidrs.length ? n.cidrs.join(', ') : 'catch-all'}</span>`;

  // Off is not an error state — it is the shipped default — so it is muted
  // rather than warned, and both states say what the operator can do next.
  const defaultNote = n.allowResolver
    ? 'Unmatched clients inside the configured resolver ACL may use DNS Daddy and receive the Default policy.'
    : 'Unmatched clients are refused. Add a Network for managed access, or enable ad-hoc access for clients already inside the configured resolver ACL.';

  return html`
    <div class="rec">
      <div class="rec-main">
        <div class="rec-title">
          <strong>${n.name}</strong>
          ${raw(statusBadge(n.status))}
          ${raw(accessBadge(n))}
        </div>
        <div class="rec-meta">
          ${raw(ranges)}
          ${raw(n.location ? html`<span>${n.location}</span>` : '')}
          <span>policy: ${policy ? policy.name : n.policyId}</span>
          <span>${num(n.queries24h)} queries</span>
          <span>${num(n.blocked24h)} blocked</span>
        </div>
        ${raw(isDefault
          ? html`<p class="rec-note">${defaultNote} It never widens
              <span class="mono">dns.allowed_client_cidrs</span>, so it cannot expose DNS Daddy to
              arbitrary clients on the internet.</p>`
          : '')}
        ${raw(publicRanges.length
          ? html`<p class="rec-note is-warn">Publicly routable: <span class="mono">${publicRanges.join(', ')}</span>. Anyone on the internet at these addresses may use this resolver.</p>`
          : '')}
        ${raw(!isDefault && !n.allowResolver && n.resolvesVia
          ? html`<p class="rec-note">Reachable anyway, inside ${n.resolvesVia} — access permissions add up and nothing here subtracts.</p>`
          : '')}
      </div>
      <div class="rec-actions">
        <label class="checkline access-cell"
               title="${isDefault
                 ? 'Allow unmatched clients that are already inside the configured resolver ACL to use DNS Daddy under the Default policy.'
                 : 'Allow this network to use DNS Daddy'}">
          <input type="checkbox" data-access="${n.id}" data-name="${n.name}"
                 ${raw(isDefault ? 'data-adhoc="1"' : '')}
                 ${raw(n.allowResolver ? 'checked' : '')}>
          <span>${isDefault ? 'Ad-hoc DNS access' : 'Allow'}</span>
        </label>
        ${raw(isDefault
          ? ''
          : html`<button class="btn btn-danger btn-sm" data-delete-network="${n.id}"
                data-name="${n.name}">Delete</button>`)}
      </div>
    </div>`;
}

function accessBadge(n) {
  // The Default row first: it is a catch-all, but its permission bit is an
  // ad-hoc access switch rather than a grant, so none of the reasoning below
  // applies to it.
  if (isDefaultNetwork(n)) return adHocBadge(n);

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
          <div><h2>Networks</h2><p>Who may use this resolver, and what they get. Last 24 hours.</p></div>
        </div>
        ${raw(
          networks.networks.length
            ? networks.networks
                .map((n) => {
                  const policy = policies.policies.find((p) => p.id === n.policyId);
                  return networkRow(n, policy);
                })
                .join('')
            : emptyState(
                'No networks yet',
                'Every client is matched by the catch-all until you add one. Add a network to give a site or VLAN its own policy, or to permit it to use the resolver at all.',
                { icon: '◇' }
              )
        )}
      </div>
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
          } else if (box.dataset.adhoc) {
            // The Default row's switch is not a grant to a named network, so
            // reporting it as one — "Default may now use DNS Daddy" — would
            // describe the wrong thing entirely.
            toast(wanted
              ? 'Unmatched clients inside the configured resolver ACL may now use DNS Daddy'
              : 'Ad-hoc access is off: unmatched clients are refused');
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
                  ${raw(
                    p.categories.includes(c.id) && !c.indexedDomains
                      ? html`<span class="cat-empty">Ticked, but the index holds no domains for
                          this category, so it is blocking nothing. Check
                          <a href="#/feeds">Threat intelligence</a>.</span>`
                      : ''
                  )}
                </span>
              </label>
            `
          )
          .join('');

        // A policy summary an operator can scan: what it blocks and who uses
        // it. Every policy used to render its whole editor at once, so three
        // policies were 2,500 pixels of identical checkbox columns and there
        // was no way to see at a glance which one enforced what.
        const enforced = categories.categories.filter((c) => p.categories.includes(c.id));
        const summaryText = enforced.length
          ? enforced.map((c) => c.label).join(' · ')
          : 'Blocks nothing — monitor only';

        return html`
          <details class="card section policy" ${raw(p.isDefault ? 'open' : '')}>
            <summary class="policy-head">
              <span class="policy-caret" aria-hidden="true"></span>
              <span class="policy-title">
                <strong>${p.name}</strong>
                ${raw(p.isDefault ? '<span class="badge ok">default</span>' : '')}
              </span>
              <span class="policy-what ${enforced.length ? '' : 'is-monitor'}">${summaryText}</span>
              <span class="policy-use">${p.assigned} network${p.assigned === 1 ? '' : 's'}</span>
            </summary>

            <div class="policy-body">
            <div class="card-head">
              <div>
                <p>${p.description || 'No description.'}</p>
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
          </details>
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
  // Matches the navigation label. They said different things, which made the
  // page look like it belonged to a different product than the link to it.
  title: 'Threat intelligence',
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
            <button class="btn btn-observe" id="refresh-feeds" ${raw(data.refreshing ? 'disabled' : '')}>
              ${data.refreshing ? 'Refreshing…' : 'Refresh now'}
            </button>
          </div>
        </div>
        ${raw(
          data.feeds
            .map(
              (f) => html`
                <div class="rec">
                  <div class="rec-main">
                    <div class="rec-title">
                      <strong>${f.name}</strong>
                      ${raw(feedStatusBadge(f))}
                      ${raw(categoryBadge(f.category))}
                    </div>
                    <div class="rec-meta">
                      <span class="mono">${f.url}</span>
                    </div>
                    <div class="rec-meta">
                      <span>${f.enabled ? `${num(f.indexedDomains)} domains indexed` : 'not enabled'}</span>
                      <span>refreshed ${relTime(f.lastRefreshedAt)}</span>
                      ${raw(
                        f.enabled && f.lastError && f.lastSuccessAt
                          ? html`<span>last good ${relTime(f.lastSuccessAt)}</span>`
                          : ''
                      )}
                    </div>
                    ${raw(f.lastError ? html`<p class="rec-note is-warn">${f.lastError}</p>` : '')}
                    ${raw(
                      f.enabled && !f.loaded && f.lastSuccessAt
                        ? html`<p class="rec-note is-warn">Downloaded before, but not in the blocklist answering queries right now${f.loadError ? ` — ${f.loadError}` : ''}.</p>`
                        : ''
                    )}
                  </div>
                  <div class="rec-actions">
                    <label class="checkline">
                      <input type="checkbox" data-feed="${f.id}" ${raw(f.enabled ? 'checked' : '')}
                             aria-label="Enable ${f.name}">
                      <span>Enabled</span>
                    </label>
                  </div>
                </div>`
            )
            .join('')
        )}
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

/* ---------- External APIs: operator-owned connections -------------------- */

const REPUTATION_MODES = {
  off: ['Off', 'No automatic domain checks. You can still save and explicitly test a connection.'],
  cache_only: ['Background checks', 'Use cached verdicts immediately. Missing verdicts are requested in the background for future queries.'],
  blocking: ['Wait for a verdict', 'On a cache miss, wait up to the configured time budget for a provider. This can delay DNS answers.'],
};

function externalAPICard() {
  return html`<div class="card section integration-cta">
    <div><div class="card-eyebrow">Your intelligence sources</div><h2>Add context with external APIs</h2>
      <p class="muted">Connect your own provider accounts, test them explicitly and choose how their evidence affects DNS decisions.</p></div>
    <a class="btn btn-observe" href="#/integrations">Manage external APIs</a>
  </div>`;
}

function providerStatusBadge(p) {
  if (p.status === 'disabled' || !p.enabled) return html`<span class="badge">Switched off</span>`;
  if (p.status !== 'ok') return html`<span class="badge warn">Needs attention</span>`;
  return html`<span class="badge info">Enabled</span>`;
}

function verificationChip(tpl) {
  if (!tpl || !tpl.verification) return '';
  return tpl.liveVerified
    ? html`<span class="badge ok claim">Adapter verified live</span>`
    : html`<span class="badge tier claim">Adapter tested with fixtures</span>`;
}

function providerStats(s) {
  if (!s || !s.calls) return html`<div class="rec-meta"><span>No automatic calls yet</span></div>`;
  return html`<div class="rec-meta">
    <span>${num(s.calls)} calls</span><span>${num(s.meanLatencyMs)} ms mean</span>
    <span>${rate(Number(s.errorRate || 0) * 100)}% errors</span>
    ${raw(s.rateWaits ? html`<span>${num(s.rateWaits)} rate-limit waits</span>` : '')}
    ${raw(s.breaker && s.breaker !== 'closed' ? html`<span class="badge warn">Requests paused: ${s.breaker}</span>` : '')}
  </div>${raw(s.lastError ? html`<p class="rec-note is-warn">Last error: ${s.lastError}</p>` : '')}`;
}

function credentialLine(p) {
  return html`<div class="rec-meta"><span>${p.secretSet ? 'Credential stored · write-only' : 'No credential stored'}</span>
    ${raw(p.rotatedAt ? html`<span>${p.secretSet ? 'updated' : 'removed'} ${relTime(p.rotatedAt)}</span>` : '')}</div>`;
}

function policyScopeControls(p, policies) {
  if (!policies.length) return '';
  const all = !p.policyScope || !p.policyScope.length;
  return html`<details class="provider-scope">
    <summary>Policy scope: ${all ? 'all policies' : `${p.policyScope.length} selected`}</summary>
    <p class="small muted">Select the policies whose domains this provider may receive. Switch the provider off to stop all sharing.</p>
    ${raw(policies.map((pol) => html`<label class="checkline">
      <input type="checkbox" data-scope="${p.id}" data-policy-id="${pol.id}" ${raw(all || p.policyScope.includes(pol.id) ? 'checked' : '')}>
      <span>${pol.name}</span></label>`).join(''))}
  </details>`;
}

function providerCard(p, policies, templates) {
  const tpl = templates.find((t) => t.kind === p.kind);
  const lastTest = p.lastTest;
  return html`<article class="rec provider-entry" data-provider="${p.id}">
    <div class="rec-main">
      <div class="rec-title"><strong>${p.name || p.displayName || p.kind}</strong>${raw(providerStatusBadge(p))}</div>
      <div class="rec-meta"><span>${p.displayName || p.kind}</span><span>${(p.capabilities || []).join(' · ')}</span>
        <span>${num(p.ratePerMinute)} requests/min · ${num(p.timeoutMs)} ms timeout</span></div>
      ${raw(p.detail ? html`<p class="rec-note ${p.status === 'error' ? 'is-warn' : ''}">${p.detail}</p>` : '')}
      <p class="rec-note">${p.privacyNote || (tpl && tpl.privacyNote) || 'The selected domain is shared with this provider when it is consulted.'}</p>
      ${raw(credentialLine(p))}
      ${raw(lastTest ? html`<p class="rec-note ${lastTest.ok ? 'is-ok' : 'is-warn'}"><strong>${lastTest.ok ? 'Connection test passed' : 'Connection test failed'}</strong>
        · ${relTime(lastTest.testedAt)}${lastTest.latencyMs !== undefined ? ` · ${num(lastTest.latencyMs)} ms` : ''}
        ${lastTest.detail ? ` — ${lastTest.detail}` : ''}</p>` : html`<p class="rec-note muted">This saved connection has not been tested.</p>`)}
      ${raw(providerStats(p.stats))}
      <label class="checkline consent-line"><input type="checkbox" data-provider-consent="${p.id}">
        <span>I agree to share the test request or selected domains with this provider when I test or enable it.</span></label>
      <div class="row provider-actions">
        <button type="button" class="btn btn-ghost btn-sm" data-test="${p.id}">Test connection</button>
        <button type="button" class="btn ${p.enabled ? 'btn-ghost' : 'btn-observe'} btn-sm" data-provider-toggle="${p.id}" data-current-enabled="${p.enabled ? 'true' : 'false'}">${p.enabled ? 'Switch off' : 'Enable provider'}</button>
      </div>
      <p class="rec-note" data-result="${p.id}" role="status" hidden></p>
      <details class="provider-scope provider-options"><summary>Connection settings</summary>
        ${raw(policyScopeControls(p, policies))}
        <form data-secret-form="${p.id}" class="credential-form" autocomplete="off">
          <label class="field"><span>${p.secretSet ? 'Replace' : 'Add'} credential</span>
            <input type="password" name="secret" autocomplete="new-password" spellcheck="false" required>
            <span class="small muted">Stored encrypted. The saved value is never sent back to this page.</span></label>
          <button class="btn btn-ghost btn-sm" type="submit">Save credential</button>
        </form>
        <div class="row provider-actions">
          ${raw(p.secretSet ? html`<button class="btn btn-ghost btn-sm" data-clear-secret="${p.id}">Remove credential</button>` : '')}
          <button class="btn btn-danger btn-sm" data-delete-provider="${p.id}">Delete provider</button>
        </div>
        ${raw(verificationChip(tpl))}
        ${raw(tpl && tpl.verification ? html`<p class="small muted">${tpl.verification}</p>` : '')}
      </details>
    </div>
  </article>`;
}

function reputationCard(rep, engine) {
  const selectable = rep.selectable || ['off', 'cache_only', 'blocking'];
  const mode = rep.reputationMode || rep.mode || 'off';
  return html`<div class="card section">
    <div class="card-head"><div><h2>How providers are used</h2><p>Save the connection first, then choose the sharing and decision behaviour.</p></div>
      <span class="badge ${mode === 'off' ? '' : 'info'}">${(REPUTATION_MODES[mode] || [mode])[0]}</span></div>
    <form id="integration-settings-form">
      <fieldset class="mode-options"><legend>Automatic domain checks</legend>
        ${raw(selectable.map((m) => html`<label class="mode-option"><input type="radio" name="reputationMode" value="${m}" ${raw(mode === m ? 'checked' : '')}>
          <span><strong>${(REPUTATION_MODES[m] || [m])[0]}</strong><span class="cat-desc">${(REPUTATION_MODES[m] || [m, ''])[1]}</span></span></label>`).join(''))}
      </fieldset>
      <label class="checkline note-tight"><input type="checkbox" name="enrichmentEnabled" ${raw(rep.enrichmentEnabled ? 'checked' : '')}>
        <span>Allow on-demand investigation enrichment<span class="cat-desc">An explicit lookup can fetch extra context from enabled providers. Opening an investigation or preview stays local.</span></span></label>
      <label class="checkline consent-line"><input type="checkbox" name="consent">
        <span>I agree to send selected domains to my enabled providers under these settings.</span></label>
      <label class="checkline" id="provider-latency-consent" ${raw(mode === 'blocking' ? '' : 'hidden')}><input type="checkbox" name="acceptDnsLatency">
        <span>I accept that waiting for a provider can delay DNS answers.</span></label>
      <div class="row note-tight"><button type="submit" class="btn btn-primary">Save API preferences</button><span class="muted small">Takes effect without a restart.</span></div>
      <p class="form-error" id="integration-settings-error" role="alert" hidden></p>
    </form>
    ${raw(engine ? html`<div class="rec-meta note-loose"><span>${num(engine.cacheSize)} cached verdicts</span><span>${num(engine.cacheHits)} hits · ${num(engine.cacheMisses)} misses</span>
      <span>${num(engine.completed)} completed lookups</span><span>${num(engine.queueDepth)}/${num(engine.queueSize)} queued</span>
      ${raw(engine.dropped ? html`<span>${num(engine.dropped)} dropped</span>` : '')}</div>` : '')}
  </div>`;
}

function templateFields(tpl) {
  if (!tpl) return '';
  return html`<div class="provider-disclosure"><p class="rec-note">${tpl.privacyNote}</p>
    ${raw(tpl.docsUrl ? html`<a href="${tpl.docsUrl}" target="_blank" rel="noopener noreferrer" class="small">Provider documentation ↗</a>` : '')}</div>
    <div class="grid grid-2">
      ${raw((tpl.fields || []).filter((f) => f.key !== 'allow_private').map((f) => html`<label class="field"><span>${f.label}${f.required ? ' *' : ''}</span>
        <input name="cfg:${f.key}" value="${f.default || ''}" placeholder="${f.placeholder || ''}" ${raw(f.required ? 'required' : '')} autocomplete="off" spellcheck="false">
        ${raw(f.help ? html`<span class="small muted">${f.help}</span>` : '')}</label>`).join(''))}
      <label class="field"><span>${tpl.secretLabel || 'Credential'}${tpl.secretRequired ? ' *' : ''}</span>
        <input name="secret" type="password" autocomplete="new-password" spellcheck="false" ${raw(tpl.secretRequired ? 'required' : '')}>
        <span class="small muted">Bring your own account and API key. Stored encrypted; never displayed after saving.</span></label>
    </div>
    ${raw((tpl.fields || []).some((f) => f.key === 'allow_private') ? html`<label class="checkline note-tight"><input type="checkbox" name="cfg:allow_private" value="true"><span>Allow my private HTTPS service<span class="cat-desc">For a receiver I control on a private IPv4 or IPv6 address. Valid TLS is required; loopback and cloud metadata remain blocked.</span></span></label>` : '')}
    <details class="provider-scope"><summary>Request limits and adapter details</summary>
      <div class="grid grid-3 note-tight">
        <label class="field"><span>Requests per minute</span><input name="ratePerMinute" type="number" min="1" value="${tpl.defaultRatePerMinute || 60}"></label>
        <label class="field"><span>Timeout (ms)</span><input name="timeoutMs" type="number" min="100" value="${tpl.defaultTimeoutMs || 2000}"></label>
        <label class="field"><span>Cache lifetime (seconds)</span><input name="cacheTtlSeconds" type="number" min="60" value="${tpl.defaultCacheTtlSeconds || 21600}"></label>
      </div>${raw(verificationChip(tpl))}<p class="small muted">${tpl.verification || ''}</p>
    </details>`;
}

function availableAdaptersCard(templates) {
  if (!templates.length) return '';
  return html`<div class="card"><div class="card-head"><div><h2>Available adapters</h2><p>Nothing is contacted by opening this list.</p></div></div>
    ${raw(templates.map((t) => html`<div class="rec"><div><div class="rec-title"><strong>${t.displayName}</strong>${raw(verificationChip(t))}</div>
      <p class="rec-note">${t.privacyNote}</p><p class="small muted">${t.verification}</p></div></div>`).join(''))}</div>`;
}

pages.integrations = {
  title: 'External APIs',
  subtitle: 'Your accounts. Your keys. Explicit control over what gets shared.',
  async render(context = {}) {
    const read = (path) => apiGet(path, { signal: context.signal });
    const [catalogue, settings, data, policies] = await Promise.all([
      read('/integrations/templates'), read('/integrations/settings'), read('/integrations/providers'), read('/policies'),
    ]);
    const templates = catalogue.templates || [];
    const providers = data.providers || [];
    if (!context.isCurrent || context.isCurrent()) this.templates = templates;
    return html`<div class="card section integration-intro">
      <div><div class="card-eyebrow">Bring your own intelligence</div><h2>Extend your DNS workspace</h2>
        <p class="muted">Choose a provider, save your credentials and test the connection. Each connection starts switched off.</p></div>
      <ol class="connection-steps" aria-label="Connection setup"><li><span>1</span>Save securely</li><li><span>2</span>Test deliberately</li><li><span>3</span>Choose how it is used</li></ol>
      ${raw(settings.encryptionAvailable === false ? html`<p class="notice-inline">Credential encryption is unavailable. Connections cannot be saved until the server’s key storage is fixed.</p>` : '')}
    </div>
    <div class="card section"><div class="card-head"><div><h2>Your connections</h2><p>${providers.length ? `${providers.length} configured. Tests and live activity are reported separately.` : 'Connect only the services you want this instance to use.'}</p></div></div>
      ${raw(providers.length ? providers.map((p) => providerCard(p, policies.policies || [], templates)).join('')
        : emptyState('No providers connected', 'Add your first provider below. No API key is bundled with DNS Daddy.', { icon: '○' }))}
    </div>
    <div class="card section"><details class="add-provider" ${raw(providers.length ? '' : 'open')}><summary><h2>Add a provider</h2></summary>
      <form id="provider-form" class="note-loose" autocomplete="off">
        <div class="grid grid-2"><label class="field"><span>Service</span><select name="kind" id="provider-kind">${raw(templates.map((t) => html`<option value="${t.kind}">${t.displayName}</option>`).join(''))}</select></label>
          <label class="field"><span>Connection name</span><input name="name" placeholder="e.g. My VirusTotal account" maxlength="128"></label></div>
        <div id="provider-fields"></div>
        <label class="checkline consent-line"><input type="checkbox" name="testConsent"><span>I agree to send one test request to this provider if I select Test connection.</span></label>
        <div class="row note-tight"><button class="btn btn-ghost" type="button" id="provider-test">Test connection</button><button class="btn btn-primary" type="submit" ${raw(settings.encryptionAvailable === false ? 'disabled' : '')}>Save connection · switched off</button></div>
        <p class="rec-note" id="provider-test-result" role="status" hidden></p>
      </form></details></div>
    ${raw(reputationCard(settings, data.engine))}
    <div id="webhook-section"></div>`;
  },
  async mounted() {
    const templates = this.templates || [];
    const byKind = Object.fromEntries(templates.map((t) => [t.kind, t]));
    const fieldsHost = $('#provider-fields');
    const kindSelect = $('#provider-kind');
    const showResult = (el, ok, message) => {
      if (!el) return;
      el.hidden = false;
      el.className = `rec-note ${ok ? 'is-ok' : 'is-warn'}`;
      el.textContent = message;
    };
    if (fieldsHost && kindSelect) {
      const paintFields = () => {
        fieldsHost.innerHTML = sanitize(templateFields(byKind[kindSelect.value]));
        const form = $('#provider-form');
        if (form && form.elements.testConsent) form.elements.testConsent.checked = false;
        const result = $('#provider-test-result');
        if (result) result.hidden = true;
      };
      kindSelect.addEventListener('change', paintFields);
      paintFields();
    }
    const candidateFromForm = () => {
      const form = new FormData($('#provider-form'));
      const config = {};
      for (const [key, value] of form.entries()) if (key.startsWith('cfg:') && String(value).trim() !== '') config[key.slice(4)] = String(value);
      return {
        kind: form.get('kind'), name: String(form.get('name') || '').trim() || (byKind[form.get('kind')] || {}).displayName || form.get('kind'),
        config, secret: String(form.get('secret') || ''), timeoutMs: Number(form.get('timeoutMs')) || undefined,
        ratePerMinute: Number(form.get('ratePerMinute')) || undefined, cacheTtlSeconds: Number(form.get('cacheTtlSeconds')) || undefined,
      };
    };
    const testButton = $('#provider-test');
    if (testButton) testButton.addEventListener('click', async () => {
      const form = $('#provider-form');
      if (!form.reportValidity()) return;
      if (!form.elements.testConsent.checked) {
        showResult($('#provider-test-result'), false, 'Please agree to the test request before contacting this provider.');
        form.elements.testConsent.focus(); return;
      }
      const candidate = candidateFromForm();
      testButton.disabled = true; testButton.textContent = 'Testing…';
      try {
        const res = await apiSend('POST', '/integrations/providers/test', { kind: candidate.kind, config: candidate.config, secret: candidate.secret, timeoutMs: candidate.timeoutMs, ratePerMinute: candidate.ratePerMinute, consent: true });
        showResult($('#provider-test-result'), res.ok, res.ok ? `${res.detail} (${num(res.latencyMs)} ms). Save the connection when you are ready.` : res.error || res.detail || 'The test did not succeed.');
      } catch (err) { showResult($('#provider-test-result'), false, err.message); }
      finally { testButton.disabled = false; testButton.textContent = 'Test connection'; }
    });
    const form = $('#provider-form');
    if (form) form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const button = $('button[type="submit"]', form); button.disabled = true;
      const candidate = candidateFromForm();
      try {
        await apiSend('POST', '/integrations/providers', { ...candidate, enabled: false, capabilities: (byKind[candidate.kind] || {}).capabilities || ['reputation'] });
        form.reset(); toast('Connection saved securely and switched off. Enable it when you are ready.');
        await router.reload();
      } catch (err) { showResult($('#provider-test-result'), false, err.message); button.disabled = false; }
    });
    const settingsForm = $('#integration-settings-form');
    if (settingsForm) {
      $$('input[name="reputationMode"]', settingsForm).forEach((radio) => radio.addEventListener('change', () => {
        $('#provider-latency-consent').hidden = settingsForm.elements.reputationMode.value !== 'blocking';
        settingsForm.elements.acceptDnsLatency.checked = false;
      }));
      settingsForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        const error = $('#integration-settings-error'); error.hidden = true;
        const mode = settingsForm.elements.reputationMode.value;
        const enrichmentEnabled = settingsForm.elements.enrichmentEnabled.checked;
        const consent = settingsForm.elements.consent.checked;
        const acceptDnsLatency = settingsForm.elements.acceptDnsLatency.checked;
        if ((mode !== 'off' || enrichmentEnabled) && !consent) { error.textContent = 'Agree to domain sharing before enabling provider use.'; error.hidden = false; settingsForm.elements.consent.focus(); return; }
        if (mode === 'blocking' && !acceptDnsLatency) { error.textContent = 'Confirm the DNS latency trade-off before enabling this mode.'; error.hidden = false; settingsForm.elements.acceptDnsLatency.focus(); return; }
        const button = $('button[type="submit"]', settingsForm); button.disabled = true;
        try { await apiSend('PUT', '/integrations/settings', { reputationMode: mode, enrichmentEnabled, consent, acceptDnsLatency }); toast('API preferences saved'); await router.reload(); }
        catch (err) { error.textContent = err.message; error.hidden = false; button.disabled = false; }
      });
    }
    const consentFor = (id) => {
      const checkbox = $(`[data-provider-consent="${id}"]`);
      if (checkbox && checkbox.checked) return true;
      showResult($(`[data-result="${id}"]`), false, 'Agree to sharing above before testing or enabling this connection.');
      if (checkbox) checkbox.focus();
      return false;
    };
    $$('[data-provider-toggle]').forEach((button) => button.addEventListener('click', async () => {
      const id = button.dataset.providerToggle; const enabled = button.dataset.currentEnabled !== 'true';
      if (enabled && !consentFor(id)) return;
      button.disabled = true;
      try { await apiSend('PATCH', `/integrations/providers/${encodeURIComponent(id)}`, { enabled, consent: enabled }); toast(enabled ? 'Provider enabled under your API preferences' : 'Provider switched off'); await router.reload(); }
      catch (err) { showResult($(`[data-result="${id}"]`), false, err.message); button.disabled = false; }
    }));
    $$('[data-test]').forEach((button) => button.addEventListener('click', async () => {
      const id = button.dataset.test; if (!consentFor(id)) return;
      button.disabled = true; button.textContent = 'Testing…';
      try { const res = await apiSend('POST', `/integrations/providers/${encodeURIComponent(id)}/test`, { consent: true }); showResult($(`[data-result="${id}"]`), res.ok, res.ok ? `${res.detail} (${num(res.latencyMs)} ms)` : res.error || res.detail || 'The test did not succeed.'); }
      catch (err) { showResult($(`[data-result="${id}"]`), false, err.message); }
      finally { button.disabled = false; button.textContent = 'Test connection'; }
    }));
    $$('[data-secret-form]').forEach((secretForm) => secretForm.addEventListener('submit', async (event) => {
      event.preventDefault(); const field = $('input[name="secret"]', secretForm); const button = $('button', secretForm); button.disabled = true;
      try { await apiSend('POST', `/integrations/providers/${encodeURIComponent(secretForm.dataset.secretForm)}/secret`, { secret: field.value }); field.value = ''; toast('Credential stored securely'); await router.reload(); }
      catch (err) { reportError(err); }
      finally { field.value = ''; button.disabled = false; }
    }));
    $$('[data-clear-secret]').forEach((button) => button.addEventListener('click', async () => {
      if (!window.confirm('Remove this provider’s credential? Requests that require it will fail until you add another.')) return;
      button.disabled = true;
      try { await apiSend('DELETE', `/integrations/providers/${encodeURIComponent(button.dataset.clearSecret)}/secret`); toast('Credential removed'); await router.reload(); }
      catch (err) { reportError(err); button.disabled = false; }
    }));
    $$('[data-delete-provider]').forEach((button) => button.addEventListener('click', async () => {
      if (!window.confirm('Delete this provider, its credential and its cached verdicts?')) return;
      button.disabled = true;
      try { await apiSend('DELETE', `/integrations/providers/${encodeURIComponent(button.dataset.deleteProvider)}`); toast('Provider deleted'); await router.reload(); }
      catch (err) { reportError(err); button.disabled = false; }
    }));
    $$('[data-scope]').forEach((checkbox) => checkbox.addEventListener('change', async () => {
      const id = checkbox.dataset.scope; const boxes = $$(`[data-scope="${id}"]`); const chosen = boxes.filter((b) => b.checked).map((b) => b.dataset.policyId);
      if (!chosen.length) { checkbox.checked = true; toast('Keep at least one policy selected, or switch the provider off.', 'error'); return; }
      // Expanding scope changes who may be shared. A narrowing needs no consent.
      if (checkbox.checked && !consentFor(id)) { checkbox.checked = false; return; }
      boxes.forEach((b) => { b.disabled = true; });
      try { await apiSend('PATCH', `/integrations/providers/${encodeURIComponent(id)}`, { policyScope: chosen.length === boxes.length ? [] : chosen, consent: checkbox.checked }); toast('Policy scope saved'); }
      catch (err) { reportError(err); checkbox.checked = !checkbox.checked; }
      finally { boxes.forEach((b) => { b.disabled = false; }); }
    }));
    if (typeof mountWebhooks === 'function') await mountWebhooks();
  },
};


/* ---------- Optional event delivery ------------------------------------ */

function webhookCard(data) {
  const config = data.config || {};
  const stats = data.stats || {};
  const events = config.eventTypes || [];
  return html`<div class="card section"><details class="webhook-panel" ${raw(config.enabled ? 'open' : '')}>
    <summary><span><h2>Send findings to your own system</h2><span class="small muted">Optional webhook delivery</span></span><span class="badge ${config.enabled ? 'info' : ''}">${config.enabled ? 'Enabled' : 'Off'}</span></summary>
    <p class="muted note-loose">Deliver selected events as signed JSON to an HTTPS endpoint you control. DNS answers never wait for delivery.</p>
    <form id="webhook-form" data-secret-set="${config.secretSet ? 'true' : 'false'}" autocomplete="off">
      <label class="field"><span>Receiver URL</span><input type="url" name="url" value="${config.url || ''}" placeholder="https://security.example/webhooks/dnsdaddy" spellcheck="false" required>
        <span class="small muted">Use HTTPS. Put authentication in the signing key below, never in the URL.</span></label>
      <div class="grid grid-2"><label class="field"><span>${config.secretSet ? 'Replace signing key (optional)' : 'Signing key'}</span>
        <input type="password" name="secret" minlength="32" maxlength="4096" autocomplete="new-password" spellcheck="false">
        <span class="small muted">At least 32 characters. ${config.secretSet ? 'A key is stored; leave blank to keep it.' : 'Provide the same key to your receiver to verify signatures.'} Stored encrypted and write-only.</span></label>
        <fieldset class="webhook-events"><legend>Events to deliver</legend><label class="checkline"><input type="checkbox" name="findingCreated" ${raw(events.includes('finding.created') ? 'checked' : '')}><span>New findings</span></label>
          <label class="checkline"><input type="checkbox" name="findingReviewed" ${raw(events.includes('finding.reviewed') ? 'checked' : '')}><span>Finding reviews</span></label></fieldset></div>
      <p class="notice-inline">Finding events can contain domains and client details. Review events also include the review notes and history metadata. Choose a receiver authorised to hold that information.</p>
      <details class="provider-scope"><summary>Delivery limits and private receivers</summary>
        <div class="grid grid-3 note-tight"><label class="field"><span>Timeout (ms)</span><input name="timeoutMs" type="number" min="100" max="15000" required value="${config.timeoutMs || 5000}"></label>
          <label class="field"><span>Maximum attempts</span><input name="maxAttempts" type="number" min="1" max="8" required value="${config.maxAttempts || 5}"></label>
          <label class="field"><span>Queued event limit</span><input name="maxQueue" type="number" min="1" max="1000" required value="${config.maxQueue || 500}"></label></div>
        <label class="checkline"><input type="checkbox" name="allowPrivate" ${raw(config.allowPrivate ? 'checked' : '')}><span>Allow my private HTTPS receiver<span class="cat-desc">For an intentional private IPv4 or IPv6 destination. Loopback and cloud metadata destinations remain disallowed.</span></span></label>
      </details>
      <label class="checkline note-tight"><input type="checkbox" name="enabled" ${raw(config.enabled ? 'checked' : '')}><span>Enable event delivery</span></label>
      <label class="checkline consent-line"><input type="checkbox" name="consent"><span>I agree to send the selected events or a test event to this receiver.</span></label>
      <div class="row note-tight"><button type="submit" class="btn btn-primary">Save webhook</button><button type="button" class="btn btn-ghost" id="webhook-test" ${raw(config.url ? '' : 'disabled')}>Test saved receiver</button>
        ${raw(config.secretSet ? html`<button type="button" class="btn btn-ghost" id="webhook-clear-secret">Remove key and disable</button>` : '')}</div>
      <p class="muted small">Only new events are delivered after enabling. Saving webhook changes discards queued events and counts them as dropped.</p>
      <p id="webhook-result" class="rec-note" role="status" hidden></p>
    </form>
    <div class="delivery-status note-loose"><h3 class="small">Delivery history</h3><div class="rec-meta"><span>${num(stats.queueDepth)} queued now</span><span>${num(stats.delivered)} delivered</span>
      <span>${num(stats.failed)} failed</span><span>${num(stats.dropped)} dropped</span><span>${num(stats.retried)} retries</span></div>
      <p class="small muted">Totals survive restarts. Last successful delivery: ${relTime(stats.lastSuccessAt)}${stats.lastHttpStatus ? ` · last HTTP status ${stats.lastHttpStatus}` : ''}.</p>
      ${raw(stats.lastError ? html`<p class="rec-note is-warn">${stats.lastError}</p>` : '')}</div>
  </details></div>`;
}

async function mountWebhooks() {
  const host = $('#webhook-section'); if (!host) return;
  let data;
  try { data = await apiGet('/integrations/webhook'); }
  catch (err) {
    if (host.isConnected && err.status !== 401) host.innerHTML = sanitize(html`<div class="card section"><h2>Optional webhook delivery</h2><p class="rec-note is-warn">${err.message}</p></div>`);
    return;
  }
  if (!host.isConnected) return;
  host.innerHTML = sanitize(webhookCard(data));
  const form = $('#webhook-form', host); const result = $('#webhook-result', host);
  const show = (ok, message) => { result.hidden = false; result.className = `rec-note ${ok ? 'is-ok' : 'is-warn'}`; result.textContent = message; };
  form.addEventListener('submit', async (event) => {
    event.preventDefault(); const fields = form.elements; const enabled = fields.enabled.checked; const consent = fields.consent.checked;
    if (enabled && !consent) { show(false, 'Agree to event sharing before enabling delivery.'); fields.consent.focus(); return; }
    if (enabled && form.dataset.secretSet !== 'true' && fields.secret.value.length < 32) { show(false, 'Add a signing key of at least 32 characters before enabling delivery.'); fields.secret.focus(); return; }
    const eventTypes = [fields.findingCreated.checked && 'finding.created', fields.findingReviewed.checked && 'finding.reviewed'].filter(Boolean);
    if (!eventTypes.length) { show(false, 'Choose at least one event type.'); return; }
    const body = { enabled, url: fields.url.value.trim(), eventTypes, allowPrivate: fields.allowPrivate.checked,
      timeoutMs: Number(fields.timeoutMs.value), maxAttempts: Number(fields.maxAttempts.value), maxQueue: Number(fields.maxQueue.value), consent };
    if (fields.secret.value) body.secret = fields.secret.value;
    fields.secret.value = ''; const button = $('button[type="submit"]', form); button.disabled = true;
    try { await apiSend('PUT', '/integrations/webhook', body); toast('Webhook saved'); await mountWebhooks(); }
    catch (err) { show(false, err.message); button.disabled = false; }
  });
  $('#webhook-test', host).addEventListener('click', async (event) => {
    if (!form.elements.consent.checked) { show(false, 'Agree to send a test event before contacting the saved receiver.'); form.elements.consent.focus(); return; }
    const button = event.currentTarget; button.disabled = true; button.textContent = 'Testing…';
    try { const test = await apiSend('POST', '/integrations/webhook/test', { consent: true }); show(test.ok, test.ok ? `${test.detail} (${num(test.latencyMs)} ms)` : test.error || test.detail || 'The receiver test failed.'); }
    catch (err) { show(false, err.message); }
    finally { button.disabled = false; button.textContent = 'Test saved receiver'; }
  });
  const clear = $('#webhook-clear-secret', host);
  if (clear) clear.addEventListener('click', async () => {
    if (!window.confirm('Remove the signing key and disable webhook delivery?')) return;
    clear.disabled = true;
    try { await apiSend('DELETE', '/integrations/webhook/secret'); toast('Webhook key removed and delivery disabled'); await mountWebhooks(); }
    catch (err) { show(false, err.message); clear.disabled = false; }
  });
}


function resolverConnectionGuide(info = {}) {
  const listenerPort = (listen) => {
    const match = typeof listen === 'string' && listen.match(/:(\d+)$/);
    const port = match && Number(match[1]);
    return Number.isInteger(port) && port > 0 && port <= 65535 ? port : null;
  };
  const udpPort = listenerPort(info.listenUdp);
  const tcpPort = listenerPort(info.listenTcp);
  if (!udpPort && !tcpPort) return html`<p class="notice-inline">No ordinary DNS listener was reported. Check the listener configuration before pointing devices at this server.</p>`;
  const commands = [];
  if (udpPort) commands.push(`dig @<server-ip> -p ${udpPort} example.com A`);
  if (tcpPort) commands.push(`dig @<server-ip> -p ${tcpPort} example.com A +tcp`);
  return html`<div class="note-loose"><h3>Test one device before changing DHCP</h3>
    <p class="small muted">Replace <code>&lt;server-ip&gt;</code> with this server’s reachable LAN or VPN IP. These commands use the reported listener ports; if Docker publishes different host ports, use those host ports instead.</p>
    <pre class="first-client-cmd">${commands.join('\n')}</pre>
    <p class="small muted">The dashboard port (usually 8080) is separate. Most device and DHCP DNS settings use port 53 and cannot specify another port. A listener or Docker host port of 5353 is useful for these tests; publish UDP and TCP 53 before using an IP-only DNS setting.</p>
    <details class="chart-data"><summary>What should the result mean?</summary><div class="table-wrap"><table><thead><tr><th>Result</th><th>Next step</th></tr></thead><tbody>
      <tr><td>NOERROR with an answer</td><td>Check the Query log and Daddybound validation result, then try one device’s normal traffic.</td></tr>
      <tr><td>REFUSED</td><td>Permit this client’s actual source IP in Networks. A VPN or NAT can change the source seen by the server.</td></tr>
      <tr><td>SERVFAIL</td><td>The server answered but could not complete the lookup. Check Daddybound status, transport errors and the server clock; run <code>dnsdaddy doctor</code>.</td></tr>
      <tr><td>Timeout or connection refused</td><td>Check the address, DNS port, listener binding and firewall. Test UDP and TCP; both must reach the resolver.</td></tr>
    </tbody></table></div></details>
  </div>`;
}

pages.setup = {
  title: 'Setup',
  subtitle: 'Point your network here.',
  async render(context = {}) {
    const [info, networks, addresses] = await Promise.all([apiGet('/resolvers'), apiGet('/networks'), apiGet('/server-addresses', { signal: context.signal }).catch((error) => {
      if (error.status === 401 || error.name === 'AbortError') throw error;
      return null;
    })]);
    const port = (listen) => (listen || '').split(':').pop() || '53';

    return html`
      ${raw(serverAddressesCard(addresses))}
      <div class="card section">
        <div class="card-head">
          <div><h2>Client connection setup</h2>
          <p>Use a compatible server address above in your firewall, DHCP scope or router. Client permission is configured separately from the listener.</p></div>
        </div>
        <p class="small muted">Configured DNS listeners: ${info.listenUdp ? `UDP ${port(info.listenUdp)}` : 'UDP disabled'} · ${info.listenTcp ? `TCP ${port(info.listenTcp)}` : 'TCP disabled'}</p>
        ${raw(resolverAccessNote(networks.clientAccess))}
        ${raw(resolverConnectionGuide(info))}
        <p class="muted small note-tight">
          On pfSense: <em>System → General Setup → DNS Servers</em>.
          On UniFi: <em>Settings → Networks → your LAN → DHCP Name Server</em>.
          After testing, restrict clients’ DNS egress to DNS Daddy if required. Keep the DNS Daddy server’s own outbound transport reachable.
        </p>
        ${raw(info.listenDot ? html`<p class="small muted note-loose">DNS-over-TLS: port ${port(info.listenDot)}. Clients must use a hostname that matches this server’s TLS certificate.</p>` : '')}
      </div>

      <div class="card section integration-cta"><div><h2>Upstream transport</h2><p class="muted">Native Live needs outbound UDP and TCP 53 to authoritative servers. For encrypted forwarding, Daddybound offers a ready Cloudflare HTTPS example using TCP 443. This outbound connection is separate from how devices connect to DNS Daddy.</p></div><a class="btn btn-observe" href="#/daddybound">Configure DNS transport</a></div>

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
        <div class="card-head"><div><h2>${info.transport === 'encrypted' ? 'Encrypted forwarding endpoints' : 'Configured forwarding upstreams'}</h2><p>${info.transport === 'encrypted' ? 'The configured encrypted path. Daddybound reports local DNSSEC validation separately.' : 'Forwarding configuration and its recorded activity. Native iterative resolution uses its own authoritative path.'}</p></div></div>
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
                      <td>${raw(['tls', 'https', 'doq', 'doh3', 'doh2'].includes(u.protocol)
                        ? html`<span class="badge ok">${u.protocol} · encrypted</span>`
                        : html`<span class="badge warn">${u.protocol} · plaintext</span>`)}</td>
                      <td class="num">${num(u.queries)}</td>
                      <td class="num">${num(u.errors)}</td>
                      <!-- No queries means no samples, and no samples is not
                           zero milliseconds. An em dash says nothing was
                           measured; "0 ms" claims an impossibly fast upstream. -->
                      <td class="num">${raw(u.queries && u.avgLatencyMs > 0 ? html`${u.avgLatencyMs} ms` : html`<span class="muted" title="Latency not measured">&mdash;</span>`)}</td>
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

/* ---------- Complete browser exports ----------------------------------- */

function exportCard() {
  return html`<div class="card section"><div class="card-head"><div><h2>Export retained records</h2>
    <p>Collect every page of the selected dataset as newline-delimited JSON.</p></div></div>
    <form id="export-form" class="query-filters"><label class="query-filter"><span>Dataset</span><select name="dataset"><option value="queries">Query log</option><option value="decisions">Decision records and evidence</option><option value="findings">Original findings</option></select></label>
      <label class="query-filter"><span>Window</span><select name="hours"><option value="24">Last 24 hours</option><option value="168">Last 7 days</option><option value="720">Last 30 days</option><option value="0">All retained records</option></select></label>
      <div class="query-filter-actions"><button class="btn btn-primary" type="submit">Download complete export</button><button type="button" class="btn btn-ghost" id="export-cancel" hidden>Cancel</button></div></form>
    <p id="export-progress" class="small muted note-tight" role="status"></p><p id="export-error" class="form-error" role="alert" hidden></p>
    <p class="muted small">The time window is fixed at the first page. No file is offered if a page fails, records are skipped or the 20 MB browser limit is reached. Retention can remove data during a long export; an export is not a backup.</p>
    <p class="small"><a href="${REPO}/docs/exports.md" target="_blank" rel="noopener noreferrer">API export guide for larger collections ↗</a></p>
  </div>`;
}

async function readCompleteExport({ dataset, hours = '24', signal, onProgress = () => {}, read = (url, options) => fetch(url, options), maxBytes = 20 * 1024 * 1024, maxPages = 1000 }) {
  if (!['queries', 'decisions', 'findings'].includes(dataset)) throw new Error('Unknown export dataset.');
  if (!['0', '24', '168', '720'].includes(String(hours))) throw new Error('Unknown export window.');
  const prefix = `/api/v1/${dataset}/export`;
  let next = `${prefix}?hours=${hours}&limit=${dataset === 'findings' ? 1000 : 500}`;
  const chunks = []; const seen = new Set();
  let rows = 0; let pages = 0; let bytes = 0; let boundary;
  while (next) {
    if (signal && signal.aborted) throw new DOMException('Export cancelled.', 'AbortError');
    if (seen.has(next) || pages >= maxPages) throw new Error('Export did not reach a final page. No complete file was created.');
    if (!next.startsWith(`${prefix}?`) || next.includes('#')) throw new Error('The next-page link did not match this export. No file was created.');
    seen.add(next);
    const response = await read(next, { credentials: 'same-origin', signal });
    if (!response.ok) {
      const detail = await response.json().catch(() => null);
      throw new ApiError(response.status, detail && detail.error || `Export page failed (${response.status}).`);
    }
    const countHeader = response.headers.get('X-Export-Count');
    const skippedHeader = response.headers.get('X-Export-Skipped');
    const truncated = response.headers.get('X-Truncated');
    const count = Number(countHeader); const skipped = Number(skippedHeader);
    if (countHeader === null || skippedHeader === null || !Number.isSafeInteger(count) || count < 0 || !Number.isSafeInteger(skipped) || skipped < 0 || !['true', 'false'].includes(truncated)) {
      throw new Error('The server did not provide complete export metadata. No file was created.');
    }
    if (skipped) throw new Error(`${num(skipped)} stored record(s) were skipped. Investigate the export data; no file was labelled complete.`);
    const currentBoundary = ['X-Export-Since', 'X-Export-Until', 'X-Export-Snapshot'].map((key) => response.headers.get(key));
    if (!currentBoundary[1] || currentBoundary[2] === null) throw new Error('The export boundary is missing. No file was created.');
    if (boundary && currentBoundary.some((value, index) => value !== boundary[index])) throw new Error('The export boundary changed between pages. Start a new export.');
    boundary = currentBoundary;
    let pageText = '';
    const reader = response.body.getReader(); const decoder = new TextDecoder();
    try {
      while (true) {
        const chunk = await reader.read(); if (chunk.done) break;
        bytes += chunk.value.byteLength;
        if (bytes > maxBytes) { await reader.cancel(); throw new Error('This export exceeds the 20 MB browser limit. Choose a smaller window or use the API export guide. No partial file was offered.'); }
        pageText += decoder.decode(chunk.value, { stream: true });
      }
      pageText += decoder.decode();
    } finally { reader.releaseLock(); }
    const lines = pageText.split('\n').filter((line) => line.trim() !== '');
    if (lines.length !== count) throw new Error('An export page ended before its reported record count. No file was created.');
    for (const line of lines) {
      try { JSON.parse(line); } catch { throw new Error('An export page contained invalid JSON. No file was created.'); }
    }
    chunks.push(pageText.endsWith('\n') || !pageText ? pageText : pageText + '\n'); rows += count; pages++;
    onProgress({ rows, pages, bytes });
    if (truncated === 'false') { next = ''; continue; }
    const link = (response.headers.get('Link') || '').match(/<([^>]+)>;\s*rel="?next"?/);
    if (!link || !response.headers.get('X-Next-Cursor')) throw new Error('The server reported more records without a next-page link. No file was created.');
    next = link[1];
  }
  return { chunks, rows, pages, bytes, since: boundary[0], until: boundary[1] };
}

function mountExports(context = {}) {
  const form = $('#export-form'); if (!form) return;
  const progress = $('#export-progress'); const error = $('#export-error'); const cancel = $('#export-cancel');
  let controller = null;
  if (context.signal) context.signal.addEventListener('abort', () => { if (controller) controller.abort(); }, { once: true });
  cancel.addEventListener('click', () => { if (controller) controller.abort(); });
  form.addEventListener('submit', async (event) => {
    event.preventDefault(); if (controller) return;
    controller = new AbortController(); error.hidden = true; cancel.hidden = false;
    const button = $('button[type="submit"]', form); button.disabled = true; const dataset = form.elements.dataset.value;
    progress.textContent = 'Reading the first page…';
    try {
      const collected = await readCompleteExport({ dataset, hours: form.elements.hours.value, signal: controller.signal,
        onProgress: ({ rows, pages }) => { progress.textContent = `${num(rows)} records collected across ${num(pages)} pages…`; },
      });
      if (!form.isConnected) return;
      const blob = new Blob(collected.chunks, { type: 'application/x-ndjson' }); const url = URL.createObjectURL(blob);
      const link = document.createElement('a'); link.href = url; link.download = `dnsdaddy-${dataset}-${new Date().toISOString().slice(0, 10)}.ndjson`;
      document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 30000);
      progress.textContent = `Complete: ${num(collected.rows)} records across ${num(collected.pages)} pages. Download started.`;
    } catch (err) {
      if (err.status === 401) showLogin();
      if (err.name === 'AbortError') progress.textContent = 'Export cancelled. No partial file was downloaded.';
      else { error.textContent = err.message; error.hidden = false; progress.textContent = ''; }
    } finally { controller = null; button.disabled = false; cancel.hidden = true; }
  });
}


pages.reports = {
  title: 'Reports',
  subtitle: 'Evidence you can forward.',
  async render() {
    const summary = await apiGet('/reports/summary?days=7');
    return html`
      ${raw(exportCard())}
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
  async mounted(context = {}) {
    mountExports(context);
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

/*
 * Claim strength, as a word with a fixed meaning.
 *
 * The Assurance page states several different kinds of thing — something CI
 * re-checks on every commit, something a scanner did once in August, something
 * shipped but not calibrated, and something nobody has done at all — and until
 * now they were all set in the same grey prose. A reader had to infer the
 * strength of each claim from its wording, which is precisely the inference an
 * assurance page should not be asking anyone to make.
 *
 * The words are deliberately narrow. "Verified" here means one thing only:
 * automation re-runs it on every change and you can read the workflow. It does
 * not mean reviewed, certified, or audited, and the Limitations card below
 * still says so in as many words.
 */
const CLAIM_TIERS = {
  verified: ['ok', 'Verified', 'Re-checked automatically on every change, in CI. The workflow is in the repository.'],
  tested: ['info', 'Tested', 'Exercised once, by a tool or a person, at a stated point in time. Not re-run on every change.'],
  experimental: ['tier', 'Experimental', 'Available for evaluation. Sample limits and performance claims require measurement; this is not an independent security review.'],
  unverified: ['warn', 'Not verified', 'Nobody has checked this. Where the word appears, treat the claim as open.'],
  limitation: ['warn', 'Limitation', 'A boundary of what this product, or the evidence behind it, can show.'],
};

function claimChip(tier) {
  const entry = CLAIM_TIERS[tier];
  if (!entry) return '';
  const [cls, label, meaning] = entry;
  return html`<span class="badge ${cls} claim" title="${meaning}">${label}</span>`;
}

/*
 * Local DNSSEC observation, on the page whose subject is "what is checked and
 * what that does not prove".
 *
 * The hardest thing to get right here is not the numbers. It is that a reader
 * who sees "bogus: 12" must not come away believing twelve queries were
 * refused. So the non-enforcing fact is stated before any count, in the
 * heading, in the prose and again next to the bogus figure — repetition being
 * the correct trade when the alternative is a reader drawing a false
 * conclusion about their own resolver.
 *
 * The dropped count sits beside the totals for the same reason. A sample that
 * silently shrank under load would invite conclusions it cannot support.
 */
// The legacy observations summary can contain more than one resolution path.
// It must not be used as a Learn-only population on the operations page.
function localDnssecCard(data) {
  const off = !data || data.mode !== 'observe';

  if (off) return html`<div class="card section"><div class="card-head"><div><h2>Sampled DNSSEC observations</h2>
    <p>Separate Learn observations are off. This does not describe whether native Live enforcement is running.</p></div></div>
    <a href="#/daddybound" class="btn btn-ghost btn-sm">Check the effective Daddybound mode</a></div>`;

  const s = data.summary || {};
  const by = s.byStatus || {};
  const runtime = data.runtime || {};
  const dis = s.disagreements || {};
  const disTotal = Object.values(dis).reduce((a, b) => a + b, 0);

  // Two different populations, and conflating them told a privacy-conscious
  // operator that no validation had happened. Verdicts are counted whatever
  // the query-log setting; the row naming the domain is only written when
  // query logging is on. Reporting the stored count as "observed" therefore
  // read as "we validated nothing", with every status below it at zero and
  // no stated reason.
  const stored = s.total || 0;
  const observed = runtime.observed;
  const withheld = (observed || 0) > 0 && stored === 0;

  const stat = (label, value, note) => html`
    <div class="qfact"><dt>${label}</dt><dd><span class="mono">${value ?? 0}</span>${raw(note ? html` <span class="muted small">${note}</span>` : '')}</dd></div>`;

  return html`
    <div class="card section">
      <div class="card-head">
        <div>
          <div class="card-eyebrow">Experimental</div>
          <h2>Daddybound — Learn ${raw(claimChip('experimental'))}</h2>
          <p><strong>Nothing here blocks anything.</strong> Daddybound validates the same
             names your clients ask for and records what it concludes. The answer a client
             receives is decided entirely by the resolver, whatever these verdicts say.</p>
        </div>
      </div>

      ${raw(daddyboundModes(true))}

      <dl class="claim-key">
        ${raw(stat('Observed', observed, 'verdicts reached since this instance started'))}
        ${raw(stat('Stored', stored, 'rows in the last 7 days — every count below is drawn from these'))}
        ${raw(stat('Secure', by.secure))}
        ${raw(stat('Insecure', by.insecure, 'provably unsigned'))}
        ${raw(stat('Bogus', by.bogus, 'recorded, not blocked'))}
        ${raw(stat('Indeterminate', by.indeterminate))}
        ${raw(stat('Could not validate', (by.timeout || 0) + (by.resource_limit || 0) + (by.unsupported || 0) + (by.internal_error || 0), 'timeout, limit or unsupported — not a DNSSEC state'))}
        ${raw(stat('Differs from upstream', disTotal, 'the point of the exercise'))}
        ${raw(stat('Not observed', runtime.dropped, 'queue saturation, stopped submissions or shutdown discards — the sample is smaller than your traffic'))}
        ${raw(stat('Observed but not stored', runtime.unrecorded, 'validated, then lost before the database — evidence that went missing'))}
        ${raw(stat('Mean latency', (s.avgDurationMs || 0).toFixed(1) + ' ms', 'off the answer path'))}
        ${raw(stat('p95 latency', (s.p95DurationMs || 0).toFixed(1) + ' ms'))}
      </dl>

      ${raw(withheld ? html`<p class="muted small">Verdicts are being counted but no rows are being stored, so the
        counts by status stay at zero. Query logging is off, and an observation row names the domain it
        validated — recording it anyway would undo that setting through a feature you enabled to measure
        DNSSEC. The totals here are aggregate and name nothing.</p>` : '')}

      ${raw(runtime.panics ? html`<p class="muted small"><span class="badge bad">${runtime.panics}</span>
        validator panics were contained. That is a defect in the validator, not a property of your traffic —
        please report it.</p>` : '')}

      <p class="muted small note-tight">
        "Differs from upstream" is not a fault in either side. Your upstream and Daddybound
        answer slightly different questions — the upstream validated the answer it sent,
        Daddybound validated the name shortly afterwards — and the disagreements are the
        evidence that decides whether local validation could ever be trusted to enforce.
      </p>
    </div>`;
}

/*
 * The Daddybound status block: what the runtime holds, section by section,
 * with every scope named. The rule for the wording is the rule for the API
 * it reads: say what was measured, say when it is not enough, never turn a
 * count into a readiness score. A missing status is rendered as unavailable
 * rather than as a healthy zero.
 */
function anchorKeyRows(keys) {
  if (!keys || !keys.length) return html`<p class="muted small">No managed keys yet. The configured anchors are in force until the first RFC 5011 refresh seeds the trust point.</p>`;
  return html`<div class="table-wrap"><table>
    <thead><tr><th>Key tag</th><th>Algorithm</th><th>State</th><th>Trusted</th><th>Seen</th><th>Timer</th></tr></thead>
    <tbody>${raw(keys.map((k) => html`<tr>
      <td class="mono">${k.keyTag}${raw(k.seeded ? html` <span class="badge">seeded</span>` : '')}</td>
      <td class="mono">${k.algorithm}</td>
      <td><span class="badge ${k.trusted ? 'ok' : k.state === 'revoked' || k.state === 'removed' ? 'bad' : 'warn'}">${k.state}</span></td>
      <td>${k.trusted ? 'yes' : 'no'}</td>
      <td class="muted small">${relTime(k.firstSeen)} → ${relTime(k.lastSeen)}</td>
      <td class="muted small">${k.addHoldDownUntil ? `add hold-down until ${new Date(k.addHoldDownUntil).toLocaleDateString('en-GB')}` : k.removeHoldDownUntil ? `remove hold-down until ${new Date(k.removeHoldDownUntil).toLocaleDateString('en-GB')}` : '—'}</td>
    </tr>`).join(''))}</tbody></table></div>`;
}

function daddyboundStatusCard(status) {
  if (!status) {
    return html`
      <div class="card section">
        <div class="card-head"><div><div class="card-eyebrow">Experimental</div><h2>Daddybound runtime</h2></div></div>
        ${raw(unavailableState('Runtime status unavailable', 'The status request failed. Nothing here is inferred from an older reading.'))}
      </div>`;
  }
  const mode = status.mode || {};
  const res = status.resolution || {};
  const an = status.anchors || {};
  const rt = status.runtime || {};
  const learnActive = rt.active === undefined ? mode.effective === 'observe' : rt.active;
  const learnScope = rt.scope === 'most_recent_learn_activation' ? 'inactive · retained from the most recent Learn activation'
    : rt.scope === 'since_current_learn_activation' ? 'since the current Learn activation' : 'since this process started';
  const st = status.stored || {};
  const ev = status.evidence || {};
  const stat = (label, value, note) => html`<div class="qfact"><dt>${label}</dt><dd>${raw(value)}${raw(note ? html` <span class="muted small">${note}</span>` : '')}</dd></div>`;
  const n = (v) => (typeof v === 'number' ? num(v) : '—');
  const persistence = an.persistence || {};
  const persistenceBadge = { ok: ['ok', 'state file written'], not_yet_written: ['', 'state file not yet written'], failing: ['bad', 'state file cannot be written'], load_failed: ['warn', 'stored state could not be read'] }[persistence.state] || ['warn', String(persistence.state || 'unknown')];

  return html`
    <div class="card section" id="daddybound-status">
      <div class="card-head"><div>
        <div class="card-eyebrow">Experimental · ${mode.enforcing ? 'local DNSSEC enforcement' : mode.effective === 'observe' ? 'observation only' : 'local validation off'}</div>
        <h2>Daddybound runtime ${raw(claimChip('experimental'))}</h2>
        <p>What the process holds about local validation, with each figure's scope named. Reading this page resolves nothing and changes no trust state.</p>
      </div></div>

      <dl class="claim-key">
        ${raw(stat('Mode', html`<span class="badge ${nativeMode(status).tone}">${nativeMode(status).label}</span>`, `configured: ${mode.configured || '—'} · chosen by ${mode.chosenBy === 'installation_default' ? 'the installation default' : ['runtime', 'dashboard'].includes(mode.chosenBy) ? 'a saved runtime setting' : 'configuration'}`))}
        ${raw(mode.live && mode.live.reason ? stat('Live availability', html`<span class="muted small">${mode.live.reason}</span>`) : '')}
        ${raw(stat('Resolution source', html`<span class="badge">${res.source || '—'}</span>`, res.transport || ''))}
        ${raw(stat('Client answers', html`<span class="muted small">${res.clientPath || ''}</span>`))}
      </dl>

      <h4>Trust anchors (RFC 5011)</h4>
      ${raw(!an.available
        ? html`<p class="muted small">${an.unavailable || 'No trust-anchor manager is running.'}</p>`
        : html`<dl class="claim-key">
            ${raw(stat('Trust point', html`<span class="mono">${an.zone}</span> <span class="badge ${an.viable ? 'ok' : 'bad'}">${an.viable ? 'viable' : 'not viable'}</span>`, `${n(an.trustedKeys)} trusted key${an.trustedKeys === 1 ? '' : 's'}`))}
            ${raw(an.needsIntervention ? stat('Needs an operator', html`<span class="badge bad">intervention required</span>`, an.interventionNote || '') : '')}
            ${raw(stat('Last refresh', html`${an.refresh && an.refresh.lastSuccess ? `succeeded ${relTime(an.refresh.lastSuccess)}` : 'no successful refresh yet'}`, an.refresh && an.refresh.lastError ? `last attempt failed: ${an.refresh.lastError}` : an.refresh && an.refresh.next ? `next ${relTime(an.refresh.next)}` : ''))}
            ${raw(stat('Persistence', html`<span class="badge ${persistenceBadge[0]}">${persistenceBadge[1]}</span>`, `${persistence.file || ''}${persistence.lastSaveError ? ` · ${persistence.lastSaveError}` : ''}${persistence.loadError ? ` · ${persistence.loadError}` : ''}`))}
          </dl>
          ${raw(anchorKeyRows(an.keys))}`)}

      <h4>Learn observer <span class="muted small">${rt.available ? learnScope : 'not running'}</span></h4>
      ${raw(!rt.available
        ? html`<p class="muted small">${rt.healthNote || 'No observer is running.'}</p>`
        : html`<dl class="claim-key">
            ${raw(stat(learnActive ? 'Health' : 'Last recorded health', html`<span class="badge ${rt.health === 'ok' ? 'ok' : rt.health === 'degraded' ? 'warn' : ''}">${rt.health}</span>`, rt.healthNote || ''))}
            ${raw(stat('Observed', html`<span class="mono">${n(rt.observed)}</span>`, `${n(rt.dropped)} not observed (queue saturation, stopped submissions or shutdown discards) · ${n(rt.unrecorded)} lost before storage · ${n(rt.writeErrors)} write errors`))}
            ${raw(stat('Could not conclude', html`<span class="mono">${n(rt.timeouts)} timeout · ${n(rt.resourceLimit)} limit · ${n(rt.unreachable)} unreachable</span>`, 'operational outcomes, not DNSSEC states'))}
            ${raw(stat('Validation work', html`<span class="mono">${n(rt.queries)}</span> DNS queries`, `${n(rt.delegations)} zone cuts crossed`))}
            ${raw(rt.panics ? stat('Observer defects', html`<span class="badge bad">${n(rt.panics)} contained panics</span>`, 'within this Learn activation; a validator defect to report') : '')}
            ${raw(rt.seamPanics ? stat('Observation dispatch defects', html`<span class="badge bad">${n(rt.seamPanics)} contained panics</span>`, 'since this process started; a resolver defect to report') : '')}
          </dl>`)}

      <h4>Stored <span class="muted small">rows within the last ${st.windowHours || '—'}h</span></h4>
      <dl class="claim-key">
        ${raw(stat('In window', html`<span class="mono">${n(st.total)}</span>`, `${n(st.retainedRows)} retained in total · retention ${n(st.retentionDays)} day(s)`))}
        ${raw(stat('Observing since', html`${st.observingSince ? relTime(st.observingSince) : 'no stored observations'}`, st.observedUntil ? `latest ${relTime(st.observedUntil)}` : ''))}
      </dl>

      <h4>Disagreement populations <span class="muted small">stored rows, by how they were obtained</span></h4>
      ${raw((status.populations || []).length
        ? html`<div class="table-wrap"><table>
            <thead><tr><th>Resolution</th><th>Client answer</th><th>Comparable</th><th class="num">Rows</th><th class="num">Local bogus, upstream validated</th><th>Reading</th></tr></thead>
            <tbody>${raw(status.populations.map((p) => html`<tr>
              <td class="mono">${p.resolution}</td>
              <td>${p.cached ? 'from cache' : 'fresh'}</td>
              <td>${p.comparable ? 'yes' : 'no'}</td>
              <td class="num">${n(p.total)}</td>
              <td class="num">${p.comparable ? n(p.disagreements && p.disagreements.local_bogus_upstream_validated) : '—'}</td>
              <td class="muted small">${p.note}</td></tr>`).join(''))}</tbody></table></div>`
        : html`<p class="muted small">No stored observations in the window.</p>`)}

      <h4>Evidence for enforcement</h4>
      <p><span class="badge warn">${ev.sufficient ? 'sufficient' : 'insufficient'}</span> <span class="muted small">${ev.note || ''}</span></p>
      ${raw((ev.criteria || []).length
        ? html`<div class="table-wrap"><table>
            <thead><tr><th>Criterion</th><th>Measured</th><th>Status</th></tr></thead>
            <tbody>${raw(ev.criteria.map((c) => html`<tr><td>${c.title}</td><td class="muted small">${c.measured}</td><td><span class="badge">${String(c.status || '').replace('_', ' ')}</span></td></tr>`).join(''))}</tbody></table></div>`
        : '')}
      <p class="muted small">The criteria and the corpus work are tracked in
        ${raw((ev.issues || []).map((u) => html`<a href="${u}" target="_blank" rel="noopener noreferrer">${u.replace('https://github.com/', '')}</a>`).join(' and '))}.
        No number on this page is a readiness score.</p>
    </div>`;
}

/* ---------- Native resolution and local traffic learning ---------------- */

const DNS_TRANSPORT_PROTOCOLS = {
  doq: { label: 'DoQ · DNS over QUIC', placeholder: 'resolver.example:853', hint: 'DoQ uses UDP port 853 by default. Confirm that the provider supports DoQ; a DNS-over-TLS (DoT) server on TCP 853 is a different protocol.' },
  doh3: { label: 'DoH · HTTP/3', placeholder: 'https://resolver.example/dns-query', hint: 'An HTTPS DNS endpoint over UDP 443 by default. HTTP/3 is required; this endpoint does not fall back to HTTP/2 or HTTP/1.' },
  doh2: { label: 'DoH · HTTP/2', placeholder: 'https://resolver.example/dns-query', hint: 'An HTTPS DNS endpoint over TCP 443 by default. HTTP/2 is required; this endpoint does not fall back to HTTP/1.' },
};

// An example is an explicit local edit. Rendering it never selects a provider,
// sends a DNS query, grants consent, or changes the saved transport/mode.
// Provider values: https://developers.cloudflare.com/1.1.1.1/ip-addresses/
// and https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/.
const DNS_TRANSPORT_EXAMPLES = {
  cloudflare: { protocol: 'doh2', address: 'https://cloudflare-dns.com/dns-query', serverName: 'cloudflare-dns.com', bootstrapIPs: ['1.1.1.1', '1.0.0.1'] },
};

function transportExampleDraft(endpoints, exampleID) {
  const example = DNS_TRANSPORT_EXAMPLES[exampleID];
  if (!example || !Object.hasOwn(DNS_TRANSPORT_EXAMPLES, exampleID)) throw new Error('Unknown encrypted DNS example.');
  const draft = (endpoints || []).map((endpoint) => ({ ...endpoint, bootstrapIPs: [...(endpoint.bootstrapIPs || [])] }));
  // Fill the initial empty editor; otherwise preserve every custom entry and
  // append the example so the operator's failover order does not change.
  if (draft.length === 1 && !draft[0].protocol && !draft[0].address && !draft[0].serverName && !draft[0].bootstrapIPs.length) draft.pop();
  if (draft.length >= 16) throw new Error('Remove an endpoint before adding an example. The limit is 16.');
  draft.push({ ...example, bootstrapIPs: [...example.bootstrapIPs] });
  return draft;
}

function transportExampleCard() {
  return html`<div class="transport-example note-loose"><h3>Start with a ready example</h3>
    <p class="small">Cloudflare’s standard resolver over HTTPS (HTTP/2), using TCP 443. The example includes the endpoint, TLS name and both bootstrap IPs. Cloudflare receives the DNS names you send to it.</p>
    <div class="row note-tight"><button type="button" class="btn btn-observe btn-sm" data-transport-example="cloudflare">Add Cloudflare example</button>
      <a class="small" href="https://developers.cloudflare.com/1.1.1.1/privacy/public-dns-resolver/" target="_blank" rel="noopener noreferrer">Provider privacy policy ↗</a></div>
    <ol class="compact-list"><li>Add the example or enter your provider’s details below. This only fills your draft.</li>
      <li>Review the provider and check the sharing agreement, then select <strong>Test endpoints</strong>.</li>
      <li>After a successful test, select <strong>Apply DNS transport</strong>. Keep or select <strong>Live</strong> in Daddybound above for local DNSSEC validation.</li></ol>
    <p class="small muted">The test checks an encrypted exchange, not a complete Live lookup. Finish by testing a device in <a href="#/setup">Setup</a>. Adding an example preserves existing entries; it does not save, connect or change your Daddybound mode.</p>
  </div>`;
}

function transportConsentError(transport, currentTransport, acknowledgeForwarding, acknowledgeNativeTransport) {
  if (transport === 'encrypted' && !acknowledgeForwarding) return 'Agree to send DNS queries to your configured forwarders before saving or testing them.';
  if (transport === 'native' && currentTransport === 'encrypted' && !acknowledgeNativeTransport) return 'Acknowledge the unencrypted authoritative DNS transport before switching to native resolution.';
  return '';
}

function transportEndpointFields(endpoint = {}, index = 0) {
  const protocol = DNS_TRANSPORT_PROTOCOLS[endpoint.protocol];
  return html`<fieldset class="transport-endpoint" data-forwarder><legend>Forwarder <span data-forwarder-number>${index + 1}</span></legend>
    <div class="grid grid-2"><label class="field"><span>Protocol</span><select name="protocol" required data-endpoint-protocol>
      <option value="" disabled ${raw(protocol ? '' : 'selected')}>Choose a protocol</option>
      ${raw(Object.entries(DNS_TRANSPORT_PROTOCOLS).map(([value, option]) => html`<option value="${value}" ${raw(endpoint.protocol === value ? 'selected' : '')}>${option.label}</option>`).join(''))}</select></label>
      <label class="field"><span>Endpoint address</span><input name="address" value="${endpoint.address || ''}" placeholder="${protocol ? protocol.placeholder : 'Choose the protocol first'}" autocomplete="off" spellcheck="false" required maxlength="2048">
        <span class="small muted" data-endpoint-hint>${protocol ? protocol.hint : 'Enter an endpoint you have chosen. No public provider is preselected.'}</span></label>
      <label class="field"><span>TLS server name <span class="muted">(optional)</span></span><input name="serverName" value="${endpoint.serverName || ''}" placeholder="resolver.example" autocomplete="off" spellcheck="false" maxlength="253">
        <span class="small muted">Defaults to the address host. The certificate name and trust chain must verify.</span></label>
      <label class="field"><span>Bootstrap IP addresses</span><textarea name="bootstrapIPs" rows="2" placeholder="203.0.113.53&#10;2001:db8::53" spellcheck="false">${(endpoint.bootstrapIPs || []).join('\n')}</textarea>
        <span class="small muted">For a hostname, provide 1–8 literal IPs, one per line. This avoids a plaintext DNS lookup to find the forwarder. A literal-IP endpoint can dial itself.</span></label>
    </div>
    <div class="row transport-endpoint-actions"><button type="button" class="btn btn-ghost btn-sm" data-transport-action="up" aria-label="Move forwarder ${index + 1} earlier">Move up</button>
      <button type="button" class="btn btn-ghost btn-sm" data-transport-action="down" aria-label="Move forwarder ${index + 1} later">Move down</button>
      <button type="button" class="btn btn-ghost btn-sm" data-transport-action="remove" aria-label="Remove forwarder ${index + 1}">Remove</button></div>
  </fieldset>`;
}

function negotiatedTLS(version) {
  if (version === undefined || version === null || version === '' || version === 0) return 'Not observed';
  return version === 772 || version === '1.3' ? 'TLS 1.3' : String(version);
}

function encryptedTransportStats(stats, { test = false } = {}) {
  if (!stats) return html`<p class="small muted">No encrypted transport counters are available for this runtime.</p>`;
  const endpoints = stats.endpoints || [];
  return html`<div class="encrypted-transport-stats"><div class="rec-meta"><span>${num(stats.queries)} ${stats.queries === 1 ? 'request' : 'requests'}</span><span>${num(stats.successes)} successful</span><span>${num(stats.failures)} failed</span>
    <span>${num(stats.rejected)} rejected</span><span>${num(stats.failovers)} failovers</span><span>${num(stats.inFlight)} in flight</span></div>
    ${raw(endpoints.length ? html`<div class="table-wrap note-tight"><table><thead><tr><th>Endpoint</th><th>Attempts / successes</th><th>Failures</th><th>Last observed TLS</th><th>Last result</th></tr></thead><tbody>${raw(endpoints.map((endpoint) => html`<tr>
      <td><strong>${(DNS_TRANSPORT_PROTOCOLS[endpoint.protocol] || {}).label || endpoint.protocol}</strong><div class="mono small">${endpoint.address}</div><div class="small muted">TLS name: ${endpoint.serverName || 'Address host'}</div></td>
      <td>${num(endpoint.attempts)} / ${num(endpoint.successes)}${raw(!endpoint.attempts ? html`<div class="small muted">Not attempted</div>` : '')}</td><td>${num(endpoint.failures)}<div class="small muted">${num(endpoint.dialFailures)} connection failures</div></td>
      <td>${negotiatedTLS(endpoint.tlsVersion)}${raw(endpoint.remoteAddress ? html`<div class="mono small">${endpoint.remoteAddress}</div>` : '')}</td>
      <td>${raw(endpoint.lastError ? html`<span class="rec-note is-warn">${endpoint.lastError}</span>` : html`<span class="small muted">${endpoint.successes && endpoint.lastSuccess && !String(endpoint.lastSuccess).startsWith('0001-01-01') ? `Last success ${relTime(endpoint.lastSuccess)}` : 'No successful request time recorded'}</span>`)}</td>
    </tr>`).join(''))}</tbody></table></div>` : '')}
    <p class="small muted">TLS and remote address describe the last authenticated connection, not a current availability check.</p>
    ${raw(test ? html`<p class="small muted">Ordered failover stops at a working endpoint. An endpoint with no attempts has not been tested.</p>` : '')}
  </div>`;
}

function transportTestResult(result) {
  return html`<div class="transport-test-summary notice-inline ${result.ok ? 'transport-test-ok' : ''}"><strong>${result.ok ? 'Test query answered' : 'Test query failed'}</strong>
    <span>${result.error || (result.rcode ? `DNS response: ${result.rcode}.` : 'No DNS response code was reported.')}</span></div>
    ${raw(encryptedTransportStats(result.stats, { test: true }))}`;
}

function dnsTransportCard(data) {
  if (!data || !['native', 'encrypted'].includes(data.transport)) return html`<section class="card section" id="dns-transport"><div class="card-head"><div><h2>DNS transport</h2><p>How DNS Daddy obtains answers and supporting DNSSEC records.</p></div></div>
    ${raw(unavailableState('Transport settings unavailable', 'The effective DNS transport could not be read. No transport or provider is assumed.'))}</section>`;
  const encrypted = data.transport === 'encrypted';
  const endpoints = data.endpoints || [];
  return html`<section class="card section transport-card" id="dns-transport"><div class="card-head"><div><div class="card-eyebrow">Outbound DNS connection</div><h2>DNS transport</h2>
    <p>Choose where DNS answers come from. Daddybound’s Off, Learn and Live settings control local DNSSEC validation separately.</p></div><span class="badge ${encrypted ? 'info' : ''}">${encrypted ? 'Encrypted forwarding' : 'Native iterative'}</span></div>
    <p class="small muted">${encrypted ? 'The configured forwarders receive the queried names and supporting DNSSEC lookups. Daddybound can validate their returned data locally in Live mode.' : data.daddyboundMode === 'enforce' ? 'Live resolves directly through root and authoritative servers over unencrypted UDP/TCP port 53.' : data.daddyboundMode === 'observe' ? 'Learn uses native DNS for separate validation observations. Client answers still use the legacy configured upstreams.' : data.daddyboundMode === 'off' ? 'With validation Off, clients use the legacy configured upstreams. Native recursion and trust-anchor refresh are stopped.' : 'Live resolves directly through authoritative DNS. Learn and Off use the legacy configured upstreams for client answers.'}</p>
    <form id="dns-transport-form" data-current-transport="${data.transport}" autocomplete="off">
      <fieldset class="mode-options transport-mode-options" ${raw(data.locked ? 'disabled' : '')}><legend>Answer transport</legend>
        <label class="mode-option"><input type="radio" name="transport" value="native" ${raw(encrypted ? '' : 'checked')}><span><strong>Native iterative</strong><span class="cat-desc">Live resolves through the DNS hierarchy on plaintext port 53. Learn and Off retain legacy forwarding for client answers.</span></span></label>
        <label class="mode-option"><input type="radio" name="transport" value="encrypted" ${raw(encrypted ? 'checked' : '')}><span><strong>Encrypted forwarding</strong><span class="cat-desc">Use your chosen DoQ or DoH endpoints, with authenticated TLS 1.3 and local DNSSEC validation available.</span></span></label>
      </fieldset>
      ${raw(data.locked ? html`<p class="notice-inline">${data.reason || 'The startup configuration pins this transport. Change that configuration to edit it here.'}</p>` : '')}
      <div id="encrypted-forwarder-options" ${raw(encrypted ? '' : 'hidden')}>
        <p class="muted small note-loose">Endpoints are tried in the order shown. Only the configured protocols are used. If they all fail, the lookup fails; there is no plaintext fallback.</p>
        <fieldset id="encrypted-endpoint-fields" class="transport-endpoint-fields" ${raw(!encrypted || data.locked ? 'disabled' : '')}><legend class="sr-only">Encrypted forwarding endpoints</legend>
          ${raw(!data.locked ? transportExampleCard() : '')}
          <div id="transport-endpoints">${raw((endpoints.length ? endpoints : [{}]).map((endpoint, index) => transportEndpointFields(endpoint, index)).join(''))}</div>
          ${raw(!data.locked ? html`<button type="button" class="btn btn-ghost btn-sm" id="transport-add-endpoint">Add another endpoint</button>` : '')}
        </fieldset>
        <p class="small muted note-tight">Maximum 16 endpoints. HTTPS endpoints cannot contain credentials, query strings or fragments. Certificates use the operating system’s trusted roots; no certificate bypass is available.</p>
        <label class="checkline consent-line"><input type="checkbox" name="acknowledgeForwarding"><span>I agree to send DNS queries and supporting DNSSEC lookups to these forwarders, including the fixed test query if I select Test endpoints.</span></label>
        <p class="small muted note-tight">Test endpoints sends a DNSKEY query for the root zone using this draft. It changes no saved configuration. A response establishes connectivity, not provider accuracy or a full Daddybound Live validation.</p>
      </div>
      <label class="checkline consent-line" id="transport-native-consent" hidden><input type="checkbox" name="acknowledgeNativeTransport"><span>I understand that native Live and Learn use unencrypted authoritative DNS on port 53. Off and Learn restore legacy forwarding for client answers, and background lookups may use system DNS.</span></label>
      <div class="row note-loose transport-actions"><button type="button" class="btn btn-ghost" id="transport-test" ${raw(encrypted ? '' : 'hidden')}>Test endpoints</button>
        ${raw(!data.locked ? html`<button type="submit" class="btn btn-primary">Apply DNS transport</button>` : '')}</div>
      <p id="dns-transport-error" class="form-error" role="alert" hidden></p>
      <p id="dns-transport-progress" class="small muted" role="status"></p>
      <div id="dns-transport-test-result" class="note-tight" role="status" hidden></div>
    </form>
    <details class="chart-data transport-health"><summary>Transport activity and connection security</summary>
      <dl class="claim-key note-tight"><div class="qfact"><dt>Configured minimum TLS</dt><dd>${data.tlsMinimum || 'Not reported'}</dd></div>
        <div class="qfact"><dt>Plaintext fallback</dt><dd>${data.plaintextFallback === false ? 'Disabled' : 'Not confirmed disabled'}</dd></div>
        <div class="qfact"><dt>Endpoint address discovery</dt><dd>${data.bootstrap === 'configured_ips' ? 'Explicit bootstrap IPs; no system DNS lookup' : data.bootstrap === 'system' ? 'System resolver configuration' : 'Not reported'}</dd></div>
        ${raw(data.scope ? html`<div class="qfact"><dt>Connection scope</dt><dd>${data.scope}</dd></div>` : '')}</dl>
      ${raw(encryptedTransportStats(data.stats))}
    </details>
  </section>`;
}

function mountDNSTransport(settings) {
  const form = $('#dns-transport-form');
  if (!form || !settings) return;
  const host = $('#transport-endpoints', form);
  const error = $('#dns-transport-error', form);
  const progress = $('#dns-transport-progress', form);
  const testResult = $('#dns-transport-test-result', form);
  const add = $('#transport-add-endpoint', form);
  const showError = (message) => { error.textContent = message; error.hidden = false; };
  const rows = () => $$('[data-forwarder]', host);
  const renumber = () => {
    const entries = rows();
    entries.forEach((row, index) => {
      $('[data-forwarder-number]', row).textContent = String(index + 1);
      for (const [action, label] of [['up', 'Move earlier'], ['down', 'Move later'], ['remove', 'Remove']]) {
        const button = $(`[data-transport-action="${action}"]`, row);
        button.setAttribute('aria-label', `${label}: forwarder ${index + 1}`);
        button.disabled = Boolean(settings.locked || action === 'up' && index === 0 || action === 'down' && index === entries.length - 1);
      }
    });
    if (add) add.disabled = entries.length >= 16;
    $$('[data-transport-example]', form).forEach((button) => { button.disabled = Boolean(settings.locked) || entries.length >= 16; });
  };
  const updateMode = () => {
    const encrypted = form.elements.transport.value === 'encrypted';
    $('#encrypted-forwarder-options', form).hidden = !encrypted;
    $('#encrypted-endpoint-fields', form).disabled = !encrypted || Boolean(settings.locked);
    $('#transport-native-consent', form).hidden = encrypted || settings.transport !== 'encrypted' || settings.locked;
    $('#transport-test', form).hidden = !encrypted;
    form.elements.acknowledgeForwarding.checked = false;
    form.elements.acknowledgeNativeTransport.checked = false;
    testResult.hidden = true;
    error.hidden = true;
  };
  $$('input[name="transport"]', form).forEach((radio) => radio.addEventListener('change', updateMode));
  const changed = () => { testResult.hidden = true; form.elements.acknowledgeForwarding.checked = false; progress.textContent = ''; };
  host.addEventListener('input', changed);
  host.addEventListener('change', (event) => {
    changed();
    if (!event.target.matches('[data-endpoint-protocol]')) return;
    const row = event.target.closest('[data-forwarder]');
    const protocol = DNS_TRANSPORT_PROTOCOLS[event.target.value];
    $('[name="address"]', row).placeholder = protocol ? protocol.placeholder : '';
    $('[data-endpoint-hint]', row).textContent = protocol ? protocol.hint : 'Choose a protocol.';
  });
  if (add) add.addEventListener('click', () => {
    if (rows().length >= 16) return;
    host.insertAdjacentHTML('beforeend', sanitize(transportEndpointFields({}, rows().length)));
    renumber(); changed(); $('[name="protocol"]', rows().at(-1)).focus();
  });
  host.addEventListener('click', (event) => {
    const button = event.target.closest('[data-transport-action]');
    if (!button || settings.locked) return;
    const row = button.closest('[data-forwarder]');
    const action = button.dataset.transportAction;
    let focusTarget = row;
    if (action === 'up' && row.previousElementSibling) host.insertBefore(row, row.previousElementSibling);
    if (action === 'down' && row.nextElementSibling) host.insertBefore(row.nextElementSibling, row);
    if (action === 'remove') { focusTarget = row.nextElementSibling || row.previousElementSibling; row.remove(); }
    renumber(); changed();
    if (focusTarget) $('[name="protocol"]', focusTarget).focus(); else if (add) add.focus();
  });
  const endpointsFromDraft = () => rows().map((row) => ({ protocol: $('[name="protocol"]', row).value,
    address: $('[name="address"]', row).value.trim(), serverName: $('[name="serverName"]', row).value.trim(),
    bootstrapIPs: $('[name="bootstrapIPs"]', row).value.split(/[\s,]+/).map((value) => value.trim()).filter(Boolean) }));
  $$('[data-transport-example]', form).forEach((button) => button.addEventListener('click', () => {
    if (settings.locked) return;
    try {
      const draft = transportExampleDraft(endpointsFromDraft(), button.dataset.transportExample);
      host.innerHTML = sanitize(draft.map(transportEndpointFields).join(''));
      renumber(); changed(); error.hidden = true;
      progress.textContent = 'Example added to your draft. Review it, agree to share queries, then test before applying.';
      $('[name="address"]', rows().at(-1)).focus();
    } catch (err) { showError(err.message); }
  }));
  const consent = (transport) => {
    const message = transportConsentError(transport, settings.transport, form.elements.acknowledgeForwarding.checked, form.elements.acknowledgeNativeTransport.checked);
    if (!message) return true;
    showError(message);
    form.elements[transport === 'encrypted' ? 'acknowledgeForwarding' : 'acknowledgeNativeTransport'].focus();
    return false;
  };
  const validEndpoints = (endpoints) => {
    if (!endpoints.length) { showError('Add at least one encrypted DNS endpoint.'); if (add) add.focus(); return false; }
    if (endpoints.length > 16 || endpoints.some((endpoint) => endpoint.bootstrapIPs.length > 8)) { showError('Use at most 16 endpoints and 8 bootstrap IPs per endpoint.'); return false; }
    return true;
  };
  const busy = (value) => {
    $$('button', form).forEach((button) => { button.disabled = value; });
    $('.transport-mode-options', form).disabled = value || Boolean(settings.locked);
    $('#encrypted-endpoint-fields', form).disabled = value || Boolean(settings.locked) || form.elements.transport.value !== 'encrypted';
    form.elements.acknowledgeForwarding.disabled = value;
    form.elements.acknowledgeNativeTransport.disabled = value;
    if (!value) renumber();
  };
  form.addEventListener('submit', async (event) => {
    event.preventDefault(); if (settings.locked) return;
    error.hidden = true;
    const transport = form.elements.transport.value;
    if (!consent(transport)) return;
    const endpoints = transport === 'encrypted' ? endpointsFromDraft() : settings.endpoints || [];
    if (transport === 'encrypted' && !validEndpoints(endpoints)) return;
    busy(true); progress.textContent = 'Applying DNS transport…'; testResult.hidden = true;
    try {
      await apiSend('PUT', '/dns/transport', { transport, endpoints, acknowledgeForwarding: form.elements.acknowledgeForwarding.checked, acknowledgeNativeTransport: form.elements.acknowledgeNativeTransport.checked });
      toast('DNS transport updated'); if (form.isConnected) await router.reload();
    } catch (err) { showError(err.message); progress.textContent = 'Your draft is still shown. Review the error before trying again.'; busy(false); }
  });
  $('#transport-test', form).addEventListener('click', async () => {
    error.hidden = true;
    if (!form.reportValidity() || !consent('encrypted')) return;
    const endpoints = endpointsFromDraft(); if (!validEndpoints(endpoints)) return;
    busy(true); testResult.hidden = true; progress.textContent = 'Sending the fixed root DNSKEY test query…';
    try {
      const result = await apiSend('POST', '/dns/transport/test', { endpoints, acknowledgeForwarding: true });
      if (!testResult.isConnected) return;
      testResult.innerHTML = sanitize(transportTestResult(result)); testResult.hidden = false;
      progress.textContent = 'Test finished. The saved transport is unchanged.';
    } catch (err) { if (error.isConnected) { showError(err.message); progress.textContent = 'Test could not complete. The saved transport is unchanged.'; } }
    finally { if (form.isConnected) busy(false); }
  });
  renumber(); updateMode();
}

function nativeMode(status) {
  const mode = (status && status.mode) || {};
  if (!status) return { label: 'Unavailable', tone: 'warn', active: false, enforcing: false };
  if (mode.effective === 'enforce') return mode.enforcing
    ? { label: 'Live · enforcing', tone: 'ok', active: true, enforcing: true }
    : { label: 'Live · needs attention', tone: 'warn', active: false, enforcing: false };
  if (mode.effective === 'observe') return { label: 'Learn · observing', tone: 'info', active: true, enforcing: false };
  return { label: 'Off', tone: '', active: false, enforcing: false };
}

function daddyboundModes(status) {
  // Boolean input remains useful to older observation callers; a full runtime
  // response is required before this helper can claim live enforcement.
  const data = typeof status === 'boolean' ? { mode: { effective: status ? 'observe' : 'off', enforcing: false } } : status;
  const mode = nativeMode(data);
  return html`<dl class="claim-key"><div class="qfact"><dt>Effective mode</dt><dd><span class="badge ${mode.tone}">${mode.label}</span></dd></div>
    <div class="qfact"><dt>DNSSEC decisions</dt><dd>${mode.enforcing ? 'Daddybound validates returned answers locally.' : mode.active ? 'Daddybound records a separate validation observation.' : 'Daddybound local DNSSEC validation is off.'}</dd></div></dl>
    <p class="muted small note-tight">Live applies local DNSSEC checks before returning an answer. Learn records separate sampled validations. DNS transport and local traffic learning are configured separately.</p>`;
}

function nativeModeCard(status) {
  if (!status) return html`<div class="card section">${raw(unavailableState('Daddybound status unavailable', 'The server did not return its effective resolution mode. No mode is assumed.'))}</div>`;
  const mode = status.mode || {};
  const state = nativeMode(status);
  const encrypted = status.transport === 'encrypted';
  const labels = { enforce: ['Live', 'Validate DNSSEC locally before returning an answer.'], observe: ['Learn', 'Record sampled local validations separately from the client answer.'], off: ['Off', 'Turn off Daddybound local DNSSEC validation.'] };
  return html`<div class="card section engine-mode-card"><div class="card-head"><div><div class="card-eyebrow">Local DNSSEC engine</div><h2>Daddybound</h2>
      <p>Local DNSSEC validation, explicit trust checks and a view of changing traffic.</p></div><span class="badge ${state.tone}">${state.label}</span></div>
    <p class="engine-mode-copy">${state.enforcing ? encrypted ? 'Daddybound validates returned data locally using your encrypted forwarders. Bogus or inconclusive validation fails the lookup; there is no plaintext fallback.' : 'Daddybound is answering through its native resolver and enforcing DNSSEC. Bogus or inconclusive validation fails the lookup; there is no forwarding fallback.' : mode.effective === 'enforce' ? 'Live is selected, but local validation is not enforcing. Review the operational status below before relying on it.' : state.active ? 'Daddybound records separate local validations. These observations do not change the answer returned to the client.' : 'Daddybound local DNSSEC validation is off. The selected DNS transport still applies.'}</p>
    <form id="daddybound-mode-form" data-transport="${encrypted ? 'encrypted' : 'native'}">
      <fieldset class="mode-options" ${raw(mode.locked ? 'disabled' : '')}><legend>Local DNSSEC mode</legend>
        ${raw(['enforce', 'observe', 'off'].map((value) => html`<label class="mode-option"><input type="radio" name="mode" value="${value}" ${raw(mode.effective === value ? 'checked' : '')} ${raw(value === 'enforce' && mode.live && mode.live.available === false ? 'disabled' : '')}>
          <span><strong>${labels[value][0]}</strong><span class="cat-desc">${labels[value][1]}</span></span></label>`).join(''))}
      </fieldset>
      ${raw(mode.locked ? html`<p class="notice-inline">${mode.reason || 'This deployment pins the resolution mode in its startup configuration.'}</p>` : html`
        <label class="checkline consent-line" id="native-transport-consent" ${raw(encrypted ? 'hidden' : '')}><input type="checkbox" name="acknowledgeNativeTransport"><span>I understand that native resolution contacts authoritative DNS servers over unencrypted UDP/TCP port 53.</span></label>
        <div class="row note-tight"><button type="submit" class="btn btn-primary">Apply validation mode</button><span class="muted small">New queries use the changed mode.</span></div>`)}
      <p id="native-mode-error" class="form-error" role="alert" hidden></p>
    </form>
    ${raw(mode.live && mode.live.available === false && mode.live.reason ? html`<p class="rec-note is-warn">${mode.live.reason}</p>` : '')}
    <p class="muted small note-tight">Experimental. DNSSEC enforcement and machine-learning findings have different responsibilities: an unusual traffic pattern alone never blocks a domain.</p>
  </div>`;
}

function nativeEnforcementCard(status) {
  const data = status && status.native;
  if (!data || !data.available) return '';
  const metric = (label, value, sub) => metricCard({ label, value: num(value), sub });
  return html`<div class="card section"><div class="card-head"><div><h2>Daddybound answer path</h2><p>Answer counters since this validation runtime was activated. Signed, unsigned and failed validation are reported separately.</p></div></div>
    <div class="grid grid-4 native-metrics">${raw(metric('Secure', data.secure, 'Validated signed answers'))}${raw(metric('Insecure', data.insecure, 'Proven unsigned answers'))}
      ${raw(metric('Bogus', data.bogus, 'Failed DNSSEC checks'))}${raw(metric('Indeterminate', data.indeterminate, 'Could not establish trust'))}</div>
    <dl class="claim-key note-loose"><div class="qfact"><dt>Other outcomes</dt><dd>${num(data.resolutionFailures)} resolution failures · ${num(data.limitRejected)} rejected at the concurrency limit</dd></div>
      <div class="qfact"><dt>Active work</dt><dd>${num(data.inflight)} in flight · peak ${num(data.peak)}</dd></div>
      <div class="qfact"><dt>Client checking disabled</dt><dd>${num(data.checkingDisabled)} requests <span class="muted small">Clients requested CD=1. Returned data is unchecked and AD is cleared; policy still applies.</span></dd></div>
      <div class="qfact"><dt>Recorded outcomes</dt><dd>${num(data.stored)} stored · ${num(data.unrecorded)} lost · ${num(data.writeErrors)} write errors <span class="muted small">since this process started</span></dd></div>
      ${raw(data.panics ? html`<div class="qfact"><dt>Contained faults</dt><dd class="rec-note is-warn">${num(data.panics)} panics. Report this as a resolver defect.</dd></div>` : '')}</dl>
  </div>`;
}

function learningWindows(results) {
  if (!results || !results.length) return html`<p class="muted small">No completed traffic windows yet. Live queries must meet the minimum sample before a baseline comparison is possible.</p>`;
  const states = { learning: ['info', 'Building baseline'], typical: ['', 'Within baseline'], anomaly: ['warn', 'Unusual'], excluded: ['', 'Excluded'], insufficient: ['', 'Too little traffic'] };
  const number = (value) => typeof value === 'number' ? String(Math.round(value * 1000) / 1000) : '—';
  return html`<div class="learning-window-list">${raw(results.map((result) => {
    const [tone, label] = states[result.state] || ['warn', result.state || 'Unknown'];
    const window = result.window || {};
    return html`<details class="learning-window"><summary><span class="mono small">${result.client || 'Unattributed client'}</span><span class="badge ${tone}">${label}</span>
      <span class="small muted">${num(window.eligibleQueries)} eligible queries</span><span class="small muted">${relTime(window.end)}</span></summary>
      <p class="muted small">${num(result.baselineWindows)} baseline windows · ${num(result.baselineQueries)} baseline queries · age ${duration(result.baselineAgeSeconds)}.
        ${result.score === null || result.score === undefined ? 'No score until enough history exists.' : `Anomaly distance ${number(result.score)}; threshold ${number(result.threshold)}. This is not a threat probability.`}</p>
      ${raw((result.excludedReasons || []).length ? html`<p class="rec-note">${result.excludedReasons.join(' · ')}</p>` : '')}
      ${raw((result.features || []).length ? html`<div class="table-wrap"><table><thead><tr><th>Feature</th><th>Measured</th><th>Baseline mean</th><th>Deviation</th></tr></thead><tbody>${raw(result.features.map((feature) => html`<tr>
        <td class="mono small">${feature.name}</td><td>${number(feature.value)}</td><td>${number(feature.baselineMean)}</td><td>${number(feature.z)}</td></tr>`).join(''))}</tbody></table></div>` : '')}
      ${raw(result.client ? html`<div class="row note-tight"><a class="btn btn-ghost btn-sm" href="${investigateHash({ client: result.client })}">Investigate client</a></div>` : '')}
    </details>`;
  }).join(''))}</div>`;
}

function localLearningCard(status) {
  if (!status) return html`<div class="card section"><div class="card-head"><h2>Local traffic learning</h2></div>
    ${raw(unavailableState('Learning status unavailable', 'The local model status could not be retrieved. No sample counts are inferred.'))}</div>`;
  if (status.available === false) return html`<div class="card section" id="local-learning"><div class="card-head"><div><h2>Local traffic learning</h2><p>Local behavioural baselines and unusual-activity findings.</p></div><span class="badge ${status.enabled ? 'warn' : ''}">${status.enabled ? 'Unavailable' : 'Off'}</span></div>
    ${raw(status.enabled ? unavailableState('The learning model is unavailable', status.error || 'Learning is configured, but its worker could not start. No sample counts are inferred.') : html`<p class="muted">Local traffic learning is disabled for this deployment.</p>`)}
    ${raw((status.limitations || []).length ? html`<ul class="compact-list small muted">${raw(status.limitations.map((item) => html`<li>${item}</li>`).join(''))}</ul>` : '')}</div>`;
  const clients = status.clients || {};
  const observations = status.observations || {};
  const windows = status.windows || {};
  const queue = status.queue || {};
  const persistence = status.persistence || {};
  const running = status.enabled && status.running;
  const label = running ? 'Learning only' : status.enabled ? 'Not running' : 'Off';
  return html`<div class="card section" id="local-learning"><div class="card-head"><div><div class="card-eyebrow">On-device behavioural model</div><h2>Local traffic learning</h2>
      <p>Builds a separate baseline for each client and records unusual changes as findings.</p></div><div class="row"><span class="badge ${running ? 'info' : status.enabled ? 'warn' : ''}">${label}</span><span class="badge tier">Experimental</span></div></div>
    <p class="muted">${running ? 'Learning stays on this resolver. The model compares new traffic windows with a client’s previous pattern; it does not call an external AI service.' : status.enabled ? 'Learning is enabled, but the worker is not running. Its counters do not imply that new traffic is being processed.' : 'Local traffic learning is disabled for this deployment.'}</p>
    <div class="grid grid-4 native-metrics note-loose">
      ${raw(metricCard({ label: 'Clients tracked', value: num(clients.tracked), sub: `${num(clients.max)} client limit` }))}
      ${raw(metricCard({ label: 'Baseline ready', value: num(clients.ready), sub: 'Enough local history to compare' }))}
      ${raw(metricCard({ label: 'Still learning', value: num(clients.warming), sub: 'Waiting for sufficient history' }))}
      ${raw(metricCard({ label: 'Unusual windows', value: num(windows.anomalous), sub: 'Signals to review, not threats proven' }))}
    </div>
    <div class="notice-inline note-loose"><strong>Learning does not enforce blocks.</strong> Review unusual activity alongside the original query evidence. Baseline readiness describes sample maturity, not detection accuracy.</div>
    <div class="row note-loose"><a class="btn btn-observe" href="#/detections">Review findings</a><a class="btn btn-ghost" href="#/investigate">Investigate a client</a></div>
    <details class="chart-data"><summary>Recent client windows</summary>${raw(learningWindows(status.recent))}</details>
    <details class="chart-data"><summary>Learning health and sample limits</summary>
      <dl class="claim-key note-tight">
        <div class="qfact"><dt>Minimum history</dt><dd>${num(status.warmupWindows)} suitable windows across at least ${duration(status.warmupSeconds)}; ${num(status.minWindowQueries)} queries per ${duration(status.windowSeconds)} window.</dd></div>
        <div class="qfact"><dt>Observations</dt><dd>${num(observations.processed)} processed / ${num(observations.received)} received · ${num(observations.dropped)} dropped</dd></div>
        <div class="qfact"><dt>Windows</dt><dd>${num(windows.trained)} trained · ${num(windows.quarantined)} quarantined · ${num(windows.insufficient)} below the sample minimum</dd></div>
        <div class="qfact"><dt>Unfinished windows</dt><dd>${num(windows.evictedPending)} evicted · ${num(windows.restartDiscarded)} discarded after restart</dd></div>
        <div class="qfact"><dt>Excluded observations</dt><dd>${num(observations.blocked)} blocked · ${num(observations.errors)} failed · ${num(observations.invalid)} invalid · ${num(observations.late)} late · ${num(observations.privacySkipped)} omitted for privacy</dd></div>
        <div class="qfact"><dt>State limits</dt><dd>${num(clients.evicted)} client baselines evicted · ${num(observations.windowOverflow)} window overflows · ${num(observations.uniqueSaturated)} unique-name limits reached</dd></div>
        <div class="qfact"><dt>Pending work</dt><dd>${num(queue.depth)} / ${num(queue.capacity)} observations queued</dd></div>
        <div class="qfact"><dt>Model findings</dt><dd>${num(status.findingsEmitted)} emitted · ${num(status.findingSuppressed)} suppressed · ${num(status.findingErrors)} write errors</dd></div>
        <div class="qfact"><dt>Last observation</dt><dd>${status.lastProcessedAt && !status.lastProcessedAt.startsWith('0001-') ? relTime(status.lastProcessedAt) : 'No observation processed yet'}</dd></div>
        <div class="qfact"><dt>Model persistence</dt><dd>${persistence.enabled ? persistence.lastSavedAt && !persistence.lastSavedAt.startsWith('0001-') ? `Saved ${relTime(persistence.lastSavedAt)}` : 'No saved checkpoint yet' : 'Not persisted'}${persistence.loaded ? ' · previous baseline loaded' : ''} · ${num(persistence.saveErrors)} save errors</dd></div>
        ${raw(persistence.lastError ? html`<div class="qfact"><dt>Persistence error</dt><dd class="rec-note is-warn">${persistence.lastError}</dd></div>` : '')}
      </dl>
      <p class="muted small">The model uses bounded rolling statistics. It holds unusual windows out of baseline updates to reduce contamination. Low activity, missing observations and client turnover limit what it can conclude.</p>
      <p class="muted small">Algorithm: <span class="mono">${status.algorithm || '—'}</span> · model ${status.modelVersion ?? '—'}. Scores are distances from a baseline, never a probability that a domain is malicious.</p>
    </details>
  </div>`;
}

function nativeOverview(status, learning) {
  const mode = nativeMode(status);
  const ready = learning && learning.clients;
  return html`<div class="card section native-overview"><div class="native-overview-item"><span class="label muted small">Daddybound</span><strong>${mode.label}</strong>
      <span class="muted small">${mode.enforcing ? 'Local DNSSEC in the answer path' : mode.active ? 'Sampled DNSSEC observations' : status ? 'Local DNSSEC validation is off' : 'Runtime status could not be read'}</span></div>
    <div class="native-overview-item"><span class="label muted small">Local learning</span><strong>${learning ? learning.enabled && learning.running ? `${num(ready && ready.ready)} baselines ready` : learning.enabled ? 'Needs attention' : 'Off' : 'Unavailable'}</strong>
      <span class="muted small">${ready ? `${num(ready.warming)} clients warming up · findings only` : 'Local observations and model health'}</span></div>
    <a href="#/daddybound" class="btn btn-observe btn-sm">Open Daddybound</a></div>`;
}

pages.daddybound = {
  title: 'Daddybound',
  subtitle: 'DNS transport, local validation and traffic learning.',
  async render(context = {}) {
    const read = (path) => apiGet(path, { signal: context.signal }).catch((error) => {
      if (error.status === 401 || error.name === 'AbortError') throw error;
      return null;
    });
    const [runtime, learning, transport] = await Promise.all([read('/dnssec/status?hours=168'), read('/learning/status'), read('/dns/transport')]);
    if (!context.isCurrent || context.isCurrent()) this.transportSettings = transport;
    return html`${raw(nativeModeCard(runtime))}${raw(dnsTransportCard(transport))}${raw(nativeEnforcementCard(runtime))}${raw(localLearningCard(learning))}
      <details class="card section engine-details"><summary><h2>Trust anchors, observation health and evidence limits</h2></summary>
        <div class="note-loose">${raw(daddyboundStatusCard(runtime))}</div>
      </details>`;
  },
  async mounted() {
    mountDNSTransport(this.transportSettings);
    const form = $('#daddybound-mode-form');
    if (!form || !$('button[type="submit"]', form)) return;
    const consent = $('#native-transport-consent');
    const update = () => { if (consent) consent.hidden = form.elements.mode.value === 'off' || form.dataset.transport === 'encrypted'; };
    $$('input[name="mode"]', form).forEach((radio) => radio.addEventListener('change', update)); update();
    form.addEventListener('submit', async (event) => {
      event.preventDefault(); const mode = form.elements.mode.value; const error = $('#native-mode-error'); error.hidden = true;
      const acknowledgeNativeTransport = form.elements.acknowledgeNativeTransport.checked;
      if (mode !== 'off' && form.dataset.transport !== 'encrypted' && !acknowledgeNativeTransport) { error.textContent = 'Confirm the native DNS transport before applying this mode.'; error.hidden = false; form.elements.acknowledgeNativeTransport.focus(); return; }
      const button = $('button[type="submit"]', form); button.disabled = true;
      try { await apiSend('PUT', '/dnssec/mode', { mode, acknowledgeNativeTransport }); toast('Validation mode updated'); await router.reload(); }
      catch (err) { error.textContent = err.message; error.hidden = false; button.disabled = false; }
    });
  },
};


pages.assurance = {
  title: 'Assurance',
  subtitle: 'What is checked, by what, and what that does not prove.',
  async render() {
    const settings = await apiGet('/settings').catch(() => ({ version: 'unknown' }));
    // Best-effort: the Assurance page must render even when local DNSSEC
    // observation is off, unreachable, or has never recorded anything.

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
          <a class="btn btn-ghost" href="${REPO}/docs/assurance.md" target="_blank" rel="noopener noreferrer">Engineering assurance</a>
          <a class="btn btn-ghost" href="${REPO}/docs/threat-model.md" target="_blank" rel="noopener noreferrer">Threat model</a>
          <a class="btn btn-ghost" href="${REPO}/docs/security-testing.md" target="_blank" rel="noopener noreferrer">Security testing</a>
        </div>
      </div>

      <div class="card section integration-cta"><div><h2>Daddybound operations</h2><p class="muted">Effective resolution mode, trust-anchor health, local learning and observation limits.</p></div><a class="btn btn-observe" href="#/daddybound">Open Daddybound</a></div>

      <div class="card section">
        <div class="card-head">
          <div>
            <div class="card-eyebrow">Vocabulary</div>
            <h2>How to read this page</h2>
            <p>Four words, used consistently across the product. Each one is a claim of a
               specific strength, and none of them means audited.</p>
          </div>
        </div>
        <dl class="claim-key">
          ${raw(
            ['verified', 'tested', 'experimental', 'unverified']
              .map(
                (tier) => html`<div class="claim-key-row">
                  <dt>${raw(claimChip(tier))}</dt>
                  <dd>${CLAIM_TIERS[tier][2]}</dd>
                </div>`
              )
              .join('')
          )}
        </dl>
        <p class="muted small note-tight">
          None of these words is a substitute for the one claim that cannot be made here:
          no independent professional security review has taken place. That is stated in
          full below.
        </p>
      </div>

      <div class="card section">
        <div class="card-head">
          <div>
            <div class="card-eyebrow">Automated</div>
            <h2>What runs on every change ${raw(claimChip('verified'))}</h2>
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
            <h2>Vulnerability scanning ${raw(claimChip('tested'))}</h2>
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
        <div class="diag-title">Limitations ${raw(claimChip('limitation'))}</div>
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

/* ---------- Recovery and recorded changes ------------------------------- */

function recoveryCard(status) {
  if (!status || !status.available) return html`<div class="card section"><div class="card-head"><h2>Encrypted backup</h2></div>
    ${raw(unavailableState('Backup unavailable', (status && status.error) || 'The server could not report its backup capabilities. Retry before relying on recovery.'))}</div>`;
  return html`<div class="card section"><div class="card-head"><div><div class="card-eyebrow">Recovery</div><h2>Download an encrypted backup</h2>
    <p>Protect the archive with a separate passphrase. Keep both somewhere you can access if this server is lost.</p></div><span class="badge info">Encrypted</span></div>
    <div class="grid grid-2"><div><h3 class="small">Included</h3><ul class="compact-list">${raw((status.included || []).map((item) => html`<li>${item}</li>`).join(''))}</ul></div>
      <div><h3 class="small">Not included</h3><ul class="compact-list">${raw((status.excluded || []).map((item) => html`<li>${item}</li>`).join(''))}</ul></div></div>
    <form id="backup-form" autocomplete="off" class="note-loose">
      <div class="grid grid-2"><label class="field"><span>Backup passphrase</span><input type="password" name="passphrase" autocomplete="new-password" minlength="12" maxlength="1024" required aria-describedby="backup-passphrase-note"></label>
        <label class="field"><span>Confirm passphrase</span><input type="password" name="confirmation" autocomplete="new-password" minlength="12" maxlength="1024" required></label></div>
      <p id="backup-passphrase-note" class="muted small">At least 12 characters. DNS Daddy cannot recover a forgotten backup passphrase.</p>
      <div class="row note-tight"><button class="btn btn-primary" type="submit">Create encrypted backup</button><span id="backup-progress" class="muted small" role="status"></span></div>
      <p id="backup-error" class="form-error" role="alert" hidden></p>
    </form>
    ${raw((status.limitations || []).length ? html`<details class="chart-data"><summary>Backup limitations</summary><ul class="compact-list">${raw(status.limitations.map((item) => html`<li>${item}</li>`).join(''))}</ul></details>` : '')}
  </div>
  <div class="card section"><div class="card-head"><div><h2>Restore into a new directory</h2><p>Restoration runs on the server while DNS Daddy is stopped. A live database is never replaced from this page.</p></div></div>
    <ol class="restore-steps"><li>Copy the encrypted backup and a private file containing its passphrase to the recovery host.</li>
      <li>Run the restore command below, choosing a new destination directory.</li><li>Check the restored configuration, paths and listener addresses, then start DNS Daddy against it and verify DNS resolution.</li></ol>
    ${raw(copyBlock('dnsdaddy restore -input backup.ddbackup -destination restored-dnsdaddy -passphrase-file /private/backup-passphrase.txt'))}
    <p class="muted small note-tight">Existing browser sessions are revoked during restore. Treat the restored directory as sensitive: it contains the keys required to use saved provider credentials.</p>
  </div>`;
}

function changeValue(value) {
  if (value === undefined || value === null) return '—';
  return typeof value === 'string' ? value : JSON.stringify(value, null, 2);
}

function changeHistoryRows(events) {
  if (!events || !events.length) return html`<p class="muted small">No configuration changes have been recorded yet.</p>`;
  const states = { complete: ['ok', 'Completed'], failed: ['bad', 'Failed'], pending: ['info', 'In progress'], incomplete: ['warn', 'Incomplete'] };
  return events.map((event) => {
    const [tone, label] = states[event.status] || ['warn', event.status || 'Unknown'];
    return html`<details class="change-event"><summary><span class="change-summary"><strong>${event.action || 'Configuration change'}</strong>
      <span class="muted small">${event.target || ''}</span></span><time class="small muted" datetime="${event.at}">${new Date(event.at).toLocaleString('en-GB')}</time><span class="badge ${tone}">${label}</span></summary>
      <div class="change-body"><p class="small muted">Actor: ${event.actor || 'unknown'}${event.httpStatus ? ` · response ${event.httpStatus}` : ''}${event.completedAt ? ` · finished ${new Date(event.completedAt).toLocaleString('en-GB')}` : ''}</p>
        ${raw(event.error ? html`<p class="rec-note is-warn">${event.error}</p>` : '')}
        ${raw((event.changes || []).length ? html`<div class="table-wrap"><table><thead><tr><th>Setting</th><th>Before</th><th>After</th></tr></thead><tbody>
          ${raw(event.changes.map((change) => html`<tr><td><strong>${change.field || change.resource}</strong>${raw(change.resource && change.field ? html`<div class="small muted">${change.resource}</div>` : '')}</td>
            <td><pre class="change-value">${change.redacted ? '[redacted]' : changeValue(change.before)}</pre></td><td><pre class="change-value">${change.redacted ? '[redacted]' : changeValue(change.after)}</pre></td></tr>`).join(''))}
        </tbody></table></div>` : html`<p class="muted small">No field differences were recorded for this event.</p>`)}
      </div></details>`;
  }).join('');
}

async function downloadEncryptedBackup(passphrase) {
  const response = await fetch('/api/v1/recovery/backup', {
    method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ passphrase }),
  });
  if (response.status === 401) { showLogin(); throw new ApiError(401, 'Your session ended. Sign in and create the backup again.'); }
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    throw new ApiError(response.status, (body && body.error) || `Backup could not be created (${response.status}).`);
  }
  const blob = await response.blob();
  const disposition = response.headers.get('Content-Disposition') || '';
  const match = disposition.match(/filename="?([a-zA-Z0-9._-]+\.ddbackup)"?/);
  const filename = match ? match[1] : `dnsdaddy-${new Date().toISOString().slice(0, 10)}.ddbackup`;
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a'); link.href = url; link.download = filename;
  document.body.append(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30000);
  return { filename, size: blob.size };
}

pages.recovery = {
  title: 'Recovery & changes',
  subtitle: 'Protect your configuration and understand how it changed.',
  async render(context = {}) {
    const read = (path) => apiGet(path, { signal: context.signal }).catch((error) => {
      if (error.status === 401 || error.name === 'AbortError') throw error;
      return { available: false, error: error.message };
    });
    const [status, history] = await Promise.all([read('/recovery/status'), read('/config/history?limit=50')]);
    if (!context.isCurrent || context.isCurrent()) this.history = history;
    return html`${raw(recoveryCard(status))}<div class="card section" id="change-history">
      <div class="card-head"><div><h2>Configuration history</h2><p>Newest first. Original event details are retained; credentials and secret values are redacted.</p></div></div>
      <div id="change-events">${raw(history.error ? unavailableState('Change history unavailable', history.error) : changeHistoryRows(history.events))}</div>
      <div class="row note-loose"><button type="button" class="btn btn-ghost" id="history-more" ${raw(history.hasMore ? '' : 'hidden')}>Load earlier changes</button><span id="history-result" class="small muted" role="status"></span></div>
      ${raw(history.scope ? html`<p class="muted small">${history.scope}</p>` : '')}
      ${raw(history.consistency ? html`<p class="muted small">${history.consistency}</p>` : '')}
      <p class="muted small note-tight">This is an application history, not a tamper-evident audit log. An incomplete event does not prove a change was applied.</p>
    </div>`;
  },
  async mounted() {
    bindCopyButtons();
    const form = $('#backup-form');
    if (form) form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const error = $('#backup-error'); const progress = $('#backup-progress'); const button = $('button[type="submit"]', form);
      error.hidden = true;
      const passphrase = form.elements.passphrase.value;
      const size = new TextEncoder().encode(passphrase).byteLength;
      if (passphrase !== form.elements.confirmation.value) { error.textContent = 'The passphrases do not match.'; error.hidden = false; form.elements.confirmation.focus(); return; }
      if (size < 12 || size > 1024) { error.textContent = 'Use a passphrase between 12 and 1024 UTF-8 bytes.'; error.hidden = false; return; }
      button.disabled = true; progress.textContent = 'Preparing the encrypted archive…'; form.reset();
      try {
        const backup = await downloadEncryptedBackup(passphrase);
        progress.textContent = `Download started: ${backup.filename} (${num(Math.ceil(backup.size / 1024))} KB). Keep your passphrase separately.`;
      } catch (err) { error.textContent = err.message; error.hidden = false; progress.textContent = ''; }
      finally { button.disabled = false; }
    });
    const button = $('#history-more');
    let cursor = this.history && this.history.nextBeforeId;
    if (button) button.addEventListener('click', async () => {
      if (!cursor) return;
      button.disabled = true; const host = $('#change-events'); const note = $('#history-result'); note.textContent = 'Loading earlier changes…';
      try {
        const data = await apiGet(`/config/history?limit=50&beforeId=${encodeURIComponent(cursor)}`);
        if (!host.isConnected) return;
        host.insertAdjacentHTML('beforeend', sanitize(changeHistoryRows(data.events)));
        cursor = data.nextBeforeId; button.hidden = !data.hasMore; note.textContent = `${num((data.events || []).length)} earlier changes loaded.`;
      } catch (err) { if (note.isConnected) note.textContent = err.message; }
      finally { button.disabled = false; }
    });
  },
};


/* ---------- Availability and DNS rebinding controls ---------------------- */

function protectionCard(data) {
  if (!data || data.error) return html`<div class="card section"><div class="card-head"><h2>Resolver protection</h2></div>
    ${raw(unavailableState('Protection settings unavailable', (data && data.error) || 'Current rate limits and rebinding settings could not be read.'))}</div>`;
  const limit = data.rateLimit || {};
  const rebinding = data.rebinding || {};
  const counters = data.counters || {};
  return html`<div class="card section" id="resolver-protection"><div class="card-head"><div><h2>Resolver protection</h2>
    <p>Bound client demand and reject public names that resolve to private addresses unless you explicitly allow them.</p></div></div>
    <form id="protection-form" data-version="${data.version}">
      <div class="grid grid-2"><div>
        <label class="checkline"><input type="checkbox" name="rateEnabled" ${raw(limit.enabled ? 'checked' : '')}><span><strong>Per-client rate limiting</strong><span class="cat-desc">Each attributed client has a bounded allowance. Excess requests are refused.</span></span></label>
        <div class="grid grid-2 note-tight"><label class="field"><span>Queries per second</span><input name="qps" type="number" min="1" max="100000" step="any" required value="${limit.qps}"></label>
          <label class="field"><span>Allowed burst</span><input name="burst" type="number" min="1" max="1000000" step="1" required value="${limit.burst}"></label></div>
        <details class="provider-scope"><summary>Client state limits</summary><div class="grid grid-2 note-tight">
          <label class="field"><span>Tracked client limit</span><input name="maxClients" type="number" min="1" max="65536" required value="${limit.maxClients}"></label>
          <label class="field"><span>Release idle state after (seconds)</span><input name="idleSeconds" type="number" min="5" max="3600" required value="${limit.idleSeconds}"></label></div>
          <p class="muted small">When tracking is full, new clients share an overflow allowance. Reverse-proxy trust and network tokens determine attribution.</p></details>
      </div><div>
        <label class="checkline"><input type="checkbox" name="rebindingEnabled" ${raw(rebinding.enabled ? 'checked' : '')}><span><strong>DNS rebinding protection</strong><span class="cat-desc">Checks IPv4, IPv6 and alias answers for private or reserved destinations.</span></span></label>
        <label class="field note-tight"><span>Allowed internal domains</span><textarea name="allowDomains" rows="3" placeholder="internal.example">${(rebinding.allowDomains || []).join('\n')}</textarea>
          <span class="small muted">One domain per line. Matches the original question and its subdomains, including legitimate split-DNS names.</span></label>
        <details class="provider-scope"><summary>Address-range exceptions</summary><label class="field note-tight"><span>Allowed destination ranges</span><textarea name="allowCIDRs" rows="3" placeholder="192.168.10.0/24">${(rebinding.allowCIDRs || []).join('\n')}</textarea>
          <span class="small muted">One CIDR per line. Every name resolving into an allowed range can pass this check; keep exceptions narrow.</span></label></details>
      </div></div>
      <div class="row note-loose"><button type="submit" class="btn btn-primary">Save resolver protection</button><span class="muted small">Applies to new queries.</span></div>
      <p class="form-error" id="protection-error" role="alert" hidden></p>
    </form>
    <div class="rec-meta note-loose"><span>${num(counters.rateLimited)} rate-limited requests</span><span>${num(counters.rateOverflow)} requests used the shared overflow allowance</span>
      <span>${num(counters.trackedClients)} clients tracked</span><span>${num(counters.rebindingBlocked)} rebinding blocks</span></div>
  </div>`;
}

function mountProtection() {
  const form = $('#protection-form'); if (!form) return;
  form.addEventListener('submit', async (event) => {
    event.preventDefault(); const error = $('#protection-error'); error.hidden = true;
    const lines = (value) => value.split('\n').map((line) => line.trim()).filter(Boolean);
    const fields = form.elements;
    const body = { version: Number(form.dataset.version),
      rateLimit: { enabled: fields.rateEnabled.checked, qps: Number(fields.qps.value), burst: Number(fields.burst.value), maxClients: Number(fields.maxClients.value), idleSeconds: Number(fields.idleSeconds.value) },
      rebinding: { enabled: fields.rebindingEnabled.checked, allowDomains: lines(fields.allowDomains.value), allowCIDRs: lines(fields.allowCIDRs.value) },
    };
    const button = $('button[type="submit"]', form); button.disabled = true;
    try {
      const result = await apiSend('PUT', '/protection', body);
      if (result && result.version !== undefined) form.dataset.version = String(result.version);
      toast('Resolver protection saved'); await router.reload();
    } catch (err) {
      error.textContent = err.status === 409 ? 'These settings changed elsewhere. Refresh this page, review the current values and save again. Your changes were not applied.' : err.message;
      error.hidden = false; button.disabled = false;
    }
  });
}


pages.settings = {
  title: 'Settings',
  subtitle: 'Runtime configuration and access.',
  async render() {
    const [settings, tokens, protection] = await Promise.all([apiGet('/settings'), apiGet('/tokens'), apiGet('/protection').catch((error) => ({ error: error.message }))]);

    return html`
      <div class="section grid grid-4">
        ${raw(metricCard({ label: 'Version', value: settings.version }))}
        ${raw(metricCard({ label: 'Uptime', value: duration(settings.uptimeSeconds) }))}
        ${raw(metricCard({ label: 'Memory', value: `${Math.round(settings.memoryMb)} MB`, sub: `${settings.goroutines} goroutines` }))}
        <!--
          A hit rate of 0% and a cache nothing has asked about yet are not the
          same reading, and until the API reported the denominator the second
          was displayed as the first. An em dash is what "not measured" looks
          like; it is never rounded up into a number.
        -->
        ${raw(
          metricCard({
            label: 'Cache hit rate',
            value: settings.cacheLookups ? `${settings.cacheHitRate}%` : '—',
            sub: settings.cacheLookups
              ? `${num(settings.cacheEntries)} entries · ${num(settings.cacheLookups)} lookups`
              : 'No lookups yet',
          })
        )}
      </div>

      ${raw(protectionCard(protection))}
      <div class="card section integration-cta"><div><h2>Recovery &amp; changes</h2><p class="muted">Create an encrypted backup and review recorded configuration changes.</p></div><a class="btn btn-observe" href="#/recovery">Open recovery</a></div>
      <div class="card section">
        <div class="card-head">
          <div><h2>Effective configuration</h2>
          <p>Startup settings from this running process. Runtime changes made in the dashboard are recorded in configuration history.</p></div>
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
              <tr><td>Feed refresh interval</td><td>${goDuration(settings.feedRefreshInterval)}</td></tr>
              <tr><td>Upstream mode</td><td>${settings.upstreamMode}</td></tr>
              <tr><td>DNS transport</td><td>${settings.resolutionTransport === 'encrypted' ? 'Encrypted forwarding' : settings.resolutionTransport === 'native' ? 'Native iterative' : 'Not reported'} · <a href="#/daddybound">Manage transport</a></td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <div class="card section">
        <div class="card-head">
          <div>
            <h2>Change admin password</h2>
            <p>Signs every browser out, including this one.</p>
          </div>
        </div>
        <!--
          The consequence is stated before the button rather than discovered
          after it. It is also the reason to use this control: an operator who
          thinks somebody else is logged in wants exactly this, and until
          recently a password change left every existing session working.
        -->
        <p class="notice-inline">
          <strong>Every session is revoked.</strong> Any other device signed in
          to this dashboard is signed out immediately, and so are you — you will
          be asked to sign in again with the new password. This is what makes a
          password change an effective response to a session you did not expect.
        </p>
        <form id="password-form" class="grid grid-3">
          <label class="field"><span>Current password</span>
            <input type="password" name="current" autocomplete="current-password" required></label>
          <label class="field"><span>New password</span>
            <input type="password" name="next" autocomplete="new-password" minlength="12" required
                   aria-describedby="pw-req"></label>
          <label class="field"><span>&nbsp;</span><button class="btn btn-primary" type="submit">Update password and sign out everywhere</button></label>
        </form>
        <p class="muted small" id="pw-req">At least 12 characters. Longer is the only thing that reliably helps.</p>
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
    mountProtection();
    $('#password-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const form = new FormData(e.target);
      try {
        const res = await apiSend('POST', '/auth/password', {
          currentPassword: form.get('current'),
          newPassword: form.get('next'),
        });
        e.target.reset();

        // Changing the password revokes every session, including this one —
        // that is the point of it, and it is what makes the change mean
        // something to somebody who thinks an intruder is logged in. The
        // browser's cookie is already dead, so anything else on this page
        // would fail on its next request with no explanation. Send them to
        // the login screen instead, and say why.
        if (res && res.sessionsRevoked) {
          toast('Password updated. Every session was signed out — sign in again.');
          showLogin();
          return;
        }
        toast('Password updated');
      } catch (err) {
        reportError(err);
      }
    });

    $('#token-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const form = new FormData(e.target);
      try {
        const token = await apiSend('POST', '/tokens', { name: form.get('name') });
        $('#token-secret').innerHTML = sanitize(html`
          <div class="card token-reveal">
            <p class="small reveal-lead"><strong>Copy this now — it is not shown again.</strong></p>
            ${raw(copyBlock(token.secret))}
          </div>
        `);
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

async function copyPlainText(text, environment = {}) {
  const clipboard = environment.clipboard === undefined ? navigator.clipboard : environment.clipboard;
  const secure = environment.secure === undefined ? window.isSecureContext : environment.secure;
  if (secure && clipboard && typeof clipboard.writeText === 'function') {
    await clipboard.writeText(String(text));
    return;
  }
  const doc = environment.document || document;
  const previous = doc.activeElement;
  const field = doc.createElement('textarea');
  field.value = String(text);
  field.className = 'clipboard-buffer';
  field.setAttribute('readonly', '');
  field.setAttribute('aria-hidden', 'true');
  field.setAttribute('tabindex', '-1');
  doc.body.append(field);
  try {
    field.select();
    // A LAN dashboard may be an insecure context. A refused legacy copy must
    // not produce the same success message as a completed clipboard write.
    if (!doc.execCommand('copy')) throw new Error('Clipboard access was refused.');
  } finally {
    field.remove();
    if (previous && typeof previous.focus === 'function') previous.focus({ preventScroll: true });
  }
}

function bindCopyButtons() {
  $$('[data-copy]').forEach((btn) => {
    if (btn.dataset.bound) return;
    btn.dataset.bound = '1';
    btn.addEventListener('click', async () => {
      if (btn.dataset.copying === '1') return;
      const text = btn.dataset.copy;
      const label = btn.textContent;
      btn.dataset.copying = '1';
      btn.setAttribute('aria-busy', 'true');
      try {
        await copyPlainText(text);
        btn.textContent = 'Copied';
        setTimeout(() => { btn.textContent = label; delete btn.dataset.copying; }, 1500);
      } catch {
        delete btn.dataset.copying;
        toast('Could not copy — select the text manually', 'error');
      } finally {
        btn.removeAttribute('aria-busy');
      }
    });
  });
}

/* ---------- router ------------------------------------------------------ */

/**
 * Which page a location hash selects.
 *
 * Pulled out of the router so it can be tested without a window: the routes in
 * the sidebar and the routes the router will actually serve have to be the
 * same set, and the redesign moved every link in that sidebar.
 *
 * Unknown hashes fall back to the dashboard rather than erroring, so an old
 * bookmark lands somewhere useful.
 */
function routeName(hash) {
  const name = String(hash || '').replace(/^#\/?/, '').split('?')[0];
  return pages[name] ? name : 'dashboard';
}

// A route owns the right to paint, not just the name of the page. Two
// requests for different filters can share a route and finish out of order.
function createRenderGate() {
  let generation = 0;
  return {
    begin() {
      const mine = ++generation;
      return () => mine === generation;
    },
    cancel() { generation++; },
  };
}

function isEditableTarget(target) {
  return Boolean(target && target.closest && target.closest(
    'input, textarea, select, [contenteditable]:not([contenteditable="false"]), [role="textbox"]'
  ));
}

function shouldFocusSearch(event) {
  return String(event.key).toLowerCase() === 'k' && Boolean(event.ctrlKey || event.metaKey) &&
    !event.altKey && !event.shiftKey && !event.repeat && !event.defaultPrevented && !isEditableTarget(event.target);
}

function shouldAutoRefresh({ route, paused, hidden, authenticated, busy, interacting }) {
  return Boolean(!paused && !hidden && authenticated && !busy && !interacting &&
    (route === 'dashboard' || route === 'threats'));
}

function pageInteractionActive() {
  const view = $('#view');
  return Boolean($('#sidebar').classList.contains('open') || $('details[open]', view) ||
    (document.activeElement && document.activeElement !== view && view.contains(document.activeElement)) ||
    isEditableTarget(document.activeElement));
}

function mobileNavigation() {
  return window.matchMedia('(max-width: 760px)').matches;
}

function setNavigation(open, { restoreFocus = true } = {}) {
  const sidebar = $('#sidebar');
  const mobile = mobileNavigation();
  const wasOpen = sidebar.classList.contains('open');
  const activeWasInside = sidebar.contains(document.activeElement) || document.activeElement === $('#nav-backdrop');
  open = Boolean(open && mobile);
  sidebar.classList.toggle('open', open);
  sidebar.hidden = mobile && !open;
  sidebar.inert = mobile && !open;
  $('.main').inert = open;
  $('#menu-btn').setAttribute('aria-expanded', String(open));
  $('#menu-btn').setAttribute('aria-label', open ? 'Close navigation' : 'Open navigation');
  const backdrop = $('#nav-backdrop');
  if (backdrop) backdrop.hidden = !open;
  document.body.classList.toggle('nav-is-open', open);
  if (open && !wasOpen) {
    ($('#nav-close') || $('.nav a', sidebar)).focus();
  } else if (wasOpen && !open && restoreFocus && activeWasInside && mobile) {
    $('#menu-btn').focus();
  }
}

const router = {
  current: 'dashboard',
  currentHash: null,
  busy: false,
  gate: createRenderGate(),
  controller: null,

  route() {
    return routeName(window.location.hash);
  },

  invalidate() {
    this.gate.cancel();
    if (this.controller) this.controller.abort();
    this.busy = false;
    $('#refresh-btn').disabled = false;
    $('#view').setAttribute('aria-busy', 'false');
  },

  async navigate({ automatic = false } = {}) {
    if (automatic && (this.busy || pageInteractionActive())) return false;
    const hash = window.location.hash;
    const name = this.route();
    const routeChanged = this.currentHash !== hash;
    const stillLatest = this.gate.begin();
    if (this.controller) this.controller.abort();
    this.controller = new AbortController();
    const context = {
      hash,
      signal: this.controller.signal,
      isCurrent: () => stillLatest() && window.location.hash === hash && !$('#app').hidden,
    };
    this.current = name;
    this.currentHash = hash;
    this.busy = true;
    const page = pages[name];

    $$('.nav a').forEach((a) => {
      const active = a.dataset.route === name;
      a.classList.toggle('active', active);
      if (active) a.setAttribute('aria-current', 'page');
      else a.removeAttribute('aria-current');
    });
    $('#page-title').textContent = page.title;
    $('#page-subtitle').textContent = page.subtitle || '';
    if (name === 'queries') $('#global-search').value = queryFilters(hash).domain;
    document.title = `${page.title} · DNS Daddy`;
    if (!automatic) setNavigation(false, { restoreFocus: false });
    $('#refresh-btn').disabled = true;
    const view = $('#view');
    view.setAttribute('aria-busy', 'true');
    if (routeChanged) {
      view.innerHTML = sanitize(emptyState('Loading…', `Opening ${page.title.toLowerCase()}.`, { icon: '·' }));
    }

    try {
      const markup = await page.render(context);
      if (!context.isCurrent() || (automatic && pageInteractionActive())) return false;
      view.innerHTML = sanitize(markup);
      if (page.mounted) await page.mounted(context);
      if (!context.isCurrent()) return false;
      paintDynamic(view);
      bindCopyButtons();
      $('#refresh-note').textContent = `Updated ${new Date().toLocaleTimeString('en-GB')}`;
      if (routeChanged && !automatic) view.focus({ preventScroll: true });
      return true;
    } catch (err) {
      if (context.isCurrent() && err.name !== 'AbortError' && !(err instanceof ApiError && err.status === 401)) {
        $('#refresh-note').textContent = 'Update unavailable';
        if (!automatic || !pageInteractionActive()) {
          view.innerHTML = sanitize(unavailableState('Could not load this page', err.message || 'The request failed. Try again.'));
        }
        reportError(err);
      }
      return false;
    } finally {
      if (stillLatest()) {
        this.busy = false;
        view.setAttribute('aria-busy', 'false');
        $('#refresh-btn').disabled = false;
      }
    }
  },

  reload(options) {
    return this.navigate(options);
  },
};

/* ---------- auth & bootstrap -------------------------------------------- */

function showLogin() {
  router.invalidate();
  sidebarGate.cancel();
  setNavigation(false, { restoreFocus: false });
  $('#app').hidden = true;
  $('#login').hidden = false;
  $('#password').focus();
}

function showApp() {
  $('#login').hidden = true;
  $('#app').hidden = false;
}

function sidebarStatus(overview) {
  if (!overview) return { tone: 'warn', text: 'Status unavailable', version: '—' };
  const status = {
    protected: ['ok', 'Filtering configured'],
    degraded: ['warn', 'No blocking rules'],
    offline: ['warn', 'No intelligence loaded'],
  }[overview.protectionStatus] || ['warn', 'Status unknown'];
  return { tone: status[0], text: status[1], version: overview.version ? `v${overview.version}` : '—' };
}

const sidebarGate = createRenderGate();

async function refreshSidebarStatus() {
  const stillLatest = sidebarGate.begin();
  let overview = null;
  try {
    overview = await apiGet('/overview');
  } catch {
    // A previous green badge is not evidence of the current state.
  }
  if (!stillLatest() || $('#app').hidden) return;
  const state = sidebarStatus(overview);
  $('#sidebar-status').className = `status-chip ${state.tone}`;
  $('#sidebar-status-text').textContent = state.text;
  $('#sidebar-version').textContent = state.version;
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

  $('#menu-btn').addEventListener('click', () => setNavigation(!$('#sidebar').classList.contains('open')));
  if ($('#nav-close')) $('#nav-close').addEventListener('click', () => setNavigation(false));
  if ($('#nav-backdrop')) $('#nav-backdrop').addEventListener('click', () => setNavigation(false));
  const navMedia = window.matchMedia('(max-width: 760px)');
  navMedia.addEventListener('change', () => setNavigation(false));
  setNavigation(false, { restoreFocus: false });

  const skip = $('.skip-link');
  if (skip) skip.addEventListener('click', (event) => {
    event.preventDefault();
    if ($('#app').hidden) $('#password').focus();
    else {
      setNavigation(false, { restoreFocus: false });
      $('#view').focus();
    }
  });

  document.addEventListener('keydown', (event) => {
    if ($('#app').hidden) return;
    const sidebar = $('#sidebar');
    if (event.key === 'Escape' && sidebar.classList.contains('open')) {
      event.preventDefault();
      setNavigation(false);
      return;
    }
    if (event.key === 'Tab' && sidebar.classList.contains('open') && mobileNavigation()) {
      const targets = $$('a[href], button:not([disabled]), input:not([disabled]), [tabindex="0"]', sidebar)
        .filter((el) => !el.hidden);
      const first = targets[0];
      const last = targets[targets.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }
    if (shouldFocusSearch(event)) {
      event.preventDefault();
      setNavigation(false, { restoreFocus: false });
      $('#global-search').focus();
    }
  });

  // This search is the query log's domain filter. The URL carries it through
  // refresh, browser history and links copied to another signed-in operator.
  $('#search-form').addEventListener('submit', (event) => {
    event.preventDefault();
    const domain = $('#global-search').value.trim();
    if (domain) setQueryFilters({ domain });
  });

  $('#view').addEventListener('click', (event) => {
    const retry = event.target.closest('[data-page-retry]');
    if (!retry) return;
    retry.disabled = true;
    router.reload();
    refreshSidebarStatus();
  });

  window.addEventListener('hashchange', () => router.navigate());

  let updatesPaused = false;
  const pause = $('#auto-refresh-btn');
  if (pause) pause.addEventListener('click', () => {
    updatesPaused = !updatesPaused;
    pause.setAttribute('aria-pressed', String(updatesPaused));
    pause.textContent = updatesPaused ? 'Resume updates' : 'Pause updates';
  });

  // Keep the two live pages fresh without closing explanations or discarding
  // an operator's input. A pause stops automatic reads until explicitly resumed.
  setInterval(() => {
    if (!shouldAutoRefresh({
      route: router.current, paused: updatesPaused, hidden: document.hidden,
      authenticated: !$('#app').hidden, busy: router.busy, interacting: pageInteractionActive(),
    })) return;
    router.reload({ automatic: true });
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
 * Pure rendering functions and the bounded export collector are exported so
 * tests can pin evidence provenance, consent boundaries and completeness.
 */
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    esc,
    ApiError,
    claimRefresh,
    feedStatusBadge,
    threatIntelPanel,
    diagnosticsBanner,
    queryTable,
    queryRow,
    queryFilters,
    queryHash,
    queryFilterForm,
    createQueryLoader,
    createRenderGate,
    shouldAutoRefresh,
    shouldFocusSearch,
    sidebarStatus,
    areaChart,
    feedHealth,
    repeatOffenders,
    firstClientCard,
    accessBadge,
    clientAccessSummary,
    resolverAccessNote,
    emptyState,
    protectionState,
    statusHero,
    blockedSplit,
    measuredFacts,
    investigateFilters,
    investigateHash,
    investigateForm,
    findingLinks,
    activitySection,
    decisionSection,
    previewSection,
    evidenceSection,
    relatedFindingsSection,
    observationsSection,
    reviewBadge,
    reviewForm,
    findingRow,
    findingFilters,
    findingHash,
    findingFilterForm,
    createFindingLoader,
    reviewHistoryList,
    REVIEW_STATES,
    attentionItems,
    attentionPanel,
    recentlyBlocked,
    protectionBreakdown,
    pages,
    routeName,
    goDuration,
    rate,
    claimChip,
    CLAIM_TIERS,
    CATEGORY_COLOURS,
    decisionRow,
    decisionsCard,
    decisionEvidenceRow,
    decisionEvidenceContent,
    investigationLearning,
    findingScore,
    dnssecBadge,
    exportCard,
    readCompleteExport,
    externalAPICard,
    nativeMode,
    nativeModeCard,
    nativeEnforcementCard,
    nativeOverview,
    copyPlainText,
    serverAddressRow,
    serverAddressesCard,
    resolverConnectionGuide,
    DNS_TRANSPORT_PROTOCOLS,
    transportExampleDraft,
    transportExampleCard,
    transportConsentError,
    transportEndpointFields,
    negotiatedTLS,
    encryptedTransportStats,
    transportTestResult,
    dnsTransportCard,
    localLearningCard,
    learningWindows,
    findingConfidence,
    recoveryCard,
    changeHistoryRows,
    protectionCard,
    webhookCard,
    providerCard,
    providerStatusBadge,
    verificationChip,
    credentialLine,
    reputationCard,
    templateFields,
    availableAdaptersCard,
    REPUTATION_MODES,
    localDnssecBadge,
    localDnssecCard,
    daddyboundModes,
    daddyboundStatusCard,
    anchorKeyRows,
    networkRow,
    adHocBadge,
    isDefaultNetwork,
    DEFAULT_NETWORK_ID,
  };
}
