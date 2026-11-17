/*
 * DNS Security Map — investigation workspace.
 *
 * Concatenated after app.js / setup.js (see embed.go) so pages["security-map"]
 * registers in the same script task before the first render. Dependency-free
 * SVG; labels go through mapHtml``/mapEsc.
 */
'use strict';

// Prefer the dashboard html``/esc/raw when concatenated; fall back for Node
// unit tests that require this file alone.
function mapEsc(value) {
  if (typeof esc === 'function') return esc(value);
  if (value === null || value === undefined) return '';
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
function mapRaw(value) {
  if (typeof raw === 'function') return raw(value);
  return { __raw: true, value };
}
function mapHtml(strings, ...values) {
  if (typeof html === 'function') return html(strings, ...values);
  return strings.reduce((out, str, i) => {
    if (i === 0) return str;
    const v = values[i - 1];
    const rendered = v && v.__raw ? v.value : mapEsc(v);
    return out + rendered + str;
  }, '');
}


const MAP_WINDOWS = [
  { id: '15m', label: '15 minutes', param: 'window=15m' },
  { id: '1', label: '1 hour', param: 'hours=1' },
  { id: '24', label: '24 hours', param: 'hours=24' },
];

function mapFilters(hash) {
  const q = new URLSearchParams((hash || '').split('?')[1] || '');
  const windowId = q.get('window') || q.get('hours') || '1';
  return {
    window: ['15m', '1', '24'].includes(windowId) ? windowId : '1',
    networkId: q.get('networkId') || '',
    action: ['', 'allowed', 'blocked', 'error'].includes(q.get('action') || '') ? (q.get('action') || '') : '',
    search: q.get('search') || '',
    focus: q.get('focus') || '',
    view: q.get('view') === 'table' ? 'table' : 'map',
  };
}

function mapHash(filters) {
  const q = new URLSearchParams();
  if (filters.window === '15m') q.set('window', '15m');
  else if (filters.window && filters.window !== '1') q.set('hours', filters.window);
  else q.set('hours', '1');
  if (filters.networkId) q.set('networkId', filters.networkId);
  if (filters.action) q.set('action', filters.action);
  if (filters.search) q.set('search', filters.search);
  if (filters.focus) q.set('focus', filters.focus);
  if (filters.view === 'table') q.set('view', 'table');
  const s = q.toString();
  return `#/security-map${s ? `?${s}` : ''}`;
}

function mapQuery(filters) {
  const parts = [];
  if (filters.window === '15m') parts.push('window=15m');
  else parts.push(`hours=${encodeURIComponent(filters.window || '1')}`);
  if (filters.networkId) parts.push(`networkId=${encodeURIComponent(filters.networkId)}`);
  if (filters.action) parts.push(`action=${encodeURIComponent(filters.action)}`);
  if (filters.search) parts.push(`search=${encodeURIComponent(filters.search)}`);
  return parts.join('&');
}

function outcomeTone(node) {
  const blocked = node.blocked || 0;
  const errors = node.errors || 0;
  const allowed = node.allowed || 0;
  if (blocked && !allowed && !errors) return 'blocked';
  if (errors && !blocked && !allowed) return 'error';
  if (blocked || errors) return 'mixed';
  return 'allowed';
}

function toneLabel(tone) {
  return ({
    allowed: 'Allowed only',
    blocked: 'Policy blocked',
    error: 'Resolution failures',
    mixed: 'Mixed outcomes',
  })[tone] || tone;
}

function findNode(data, id) {
  if (!data || !id) return null;
  for (const c of data.clients || []) if (c.id === id) return { kind: 'client', node: c };
  for (const d of data.domains || []) if (d.id === id) return { kind: 'domain', node: d };
  for (const n of data.networks || []) if (`network:${n.id}` === id) return { kind: 'network', node: n };
  return null;
}

function mapToolbar(filters, networks, data) {
  const netOpts = (networks || []).map((n) =>
    mapHtml`<option value="${n.id}" ${filters.networkId === n.id ? 'selected' : ''}>${n.name}</option>`
  ).join('');
  const winOpts = MAP_WINDOWS.map((w) =>
    mapHtml`<option value="${w.id}" ${filters.window === w.id ? 'selected' : ''}>${w.label}</option>`
  ).join('');
  const trunc = data && data.limits && (data.limits.truncatedClients || data.limits.truncatedDomains || data.limits.truncatedEdges || data.limits.truncatedSource);
  return mapHtml`
    <form class="map-toolbar card section" id="map-filters" method="get">
      <div class="map-toolbar-grid">
        <label>Time window
          <select name="window" id="map-window">${mapRaw(winOpts)}</select>
        </label>
        <label>Network
          <select name="networkId" id="map-network">
            <option value="">All networks in window</option>
            ${mapRaw(netOpts)}
          </select>
        </label>
        <label>Outcome
          <select name="action" id="map-action">
            <option value="" ${!filters.action ? 'selected' : ''}>All outcomes</option>
            <option value="allowed" ${filters.action === 'allowed' ? 'selected' : ''}>Allowed</option>
            <option value="blocked" ${filters.action === 'blocked' ? 'selected' : ''}>Policy blocked</option>
            <option value="error" ${filters.action === 'error' ? 'selected' : ''}>Resolution failure</option>
          </select>
        </label>
        <label class="map-search">Search displayed dataset
          <input type="search" name="search" id="map-search" value="${filters.search}"
            placeholder="Client, name or domain in this map" autocomplete="off" />
        </label>
      </div>
      <div class="row map-toolbar-actions">
        <button type="submit" class="btn btn-observe btn-sm">Apply</button>
        <a class="btn btn-ghost btn-sm" href="${mapHash({ window: filters.window, view: filters.view })}">Clear filters</a>
        <button type="button" class="btn btn-ghost btn-sm" id="map-view-toggle"
          aria-pressed="${filters.view === 'table' ? 'true' : 'false'}">${filters.view === 'table' ? 'Show map' : 'Show table'}</button>
        <button type="button" class="btn btn-ghost btn-sm" id="map-refresh">Refresh</button>
      </div>
      <p class="muted small map-disclaimer">Edges mean DNS queries recorded in this window — not visits, downloads or connections.
        ${mapRaw(trunc ? mapHtml`<strong>Partial dataset:</strong> display or source limits applied; counts describe this subset.` : '')}
      </p>
    </form>`;
}

function detailsPanel(sel, data) {
  if (!sel) {
    return mapHtml`<aside class="map-details card" aria-live="polite">
      <div class="card-head"><div><h2>Details</h2><p>Select a client, domain or relationship.</p></div></div>
      <p class="muted small">Client IPs are observed addresses, not authenticated devices. Network groups use the networkId recorded on each query.</p>
    </aside>`;
  }
  if (sel.kind === 'client') {
    const c = sel.node;
    const tone = outcomeTone(c);
    const findings = (data.findings || []).filter((f) => f.clientId === c.id);
    return mapHtml`<aside class="map-details card" aria-live="polite">
      <div class="card-head"><div><div class="card-eyebrow">Observed client</div>
        <h2>${c.clientName || c.clientIp}</h2>
        <p class="mono small">${c.clientIp}${c.clientName ? mapHtml` · recorded name` : ''}</p></div>
        <span class="badge ${tone === 'blocked' ? 'bad' : tone === 'error' ? 'warn' : tone === 'mixed' ? 'warn' : ''}">${toneLabel(tone)}</span>
      </div>
      <dl class="qfact-grid">
        <div class="qfact"><dt>Network (recorded)</dt><dd>${c.networkId || '—'}</dd></div>
        <div class="qfact"><dt>Queries in window</dt><dd>${num(c.queries)}</dd></div>
        <div class="qfact"><dt>Allowed / blocked / errors</dt><dd>${num(c.allowed)} / ${num(c.blocked)} / ${num(c.errors)}</dd></div>
        <div class="qfact"><dt>Distinct names</dt><dd>${num(c.distinctDomains)}</dd></div>
        <div class="qfact"><dt>First / last in window</dt><dd>${relTime(c.firstSeen)} · ${relTime(c.lastSeen)}</dd></div>
      </dl>
      <div class="row note-tight">
        <a class="btn btn-observe btn-sm" href="${investigateHash({ client: c.clientIp, hours: data.requestedHours || '1' })}">Investigate client</a>
        <a class="btn btn-ghost btn-sm" href="${typeof queryHash === 'function' ? queryHash({ clientIp: c.clientIp, hours: data.requestedHours || '1' }) : `#/queries?clientIp=${encodeURIComponent(c.clientIp)}&hours=${encodeURIComponent(data.requestedHours || '1')}`}">Query log</a>
      </div>
      ${mapRaw(findings.length ? mapHtml`<h3 class="map-subhead">Related findings <span class="badge">experimental</span></h3>
        <ul class="map-finding-list">${mapRaw(findings.map((f) => mapHtml`<li><a href="#/detections?id=${encodeURIComponent(f.id)}">${f.title}</a>
          <span class="muted small">${f.severity} · ${f.eventType}</span></li>`).join(''))}</ul>` : mapHtml`<p class="muted small">No findings linked to this client in the loaded set.</p>`)}
    </aside>`;
  }
  if (sel.kind === 'domain') {
    const d = sel.node;
    const tone = outcomeTone(d);
    const findings = (data.findings || []).filter((f) => f.domainId === d.id);
    return mapHtml`<aside class="map-details card" aria-live="polite">
      <div class="card-head"><div><div class="card-eyebrow">Queried name</div>
        <h2 class="mono">${d.domain}</h2>
        <p class="muted small">Exact name as recorded — not a registrable-domain rollup.</p></div>
        <span class="badge ${tone === 'blocked' ? 'bad' : tone === 'error' ? 'warn' : tone === 'mixed' ? 'warn' : ''}">${toneLabel(tone)}</span>
      </div>
      <dl class="qfact-grid">
        <div class="qfact"><dt>Queries in window</dt><dd>${num(d.queries)}</dd></div>
        <div class="qfact"><dt>Allowed / blocked / errors</dt><dd>${num(d.allowed)} / ${num(d.blocked)} / ${num(d.errors)}</dd></div>
        <div class="qfact"><dt>Distinct clients</dt><dd>${num(d.distinctClients)}</dd></div>
        <div class="qfact"><dt>Block category</dt><dd>${d.category || '—'}</dd></div>
        <div class="qfact"><dt>First / last in window</dt><dd>${relTime(d.firstSeen)} · ${relTime(d.lastSeen)}</dd></div>
      </dl>
      <div class="row note-tight">
        <a class="btn btn-observe btn-sm" href="${investigateHash({ domain: d.domain, hours: data.requestedHours || '1' })}">Investigate domain</a>
        <a class="btn btn-ghost btn-sm" href="${typeof queryHash === 'function' ? queryHash({ domain: d.domain, hours: data.requestedHours || '1' }) : `#/queries?domain=${encodeURIComponent(d.domain)}&hours=${encodeURIComponent(data.requestedHours || '1')}`}">Query log</a>
      </div>
      ${mapRaw(findings.length ? mapHtml`<h3 class="map-subhead">Related findings <span class="badge">experimental</span></h3>
        <ul class="map-finding-list">${mapRaw(findings.map((f) => mapHtml`<li><a href="#/detections?id=${encodeURIComponent(f.id)}">${f.title}</a>
          <span class="muted small">${f.severity}</span></li>`).join(''))}</ul>` : '')}
      <p class="muted small">Secure DNSSEC (when present elsewhere) does not mean this name is harmless. A policy block is not a DNSSEC failure.</p>
    </aside>`;
  }
  if (sel.kind === 'network') {
    const n = sel.node;
    return mapHtml`<aside class="map-details card" aria-live="polite">
      <div class="card-head"><div><div class="card-eyebrow">Configured network</div>
        <h2>${n.name}</h2><p class="mono small">${n.id}</p></div></div>
      <dl class="qfact-grid">
        <div class="qfact"><dt>Clients in window</dt><dd>${num(n.clientsInWindow)}</dd></div>
        <div class="qfact"><dt>Queries / blocked / errors</dt><dd>${num(n.queries)} / ${num(n.blocked)} / ${num(n.errors)}</dd></div>
        <div class="qfact"><dt>CIDRs</dt><dd class="mono small">${(n.cidrs || []).join(', ') || '—'}</dd></div>
      </dl>
      <a class="btn btn-ghost btn-sm" href="#/networks">Open Networks configuration</a>
    </aside>`;
  }
  return '';
}

function layoutGraph(data, focusId) {
  const width = 960;
  const height = 560;
  const leftX = 200;
  const rightX = 760;
  const networks = data.networks || [];
  const clients = data.clients || [];
  const domains = data.domains || [];
  const edges = data.edges || [];

  const clientsByNet = new Map();
  for (const c of clients) {
    const list = clientsByNet.get(c.networkId) || [];
    list.push(c);
    clientsByNet.set(c.networkId, list);
  }

  const positions = new Map();
  let y = 48;
  for (const net of networks) {
    positions.set(`network:${net.id}`, { x: 48, y, kind: 'network' });
    const group = clientsByNet.get(net.id) || [];
    let cy = y;
    for (const c of group) {
      positions.set(c.id, { x: leftX, y: cy, kind: 'client' });
      cy += 44;
    }
    y = Math.max(y + 56, cy + 12);
  }
  // Clients whose network container was omitted.
  for (const c of clients) {
    if (!positions.has(c.id)) {
      positions.set(c.id, { x: leftX, y, kind: 'client' });
      y += 44;
    }
  }
  let dy = 48;
  for (const d of domains) {
    positions.set(d.id, { x: rightX, y: dy, kind: 'domain' });
    dy += 44;
  }
  const contentH = Math.max(height, y, dy) + 40;

  const edgePaths = edges.map((e) => {
    const a = positions.get(e.clientId);
    const b = positions.get(e.domainId);
    if (!a || !b) return '';
    const mid = (a.x + b.x) / 2;
    const tone = outcomeTone(e);
    const dim = focusId && focusId !== e.clientId && focusId !== e.domainId;
    return mapHtml`<path class="map-edge map-edge-${tone}${dim ? ' is-dim' : ''}"
      d="M ${a.x + 56} ${a.y} C ${mid} ${a.y}, ${mid} ${b.y}, ${b.x - 56} ${b.y}"
      data-edge-id="${e.id}" data-client-id="${e.clientId}" data-domain-id="${e.domainId}" />`;
  }).join('');

  const netNodes = networks.map((n) => {
    const p = positions.get(`network:${n.id}`);
    if (!p) return '';
    return mapHtml`<g class="map-node map-node-network" transform="translate(${p.x},${p.y})" data-node-id="network:${n.id}" tabindex="0" role="button" aria-label="Network ${n.name}">
      <rect x="-36" y="-16" width="72" height="32" rx="6" />
      <text text-anchor="middle" dy="4" class="map-label">${n.name}</text>
    </g>`;
  }).join('');

  const clientNodes = clients.map((c) => {
    const p = positions.get(c.id);
    if (!p) return '';
    const tone = outcomeTone(c);
    const label = c.clientName || c.clientIp;
    const dim = focusId && focusId !== c.id && !(data.edges || []).some((e) => e.clientId === c.id && e.domainId === focusId);
    const focused = focusId === c.id;
    return mapHtml`<g class="map-node map-node-client map-tone-${tone}${dim ? ' is-dim' : ''}${focused ? ' is-focus' : ''}"
      transform="translate(${p.x},${p.y})" data-node-id="${c.id}" tabindex="0" role="button"
      aria-label="Client ${label}">
      <circle r="14" />
      <text x="22" dy="4" class="map-label">${label}</text>
    </g>`;
  }).join('');

  const domainNodes = domains.map((d) => {
    const p = positions.get(d.id);
    if (!p) return '';
    const tone = outcomeTone(d);
    const dim = focusId && focusId !== d.id && !(data.edges || []).some((e) => e.domainId === d.id && e.clientId === focusId);
    const focused = focusId === d.id;
    return mapHtml`<g class="map-node map-node-domain map-tone-${tone}${dim ? ' is-dim' : ''}${focused ? ' is-focus' : ''}"
      transform="translate(${p.x},${p.y})" data-node-id="${d.id}" tabindex="0" role="button"
      aria-label="Domain ${d.domain}">
      <rect x="-52" y="-14" width="104" height="28" rx="6" />
      <text text-anchor="middle" dy="4" class="map-label mono">${d.domain}</text>
    </g>`;
  }).join('');

  return { width, height: contentH, edgePaths, netNodes, clientNodes, domainNodes };
}

function renderSVG(data, focusId, transform) {
  const L = layoutGraph(data, focusId);
  const t = transform || { x: 0, y: 0, k: 1 };
  return mapHtml`
    <div class="map-canvas-wrap">
      <div class="map-zoom-controls" role="group" aria-label="Map zoom">
        <button type="button" class="btn btn-ghost btn-sm" id="map-zoom-in" title="Zoom in">+</button>
        <button type="button" class="btn btn-ghost btn-sm" id="map-zoom-out" title="Zoom out">−</button>
        <button type="button" class="btn btn-ghost btn-sm" id="map-zoom-reset" title="Reset view">Reset</button>
        <button type="button" class="btn btn-ghost btn-sm" id="map-zoom-fit" title="Fit">Fit</button>
      </div>
      <svg class="map-canvas" id="map-canvas" viewBox="0 0 ${L.width} ${L.height}" role="img"
        aria-label="DNS security relationship map">
        <g id="map-viewport" transform="translate(${t.x},${t.y}) scale(${t.k})">
          <text x="200" y="20" class="map-column-label">Clients by network</text>
          <text x="760" y="20" class="map-column-label" text-anchor="middle">Queried names</text>
          ${mapRaw(L.edgePaths)}
          ${mapRaw(L.netNodes)}
          ${mapRaw(L.clientNodes)}
          ${mapRaw(L.domainNodes)}
        </g>
      </svg>
      <p class="muted small map-legend">
        <span class="map-swatch map-tone-allowed"></span> Allowed
        <span class="map-swatch map-tone-blocked"></span> Policy blocked
        <span class="map-swatch map-tone-error"></span> Failure
        <span class="map-swatch map-tone-mixed"></span> Mixed
      </p>
    </div>`;
}

function renderTable(data) {
  const rows = (data.edges || []).map((e) => {
    const client = (data.clients || []).find((c) => c.id === e.clientId);
    const domain = (data.domains || []).find((d) => d.id === e.domainId);
    return mapHtml`<tr data-edge-id="${e.id}">
      <td>${client ? (client.clientName || client.clientIp) : e.clientId}</td>
      <td class="mono">${client ? client.networkId : ''}</td>
      <td class="mono">${domain ? domain.domain : e.domainId}</td>
      <td class="num">${num(e.queries)}</td>
      <td class="num">${num(e.allowed)}</td>
      <td class="num">${num(e.blocked)}</td>
      <td class="num">${num(e.errors)}</td>
      <td>
        ${mapRaw(client ? mapHtml`<a class="btn btn-ghost btn-sm" href="${investigateHash({ client: client.clientIp })}">Client</a>` : '')}
        ${mapRaw(domain ? mapHtml`<a class="btn btn-ghost btn-sm" href="${investigateHash({ domain: domain.domain })}">Domain</a>` : '')}
      </td>
    </tr>`;
  }).join('');
  return mapHtml`<div class="card section map-table-card">
    <div class="card-head"><div><h2>Relationship table</h2>
      <p>Same dataset as the map. Accessible alternative to graph gestures.</p></div></div>
    <div class="table-wrap"><table class="map-table">
      <thead><tr><th>Client</th><th>Network</th><th>Domain</th><th>Queries</th><th>Allowed</th><th>Blocked</th><th>Errors</th><th></th></tr></thead>
      <tbody>${mapRaw(rows || mapHtml`<tr><td colspan="8" class="muted">No query relationships in this window.</td></tr>`)}</tbody>
    </table></div>
  </div>`;
}

function limitationsCard(data) {
  const items = (data.limitations || []).map((l) => mapHtml`<li>${l}</li>`).join('');
  return mapHtml`<div class="card section map-limits">
    <div class="card-head"><div><h2>What this map knows</h2>
      <p>Generated ${relTime(data.generatedAt)} · window ${relTime(data.effectiveFrom)} → ${relTime(data.effectiveTo)}</p></div></div>
    <ul class="map-limit-list">${mapRaw(items)}</ul>
    ${mapRaw(data.resolverStatus ? mapHtml`<p class="muted small"><strong>Resolver status:</strong> ${data.resolverStatus.note}${data.resolverStatus.mode ? mapHtml` (mode: ${data.resolverStatus.mode})` : ''}</p>` : '')}
  </div>`;
}

const securityMapPage = {
  title: 'DNS Security Map',
  subtitle: 'Which clients queried which names — from retained DNS evidence only.',
  _viewport: { x: 0, y: 0, k: 1 },
  clearSensitive() {
    this._viewport = { x: 0, y: 0, k: 1 };
  },
  async render(context = {}) {
    const hash = context.hash === undefined ? window.location.hash : context.hash;
    const filters = mapFilters(hash);
    const read = (path) => apiGet(path, { signal: context.signal });

    let networksPayload = { networks: [] };
    try {
      networksPayload = await read('/networks');
    } catch (err) {
      if (err.status === 401 || err.name === 'AbortError') throw err;
    }

    let data;
    try {
      data = await read(`/network-map?${mapQuery(filters)}`);
    } catch (err) {
      if (err.status === 401 || err.name === 'AbortError') throw err;
      return mapHtml`${mapRaw(mapToolbar(filters, networksPayload.networks || [], null))}
        ${mapRaw(unavailableState('DNS Security Map unavailable', err.message || 'The request failed.'))}`;
    }

    // Preserve requested hours for investigate links.
    if (!data.requestedHours && filters.window !== '15m') data.requestedHours = Number(filters.window) || 1;

    if (!data.available) {
      return mapHtml`${mapRaw(mapToolbar(filters, networksPayload.networks || [], data))}
        ${mapRaw(emptyState('Map limited by privacy or logging settings', data.unavailable || 'Per-query relationships are not available.', { icon: '○' }))}
        ${mapRaw(limitationsCard(data))}`;
    }

    const sel = findNode(data, filters.focus);
    const body = filters.view === 'table'
      ? renderTable(data)
      : renderSVG(data, filters.focus, this._viewport);

    const emptyGraph = !(data.clients || []).length && !(data.domains || []).length;
    return mapHtml`
      ${mapRaw(mapToolbar(filters, networksPayload.networks || [], data))}
      ${mapRaw(emptyGraph
        ? emptyState('No attributed DNS activity in this window', 'Widen the time window, choose another network, or confirm clients are resolving through DNS Daddy with query logging and client addresses enabled.', { icon: '◇' })
        : mapHtml`<div class="map-workspace">
            <div class="map-main">${mapRaw(body)}</div>
            ${mapRaw(detailsPanel(sel, data))}
          </div>`)}
      ${mapRaw(limitationsCard(data))}
    `;
  },
  mounted(context = {}) {
    const root = typeof $ === 'function' ? $('#view') : null;
    if (!root || !root.querySelector) return;
    const filters = mapFilters(context.hash === undefined ? window.location.hash : context.hash);
    const form = root.querySelector('#map-filters');
    if (form) {
      form.addEventListener('submit', (ev) => {
        ev.preventDefault();
        const fd = new FormData(form);
        window.location.hash = mapHash({
          window: fd.get('window') || '1',
          networkId: fd.get('networkId') || '',
          action: fd.get('action') || '',
          search: fd.get('search') || '',
          focus: filters.focus,
          view: filters.view,
        });
      });
    }
    const toggle = root.querySelector('#map-view-toggle');
    if (toggle) {
      toggle.addEventListener('click', () => {
        window.location.hash = mapHash({ ...filters, view: filters.view === 'table' ? 'map' : 'table' });
      });
    }
    const refresh = root.querySelector('#map-refresh');
    if (refresh) {
      refresh.addEventListener('click', () => {
        if (typeof router !== 'undefined' && router && router.reload) router.reload();
        else window.dispatchEvent(new HashChangeEvent('hashchange'));
      });
    }

    const state = this._viewport || { x: 0, y: 0, k: 1 };
    this._viewport = state;
    const viewport = root.querySelector('#map-viewport');
    const canvas = root.querySelector('#map-canvas');
    const applyTransform = () => {
      if (viewport) viewport.setAttribute('transform', `translate(${state.x},${state.y}) scale(${state.k})`);
    };
    applyTransform();
    const zoom = (factor, cx, cy) => {
      const prev = state.k;
      state.k = Math.min(2.5, Math.max(0.4, state.k * factor));
      if (cx != null) {
        state.x = cx - (cx - state.x) * (state.k / prev);
        state.y = cy - (cy - state.y) * (state.k / prev);
      }
      applyTransform();
    };
    const zoomIn = root.querySelector('#map-zoom-in');
    const zoomOut = root.querySelector('#map-zoom-out');
    const zoomReset = root.querySelector('#map-zoom-reset');
    const zoomFit = root.querySelector('#map-zoom-fit');
    if (zoomIn) zoomIn.addEventListener('click', () => zoom(1.2));
    if (zoomOut) zoomOut.addEventListener('click', () => zoom(1 / 1.2));
    if (zoomReset) zoomReset.addEventListener('click', () => {
      state.x = 0; state.y = 0; state.k = 1; applyTransform();
    });
    if (zoomFit) zoomFit.addEventListener('click', () => {
      state.x = 0; state.y = 0; state.k = 1; applyTransform();
    });

    if (canvas) {
      let dragging = false;
      let lastX = 0;
      let lastY = 0;
      canvas.addEventListener('pointerdown', (ev) => {
        if (ev.target.closest && ev.target.closest('.map-node')) return;
        dragging = true;
        lastX = ev.clientX;
        lastY = ev.clientY;
        if (canvas.setPointerCapture) canvas.setPointerCapture(ev.pointerId);
      });
      canvas.addEventListener('pointermove', (ev) => {
        if (!dragging) return;
        state.x += ev.clientX - lastX;
        state.y += ev.clientY - lastY;
        lastX = ev.clientX;
        lastY = ev.clientY;
        applyTransform();
      });
      canvas.addEventListener('pointerup', () => { dragging = false; });
      canvas.addEventListener('wheel', (ev) => {
        ev.preventDefault();
        const rect = canvas.getBoundingClientRect();
        zoom(ev.deltaY < 0 ? 1.1 : 1 / 1.1, ev.clientX - rect.left, ev.clientY - rect.top);
      }, { passive: false });
    }

    const selectNode = (id) => {
      window.location.hash = mapHash({ ...filters, focus: id });
    };
    root.querySelectorAll('.map-node').forEach((node) => {
      const activate = (ev) => {
        ev.preventDefault();
        selectNode(node.getAttribute('data-node-id'));
      };
      node.addEventListener('click', activate);
      node.addEventListener('keydown', (ev) => {
        if (ev.key === 'Enter' || ev.key === ' ') activate(ev);
      });
    });
  },
};

if (typeof pages !== 'undefined') {
  pages['security-map'] = securityMapPage;
}

if (typeof module !== 'undefined' && module.exports) {
  Object.assign(module.exports, {
    mapFilters,
    mapHash,
    outcomeTone,
    layoutGraph,
    mapQuery,
    securityMapPage,
    findNode,
    detailsPanel,
    renderTable,
    renderSVG,
    mapToolbar,
  });
}
