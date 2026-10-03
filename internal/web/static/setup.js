/* Post-install setup. Technical configuration stays behind Advanced; the
 * normal path saves the displayed DNS address and a reviewed client grant. */
'use strict';
(() => {
  const encode = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const options = (rows, selected) => rows.map(r => `<option value="${encode(r.id)}"${r.id === selected ? ' selected' : ''}>${encode(r.name)}</option>`).join('');
  const connections = [
    {id:'lan', name:'At home or work', hint:'Enter the device’s local IP. For a whole network, use a range such as 192.168.1.0/24.'},
    {id:'vps', name:'On a cloud server', hint:'Enter your home or office’s public internet IP — not the cloud server’s IP or a 192.168 address.'},
    {id:'vpn', name:'Through a VPN', hint:'Enter the device’s VPN IP. Your VPN must already be connected.'},
    {id:'roaming', name:'Roaming device (encrypted DNS)', hint:'No client IP is needed. Use the network’s private HTTPS link after saving. HTTPS must already be set up.'},
    {id:'local', name:'Only on the server itself', hint:'Use 127.0.0.1 or ::1. Other devices cannot connect to those addresses.'},
  ];
  function networkWrite(plan, name, policyId, reviewed, publicAck) {
    if (!plan || !reviewed) throw new Error('Review the addresses before allowing access.');
    if (plan.publicAckRequired && !publicAck) throw new Error('Confirm that you intend to allow the displayed public IPs.');
    if (!name.trim() || !policyId) throw new Error('Choose a name and a filtering policy under More options.');
    return {name:name.trim(), policyId, cidrs:plan.cidrs, enabled:true, allowResolver:plan.grantSourceAccess, publicAck:!!publicAck};
  }
  function needsConfirmation(plan, editing) {
    return !!editing || plan.publicAckRequired || plan.addresses.some(a => !a.single) || plan.cidrs.length > 1;
  }
  // This is a suggestion for an explicitly clicked control, not an automatic
  // permission or a claim that the browser and DNS client share a route.
  function connectionSuggestion(value) {
    const ip = String(value || '');
    if (!/^[0-9a-fA-F:.]+$/.test(ip)) return '';
    if (/^(127\.|169\.254\.|0\.|224\.|ff|fe[89ab])/i.test(ip) || ['::','::1','0:0:0:0:0:0:0:1'].includes(ip)) return '';
    if (/^::ffff:/i.test(ip)) return connectionSuggestion(ip.slice(7));
    return ip;
  }
  function suggestedServer(data, addresses) {
    if (data.serverIp || addresses?.runtime !== 'host') return data;
    const candidate = addresses.addresses?.find(a => a.address === addresses.preferredAddress && ['private','public'].includes(a.type));
    const udp = candidate?.dns?.find(e => e.transport === 'udp');
    const tcp = candidate?.dns?.find(e => e.transport === 'tcp');
    if (!udp || !tcp || udp.port !== tcp.port) return data;
    return {...data, serverIp:candidate.address, dnsPort:udp.port, suggested:true};
  }
  function connectionsMarkup(networks) {
    const named = networks.filter(n => n.id !== 'n_default');
    return `<h2>Your connections</h2>${named.length ? named.map(n => `<div class="rec"><div><strong>${encode(n.name)}</strong><p class="small muted">${encode((n.cidrs || []).join(', ') || 'Encrypted link')} · ${!n.enabled ? 'Disabled; other access rules may still apply' : !(n.cidrs || []).length ? 'Link enabled' : n.coverage === 'full' ? 'Allowed to query' : n.coverage === 'partial' ? 'Some addresses allowed' : n.coverage === 'none' ? 'Not allowed yet' : 'Check access status'}</p></div><button type="button" class="btn btn-ghost btn-sm" data-connect-edit="${encode(n.id)}">Edit</button></div>`).join('') : '<p class="small muted">No named connections added yet.</p>'}`;
  }
  function guideMarkup(data, networks, policies) {
    const policy = policies.find(p => p.isDefault) || policies[0];
    return `<section class="card section" id="setup-guide" aria-labelledby="setup-guide-title">
      <div class="card-head"><div><h2 id="setup-guide-title">Connect to DNS Daddy</h2><p>Allow your device, then copy the DNS address into its network settings.</p></div></div>
      <form id="setup-guide-form">
        <div class="field"><label for="setup-preset">Where is DNS Daddy?</label><select id="setup-preset">${options(connections, 'lan')}</select></div>
        <div class="field"><label for="setup-server" id="setup-server-label">DNS server IP</label><input id="setup-server" value="${encode(data.serverIp)}" maxlength="64" autocomplete="off" required${data.addressLocked ? ' readonly' : ''}><p class="small muted" id="setup-server-help">${data.serverIp ? (data.suggested ? 'Detected on this server. Confirm that your device can reach this address.' : 'The saved address is filled in. Connecting also saves any change here.') : 'Enter the server’s LAN, VPN or public IP once. Do not use its Docker-internal IP.'}${data.addressLocked ? ' This address is managed by your installation settings.' : ''}</p></div>
        <div class="field" id="setup-client-field"><label for="setup-clients" id="setup-client-label">Device or network IP</label><input id="setup-clients" autocomplete="off" maxlength="4096" required aria-describedby="setup-client-help"><p id="setup-client-help" class="small muted">${encode(connections[0].hint)}</p>${connectionSuggestion(data.dashboardClientIp) ? `<button type="button" class="btn btn-ghost btn-sm" id="setup-use-connection">Use this connection (${encode(connectionSuggestion(data.dashboardClientIp))})</button>` : ''}</div>
        <p class="small muted">Filtering policy: <strong id="setup-policy-label">${encode(policy?.name || 'Unavailable')}</strong>. Your resolver mode stays unchanged.</p>
        <details id="setup-options"><summary>More options</summary>
          <div class="field"><label for="setup-existing">Update an existing connection</label><select id="setup-existing"><option value="">Create a new connection</option>${options(networks.filter(n => n.id !== 'n_default'), '')}</select></div>
          <div class="field"><label for="setup-name">Name (optional)</label><input id="setup-name" maxlength="100" placeholder="Named automatically"></div>
          <div class="field"><label for="setup-policy">Filtering policy</label><select id="setup-policy">${options(policies, policy?.id)}</select></div>
          <div class="field"><label for="setup-port">DNS port</label><input id="setup-port" type="number" min="1" max="65535" value="${encode(data.dnsPort || 53)}"${data.addressLocked ? ' readonly' : ''}><p class="small muted">Normally 53. This describes the published port; it does not change the server’s listeners.</p></div>
          <p class="small muted">One IP is enough: IPv4 becomes /32 and IPv6 becomes /128 automatically. Separate multiple IPs with commas. A subnet permits its whole range, not one device. Existing permissions remain in place.</p>
        </details>
        <p><button class="btn btn-primary" type="submit" id="setup-connect">Connect</button></p>
      </form>
      <div id="setup-result" aria-live="polite"></div><p id="setup-message" role="status"></p>
    </section>`;
  }
  function previewMarkup(plan, editing) {
    return `<div class="section"><h3>${editing ? 'Replace this connection’s addresses?' : 'Allow these addresses?'}</h3><p>${plan.addresses.map(a => `<code>${encode(a.cidr)}</code>${a.single ? '' : ' (whole subnet)'}`).join(', ') || 'Encrypted network link only.'}</p>
      <p>${editing ? 'This replaces the selected connection’s ranges and enables it. Its private link is kept. ' : ''}Other connections and existing access stay unchanged.</p>
      ${plan.publicAckRequired ? '<p><label><input type="checkbox" id="setup-public-ack"> I control these public IPs and want to allow them. An internet IP may represent every device sharing that connection; restrict the firewall too.</label></p>' : ''}
      <button class="btn btn-primary" type="button" id="setup-apply">Allow connection</button>
      <details><summary>Technical details</summary>${plan.warnings.map(w => `<p class="small muted">${encode(w)}</p>`).join('')}</details></div>`;
  }
  function successMarkup(plan, input, warning) {
    const roaming = input.preset === 'roaming';
    return `<div class="section"><h3>${warning ? 'Saved — needs attention' : 'Access saved'}</h3>
      ${warning ? `<p role="alert">${encode(warning)}</p>` : ''}
      ${roaming ? '<p><a class="btn btn-primary" href="#/setup?advanced=1">Open encrypted connection instructions</a></p><p>Copy this network’s private HTTPS link. Do not share it publicly.</p>' : `<p>Set your device or router’s DNS server to:</p><div class="copy-row"><strong class="mono">${encode(input.serverIp)}</strong><button type="button" class="btn btn-primary btn-sm" id="setup-copy">Copy DNS IP</button></div>${input.dnsPort !== 53 ? `<p>Port ${encode(input.dnsPort)}: your device must support a custom DNS port. Most ordinary DNS settings require port 53.</p>` : ''}<p>Then open a website on that device and check <a href="#/dashboard">Overview</a> for DNS activity. Access is saved; the device’s connection has not been tested yet.</p>`}
      <p><button type="button" class="btn btn-ghost btn-sm" id="setup-another">Add another device or network</button></p><details><summary>Troubleshooting and configuration files</summary><pre>${encode(plan.udpTest)}\n${encode(plan.tcpTest)}</pre><p>These are optional starters for a new installation, not updates to this running server. They use Forward mode, keep the dashboard on loopback, and need a named client grant on the target installation. VPN and HTTPS prerequisites are separate. The port override requires Compose 2.24.4+.</p>${[['environment','Environment file'],['composeOverride','Compose port override'],['nativeYaml','Native YAML']].map(([key,label]) => `<details><summary>${label}</summary><pre>${encode(plan[key])}</pre></details>`).join('')}</details>
    </div>`;
  }
  // Two existing audited operations, not a pretend transaction. Remember each
  // completed step and block blind retries when the network response is lost.
  async function saveConnection(draft, data, state, send) {
    if (state.ambiguous) throw new Error('The previous save could not be confirmed. Refresh and check existing connections before retrying.');
    if (data.addressLocked && draft.plan.endpoint !== data.endpoint) throw new Error('This DNS address is managed by your installation settings.');
    if (!data.addressLocked && draft.plan.endpoint !== data.endpoint) {
      const saved = await send('PUT','/setup/address',{serverIp:draft.input.serverIp,dnsPort:draft.input.dnsPort,previous:data.endpoint});
      data.endpoint = saved.endpoint;
    }
    try {
      const saved = await send(state.target ? 'PATCH' : 'POST', state.target ? '/networks/'+encodeURIComponent(state.target) : '/networks', draft.body);
      const network = saved.network || saved;
      if (!network.id) throw new Error('The server did not return the saved connection.');
      state.target = network.id;
      return {network, warning:saved.warning || ''};
    } catch (error) {
      state.ambiguous = true;
      throw new Error('The network save could not be confirmed. The displayed DNS address may already be saved. Refresh and check existing connections before retrying. '+error.message);
    }
  }
  async function mountGuide(data, networks, context = {}) {
    const root = document.getElementById('setup-guide');
    if (!root) return;
    const el = id => root.querySelector('#'+id);
    const form = el('setup-guide-form');
    const active = () => root.isConnected && !context.signal?.aborted && (!context.isCurrent || context.isCurrent());
    const state = {target:'', ambiguous:false};
    let revision = 0, busy = false;
    const say = text => { if (active()) el('setup-message').textContent = text; };
    const invalidate = () => { revision++; el('setup-result').replaceChildren(); say(''); };
    const input = () => ({preset:el('setup-preset').value,serverIp:el('setup-server').value.trim(),dnsPort:Number(el('setup-port').value),clients:el('setup-clients').value.trim(),mode:'off'});
    const help = () => {
      const kind = el('setup-preset').value;
      el('setup-client-help').textContent = connections.find(c => c.id === kind).hint;
      el('setup-server-label').textContent = kind === 'vps' ? 'Cloud server’s public IP' : kind === 'vpn' ? 'Server’s VPN IP' : 'DNS server IP';
      el('setup-client-label').textContent = kind === 'vps' ? 'Your home or office’s internet IP' : kind === 'vpn' ? 'Device’s VPN IP' : 'Device or network IP';
      el('setup-client-field').hidden = kind === 'roaming';
      el('setup-clients').required = kind !== 'roaming';
      el('setup-clients').disabled = kind === 'roaming';
      if (kind === 'roaming') el('setup-clients').value = '';
      el('setup-policy-label').textContent = el('setup-policy').selectedOptions[0]?.textContent || 'Unavailable';
    };
    const freeze = value => {
      busy = value;
      for (const control of root.querySelectorAll('input,select,button')) control.disabled = value;
      if (!value) { help(); el('setup-connect').disabled = state.ambiguous; }
    };
    form.addEventListener('input', () => { invalidate(); help(); });
    form.addEventListener('change', invalidate);
    el('setup-preset').addEventListener('change', () => {
      if (el('setup-preset').value === 'local') {
        if (!data.addressLocked) { el('setup-server').value='127.0.0.1'; el('setup-port').value='5353'; }
        el('setup-clients').value='127.0.0.1';
      }
      help();
    });
    el('setup-existing').addEventListener('change', () => {
      state.target = el('setup-existing').value;
      const n = networks.find(n => n.id === state.target);
      el('setup-name').value = n?.name || '';
      el('setup-clients').value = (n?.cidrs || []).join(', ');
      if (n) el('setup-policy').value = n.policyId;
      help();
    });
    el('setup-use-connection')?.addEventListener('click', () => {
      invalidate(); el('setup-clients').value = connectionSuggestion(data.dashboardClientIp);
      say('Filled from this dashboard connection. Use it only when your DNS device connects the same way — not through a different proxy, tunnel or VPN.');
    });
    async function apply(plan, values, ticket) {
      if (busy || !active() || ticket !== revision) return;
      let body;
      try { body = networkWrite(plan,el('setup-name').value || 'Connection '+(plan.cidrs[0] || 'roaming'),el('setup-policy').value,true,!!el('setup-public-ack')?.checked); }
      catch (error) { say(error.message); return; }
      freeze(true); say('Saving connection…');
      try {
        const result = await saveConnection({plan,input:values,body},data,state,apiSend);
        if (!active()) return;
        const n = result.network;
        const index = networks.findIndex(item => item.id === n.id);
        if (index >= 0) networks[index] = n;
        else {
          networks.push(n);
          const option = document.createElement('option'); option.value=n.id; option.textContent=n.name;
          el('setup-existing').append(option);
        }
        el('setup-existing').value = n.id;
        el('setup-result').innerHTML = sanitize(successMarkup(plan,values,result.warning));
        form.hidden = true;
        el('setup-another').addEventListener('click', () => {
          state.target=''; el('setup-existing').value=''; el('setup-name').value=''; el('setup-clients').value='';
          form.hidden=false; invalidate(); el('setup-clients').focus();
        });
        el('setup-copy')?.addEventListener('click', async () => {
          try { await copyPlainText(values.serverIp); if (active()) el('setup-copy').textContent='Copied'; }
          catch { say('Copy was unavailable. Select the DNS IP above and copy it.'); }
        });
        say(result.warning || 'DNS address and connection saved.');
        try {
          const current = await apiGet('/networks');
          if (active()) document.getElementById('setup-connections').innerHTML = sanitize(connectionsMarkup(current.networks));
        } catch { /* The successful write remains true; do not invent a live coverage reading. */ }
      } catch (error) { say(error.message); }
      finally { if (active()) freeze(false); }
    }
    form.addEventListener('submit', async event => {
      event.preventDefault(); if (busy || state.ambiguous) return;
      invalidate(); const ticket=revision, values=input(); freeze(true); say('Checking addresses…');
      try {
        const plan=await apiSend('POST','/setup/preview',values);
        if (!active() || ticket !== revision) return;
        freeze(false); say('');
        if (needsConfirmation(plan,state.target)) {
          el('setup-result').innerHTML=sanitize(previewMarkup(plan,!!state.target));
          el('setup-apply').addEventListener('click',()=>apply(plan,values,ticket));
        } else await apply(plan,values,ticket);
      } catch(error) { say(error.message); }
      finally { if (active()) freeze(false); }
    });
    document.getElementById('setup-connections')?.addEventListener('click', event => {
      const edit = event.target.closest('[data-connect-edit]');
      if (!edit || busy || state.ambiguous) return;
      form.hidden = false;
      el('setup-existing').value = edit.dataset.connectEdit;
      el('setup-existing').dispatchEvent(new Event('change', {bubbles:true}));
      el('setup-options').open = true;
      el('setup-clients').focus();
    });
    help();
  }
  function advancedMarkup(original, open = false) {
    return `<details class="card section" id="setup-advanced-tools"${open ? ' open' : ''}><summary>Advanced settings</summary>${original}</details>`;
  }
  function install() {
    for (const route of ['setup','networks']) {
      const previous=pages[route];
      pages[route]={...previous,
        async render(context) {
          const original=await previous.render.call(this,context);
          try {
            const [settings,ns,ps,addresses]=await Promise.all([apiGet('/setup'),apiGet('/networks'),apiGet('/policies'),apiGet('/server-addresses').catch(() => null)]);
            const data = suggestedServer(settings,addresses);
            this.setupGuide={data,networks:ns.networks || []};
            return guideMarkup(data,ns.networks || [],ps.policies || [])+'<section class="card section" id="setup-connections">'+connectionsMarkup(ns.networks || [])+'</section>'+advancedMarkup(original, context?.hash?.includes('advanced=1'));
          } catch(error) {
            this.setupGuide=null;
            return '<section class="card section"><h2>Connection setup unavailable</h2><p>'+encode(error.message)+'</p></section>'+original;
          }
        },
        async mounted(context) {
          if (previous.mounted) await previous.mounted.call(this,context);
          if (this.setupGuide) await mountGuide(this.setupGuide.data,this.setupGuide.networks,context);
        }
      };
    }
  }
  if (typeof pages !== 'undefined' && typeof document !== 'undefined') install();
  if (typeof module !== 'undefined' && module.exports) module.exports={guideMarkup,previewMarkup,networkWrite,needsConfirmation,connectionSuggestion,saveConnection,successMarkup,advancedMarkup,suggestedServer,connectionsMarkup};
})();
