/* Guided setup is a separate dashboard extension; no framework or build step.
 * It uses the existing authenticated API and network-write safety checks. */
'use strict';
(() => {
  const encode = (s) => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const options = (rows, value, label, selected = '') => rows.map(r => `<option value="${encode(r[value])}"${r[value] === selected ? ' selected' : ''}>${encode(r[label])}</option>`).join('');
  function networkWrite(plan, name, policyId, reviewed, publicAck) {
    if (!plan || !reviewed) throw new Error('Preview and review the source addresses before applying access.');
    if (plan.publicAckRequired && !publicAck) throw new Error('Confirm the displayed public client ranges before granting access.');
    if (!name.trim() || !policyId) throw new Error('Choose a network name and policy.');
    return {name: name.trim(), policyId, cidrs: plan.cidrs, enabled: true, allowResolver: plan.grantSourceAccess, publicAck: !!publicAck};
  }
  function guideMarkup(data, networks, policies) {
    const editable = networks.filter(n => n.id !== 'n_default');
    const preferredPolicy = policies.find(p => p.isDefault) || policies[0];
    return `<section class="card section" id="setup-guide" aria-labelledby="setup-guide-title">
      <div class="card-head"><div><div class="card-eyebrow">Start here</div><h2 id="setup-guide-title">Connect a device or network</h2><p>Choose where your clients connect from. Preview first; apply only the access you intend.</p></div></div>
      <p><strong>Server address = where queries go. Client addresses = who may send them.</strong> The dashboard URL and Docker-internal IP are not automatically either of these.</p>
      <form id="setup-guide-form">
        <div class="field"><label for="setup-preset">Connection preset</label><select id="setup-preset">${options(data.presets, 'id', 'name')}</select></div>
        <div class="grid grid-2">
          <div class="field"><label for="setup-server">Client-facing DNS server IP</label><input id="setup-server" value="${encode(data.serverIp)}" maxlength="64" autocomplete="off" required><p id="setup-server-help" class="small muted"></p></div>
          <div class="field"><label for="setup-port">Published DNS port</label><input id="setup-port" type="number" min="1" max="65535" value="${encode(data.dnsPort || 53)}" required><p class="small muted">Normally 53. Docker's internal 5353 is not necessarily the published port.</p></div>
        </div>
        <p class="small muted">${data.addressLocked ? 'Display address is controlled by DNSDADDY_ADVERTISED_DNS / YAML. Remove that setting and restart to edit it here.' : 'Save this address to correct the Overview card. This does not alter ports or grant access.'}</p>
        <button type="button" class="btn btn-ghost btn-sm" id="setup-save-address"${data.addressLocked ? ' disabled' : ''}>Save display address</button>
        <div class="field"><label for="setup-existing">Create or update a network</label><select id="setup-existing"><option value="">Create a new network</option>${options(editable, 'id', 'name')}</select></div>
        <div class="grid grid-2">
          <div class="field"><label for="setup-name">Network name</label><input id="setup-name" value="" placeholder="Home office" maxlength="100" required></div>
          <div class="field"><label for="setup-policy">Filtering policy</label><select id="setup-policy" required>${options(policies, 'id', 'name', preferredPolicy?.id)}</select></div>
        </div>
        <div class="field"><label for="setup-clients">Client source IPs or subnets</label><textarea id="setup-clients" rows="3" maxlength="4096" aria-describedby="setup-client-help"></textarea><p id="setup-client-help" class="small muted"></p></div>
        <details><summary>Single IP, subnet, NAT and IPv6 examples</summary>
          <p><code>192.168.1.50</code> means one IPv4 address (<code>/32</code>). <code>192.168.1.0/24</code> means that subnet. <code>2001:db8::50</code> means one IPv6 address (<code>/128</code>). Enter only a prefix you actually own or administer; <code>/64</code> is not a universal IPv6 setting.</p>
          <p>Separate multiple entries with commas or new lines. Host bits in a subnet are normalised in the preview. URLs, DNS names, ports, dash ranges and wildcard routes are not accepted by this guide.</p>
          <p>For a public VPS, use your site's public egress address. An IPv4 public /32 may represent everyone behind its NAT router. For VPN clients, use the VPN source address. A router forwarding DNS may hide individual client IPs.</p>
          <p>For changing ISP addresses or roaming devices, prefer a private VPN or the tokenised DoH setup. Do not automatically allow whatever address visits the dashboard.</p>
        </details>
        <p class="small muted">Management connection source: <code>${encode(data.dashboardClientIp)}</code>. ${encode(data.dashboardClientNote)}</p>
        <details><summary>Optional starter files for a new installation</summary>
          <label for="setup-mode">Resolution mode in exported files only</label><select id="setup-mode"><option value="off"${data.mode === 'off' ? ' selected' : ''}>Forward — Cloudflare HTTPS starter</option><option value="observe"${data.mode === 'observe' ? ' selected' : ''}>Learn — forwarding plus separate native observations</option><option value="enforce"${data.mode === 'enforce' ? ' selected' : ''}>Live — experimental native DNSSEC enforcement</option></select>
          <p class="small muted">Preview generates .env, a Compose port override and native YAML. Applying a network here never changes this server's resolution mode, upstream provider, TLS, privacy or firewall. Existing transport controls remain below.</p>
        </details>
        <button class="btn btn-primary" type="submit" id="setup-preview">Preview configuration and access</button>
      </form>
      <div id="setup-result" aria-live="polite"></div><p id="setup-message" role="status"></p>
    </section>`;
  }
  function previewMarkup(plan, editing) {
    return `<div class="section"><h3>Review before applying</h3>
      <p><strong>DNS destination:</strong> <code>${encode(plan.endpoint)}</code></p>
      <p><strong>${editing ? 'Replace this network’s source ranges with' : 'Permit these client source ranges'}:</strong> ${plan.addresses.length ? plan.addresses.map(a => `<code>${encode(a.cidr)}</code> (${encode(a.scope)}, ${a.single ? 'one address' : 'subnet'})`).join(', ') : 'None — tokenised encrypted DNS only.'}</p>
      <p>Existing permissions are additive and remain unchanged. Updating a network preserves its token, replaces its ranges and enables it. This does not remove access granted by other networks or Default.</p>
      ${plan.warnings.map(w => `<p class="small muted">${encode(w)}</p>`).join('')}
      <p><label><input type="checkbox" id="setup-reviewed"> I have reviewed these source addresses and the selected policy.</label></p>
      ${plan.publicAckRequired ? '<p><label><input type="checkbox" id="setup-public-ack"> I control these public client ranges and intend to grant them resolver access. I will restrict the host/cloud firewall as well.</label></p>' : ''}
      <button class="btn btn-primary" type="button" id="setup-apply">Apply network access</button>
      <h3>Test from a permitted client</h3><pre>${encode(plan.udpTest)}\n${encode(plan.tcpTest)}</pre>
      <p class="small muted">For tokenised DoH, use the encrypted client instructions below instead of these plaintext tests. NOERROR with an answer is a successful lookup; REFUSED, SERVFAIL and timeout need different diagnoses. Check the live activity and query reason.</p>
      <details><summary>Generated starter files — review before installing</summary>
        <p>These files have not been deployed. Keep your existing .env, configuration and data when upgrading. The files deliberately keep bootstrap access loopback-only: Apply network access creates the reviewed named grant.</p>
        <p>Docker: use the generated environment with the repository’s docker-compose.yml and the generated port override. The override requires Compose 2.24.4+. LAN/VPN addresses must exist on the host; a public VPS may use NAT. Existing TLS/proxy settings are not included or overwritten.</p>
        <pre>docker compose --env-file .env.ready -f docker-compose.yml -f compose.ready.yaml config\ndocker compose --env-file .env.ready -f docker-compose.yml -f compose.ready.yaml up -d --build</pre>
        ${[['environment','.env.ready'],['composeOverride','compose.ready.yaml'],['nativeYaml','dnsdaddy.ready.yaml']].map(([key,name]) => `<h4>${encode(name)}</h4><button type="button" class="btn btn-ghost btn-sm" data-setup-download="${key}">Download ${encode(name)}</button><pre>${encode(plan[key])}</pre>`).join('')}
      </details></div>`;
  }
  async function mountGuide(data, networks, context = {}) {
    const el = id => document.getElementById(id);
    const form = el('setup-guide-form');
    if (!form) return;
    const active = () => !context.signal?.aborted && (!context.isCurrent || context.isCurrent());
    let plan = null, revision = 0, writing = false;
    const say = message => { if (active()) el('setup-message').textContent = message; };
    const invalidate = () => { revision++; plan = null; el('setup-result').replaceChildren(); };
    const freeze = busy => {
      for (const control of form.querySelectorAll('input, select, textarea, button')) control.disabled = busy;
      if (!busy) { help(); el('setup-save-address').disabled = !!data.addressLocked; }
    };
    const input = () => ({preset:el('setup-preset').value,serverIp:el('setup-server').value.trim(),dnsPort:Number(el('setup-port').value),clients:el('setup-clients').value,mode:el('setup-mode').value});
    const help = () => {
      const p = data.presets.find(p => p.id === el('setup-preset').value);
      el('setup-server-help').textContent = p.serverHelp;
      el('setup-client-help').textContent = p.clientHelp;
      el('setup-clients').placeholder = p.example;
      el('setup-clients').disabled = p.id === 'roaming';
      if (p.id === 'roaming') el('setup-clients').value = '';
    };
    form.addEventListener('input', invalidate);
    el('setup-preset').addEventListener('change', () => { invalidate(); help(); });
    el('setup-existing').addEventListener('change', () => {
      const n = networks.find(n => n.id === el('setup-existing').value);
      if (n) { el('setup-name').value=n.name; el('setup-clients').value=(n.cidrs || []).join('\n'); el('setup-policy').value=n.policyId; }
      invalidate(); help();
    });
    help();
    el('setup-save-address').addEventListener('click', async () => {
      if (writing) return;
      writing=true; freeze(true);
      try {
        const v=input();
        const saved=await apiSend('PUT','/setup/address',{serverIp:v.serverIp,dnsPort:v.dnsPort,previous:data.endpoint});
        data.endpoint=saved.endpoint;
        say('Display address saved. Overview will show '+saved.endpoint+'. No listener or client access was changed.');
      } catch(e) {say(e.message);} finally {writing=false;if(active())freeze(false);}
    });
    form.addEventListener('submit', async event => {
      event.preventDefault(); invalidate(); const ticket=revision;
      el('setup-preview').disabled=true;
      try {
        const result=await apiSend('POST','/setup/preview',input());
        if(!active() || ticket!==revision) return;
        plan=result; el('setup-result').innerHTML=sanitize(previewMarkup(plan,!!el('setup-existing').value));
        el('setup-apply').addEventListener('click', async () => {
          if(writing || !plan) return;
          let body;
          try {body=networkWrite(plan,el('setup-name').value,el('setup-policy').value,el('setup-reviewed').checked,!!el('setup-public-ack')?.checked);} catch(e){say(e.message);return;}
          writing=true; freeze(true); el('setup-apply').disabled=true;
          const target=el('setup-existing').value;
          try {
            const saved=await apiSend(target?'PATCH':'POST',target?'/networks/'+encodeURIComponent(target):'/networks',body);
            // A retry must not create a second network after a saved grant or
            // reload warning. Keep the returned ID, even when a warning exists.
            if(!active()) return;
            const n=saved.network || saved;
            if(!target && n.id){
              const option=document.createElement('option');option.value=n.id;option.textContent=n.name || body.name;el('setup-existing').append(option);el('setup-existing').value=n.id;
              networks.push(n);
            }
            say(saved.warning || 'Network saved and reload reported successful. Test from your device now; this is not a reachability test. Save the display address separately to update Overview.');
          } catch(e) {say(e.message+' Inspect Networks before retrying: a failed response can follow a persisted change.');}
          finally {writing=false; if(active()){freeze(false);if(el('setup-apply'))el('setup-apply').disabled=false;}}
        });
        document.querySelectorAll('[data-setup-download]').forEach(button=>button.addEventListener('click',()=>{
          if(!plan)return;const key=button.dataset.setupDownload;
          const names={environment:'.env.ready',composeOverride:'compose.ready.yaml',nativeYaml:'dnsdaddy.ready.yaml'};
          if(!names[key])return;
          const url=URL.createObjectURL(new Blob([plan[key]],{type:'text/plain'}));const a=document.createElement('a');a.href=url;a.download=names[key];a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
        }));
      } catch(e){say(e.message);} finally {if(active())el('setup-preview').disabled=false;}
    });
  }
  function install() {
    for (const route of ['setup','networks']) {
      const previous=pages[route];
      pages[route]={...previous,
        async render(context){
          const original=await previous.render.call(this,context);
          try {
            const [data,ns,ps]=await Promise.all([apiGet('/setup'),apiGet('/networks'),apiGet('/policies')]);
            this.setupGuide={data,networks:ns.networks || []};
            return guideMarkup(data,ns.networks || [],ps.policies || [])+original;
          } catch(e){this.setupGuide=null;return '<section class="card section"><h2>Guided setup unavailable</h2><p>'+encode(e.message)+'</p><p>Existing controls remain available below. Retry after checking the API.</p></section>'+original;}
        },
        async mounted(context){
          if(previous.mounted)await previous.mounted.call(this,context);
          if(this.setupGuide)await mountGuide(this.setupGuide.data,this.setupGuide.networks,context);
        }
      };
    }
  }
  // Assembled after app.js in the same script response, before boot's first
  // awaited session request completes. Both share helpers and the page registry.
  // Setup is not a separate authentication surface.
  if(typeof pages!=='undefined' && typeof document!=='undefined')install();
  if(typeof module!=='undefined' && module.exports)module.exports={guideMarkup,previewMarkup,networkWrite};
})();
