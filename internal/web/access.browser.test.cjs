/* Real daemon and browser: rejected source -> reviewed grant -> DNS answers and
 * query history with no loaded feeds. All DNS packets remain on loopback. */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const dgram = require('node:dgram');
const { spawn } = require('node:child_process');
const { chromium } = require('playwright');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
async function freePort() {
  const s = net.createServer(); await new Promise(resolve => s.listen(0, '127.0.0.1', resolve));
  const p = s.address().port; await new Promise(resolve => s.close(resolve)); return p;
}
function question(name, id) {
  const h = Buffer.alloc(12); h.writeUInt16BE(id); h.writeUInt16BE(0x0100, 2); h.writeUInt16BE(1, 4);
  return Buffer.concat([h, ...name.split('.').map(l => Buffer.concat([Buffer.from([l.length]), Buffer.from(l)])), Buffer.from([0,0,1,0,1])]);
}
async function ask(port, name, id, protocol, source = '127.0.0.2') {
  const wire = question(name,id); let socket, timer;
  try {
    return await new Promise((resolve,reject) => {
      timer = setTimeout(() => reject(new Error('DNS test timed out')), 4000);
      if (protocol === 'udp') {
        socket = dgram.createSocket('udp4'); socket.once('error',reject);
        socket.once('message',resolve);
        socket.bind(0,source,() => socket.send(wire,port,'127.0.0.1'));
      } else {
        socket = net.createConnection({host:'127.0.0.1',port,localAddress:source}); socket.once('error',reject);
        let data = Buffer.alloc(0);
        socket.on('data',b => {data=Buffer.concat([data,b]);if(data.length>=2 && data.length>=data.readUInt16BE(0)+2)resolve(data.subarray(2,2+data.readUInt16BE(0)));});
        socket.once('connect',() => {const length=Buffer.alloc(2);length.writeUInt16BE(wire.length);socket.write(Buffer.concat([length,wire]));});
      }
    });
  } finally {clearTimeout(timer);if(socket){if(protocol==='udp')socket.close();else socket.destroy();}}
}
(async () => {
  assert.ok(process.env.DNSDADDY_UI_BINARY && process.env.DNSDADDY_UI_BROWSER,'Supply the real binary and browser; this test must not silently skip.');
  const work=await fs.mkdtemp(path.join(os.tmpdir(),'dnsdaddy-access-'));
  const upstream=dgram.createSocket('udp4');await new Promise(resolve=>upstream.bind(0,'127.0.0.1',resolve));
  let upstreamQueries=0;
  upstream.on('message',(message,peer)=>{
    upstreamQueries++;let end=12;while(message[end])end+=message[end]+1;end+=5;
    const h=Buffer.from(message.subarray(0,12));h.writeUInt16BE(0x8180,2);h.writeUInt16BE(1,6);h.writeUInt32BE(0,8);
    upstream.send(Buffer.concat([h,message.subarray(12,end),Buffer.from([0xc0,0x0c,0,1,0,1,0,0,0,60,0,4,8,8,4,4])]),peer.port,peer.address);
  });
  const httpPort=await freePort(),dnsPort=await freePort(),base=`http://127.0.0.1:${httpPort}`;
  const password='isolated-access-regression-password';const config=path.join(work,'config.yaml');
  await fs.writeFile(config,`data_dir: ${JSON.stringify(path.join(work,'data'))}\ndns:\n  listen_udp: "127.0.0.1:${dnsPort}"\n  listen_tcp: "127.0.0.1:${dnsPort}"\n  allowed_client_cidrs: ["127.0.0.1/32"]\n  upstreams: ["127.0.0.1:${upstream.address().port}"]\nhttp:\n  listen: "127.0.0.1:${httpPort}"\n  admin_password: "${password}"\nfeeds:\n  refresh_on_start: false\nlog:\n  query_log: true\n  log_client_ip: true\n`);
  const env={...process.env};for(const key of Object.keys(env))if(key.startsWith('DNSDADDY_'))delete env[key];
  const app=spawn(process.env.DNSDADDY_UI_BINARY,['-config',config],{env,stdio:['ignore','pipe','pipe']});
  let browser;app.stdout.resume();app.stderr.resume();
  try {
    for(let i=0;i<100;i++){
      if(app.exitCode!==null)throw new Error('Test daemon exited before readiness.');
      try {if((await fetch(base+'/api/v1/health')).ok)break;}catch{/* startup */}
      if(i===99)throw new Error('Test daemon never became ready.');await delay(100);
    }
    browser=await chromium.launch({executablePath:process.env.DNSDADDY_UI_BROWSER,args:['--no-sandbox']});
    const context=await browser.newContext();const page=await context.newPage();const errors=[];page.on('pageerror',e=>errors.push(e.message));
    await page.goto(base);await page.locator('#password').fill(password);await page.locator('#login-form button[type=submit]').click();
    await page.locator('#resolver-access').waitFor();
    const read=async route=>{const r=await context.request.get(base+'/api/v1'+route);assert.equal(r.status(),200);return r.json();};
    assert.equal((await read('/overview')).blocklistDomains,0,'feed index must remain empty');
    const initial=await read('/networks');const initialDefault=initial.networks.find(n=>n.id==='n_default');
    for(const proto of ['udp','tcp']){const r=await ask(dnsPort,'refused.example.test',1,proto);assert.equal(r.readUInt16BE(2)&15,5);}
    assert.equal(upstreamQueries,0,'unapproved DNS must not reach upstream');
    await page.locator('[data-review-access="127.0.0.2"]').waitFor();
    assert.equal(await page.locator('.first-client').count(),0,'obsolete lifetime-refusal card remains');
    await page.locator('[data-review-access="127.0.0.2"]').click();
    await page.locator('[data-allow-access]').click();
    assert.equal((await read('/networks')).networks.length,initial.networks.length,'unchecked confirmation allowed a write');
    await page.locator('[data-access-confirm]').check();await page.locator('[data-allow-access]').click();
    await page.waitForFunction(()=>document.querySelector('[data-access-message]').textContent.includes('Permission saved'));
    const current=await read('/networks');const grant=current.networks.find(n=>n.cidrs?.includes('127.0.0.2/32'));
    assert.ok(grant && grant.allowResolver && grant.enabled);assert.deepEqual(grant.cidrs,['127.0.0.2/32']);
    assert.equal(grant.policyId,initialDefault.policyId);assert.equal(current.networks.find(n=>n.id==='n_default').allowResolver,initialDefault.allowResolver);
    assert.equal((await read('/activity/live')).clientAccess.entries.find(e=>e.address==='127.0.0.2').status,'permitted_waiting');
    for(const proto of ['udp','tcp']){const r=await ask(dnsPort,'allowed.example.test',2,proto);assert.equal(r.readUInt16BE(2)&15,0);assert.ok(r.readUInt16BE(6)>0,'NOERROR without an answer');}
    const other=await ask(dnsPort,'other.example.test',3,'udp','127.0.0.3');assert.equal(other.readUInt16BE(2)&15,5,'grant widened');
    await page.waitForFunction(()=>document.querySelector('[data-access-rows]').textContent.includes('Answer produced after refusal'));
    let records;
    for(let i=0;i<50;i++){records=await read('/queries?limit=100');if(records.queries.filter(q=>q.domain==='allowed.example.test').length===2)break;await delay(100);}
    assert.equal(records.queries.filter(q=>q.domain==='allowed.example.test').length,2,'admitted queries missing from reporting');
    assert.ok(records.queries.every(q=>!['refused.example.test','other.example.test'].includes(q.domain)),'refusal stored queried names');
    assert.equal((await read('/overview')).blocklistDomains,0);
    assert.ok((await read('/activity/live')).sinceStart.refused>0,'history counter was improperly reset to hide refusals');
    assert.deepEqual(errors,[]);
    console.log('PASS: actual UDP/TCP refusal -> browser-confirmed single-host grant -> real DNS answers and query history, no feeds, unrelated source still refused.');
  } finally {
    if(browser)await browser.close();app.kill('SIGTERM');await Promise.race([new Promise(resolve=>app.once('exit',resolve)),delay(3000)]);if(app.exitCode===null)app.kill('SIGKILL');upstream.close();await fs.rm(work,{recursive:true,force:true});
  }
})().catch(error=>{console.error(error);process.exitCode=1;});
