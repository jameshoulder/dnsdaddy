'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {accessSummary, accessGrant, applyAccess, accessRows, accessPanel} = require('./static/setup.js').resolverAccess;
const entry = {address:'203.0.113.9',cidr:'203.0.113.9/32',canAuthorize:true,sourceAllowed:false,public:true,networkId:'n_default',policyId:'p_strict',policyName:'Strict',protocols:['udp'],refused:4,status:'needs_permission',reason:'Source not permitted'};
const latest = e => ({clientAccess:{enabled:true,aclStale:false,entries:[e]}});
test('historic refusal does not masquerade as current failure',()=>{
 const s={sinceStart:{refused:5000},recent:{answered:2,refused:0,errors:0}};
 assert.equal(accessSummary(s),'DNS responses are being produced.');
 assert.ok(accessSummary({sinceStart:s.sinceStart,recent:{}}).includes('historical refusal is not a current outage'));
});
test('resolution failures and source refusals remain distinct',()=>{
 assert.ok(accessSummary({recent:{errors:2}}).includes('DNSSEC failure'));
 assert.ok(accessSummary({recent:{refused:2}}).includes('not permitted'));
 assert.ok(accessSummary({recent:{answered:2,refused:2}}).includes('Other source'));
});
test('source observation never grants permission without confirmation',()=>{
 assert.throws(()=>accessGrant(entry,false,[]),/Confirm/);
 assert.throws(()=>accessGrant({...entry,canAuthorize:false},true,[]));
 assert.throws(()=>accessGrant({...entry,sourceAllowed:true},true,[]));
});
test('grant is one observed host and retains its strict policy',()=>{
 const g=accessGrant(entry,true,[]);
 assert.deepEqual(g.body.cidrs,['203.0.113.9/32']);assert.equal(g.body.policyId,'p_strict');
 assert.equal(g.body.publicAck,true);assert.equal(g.body.allowResolver,true);
 assert.equal(g.path,'/networks');
});
test('only an exact matching single-host network can be patched',()=>{
 const e={...entry,networkId:'n_home'};
 const n={id:'n_home',enabled:true,policyId:'p_strict',cidrs:['203.0.113.9/32']};
 assert.equal(accessGrant(e,true,[n]).method,'PATCH');
 assert.deepEqual(accessGrant(e,true,[n]).body,{allowResolver:true,publicAck:true});
 assert.equal(accessGrant(e,true,[{...n,cidrs:['203.0.113.0/24']}]).method,'POST');
 assert.equal(accessGrant(e,true,[{...n,enabled:false}]).method,'POST');
 assert.equal(accessGrant(entry,true,[{...n,id:'n_default'}]).method,'POST');
});
test('no write occurs for stale, private, expired or policy-changed evidence',async()=>{
 for(const s of [{clientAccess:{enabled:false}}, {clientAccess:{enabled:true,aclStale:true}}, {clientAccess:{enabled:true,entries:[]}}, latest({...entry,policyId:'p_monitor'})]){
  let writes=0;await assert.rejects(applyAccess(entry,true,async()=>s,async()=>writes++));assert.equal(writes,0);
 }
});
test('already-permitted source is idempotent and creates no extra network',async()=>{
 let writes=0;const r=await applyAccess(entry,true,async()=>latest({...entry,sourceAllowed:true}),async()=>writes++);
 assert.equal(r.alreadyAllowed,true);assert.equal(writes,0);
});
test('fresh evidence and networks are read before the narrow audited write',async()=>{
 const calls=[];
 const r=await applyAccess(entry,true,async p=>{calls.push(p);return p==='/activity/live'?latest(entry):{networks:[]};},async(m,p,b)=>{calls.push(m+' '+p);assert.equal(b.policyId,'p_strict');return {id:'n_new',warning:'Reload pending'};});
 assert.deepEqual(calls,['/activity/live','/networks','POST /networks']);assert.equal(r.warning,'Reload pending');
});
test('lost write response is labelled uncertain instead of blindly repeated',async()=>{
 const read=async p=>p==='/activity/live'?latest(entry):{networks:[]};
 await assert.rejects(applyAccess(entry,true,read,async()=>{throw new Error('connection lost');}),e=>e.accessWriteUncertain===true);
});
test('untrusted labels are escaped and no query content is requested',()=>{
 const html=accessRows({enabled:true,entries:[{...entry,address:'<img onerror=1>',reason:'<script>bad</script>'}]});
 assert.ok(!html.includes('<img'));assert.ok(!html.includes('<script>'));assert.ok(html.includes('&lt;script&gt;'));
 assert.ok(accessPanel().includes('no queried names or tokens'));
 assert.equal(accessRows({enabled:false,entries:[entry]}),'');
});
