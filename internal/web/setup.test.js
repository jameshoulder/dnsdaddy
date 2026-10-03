'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {
  guideMarkup, previewMarkup, networkWrite, needsConfirmation, connectionSuggestion,
  saveConnection, successMarkup, advancedMarkup, suggestedServer, connectionsMarkup,
} = require('./static/setup.js');
const plan = {endpoint:'203.0.113.53:53',cidrs:['198.51.100.9/32'],addresses:[{cidr:'198.51.100.9/32',scope:'public',single:true}],publicAckRequired:true,grantSourceAccess:true,warnings:[],environment:'env',nativeYaml:'yaml',composeOverride:'ports',udpTest:'dig',tcpTest:'dig +tcp'};
const input = {preset:'vps',serverIp:'203.0.113.53',dnsPort:53};
const body = {name:'Home',policyId:'p_standard',cidrs:plan.cidrs,enabled:true,allowResolver:true,publicAck:true};

test('normal setup has three inputs and one submit; technical choices are collapsed', () => {
  const s = guideMarkup({serverIp:'',dnsPort:53},[],[{id:'p_standard',name:'Standard',isDefault:true}]);
  const basic = s.replace(/<details[\s\S]*?<\/details>/g, '');
  assert.equal((basic.match(/<(input|select)\b/g)||[]).length,3);
  assert.equal((basic.match(/type="submit"/g)||[]).length,1);
  for (const old of ['setup-save-address','setup-preview','setup-mode','setup-reviewed']) assert.ok(!s.includes(old),old);
  assert.ok(!basic.includes('CIDR')); assert.ok(!basic.includes('Compose'));
  assert.ok(!s.includes('value="192.168.1.50"'),'example must not become an actual grant');
});
test('only public, multi-address, subnet and replacement grants need the extra confirmation', () => {
  assert.ok(needsConfirmation(plan,false));
  const privateHost={...plan,publicAckRequired:false};
  assert.equal(needsConfirmation(privateHost,false),false);
  assert.ok(needsConfirmation(privateHost,true));
  assert.ok(needsConfirmation({...privateHost,addresses:[{single:false}]},false));
  assert.ok(needsConfirmation({...privateHost,cidrs:['a','b']},false));
});
test('public confirmation remains mandatory and editing states its replacement scope', () => {
  assert.throws(()=>networkWrite(plan,'Home','p_standard',false,true));
  assert.throws(()=>networkWrite(plan,'Home','p_standard',true,false));
  assert.deepEqual(networkWrite(plan,' Home ','p_standard',true,true),body);
  const s=previewMarkup(plan,true);
  assert.ok(s.includes('replaces the selected connection'));
  assert.ok(s.includes('198.51.100.9/32')); assert.ok(s.includes('sharing that connection'));
});
test('roaming creates an enabled private link without an IP grant', () => {
  const b=networkWrite({...plan,cidrs:[],publicAckRequired:false,grantSourceAccess:false},'Laptop','p_standard',true,false);
  assert.equal(b.allowResolver,false); assert.equal(b.enabled,true); assert.deepEqual(b.cidrs,[]);
  assert.ok(successMarkup(plan,{...input,preset:'roaming'},'').includes('#/setup?advanced=1'));
});
test('one action saves the DNS address then one network, without a mode or transport write', async () => {
  const calls=[], data={endpoint:'',addressLocked:false}, state={target:'',ambiguous:false};
  const send=async(method,path,payload)=>{calls.push({method,path,payload});return path==='/setup/address'?{endpoint:plan.endpoint}:{id:'n_new',...body};};
  await saveConnection({plan,input,body},data,state,send);
  assert.deepEqual(calls.map(c=>c.path),['/setup/address','/networks']);
  assert.equal(data.endpoint,plan.endpoint); assert.equal(state.target,'n_new');
  await saveConnection({plan,input,body},data,state,send);
  assert.deepEqual(calls.map(c=>c.path),['/setup/address','/networks','/networks/n_new']);
  assert.equal(calls[2].method,'PATCH');
});
test('locked display configuration is not overwritten and cannot quietly disagree', async () => {
  const calls=[], data={endpoint:plan.endpoint,addressLocked:true};
  const send=async(method,path)=>{calls.push(path);return{id:'n_new'};};
  await saveConnection({plan,input,body},data,{target:''},send);
  assert.deepEqual(calls,['/networks']);
  await assert.rejects(()=>saveConnection({plan:{...plan,endpoint:'192.0.2.1:53'},input,body},data,{},send));
  assert.equal(calls.length,1);
});
test('a failed display save never proceeds to granting DNS access', async () => {
  const calls=[];
  await assert.rejects(()=>saveConnection({plan,input,body},{endpoint:''},{},async(m,p)=>{calls.push(p);throw new Error('address conflict');}));
  assert.deepEqual(calls,['/setup/address']);
});
test('a lost network response blocks blind duplicate creation and preserves the saved address', async () => {
  const calls=[], data={endpoint:''}, state={target:'',ambiguous:false};
  const send=async(m,p)=>{calls.push(p);if(p==='/setup/address')return{endpoint:plan.endpoint};throw new Error('connection lost');};
  await assert.rejects(()=>saveConnection({plan,input,body},data,state,send),/could not be confirmed/);
  assert.equal(data.endpoint,plan.endpoint); assert.ok(state.ambiguous);
  await assert.rejects(()=>saveConnection({plan,input,body},data,state,send),/Refresh/);
  assert.equal(calls.length,2);
});
test('a reload warning stays a warning, never a successful connectivity claim', async () => {
  const warning='Saved but client access reload failed';
  const result=await saveConnection({plan,input,body},{endpoint:plan.endpoint},{},async()=>({id:'n_new',warning}));
  assert.equal(result.warning,warning);
  const s=successMarkup(plan,input,warning);
  assert.ok(s.includes(warning)); assert.ok(s.includes('has not been tested'));
  assert.ok(s.includes('Copy DNS IP')); assert.ok(!s.includes('Connected successfully'));
});
test('public and private management addresses are explicit suggestions, never prefilled permissions', () => {
  for(const ip of ['127.0.0.1','::1','::ffff:127.0.0.1','169.254.1.1','fe80::1','', '<script>'])assert.equal(connectionSuggestion(ip),'',ip);
  assert.equal(connectionSuggestion('198.51.100.9'),'198.51.100.9');
  const s=guideMarkup({dashboardClientIp:'198.51.100.9'},[],[]);
  assert.ok(s.includes('Use this connection (198.51.100.9)'));
  assert.ok(!s.includes('value="198.51.100.9"'));
});
test('only native host interfaces with matching plain DNS listeners may prefill a server suggestion', () => {
  const data={serverIp:'',endpoint:''}, addresses={runtime:'host',preferredAddress:'192.168.1.2',addresses:[{address:'192.168.1.2',type:'private',dns:[{transport:'udp',port:53},{transport:'tcp',port:53}]}]};
  const suggested=suggestedServer(data,addresses);
  assert.equal(suggested.serverIp,'192.168.1.2'); assert.equal(suggested.dnsPort,53);
  assert.ok(suggested.suggested); assert.equal(data.serverIp,'');
  for(const runtime of ['container','unknown',undefined])assert.equal(suggestedServer(data,{...addresses,runtime}),data);
  assert.equal(suggestedServer({...data,serverIp:'198.51.100.53'},addresses).serverIp,'198.51.100.53');
  assert.equal(suggestedServer(data,{...addresses,preferredAddress:'127.0.0.1'}),data);
});
test('the previous technical screen is closed by default, but encrypted instructions can open it', () => {
  const s=advancedMarkup('<div>existing controls</div>');
  assert.ok(s.includes('Advanced settings')); assert.ok(!s.includes(' open'));
  assert.ok(advancedMarkup('controls',true).includes(' open'));
});
test('existing connections remain visible and do not claim to be connected', () => {
  const s=connectionsMarkup([{id:'n_default',name:'Default'},{id:'n_one',name:'Home',cidrs:['192.168.1.50/32'],enabled:true,coverage:'none'}]);
  assert.ok(s.includes('Your connections')); assert.ok(s.includes('Home')); assert.ok(s.includes('Not allowed yet'));
  assert.ok(!s.includes('Default')); assert.ok(!s.includes('Connected'));
  assert.ok(s.includes('data-connect-edit="n_one"'));
});
test('API values and generated file text remain escaped', () => {
  const s=guideMarkup({serverIp:'" onfocus="oops',dashboardClientIp:'<script>x</script>'},[],[{id:'x',name:'<img onerror=x>'}]);
  assert.ok(!s.includes('<img')); assert.ok(!s.includes('<script>'));
  const rendered=successMarkup({...plan,environment:'</pre><script>x</script>'},input,'<img src=x>');
  assert.ok(!rendered.includes('<script>')); assert.ok(!rendered.includes('<img'));
});
