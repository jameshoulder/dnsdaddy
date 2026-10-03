'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {guideMarkup, previewMarkup, networkWrite} = require('./static/setup.js');
const plan = {endpoint:'203.0.113.53:53',cidrs:['198.51.100.1/32'],addresses:[{cidr:'198.51.100.1/32',scope:'public',single:true}],publicAckRequired:true,grantSourceAccess:true,warnings:[],environment:'x',nativeYaml:'x',composeOverride:'x',udpTest:'dig',tcpTest:'dig +tcp'};
test('public client grants require explicit review and acknowledgement',()=>{
 assert.throws(()=>networkWrite(plan,'Home','p_standard',false,true));
 assert.throws(()=>networkWrite(plan,'Home','p_standard',true,false));
 assert.equal(networkWrite(plan,'Home','p_standard',true,true).allowResolver,true);
});
test('tokenised roaming never invents a source grant',()=>{
 const p={...plan,cidrs:[],publicAckRequired:false,grantSourceAccess:false};
 const b=networkWrite(p,'Laptop','p_standard',true,false);
 assert.equal(b.allowResolver,false);assert.equal(b.enabled,true);assert.deepEqual(b.cidrs,[]);
});
test('setup distinguishes destinations, sources and configuration-only mode',()=>{
 const s=guideMarkup({presets:[{id:'lan',name:'LAN'}],serverIp:'',dnsPort:53,mode:'off',dashboardClientIp:'127.0.0.1'},[],[{id:'p_standard',name:'Standard',isDefault:true}]);
 for(const label of ['Server address =','Client addresses =','/32','/128','public egress','exported files only','Save display address'])assert.ok(s.includes(label),label);
 assert.ok(!s.includes('value="192.168.1.50"'),'example became an active grant');
});
test('all API-provided labels and generated file content remain escaped',()=>{
 const s=guideMarkup({presets:[{id:'x',name:'<img onerror=alert(1)>'}],serverIp:'" onfocus="oops',dashboardClientIp:'<script>x</script>'},[],[]);
 assert.ok(!s.includes('<img'));assert.ok(!s.includes('<script>'));
 const p=previewMarkup({...plan,environment:'</pre><script>x</script>'},false);
 assert.ok(!p.includes('<script>'));assert.ok(p.includes('&lt;script&gt;'));
});
test('preview makes replacement, additive grants and undeployed files explicit',()=>{
 const s=previewMarkup(plan,true);
 for(const label of ['Replace this network','Existing permissions are additive','have not been deployed','Compose 2.24.4','source addresses'])assert.ok(s.includes(label),label);
});
