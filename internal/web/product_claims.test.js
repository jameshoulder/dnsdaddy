'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function dashboard() {
  const policy = {
    id:'p_standard', name:'<img src=x onerror=1>', description:'Compatibility fixture',
    categories:[], blockMode:'nxdomain', logQueries:true, isDefault:true,
    safeSearch:true, allowDomains:[], blockDomains:[],
  };
  const requests = [];
  const sandbox = {
    module:{exports:{}}, console, URL, URLSearchParams, Headers, Response,
    AbortController, AbortSignal, performance, setTimeout, clearTimeout,
    setInterval, clearInterval,
    fetch:async (raw, options={}) => {
      const url = new URL(raw, 'https://fixture.invalid');
      requests.push({path:url.pathname, method:options.method || 'GET'});
      let value;
      if (url.pathname === '/api/v1/policies') value={policies:[policy]};
      else if (url.pathname === '/api/v1/policies/p_standard') value=policy;
      else if (url.pathname === '/api/v1/categories') value={categories:[]};
      else if (url.pathname === '/api/v1/settings') value={version:'<svg onload=1>',queryLog:true};
      else throw new Error('Unexpected fixture request: '+url.pathname);
      return new Response(JSON.stringify(value), {status:200,headers:{'Content-Type':'application/json'}});
    },
  };
  vm.createContext(sandbox);
  // Execute the actual renderer and extension without a DOM: no boot, timers,
  // network or fake replacement policy form. Export the lexical page registry.
  const main = fs.readFileSync(path.join(__dirname,'static/app.js'),'utf8');
  const extension = fs.readFileSync(path.join(__dirname,'static/setup.js'),'utf8');
  vm.runInContext(main+'\n;\n'+extension+'\nmodule.exports.phase1Pages = pages;', sandbox);
  const {productClaims,phase1Pages} = sandbox.module.exports;
  productClaims.installProductClaims(phase1Pages);
  return {pages:phase1Pages, productClaims, policy, requests};
}

test('Phase1: the real policy editor never presents safeSearch as enforcement', async () => {
  const d=dashboard();
  for (const stored of [false,true]) {
    d.policy.safeSearch=stored;
    const markup=await d.pages.policies.render({});
    assert.ok(markup.includes('Safe Search is not enforced.'));
    assert.ok(markup.includes('even true does not rewrite DNS answers'));
    assert.doesNotMatch(markup, /<(?:input|select|button|textarea)\b[^>]*safe[-_ ]?search/i);
    assert.ok(!markup.includes('<img src=x onerror=1>'), 'operator-controlled policy name was not escaped');
  }
  assert.ok(d.requests.every(r=>r.method==='GET'), 'rendering a disclaimer changed configuration');
});

test('Phase1: actual Assurance render states the fresh default, not a live status', async () => {
  const d=dashboard();
  const markup=await d.pages.assurance.render({});
  assert.ok(markup.includes(d.productClaims.defaultModeFact));
  assert.ok(markup.includes('not this server’s current mode'));
  assert.ok(markup.includes('Daddybound Live remains experimental'));
  assert.ok(markup.includes('behavioural detectors remain alert-only'));
  assert.ok(!markup.includes('<svg onload=1>'), 'attacker-controlled version text became markup');
  assert.ok(d.requests.every(r=>r.method==='GET'));
});

test('Phase1: installing the disclosure twice does not duplicate it or alter callbacks', async () => {
  const d=dashboard();
  const mounted=d.pages.policies.mounted;
  d.productClaims.installProductClaims(d.pages);
  const markup=await d.pages.policies.render({});
  assert.equal(markup.split('Safe Search is not enforced.').length-1,1);
  assert.equal(d.pages.policies.mounted,mounted);
});
