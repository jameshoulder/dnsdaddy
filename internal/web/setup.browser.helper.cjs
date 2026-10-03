'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');

// This fixture uses the real daemon and API. Documentation addresses are
// configured as access rules, never contacted by the browser test.
module.exports = async function verifyGuidedSetup(page, context, base) {
  const beforeResponse = await context.request.get(base + '/api/v1/networks');
  assert.equal(beforeResponse.status(), 200);
  const before = await beforeResponse.json();
  const originalDefault = before.networks.find(n => n.id === 'n_default');
  const writes = [];
  const record = request => {
    if (request.method() !== 'GET' && (request.url().endsWith('/setup/address') || request.url().endsWith('/networks'))) writes.push(request.url());
  };
  page.on('request', record);
  await page.locator('a[href$="setup"]').first().click();
  await page.locator('#setup-guide-form').waitFor();
  assert.equal(await page.locator('#setup-options').evaluate(e => e.open), false);
  assert.equal(await page.locator('#setup-advanced-tools').evaluate(e => e.open), false);
  assert.equal(await page.locator('#setup-guide-form input:visible, #setup-guide-form select:visible').count(), 3);
  for (const removed of ['setup-save-address','setup-preview','setup-mode','setup-reviewed']) assert.equal(await page.locator('#'+removed).count(),0);

  await page.locator('#setup-preset').selectOption('vps');
  await page.locator('#setup-server').fill('203.0.113.53');
  await page.locator('#setup-clients').fill('192.168.1.0/24');
  await page.locator('#setup-connect').click();
  await page.waitForFunction(() => document.querySelector('#setup-message').textContent.includes('public egress'));
  assert.equal(writes.length,0,'validation must precede display and permission writes');
  await page.locator('#setup-clients').fill('198.51.100.9');
  await page.locator('#setup-connect').click();
  await page.locator('#setup-apply').waitFor();
  assert.ok((await page.locator('#setup-result').textContent()).includes('198.51.100.9/32'));
  assert.equal(await page.locator('#setup-public-ack').isChecked(), false);
  await page.locator('#setup-apply').click();
  await page.waitForFunction(() => document.querySelector('#setup-message').textContent.includes('Confirm'));
  assert.equal(writes.length,0,'a public grant must still require explicit acknowledgement');

  // An edit invalidates the reviewed plan instead of applying stale addresses.
  await page.locator('#setup-clients').fill('198.51.100.10');
  assert.equal(await page.locator('#setup-apply').count(),0);
  await page.locator('#setup-clients').fill('198.51.100.9');
  await page.locator('#setup-connect').click();
  await page.locator('#setup-public-ack').check();
  await page.locator('#setup-apply').click();
  await page.locator('#setup-copy').waitFor();
  assert.equal(writes.filter(p=>p.endsWith('/setup/address')).length,1);
  assert.equal(writes.filter(p=>p.endsWith('/networks')).length,1);
  assert.equal(await page.locator('#setup-guide-form').isVisible(),false,'completion replaces the form with the copy step');
  let current = await (await context.request.get(base + '/api/v1/networks')).json();
  const created = current.networks.find(n => n.cidrs.includes('198.51.100.9/32'));
  assert.ok(created && created.enabled && created.allowResolver);
  assert.deepEqual(created.cidrs,['198.51.100.9/32']);
  assert.equal(current.networks.find(n=>n.id==='n_default').allowResolver,originalDefault.allowResolver);
  assert.equal(await page.locator('#setup-existing').inputValue(),created.id);
  const addresses=await (await context.request.get(base+'/api/v1/server-addresses')).json();
  assert.equal(addresses.advertised.address,'203.0.113.53');
  assert.equal(addresses.advertised.verified,false);
  assert.ok((await page.locator('#setup-result').innerText()).includes('has not been tested'));

  // Retain only the credential-free new card, never the old token URL panel.
  if (process.env.RUNNER_TEMP) {
    const output=path.join(process.env.RUNNER_TEMP,'evidence','simple-setup');
    await fs.mkdir(output,{recursive:true});
    await page.locator('#setup-guide').screenshot({path:path.join(output,'saved.png')});
    const viewport=page.viewportSize();
    await page.locator('#setup-another').click();
    await page.setViewportSize({width:390,height:844});
    assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),'simple setup must fit a phone');
    await page.locator('#setup-guide').screenshot({path:path.join(output,'connect-mobile.png')});
    await page.setViewportSize(viewport);
  } else await page.locator('#setup-another').click();

  // A private single address takes one Connect click, with no separate preview,
  // display-save, name, policy selector or access checkbox to operate.
  await page.locator('#setup-preset').selectOption('lan');
  await page.locator('#setup-clients').fill('192.168.1.50');
  await page.locator('#setup-connect').click();
  await page.locator('#setup-copy').waitFor();
  assert.equal(await page.locator('#setup-apply').count(),0);
  current=await (await context.request.get(base+'/api/v1/networks')).json();
  assert.ok(current.networks.some(n=>n.allowResolver && n.cidrs.includes('192.168.1.50/32')));
  assert.equal(writes.filter(p=>p.endsWith('/networks')).length,2);
  assert.equal(writes.filter(p=>p.endsWith('/setup/address')).length,1,'unchanged address must not require a second save');
  page.off('request',record);
  await page.goto(base);
  await page.locator('#resolver-live').waitFor();
  await page.waitForFunction(()=>document.body.textContent.includes('203.0.113.53'));
  console.log('PASS: three-field Connect screen; public review; obsolete review invalidation; combined display/access save; one-click private grant; visible connections; unchanged Default; correct Overview address.');
};
