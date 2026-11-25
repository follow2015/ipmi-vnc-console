'use strict';
const crypto = require('crypto');
const { chromium } = require(process.env.KVM_PLAYWRIGHT);
(async () => {
  const browser = await chromium.launch({ executablePath: process.env.KVM_CHROMIUM, headless: true });
  try {
    const page = await browser.newPage();
    const errors = []; const logs = [];
    page.on('console', m => { if(logs.length < 20) logs.push(m.text()); });
    page.on('pageerror', e => errors.push(e.message));
    await page.goto(process.argv[2], { waitUntil: 'load' });
    try { await page.waitForFunction(() => {
      const c = document.getElementById('screen');
      if (c.width !== 128 || c.height !== 128) return false;
      const d = c.getContext('2d').getImageData(0, 0, 1, 1).data;
      return d[0] === 0 && d[1] === 0 && d[2] === 255;
    }, null, { timeout: 10000 }); } catch(e) {
      console.error(JSON.stringify({errors,logs,canvas:await page.evaluate(() => ({w:document.getElementById('screen').width,h:document.getElementById('screen').height}))}));
      throw e;
    }
    const pixels = await page.evaluate(() => Array.from(document.getElementById('screen').getContext('2d').getImageData(0, 0, 128, 128).data));
    console.log(JSON.stringify({ errors, sha256: crypto.createHash('sha256').update(Buffer.from(pixels)).digest('hex') }));
  } finally { await browser.close(); }
})().catch(e => { console.error(e.stack); process.exit(1); });
