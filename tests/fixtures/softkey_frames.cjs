'use strict';
const fs = require('fs');
const { chromium } = require(process.env.KVM_PLAYWRIGHT);

const argv = process.argv.slice(2);
function opt(name, fallback) {
  const index = argv.indexOf('--' + name);
  return index >= 0 ? argv[index + 1] : fallback;
}

const HTML = fs.readFileSync(opt('html'), 'utf8');
const KEYMAP = fs.readFileSync(opt('keymap'), 'utf8');
const CASES = JSON.parse(fs.readFileSync(opt('cases'), 'utf8'));
const ORIGIN = 'https://softkey.example';
const PROTOCOL = opt('protocol') || 'insyde18';

async function main() {
  const browser = await chromium.launch({
    executablePath: process.env.KVM_CHROMIUM || undefined,
    headless: true,
  });
  const page = await browser.newPage({ viewport: { width: 1100, height: 940 } });
  const errors = [];
  page.on('pageerror', (error) => errors.push(String(error.message).slice(0, 200)));

  await page.route(ORIGIN + '/**', (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/console') {
      return route.fulfill({ status: 200, contentType: 'text/html', body: HTML });
    }
    if (path === '/_platform/keymap') {
      return route.fulfill({ status: 200, contentType: 'application/json', body: KEYMAP });
    }
    if (path === '/_platform/meta') {
      return route.fulfill({ status: 200, contentType: 'application/json',
        body: JSON.stringify({ address: '192.0.2.11', input_protocol: PROTOCOL }) });
    }
    if (path === '/_platform/limits') {
      return route.fulfill({
        status: 200, contentType: 'application/json',
        body: JSON.stringify({ connections: 1, opening: 0, limit: 4 }),
      });
    }
    return route.fulfill({ status: 200, contentType: 'application/javascript', body: '/* stub */' });
  });

  await page.addInitScript(() => {
    window.__sent = [];
    window.RFB = class RecordingRFB {
      constructor(options) {
        this.options = options;
        this._rfb_state = 'connecting';
        this._sock = { send: (frame) => { window.__sent.push(Array.from(frame)); } };
      }
      connect() {
        this._rfb_state = 'normal';
        this.options.onUpdateState(this, 'normal', 'connecting', '');
      }
      disconnect() { this._rfb_state = 'disconnected'; }
    };
  });

  await page.goto(ORIGIN + '/console', { waitUntil: 'domcontentloaded' });
  await page.click('#input-toggle');

  await page.waitForFunction(() => {
    const button = document.querySelector('#softkey [data-send="a"]');
    return !!button && !button.disabled;
  }, null, { timeout: 20000 });

  const results = [];
  for (const item of CASES) {
    await page.evaluate(() => { window.__sent.length = 0; });
    const problem = await page.evaluate(async (spec) => {
      const buttons = () => Array.from(document.querySelectorAll('#softkey [data-send]'));
      if (spec.macro) {
        const macro = Array.from(document.querySelectorAll('#sk-macros button'))
          .find((button) => button.textContent.trim() === spec.macro);
        if (!macro) return 'missing macro ' + spec.macro;
        if (macro.disabled) return 'disabled macro ' + spec.macro;
        macro.click();
        return null;
      }
      for (const token of spec.keys || []) {
        const button = buttons().find((item_) => item_.getAttribute('data-send') === token);
        if (!button) return 'missing key ' + token;
        if (button.disabled) return 'disabled key ' + token;
        button.click();
        await new Promise((resolve) => setTimeout(resolve, 40));
      }
      return null;
    }, item);

    const expected = Array.isArray(item.frames) ? item.frames.length : 0;
    const deadline = Date.now() + 8000;
    let last = -1;
    while (Date.now() < deadline) {
      const count = await page.evaluate(() => window.__sent.length);
      if (count === expected) break;
      if (count === last && count > expected) break;
      last = count;
      await page.waitForTimeout(50);
    }
    const sent = await page.evaluate(() => window.__sent.map((frame) => Array.from(frame)));
    results.push({ label: item.label, problem, sent });
  }

  const ui = await page.evaluate(() => ({
    key_buttons: document.querySelectorAll('#softkey [data-send]').length,
    macros: Array.from(document.querySelectorAll('#sk-macros button')).map((b) => b.textContent.trim()),
    status: document.getElementById('sk-status').textContent,
    panel_height: Math.round(document.getElementById('softkey').getBoundingClientRect().height),
    levels: Array.from(document.querySelectorAll('#softkey [data-send]'))
      .reduce((acc, button) => {
        const level = button.getAttribute('data-level') || 'none';
        acc[level] = (acc[level] || 0) + 1;
        return acc;
      }, {}),
  }));

  const shot = opt('shot');
  if (shot) await page.screenshot({ path: shot, fullPage: true });

  await browser.close();
  console.log(JSON.stringify({ results, ui, errors }));
}

main().catch((error) => {
  console.error(String((error && error.stack) || error));
  process.exit(1);
});
