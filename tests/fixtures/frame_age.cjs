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
const ORIGIN = 'https://softkey.example';

async function main() {
  const browser = await chromium.launch({
    executablePath: process.env.KVM_CHROMIUM || undefined, headless: true,
  });
  const page = await browser.newPage({ viewport: { width: 1100, height: 860 } });
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
        body: JSON.stringify({ address: '192.0.2.11' }) });
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
    window.RFB = class RecordingRFB {
      constructor(options) {
        this.options = options;
        this._rfb_state = 'connecting';
        const listeners = {};
        const raw = {
          addEventListener(type, fn) { (listeners[type] = listeners[type] || []).push(fn); },
          emit(type, event) { (listeners[type] || []).forEach((fn) => fn(event)); },
        };
        this._sock = { _websocket: raw, send() {} };
        this.options.onUpdateState(this, 'loaded', 'disconnected', 'ready');
      }
      connect() {
        setTimeout(() => {
          this._rfb_state = 'normal';
          this.options.onUpdateState(this, 'normal', 'connecting', '');
        }, 0);
      }
      disconnect() { this._rfb_state = 'disconnected'; }
    };
  });

  if (opt('retry', '0') === '1') {
    await page.addInitScript(() => {
      const sid = location.host;
      sessionStorage.setItem('__kvm_recovery_v2_' + sid,
        JSON.stringify({ sid, attempts: 1, total: 1 }));
    });
  }

  const read = () => page.evaluate(() => {
    const el = document.getElementById('frame-age');
    return { text: el ? el.textContent : null, cls: el ? el.className : null };
  });

  await page.goto(ORIGIN + '/console', { waitUntil: 'domcontentloaded' });
  await page.waitForFunction(() => {
    const el = document.getElementById('frame-age');
    return el && el.textContent && el.textContent.length > 0;
  }, null, { timeout: 20000 });

  const steps = [{ step: 'just-connected', ...(await read()) }];
  await page.waitForTimeout(2300);
  steps.push({ step: 'quiet-2s', ...(await read()) });
  await page.evaluate(() => window.__kvm._sock._websocket.emit('message', { data: new ArrayBuffer(8) }));
  await page.waitForTimeout(150);
  steps.push({ step: 'after-update', ...(await read()) });
  await page.waitForTimeout(1300);
  steps.push({ step: 'quiet-again', ...(await read()) });

  const health = await page.evaluate(() => window.__kvm_health);
  console.log(JSON.stringify({ steps, errors, health }));
  await browser.close();
}

main().catch((error) => {
  console.error(String((error && error.stack) || error));
  process.exit(1);
});
