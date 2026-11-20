'use strict';
const fs = require('fs');
const { chromium } = require(process.env.KVM_PLAYWRIGHT);
const argv = process.argv.slice(2);
function opt(name, fb) { const i = argv.indexOf('--' + name); return i >= 0 ? argv[i + 1] : fb; }
const HTML = fs.readFileSync(opt('html'), 'utf8');
const KEYMAP = fs.readFileSync(opt('keymap'), 'utf8');
const ORIGIN = 'https://keyiso.example';

async function main() {
  const browser = await chromium.launch({ executablePath: process.env.KVM_CHROMIUM || undefined, headless: true });
  const context = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(String(e.message).slice(0, 200)));
  await page.route(ORIGIN + '/**', (route) => {
    const p = new URL(route.request().url()).pathname;
    if (p === '/console') return route.fulfill({ status: 200, contentType: 'text/html', body: HTML });
    if (p === '/_platform/keymap') return route.fulfill({ status: 200, contentType: 'application/json', body: KEYMAP });
    if (p === '/_platform/meta') return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ address: 'x' }) });
    if (p === '/_platform/limits') return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ connections: 1, opening: 0, limit: 4 }) });
    return route.fulfill({ status: 200, contentType: 'application/javascript', body: '/* stub */' });
  });
  await page.addInitScript(() => {
    window.RFB = class StandInRFB {
      constructor(o) {
        this.options = o; this._rfb_state = 'connecting'; this._sock = { send() {} };
        const c = o.target;
        this._display = { _fb_width: 0, _fb_height: 0, _scale: 1,
          autoscale(cw, ch) {
            const r = Math.min(cw / 1024, ch / 768);
            c.style.width = Math.round(1024 * r) + 'px'; c.style.height = Math.round(768 * r) + 'px';
            this._scale = r; return r;
          } };
        this._mouse = { _scale: 1 };
      }
      connect() {
        this._rfb_state = 'normal';
        this.options.onUpdateState(this, 'normal', 'connecting', '');
        this._display._fb_width = 1024; this._display._fb_height = 768;
        this.options.onFBResize(this, 1024, 768);
      }
      disconnect() {}
    };
    window.__docKeys = [];
    ['keydown', 'keyup', 'keypress'].forEach(function (type) {
      document.addEventListener(type, function (e) {
        window.__docKeys.push(e.key || e.which);
        e.preventDefault();
        e.stopPropagation();
      }, false);
    });
  });

  await page.goto(ORIGIN + '/console', { waitUntil: 'domcontentloaded' });
  await page.waitForFunction(() => parseFloat(document.getElementById('stage')?.getAttribute('data-scale') || '0') > 0,
    null, { timeout: 20000 });

  await page.locator('#screen').focus();
  await page.keyboard.press('a');
  const canvasReached = await page.evaluate(() => window.__docKeys.slice());

  await page.evaluate(() => document.getElementById('input-toggle').click());
  await page.evaluate(() => document.getElementById('tab-paste').click());
  await page.waitForTimeout(150);

  await page.evaluate(() => { window.__docKeys = []; });
  await page.locator('#paste-text').click();
  await page.keyboard.type('ls -la /tmp');
  const typed = await page.evaluate(() => ({
    value: document.getElementById('paste-text').value,
    docKeys: window.__docKeys.slice(),
  }));

  await page.locator('#paste-preview').click();
  const sendDisabled = await page.locator('#paste-send').isDisabled();

  console.log(JSON.stringify({ canvasReached, typed, sendDisabled, errors }));
  await browser.close();
}
main().catch((e) => { console.error(String((e && e.stack) || e)); process.exit(1); });
