'use strict';
const fs = require('fs');
const { chromium } = require(process.env.KVM_PLAYWRIGHT);

const argv = process.argv.slice(2);
function opt(name, fb) { const i = argv.indexOf('--' + name); return i >= 0 ? argv[i + 1] : fb; }
const HTML = fs.readFileSync(opt('html'), 'utf8');
const KEYMAP = fs.readFileSync(opt('keymap'), 'utf8');
const ORIGIN = 'https://softkey.example';

async function main() {
  const browser = await chromium.launch({ executablePath: process.env.KVM_CHROMIUM || undefined, headless: true });
  const context = await browser.newContext({ viewport: { width: 1280, height: 900 }, deviceScaleFactor: 1 });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(String(e.message).slice(0, 200)));
  await page.route(ORIGIN + '/**', (route) => {
    const p = new URL(route.request().url()).pathname;
    if (p === '/console') return route.fulfill({ status: 200, contentType: 'text/html', body: HTML });
    if (p === '/_platform/keymap') return route.fulfill({ status: 200, contentType: 'application/json', body: KEYMAP });
    if (p === '/_platform/meta') return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ address: '192.0.2.11' }) });
    if (p === '/_platform/limits') return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ connections: 1, opening: 0, limit: 4 }) });
    return route.fulfill({ status: 200, contentType: 'application/javascript', body: '/* stub */' });
  });
  await page.addInitScript(() => {
    window.__sent = [];
    window.RFB = class StandInRFB {
      constructor(o) {
        this.options = o; this._rfb_state = 'connecting'; this._sock = { send() {} };
        const c = o.target;
        this._display = { _fb_width: 0, _fb_height: 0, _scale: 1,
          autoscale(cw, ch, down) {
            const fr = this._fb_width / this._fb_height, tr = cw / ch;
            let r = fr >= tr ? cw / this._fb_width : ch / this._fb_height;
            let w, h;
            if (r > 1 && down) { w = this._fb_width; h = this._fb_height; r = 1; }
            else if (fr >= tr) { w = cw; h = Math.round(cw / fr); }
            else { w = Math.round(ch * fr); h = ch; }
            c.style.width = w + 'px'; c.style.height = h + 'px';
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
  });

  await page.goto(ORIGIN + '/console', { waitUntil: 'domcontentloaded' });
  await page.waitForFunction(() => parseFloat(document.getElementById('stage')?.getAttribute('data-scale') || '0') > 0,
    null, { timeout: 20000 });
  await page.evaluate(() => document.getElementById('input-toggle').click());
  await page.waitForTimeout(250);
  const collapsed = await page.evaluate(() => document.getElementById('sk-body').classList.contains('hidden'));
  if (collapsed) await page.evaluate(() => document.getElementById('softkey-toggle').click());
  await page.waitForTimeout(150);

  const snap = () => page.evaluate(() => {
    const q = id => document.getElementById(id);
    const activeTab = document.querySelector('#sk-tabs .sktab.on');
    const visibleRowPages = [].slice.call(document.querySelectorAll('#sk-body .skrow'))
      .filter(r => getComputedStyle(r).display !== 'none')
      .map(r => r.getAttribute('data-skpage'));
    return {
      page: q('sk-body').getAttribute('data-page'),
      activeTab: activeTab ? activeTab.textContent : null,
      visibleRowPages: [...new Set(visibleRowPages)],
      visibleKeyCount: [].slice.call(document.querySelectorAll('#softkey [data-send]'))
        .filter(k => getComputedStyle(k.closest('.skrow')).display !== 'none').length,
      modState: q('sk-modstate').textContent,
      modStateOn: q('sk-modstate').classList.contains('on'),
      brokenKeys: document.querySelectorAll('#softkey [data-level="known_broken"]').length,
      verifiedKeys: document.querySelectorAll('#softkey [data-level="verified"]').length,
    };
  });

  const steps = [];
  steps.push(await snap()); // default: chars
  await page.evaluate(() => document.querySelector('#sk-tabs [data-skpage="symbols"]').click());
  await page.waitForTimeout(80);
  steps.push(await snap()); // symbols
  await page.evaluate(() => document.querySelector('#sk-tabs [data-skpage="func"]').click());
  await page.waitForTimeout(80);
  steps.push(await snap()); // func
  await page.evaluate(() => {
    const b = document.querySelector('#softkey [data-send="lctrl"]');
    if (b && !b.disabled) b.click();
  });
  await page.waitForTimeout(80);
  steps.push(await snap()); // ctrl latched (still func page)
  console.log(JSON.stringify({ steps, errors }));
  await browser.close();
}
main().catch((e) => { console.error(String((e && e.stack) || e)); process.exit(1); });
