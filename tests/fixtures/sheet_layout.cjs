'use strict';
const fs = require('fs');
const { chromium } = require(process.env.KVM_PLAYWRIGHT);
const argv = process.argv.slice(2);
function opt(name, fb) { const i = argv.indexOf('--' + name); return i >= 0 ? argv[i + 1] : fb; }
const HTML = fs.readFileSync(opt('html'), 'utf8');
const KEYMAP = fs.readFileSync(opt('keymap'), 'utf8');
const W = parseInt(opt('width', '1280'), 10);
const H = parseInt(opt('height', '900'), 10);
const TOUCH = opt('touch', '0') === '1';
const SHOT = opt('shot', null);
const ORIGIN = 'https://sheet.example';

async function main() {
  const browser = await chromium.launch({ executablePath: process.env.KVM_CHROMIUM || undefined, headless: true });
  const context = await browser.newContext({
    viewport: { width: W, height: H }, deviceScaleFactor: 1,
    hasTouch: TOUCH,
  });
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
  const before = await page.evaluate(() => {
    const b = id => { const r = document.getElementById(id).getBoundingClientRect(); return { w: Math.round(r.width), h: Math.round(r.height), t: Math.round(r.top), b: Math.round(r.bottom), l: Math.round(r.left), r: Math.round(r.right) }; };
    return { stage: b('stage'), canvas: b('screen'), panel: b('inputpanel') };
  });
  await page.evaluate(() => document.getElementById('input-toggle').click());
  await page.waitForTimeout(250);
  const after = await page.evaluate(() => {
    const b = id => { const r = document.getElementById(id).getBoundingClientRect(); return { w: Math.round(r.width), h: Math.round(r.height), t: Math.round(r.top), b: Math.round(r.bottom), l: Math.round(r.left), r: Math.round(r.right) }; };
    const soft = document.getElementById('softkey');
    const paste = document.getElementById('pastebar');
    return {
      sheetOpen: document.body.classList.contains('sheet-open'),
      stage: b('stage'), canvas: b('screen'), panel: b('inputpanel'),
      keyboardFirst: getComputedStyle(soft).display !== 'none' && getComputedStyle(paste).display === 'none',
      visibleKeyCount: [].slice.call(document.querySelectorAll('#softkey [data-send]'))
        .filter(k => getComputedStyle(k.closest('.skrow')).display !== 'none').length,
      viewportW: Math.round(document.documentElement.clientWidth),
      keyRows: [...document.querySelectorAll('#sk-body .skrow[data-skpage="chars"]')].map(row => {
        const keys = [...row.querySelectorAll('button')];
        const rects = keys.map(key => key.getBoundingClientRect());
        return {
          sameLine: rects.every(rect => Math.abs(rect.top - rects[0].top) < 1),
          labelsFit: keys.every(key => key.scrollWidth <= key.clientWidth + 1),
          height: Math.min(...rects.map(rect => rect.height)),
        };
      }),
      keyboardScrolls: document.getElementById('sk-keybed').scrollWidth > document.getElementById('sk-keybed').clientWidth,
      pageOverflows: document.documentElement.scrollWidth > window.innerWidth,
    };
  });
  const keybed = page.locator('#sk-keybed');
  await keybed.evaluate(el => { el.scrollLeft = el.scrollWidth; });
  const endKeyReachable = await page.evaluate(() => {
    const key = document.querySelector('[data-send="bksp"]').getBoundingClientRect();
    const bed = document.getElementById('sk-keybed').getBoundingClientRect();
    return key.left >= bed.left - 1 && key.right <= bed.right + 1;
  });
  await keybed.evaluate(el => { el.scrollLeft = 0; });
  after.endKeyReachable = endKeyReachable;
  if (SHOT) await page.screenshot({ path: SHOT, fullPage: false });
  const widgetState = () => page.evaluate(() => {
    const panel = document.getElementById('inputpanel').getBoundingClientRect();
    const canvas = document.getElementById('screen').getBoundingClientRect();
    return { x: panel.x, y: panel.y, w: panel.width, h: panel.height,
      scale: parseFloat(document.getElementById('inputpanel').dataset.widgetScale),
      canvas: { w: canvas.width, h: canvas.height },
      inside: panel.left >= 0 && panel.top >= 0 && panel.right <= innerWidth + 1 && panel.bottom <= innerHeight + 1 };
  });
  const widgetBefore = await widgetState();
  await page.selectOption('#widget-scale', '0.5');
  await page.waitForTimeout(80);
  const scaled = await widgetState();
  const dragBox = await page.locator('#input-bar').boundingBox();
  await page.mouse.move(dragBox.x + 8, dragBox.y + 8);
  await page.mouse.down();
  await page.mouse.move(40, 30, { steps: 8 });
  await page.mouse.up();
  const dragged = await widgetState();
  await page.selectOption('#widget-scale', '1.2');
  await page.setViewportSize({ width: 640, height: 420 });
  await page.waitForTimeout(100);
  const resized = await widgetState();
  await page.locator('#widget-reset').click();
  const reset = await widgetState();
  console.log(JSON.stringify({ W, H, TOUCH, before, after, errors,
    widget: { before: widgetBefore, scaled, dragged, resized, reset } }));
  await browser.close();
}
main().catch((e) => { console.error(String((e && e.stack) || e)); process.exit(1); });
