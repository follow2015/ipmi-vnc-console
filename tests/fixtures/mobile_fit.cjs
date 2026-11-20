'use strict';
const fs = require('fs');
const { chromium } = require(process.env.KVM_PLAYWRIGHT);

const argv = process.argv.slice(2);
function opt(name, fb) { const i = argv.indexOf('--' + name); return i >= 0 ? argv[i + 1] : fb; }
const HTML = fs.readFileSync(opt('html'), 'utf8');
const KEYMAP = fs.readFileSync(opt('keymap'), 'utf8');
const SHOT = opt('shot', null);
const ORIGIN = 'https://mobile.example';

async function main() {
  const browser = await chromium.launch({ executablePath: process.env.KVM_CHROMIUM || undefined, headless: true });
  const context = await browser.newContext({
    viewport: { width: 390, height: 844 },
    deviceScaleFactor: 3,
    isMobile: true,
    hasTouch: true,
    userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1',
  });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', (error) => errors.push(String(error.message).slice(0, 200)));
  await page.route(ORIGIN + '/**', (route) => {
    const p = new URL(route.request().url()).pathname;
    if (p === '/console') return route.fulfill({ status: 200, contentType: 'text/html', body: HTML });
    if (p === '/_platform/keymap') return route.fulfill({ status: 200, contentType: 'application/json', body: KEYMAP });
    if (p === '/_platform/meta') return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ address: '192.0.2.11' }) });
    if (p === '/_platform/limits') return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ connections: 1, opening: 0, limit: 4 }) });
    return route.fulfill({ status: 200, contentType: 'application/javascript', body: '/* stub */' });
  });
  await page.addInitScript(() => {
    window.__fitCalls = [];
    window.RFB = class StandInRFB {
      constructor(o) {
        this.options = o; this._rfb_state = 'connecting'; this._sock = { send() {} };
        const c = o.target, calls = window.__fitCalls;
        this._display = { _fb_width: 0, _fb_height: 0, _scale: 1,
          autoscale(cw, ch, down) {
            const fr = this._fb_width / this._fb_height, tr = cw / ch;
            let r = fr >= tr ? cw / this._fb_width : ch / this._fb_height;
            let w, h;
            if (r > 1 && down) { w = this._fb_width; h = this._fb_height; r = 1; }
            else if (fr >= tr) { w = cw; h = Math.round(cw / fr); }
            else { w = Math.round(ch * fr); h = ch; }
            c.style.width = w + 'px'; c.style.height = h + 'px';
            this._scale = r; calls.push({ cw, ch, r }); return r;
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

  const measure = () => page.evaluate(() => {
    const q = id => document.getElementById(id);
    const box = e => { const b = e.getBoundingClientRect(); return { w: b.width, h: b.height, l: b.left, t: b.top, r: b.right, b: b.bottom }; };
    const stage = q('stage'), canvas = q('screen');
    return {
      coarse: window.matchMedia('(pointer: coarse)').matches,
      visualW: window.visualViewport ? window.visualViewport.width : window.innerWidth,
      stage: { ...box(stage), clientW: stage.clientWidth, clientH: stage.clientHeight,
               scale: parseFloat(stage.getAttribute('data-scale') || 'NaN'),
               overflow: getComputedStyle(stage).overflow,
               justify: getComputedStyle(stage).justifyContent },
      canvas: { ...box(canvas), bitmapW: canvas.width, bitmapH: canvas.height,
                cssW: parseFloat(canvas.style.width), cssH: parseFloat(canvas.style.height) },
      mouseScale: window.__kvm ? window.__kvm._mouse._scale : null,
      hintHidden: q('phone-hint').hidden,
      zoom: q('zoom').textContent,
    };
  });

  const steps = [];
  await page.goto(ORIGIN + '/console', { waitUntil: 'domcontentloaded' });
  await page.waitForFunction(() => {
    const s = document.getElementById('stage');
    return s && parseFloat(s.getAttribute('data-scale') || '0') > 0;
  }, null, { timeout: 20000 });
  await page.waitForTimeout(200);
  const first = await measure();
  steps.push(first);
  if (SHOT) await page.screenshot({ path: SHOT });

  await page.evaluate(() => {
    const stage = document.getElementById('stage');
    const t = (id, x, y) => new Touch({ identifier: id, target: stage, clientX: x, clientY: y });
    const ev = (type, touches) => stage.dispatchEvent(new TouchEvent(type, {
      bubbles: true, cancelable: true,
      touches, targetTouches: touches, changedTouches: touches,
    }));
    ev('touchstart', [t(1, 100, 300), t(2, 200, 300)]);
    ev('touchmove', [t(1, 60, 300), t(2, 260, 300)]);
    ev('touchend', []);
  });
  await page.waitForTimeout(100);
  steps.push(await measure());

  console.log(JSON.stringify({ steps, errors }));
  await browser.close();
}
main().catch((error) => { console.error(String((error && error.stack) || error)); process.exit(1); });
