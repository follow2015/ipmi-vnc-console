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
const SHOT = opt('shot', null);
const ORIGIN = 'https://softkey.example';

async function main() {
  const browser = await chromium.launch({
    executablePath: process.env.KVM_CHROMIUM || undefined, headless: true,
  });
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
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
    window.__fitCalls = [];
    window.RFB = class StandInRFB {
      constructor(options) {
        this.options = options;
        this._rfb_state = 'connecting';
        this._sock = { send() {} };
        const canvas = options.target;
        const calls = window.__fitCalls;
        this._display = {
          _fb_width: 0, _fb_height: 0, _scale: 1,
          autoscale(cw, ch, downscaleOnly) {
            const fbRatio = this._fb_width / this._fb_height;
            const targetRatio = cw / ch;
            let ratio = fbRatio >= targetRatio
              ? cw / this._fb_width
              : ch / this._fb_height;
            let tw;
            let th;
            if (ratio > 1.0 && downscaleOnly) {
              tw = this._fb_width; th = this._fb_height; ratio = 1.0;
            } else if (fbRatio >= targetRatio) {
              tw = cw; th = Math.round(cw / fbRatio);
            } else {
              tw = Math.round(ch * fbRatio); th = ch;
            }
            canvas.style.width = tw + 'px';
            canvas.style.height = th + 'px';
            this._scale = ratio;
            calls.push({ cw, ch, ratio });
            return ratio;
          },
        };
        this._mouse = { _scale: 1 };
      }
      connect() {
        this._rfb_state = 'normal';
        this.options.onUpdateState(this, 'normal', 'connecting', '');
        this._display._fb_width = 1024;
        this._display._fb_height = 768;
        this.options.onFBResize(this, 1024, 768);
      }
      disconnect() {}
    };
  });

  const measure = (step) => page.evaluate((label) => {
    const stage = document.getElementById('stage');
    const panel = document.getElementById('inputpanel');
    const canvas = document.getElementById('screen');
    const sbox = stage.getBoundingClientRect();
    const pbox = panel.getBoundingClientRect();
    const cbox = canvas.getBoundingClientRect();
    const zoom = document.getElementById('zoom');
    const pad = 8;
    const availW = stage.clientWidth - pad * 2;
    const availH = stage.clientHeight - pad * 2;
    const expected = Math.min(availW / canvas.width, availH / canvas.height, 1);
    return {
      step: label,
      viewport: { width: window.innerWidth, height: window.innerHeight },
      stage: { width: sbox.width, height: sbox.height, left: sbox.left, top: sbox.top,
        right: sbox.right, bottom: sbox.bottom, clientWidth: stage.clientWidth,
        clientHeight: stage.clientHeight },
      panel: { height: pbox.height, top: pbox.top, bottom: pbox.bottom,
        scrollHeight: panel.scrollHeight, clientHeight: panel.clientHeight },
      canvas: { cssWidth: cbox.width, cssHeight: cbox.height, left: cbox.left,
        top: cbox.top, right: cbox.right, bottom: cbox.bottom,
        bitmapWidth: canvas.width, bitmapHeight: canvas.height },
      scale: parseFloat(stage.getAttribute('data-scale') || 'NaN'),
      mouseScale: (window.__kvm && window.__kvm._mouse) ? window.__kvm._mouse._scale : null,
      expected,
      zoom: zoom ? zoom.textContent : null,
      keyboardOpen: !document.getElementById('sk-body').classList.contains('hidden'),
      pageScrollHeight: document.documentElement.scrollHeight,
      fitCalls: window.__fitCalls.length,
    };
  }, step);

  const steps = [];
  await page.goto(ORIGIN + '/console', { waitUntil: 'domcontentloaded' });
  await page.waitForFunction(() => {
    const canvas = document.getElementById('screen');
    return canvas && parseFloat(document.getElementById('stage').getAttribute('data-scale') || '0') > 0;
  }, null, { timeout: 20000 });

  await page.click('#input-toggle');
  await page.waitForTimeout(150);

  steps.push(await measure('900-keyboard-collapsed'));

  await page.click('#softkey-toggle');
  await page.waitForTimeout(200);
  steps.push(await measure('900-keyboard-open'));
  if (SHOT) await page.screenshot({ path: SHOT });

  await page.setViewportSize({ width: 1280, height: 720 });
  await page.waitForTimeout(250);
  steps.push(await measure('720-keyboard-open'));

  await page.click('#softkey-toggle');
  await page.waitForTimeout(200);
  steps.push(await measure('720-keyboard-collapsed'));

  await page.click('#softkey-toggle');
  await page.setViewportSize({ width: 1600, height: 1000 });
  await page.waitForTimeout(250);
  steps.push(await measure('1000-keyboard-open'));

  console.log(JSON.stringify({ steps, errors }));
  await browser.close();
}

main().catch((error) => {
  console.error(String((error && error.stack) || error));
  process.exit(1);
});
