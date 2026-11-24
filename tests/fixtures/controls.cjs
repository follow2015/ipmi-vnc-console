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
const ORIGIN = 'https://controls.example';

async function main() {
  const browser = await chromium.launch({
    executablePath: process.env.KVM_CHROMIUM || undefined, headless: true,
  });
  const page = await browser.newPage({ viewport: { width: 1280, height: 620 } });
  const errors = [];
  page.on('pageerror', (error) => errors.push(String(error.message).slice(0, 200)));

  let keymapRequests = 0;
  await page.route(ORIGIN + '/**', (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/console') {
      return route.fulfill({ status: 200, contentType: 'text/html', body: HTML });
    }
    if (path === '/_platform/keymap') {
      keymapRequests += 1;
      return route.fulfill({ status: 200, contentType: 'application/json', body: KEYMAP });
    }
    if (path === '/_platform/meta') {
      return route.fulfill({ status: 200, contentType: 'application/json',
        body: JSON.stringify({ address: '192.0.2.11' }) });
    }
    if (path === '/_platform/limits') {
      return route.fulfill({ status: 200, contentType: 'application/json',
        body: JSON.stringify({ connections: 1, opening: 0, limit: 4 }) });
    }
    return route.fulfill({ status: 200, contentType: 'application/javascript', body: '/* stub */' });
  });

  await page.addInitScript(() => {
    window.RFB = class ControlRFB {
      constructor(options) {
        this.options = options;
        window.__rfb = this;
        this._rfb_state = 'connecting';
        this._sock = { send() {} };
        const canvas = options.target;
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

  const measure = (step) => page.evaluate(([stepLabel, requests]) => {
    const panel = document.getElementById('inputpanel');
    const body = document.getElementById('input-body');
    const toggle = document.getElementById('input-toggle');
    const stage = document.getElementById('stage');
    const canvas = document.getElementById('screen');
    const overlay = document.getElementById('nosignal');
    const key = document.querySelector('#softkey [data-send]');
    const labelEl = document.getElementById('asset-label');
    const zoom = document.getElementById('zoom');
    const cbox = canvas.getBoundingClientRect();
    const tbox = toggle.getBoundingClientRect();
    return {
      step: stepLabel,
      keymapRequests: requests,
      panelWidth: Math.round(panel.getBoundingClientRect().width),
      toggleVisible: tbox.width > 0 && tbox.height > 0,
      inputBodyVisible: body.getBoundingClientRect().height > 0,
      panelCollapsed: panel.classList.contains('collapsed'),
      sheetOpen: document.body.classList.contains('sheet-open'),
      stageWidth: Math.round(stage.getBoundingClientRect().width),
      stageBottom: Math.round(stage.getBoundingClientRect().bottom),
      stageRight: Math.round(stage.getBoundingClientRect().right),
      panelTop: Math.round(panel.getBoundingClientRect().top),
      panelLeft: Math.round(panel.getBoundingClientRect().left),
      keyEnabled: !!key && !key.disabled,
      label: labelEl ? labelEl.textContent : null,
      title: document.title,
      scale: parseFloat(stage.getAttribute('data-scale') || 'NaN'),
      mouseScale: window.__kvm && window.__kvm._mouse ? window.__kvm._mouse._scale : null,
      cssWidth: Math.round(cbox.width),
      cssHeight: Math.round(cbox.height),
      stageOverflow: getComputedStyle(stage).overflow,
      stageScrollHeight: stage.scrollHeight,
      stageClientHeight: stage.clientHeight,
      zoom: zoom ? zoom.textContent : null,
      overlayVisible: overlay ? overlay.getBoundingClientRect().height > 0 : false,
      overlayText: overlay ? overlay.textContent.replace(/\s+/g, ' ').trim() : '',
    };
  }, [step, keymapRequests]);

  const steps = [];
  await page.goto(ORIGIN + '/console', { waitUntil: 'domcontentloaded' });
  await page.waitForFunction(() => {
    const stage = document.getElementById('stage');
    return stage && parseFloat(stage.getAttribute('data-scale') || '0') > 0;
  }, null, { timeout: 20000 });
  await page.waitForTimeout(100);
  steps.push(await measure('initial'));

  await page.click('#zoom-mode');
  await page.waitForTimeout(150);
  steps.push(await measure('fit'));

  await page.evaluate(() => window.__rfb.options.onUpdateFps('No Signal', 'Unknown'));
  steps.push(await measure('nosignal'));
  await page.evaluate(() => window.__rfb.options.onUpdateFps(30, '1024x768'));
  steps.push(await measure('signal'));

  await page.click('#zoom-mode');
  await page.waitForTimeout(150);
  steps.push(await measure('oneone'));

  await page.click('#input-toggle');
  await page.waitForFunction(() => {
    const key = document.querySelector('#softkey [data-send]');
    return !!key && !key.disabled;
  }, null, { timeout: 20000 });
  steps.push(await measure('opened'));

  await page.click('#input-toggle');
  await page.waitForTimeout(150);
  steps.push(await measure('closed'));

  console.log(JSON.stringify({ steps, errors }));
  await browser.close();
}

main().catch((error) => {
  console.error(String((error && error.stack) || error));
  process.exit(1);
});
