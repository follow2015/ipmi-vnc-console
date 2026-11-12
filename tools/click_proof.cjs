'use strict';
const PW = process.env.KVM_PLAYWRIGHT;
const CHROME = process.env.KVM_CHROMIUM;
const BASE = process.env.KVM_BASE;
const TOKEN = process.env.KVM_TOKEN;
const ASSET = process.env.KVM_ASSET || 'real-1';
const SHOTS = process.env.KVM_SHOTS;
const UNLOCK = process.env.KVM_UNLOCK === '1';
const CLICK_X = Number(process.env.KVM_CLICK_X || 512);
const CLICK_Y = Number(process.env.KVM_CLICK_Y || 384);
const DISMISS_X = process.env.KVM_DISMISS_X ? Number(process.env.KVM_DISMISS_X) : null;
const DISMISS_Y = process.env.KVM_DISMISS_Y ? Number(process.env.KVM_DISMISS_Y) : null;
const { chromium } = require(PW);

const PIXEL_DELTA = 24;
const MIN_LIT_PIXELS = 500;
const MAX_CLICKS = 2;
const BIG_CHANGE = 1500;
const MIN_SECONDS_BEFORE_BOUNDARY = 40;

let clicks = 0;
const sentFrames = [];
let wsSockets = 0;

const shot = async (page, name) => {
  if (SHOTS) await page.screenshot({ path: SHOTS + '/click-' + name + '.png' }).catch(() => {});
};

(async () => {
  const result = { steps: [], errors: [], console_errors: [], clicks: 0 };
  let browser;
  try {
    browser = await chromium.launch({ executablePath: CHROME, headless: true });
    const context = await browser.newContext({
      ignoreHTTPSErrors: true, viewport: { width: 1280, height: 900 },
    });
    const page = await context.newPage();
    page.on('pageerror', (error) => result.console_errors.push(String(error.message).slice(0, 200)));

    await page.goto(BASE, { waitUntil: 'domcontentloaded', timeout: 30000 });
    await page.fill('input[name=token]', TOKEN);
    await page.click('button');
    await page.waitForSelector(`[data-open="${ASSET}"]`, { timeout: 20000 });
    result.steps.push('manager_login');

    const [consolePage] = await Promise.all([
      context.waitForEvent('page', { timeout: 20000 }),
      page.click(`[data-open="${ASSET}"]`),
    ]);
    consolePage.on('pageerror', (error) => result.console_errors.push(String(error.message).slice(0, 200)));
    consolePage.on('console', (message) => {
      if (message.type() === 'error') result.console_errors.push(message.text().slice(0, 200));
    });
    consolePage.on('websocket', (socket) => {
      wsSockets += 1;
      socket.on('framesent', (frame) => {
        const payload = frame.payload;
        if (typeof payload === 'string') return;
        const bytes = Array.from(payload);
        if (bytes.length <= 24) sentFrames.push(bytes);
      });
    });
    await consolePage.waitForURL(/w1-[0-9a-f]{32}\.kvm\.localhost/, { timeout: 30000 });
    await consolePage.waitForLoadState('domcontentloaded');
    result.steps.push('console_opened');

    await consolePage.waitForFunction(
      () => window.__kvm && window.__kvm._rfb_state === 'normal', null, { timeout: 40000 });
    result.steps.push('rfb_normal');

    let lastSize = '';
    let stable = 0;
    for (let attempt = 0; attempt < 40 && stable < 3; attempt += 1) {
      const size = await consolePage.evaluate(() => {
        const canvas = document.getElementById('screen');
        return canvas.width + 'x' + canvas.height;
      });
      if (size === lastSize) stable += 1;
      else { lastSize = size; stable = 0; }
      if (stable < 3) await consolePage.waitForTimeout(250);
    }
    result.canvas_size = lastSize;
    result.canvas_size_stable = stable >= 3;
    result.steps.push('framebuffer_settled');

    await consolePage.evaluate((pixelDelta) => {
      const canvas = document.getElementById('screen');
      const read = () => canvas.getContext('2d').getImageData(0, 0, canvas.width, canvas.height);
      const lit = (image) => {
        let count = 0;
        for (let i = 0; i < image.data.length; i += 4) {
          if (image.data[i] + image.data[i + 1] + image.data[i + 2] > 24) count += 1;
        }
        return count;
      };
      const compare = (before) => {
        const after = read();
        if (!before || before.width !== after.width || before.height !== after.height) {
          return { resized: true, pixels: -1, width: after.width, height: after.height };
        }
        let pixels = 0, x0 = 1e9, y0 = 1e9, x1 = -1, y1 = -1;
        const a = before.data, b = after.data;
        for (let y = 0; y < after.height; y += 1) {
          for (let x = 0; x < after.width; x += 1) {
            const i = (y * after.width + x) * 4;
            if (Math.abs(a[i] - b[i]) + Math.abs(a[i + 1] - b[i + 1]) + Math.abs(a[i + 2] - b[i + 2]) > pixelDelta) {
              pixels += 1;
              if (x < x0) x0 = x;
              if (x > x1) x1 = x;
              if (y < y0) y0 = y;
              if (y > y1) y1 = y;
            }
          }
        }
        return {
          pixels, width: after.width, height: after.height,
          bbox: pixels ? [x0, y0, x1 - x0 + 1, y1 - y0 + 1] : null,
        };
      };
      window.__kf = {
        mark() { this.base = read(); this.previous = this.base; return { lit: lit(this.base), width: this.base.width, height: this.base.height }; },
        keep() { this.previous = read(); },
        diff() { return compare(this.previous); },
      };
    }, PIXEL_DELTA);

    result.canvas_lit = await consolePage.evaluate(() => window.__kf.mark());
    if ((result.canvas_lit.lit || 0) < MIN_LIT_PIXELS) {
      result.steps.push('no_signal_detected');
      result.errors.push('framebuffer is blank; no click was sent');
      result.state_after_input = await consolePage.evaluate(() => window.__kvm._rfb_state);
      await consolePage.click('#close');
      await consolePage.waitForTimeout(1200);
      throw new Error('blank framebuffer');
    }

    result.sock_hook = await consolePage.evaluate(() => {
      window.__frames = [];
      const rfb = window.__kvm;
      const sock = rfb && rfb._sock;
      if (!sock) return { attached: false, reason: 'client object has no _sock' };
      if (!sock.__recordedForClick) {
        const original = sock.send.bind(sock);
        sock.send = function (data) {
          try {
            let bytes = null;
            if (data instanceof ArrayBuffer) bytes = new Uint8Array(data);
            else if (ArrayBuffer.isView(data)) bytes = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
            if (bytes && bytes.length <= 24) window.__frames.push(Array.from(bytes));
          } catch (error) { /* recording must never break input */ }
          return original(data);
        };
        sock.__recordedForClick = true;
      }
      return { attached: true, keys: Object.keys(sock).slice(0, 12) };
    });

    await consolePage.waitForTimeout(1200);
    result.canvas_idle = await consolePage.evaluate(() => window.__kf.diff());
    await shot(consolePage, 'before');
    result.steps.push('idle_sampled');

    const box = await consolePage.locator('#screen').boundingBox();
    if (!box) throw new Error('canvas has no bounding box');
    const canvasDims = await consolePage.evaluate(() => {
      const canvas = document.getElementById('screen');
      return { width: canvas.width, height: canvas.height };
    });
    const toPage = (fx, fy) => ({
      x: box.x + (fx / canvasDims.width) * box.width,
      y: box.y + (fy / canvasDims.height) * box.height,
    });

    if (UNLOCK) {
      await consolePage.evaluate(() => window.__kf.keep());
      await consolePage.keyboard.press('Control+Alt+Delete');
      await consolePage.waitForTimeout(2200);
      result.prepared_screen = await consolePage.evaluate(() => window.__kf.diff());
      await shot(consolePage, 'screen');
      result.steps.push('unlock_gesture_sent');
    }

    for (let guard = 0; guard < 60; guard += 1) {
      if (new Date().getSeconds() < MIN_SECONDS_BEFORE_BOUNDARY) break;
      await consolePage.waitForTimeout(1000);
    }
    result.measurement_window = new Date().toISOString();

    const target = toPage(CLICK_X, CLICK_Y);
    await consolePage.mouse.move(target.x, target.y, { steps: 6 });
    await consolePage.waitForTimeout(700);
    await consolePage.evaluate(() => window.__kf.keep());
    await consolePage.waitForTimeout(500);
    await consolePage.evaluate(() => window.__kf.keep());
    await shot(consolePage, 'parked');
    result.steps.push('pointer_parked');

    await consolePage.mouse.click(target.x, target.y, { button: 'left' });
    clicks += 1;
    await consolePage.waitForTimeout(1100);
    result.clicked = await consolePage.evaluate(() => window.__kf.diff());
    await shot(consolePage, 'clicked');
    result.steps.push('clicked');

    if (result.clicked.bbox) {
      const [x, y, w, h] = result.clicked.bbox;
      const tolerance = 260;
      result.change_at_target = CLICK_X >= x - tolerance && CLICK_X <= x + w + tolerance
        && CLICK_Y >= y - tolerance && CLICK_Y <= y + h + tolerance;
    } else {
      result.change_at_target = false;
    }

    await consolePage.keyboard.press('Escape');
    await consolePage.waitForTimeout(1100);
    let restored = await consolePage.evaluate(() => window.__kf.diff());
    let method = 'escape';
    await shot(consolePage, 'restored');
    result.steps.push('dismissed:escape');

    const stillOpen = (restored.pixels || 0) >= Math.max(BIG_CHANGE, (result.clicked.pixels || 0) * 0.5);
    if (stillOpen && DISMISS_X !== null && DISMISS_Y !== null && clicks < MAX_CLICKS) {
      const away = toPage(DISMISS_X, DISMISS_Y);
      await consolePage.mouse.move(away.x, away.y, { steps: 5 });
      await consolePage.waitForTimeout(350);
      await consolePage.mouse.click(away.x, away.y, { button: 'left' });
      clicks += 1;
      await consolePage.waitForTimeout(1100);
      const second = await consolePage.evaluate(() => window.__kf.diff());
      await shot(consolePage, 'restored2');
      result.steps.push('dismissed:outside_click');
      if ((second.pixels || 0) < (restored.pixels || 0)) { restored = second; method = 'outside_click'; }
    }
    result.restored = restored;
    result.restored_by = method;

    const hookedFrames = await consolePage.evaluate(() => window.__frames || []);
    const shapes = {};
    for (const frame of sentFrames.concat(hookedFrames)) {
      const key = frame.length + ':' + frame.map((b) => b.toString(16).padStart(2, '0')).join('');
      shapes[key] = (shapes[key] || 0) + 1;
    }
    result.wire_frames = {
      websocket_events: wsSockets,
      playwright_frames: sentFrames.length,
      sock_hook_frames: hookedFrames.length,
      shapes,
      last: (hookedFrames.length ? hookedFrames : sentFrames).slice(-8),
    };

    const allFrames = hookedFrames.length ? hookedFrames : sentFrames;
    result.wire_pointer_sequence = allFrames
      .filter((frame) => frame.length >= 7 && frame[0] === 5)
      .map((frame) => ({ mask: frame[2], x: frame[3] * 256 + frame[4], y: frame[5] * 256 + frame[6] }));
    const masks = result.wire_pointer_sequence.map((event) => event.mask);
    result.press_and_release_paired = masks.includes(1)
      && masks.slice(masks.indexOf(1)).includes(0);
    result.clicks = clicks;
    result.desktop_name = await consolePage.title();
    result.state_after_input = await consolePage.evaluate(() => window.__kvm._rfb_state);

    await consolePage.click('#close');
    await consolePage.waitForTimeout(1500);
    result.steps.push('close_requested');
  } catch (error) {
    result.errors.push(String((error && error.message) || error).slice(0, 300));
  } finally {
    if (browser) await browser.close().catch(() => {});
  }
  process.stdout.write('RESULT ' + JSON.stringify(result) + '\n');
})();
