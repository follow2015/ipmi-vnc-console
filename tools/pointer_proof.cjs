'use strict';
const PW = process.env.KVM_PLAYWRIGHT;
const CHROME = process.env.KVM_CHROMIUM;
const BASE = process.env.KVM_BASE;
const TOKEN = process.env.KVM_TOKEN;
const ASSET = process.env.KVM_ASSET || 'real-1';
const SHOTS = process.env.KVM_SHOTS;
const { chromium } = require(PW);

const PIXEL_DELTA = 24;
const MAX_MOVES = 16;
const MAX_RIGHT_CLICKS = 3;
const MIN_LIT_PIXELS = 500;

const HOVER_SPOTS = [
  ['top_left', 0.03, 0.03],
  ['top_center', 0.5, 0.03],
  ['top_right', 0.97, 0.03],
  ['left_edge', 0.02, 0.5],
  ['bottom_left', 0.03, 0.97],
  ['bottom_center', 0.5, 0.97],
  ['center', 0.5, 0.5],
  ['center_right', 0.85, 0.5],
  ['upper_center', 0.5, 0.2],
];

let moves = 0;
let rightClicks = 0;

(async () => {
  const result = { steps: [], errors: [], console_errors: [], http_404: [], moves: 0, right_clicks: 0 };
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
    consolePage.on('response', (response) => {
      if (response.status() === 404) result.http_404.push(new URL(response.url()).pathname);
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
        diffBase() { return compare(this.base); },
      };
    }, PIXEL_DELTA);

    result.canvas_lit = await consolePage.evaluate(() => window.__kf.mark());
    if ((result.canvas_lit.lit || 0) < MIN_LIT_PIXELS) {
      result.steps.push('no_signal_detected');
      result.errors.push('framebuffer is blank; no pointer input was sent');
      result.state_after_input = await consolePage.evaluate(() => window.__kvm._rfb_state);
      await consolePage.click('#close');
      await consolePage.waitForTimeout(1200);
      result.steps.push('close_requested');
      throw new Error('blank framebuffer');
    }

    await consolePage.waitForTimeout(1200);
    result.canvas_idle = await consolePage.evaluate(() => window.__kf.diff());
    await consolePage.evaluate(() => window.__kf.keep());
    result.steps.push('idle_sampled');

    const box = await consolePage.locator('#screen').boundingBox();
    if (!box) throw new Error('canvas has no bounding box');
    const at = (fx, fy) => ({ x: box.x + box.width * fx, y: box.y + box.height * fy });
    const canvasDims = await consolePage.evaluate(() => {
      const canvas = document.getElementById('screen');
      return { width: canvas.width, height: canvas.height };
    });

    result.rfb_introspect = await consolePage.evaluate(() => {
      const rfb = window.__kvm;
      const out = { canvas: [document.getElementById('screen').width,
                             document.getElementById('screen').height] };
      for (const key of Object.keys(rfb)) {
        if (!/mouse|pointer|scale|screen|view|size|cursor/i.test(key)) continue;
        const value = rfb[key];
        out[key] = typeof value === 'function' ? 'fn'
          : (value && typeof value === 'object' ? JSON.stringify(value).slice(0, 120) : value);
      }
      return out;
    });
    await consolePage.evaluate(() => {
      window.__sentFrames = [];
      window.__moveArgs = [];
      const rfb = window.__kvm;
      if (typeof rfb._onMouseMove === 'function' && !rfb._onMouseMove.__probed) {
        const original = rfb._onMouseMove.bind(rfb);
        const patched = function (x, y, ev) {
          window.__moveArgs.push([x, y]);
          return original(x, y, ev);
        };
        patched.__probed = true;
        rfb._onMouseMove = patched;
      }
      const sock = rfb._sock;
      if (sock && !sock.__recorded) {
        const original = sock.send.bind(sock);
        sock.send = function (data) {
          try {
            let bytes = null;
            if (data instanceof ArrayBuffer) bytes = new Uint8Array(data);
            else if (ArrayBuffer.isView(data)) {
              bytes = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
            } else if (typeof data === 'string') bytes = new TextEncoder().encode(data);
            if (bytes) window.__sentFrames.push({ n: bytes.length, b: Array.from(bytes).slice(0, 24) });
          } catch (error) { /* recording must never break input */ }
          return original(data);
        };
        sock.__recorded = true;
      }
    });

    result.cursor_steps = [];
    const cursorTargets = [
      ['upper_left', 0.08, 0.08],
      ['lower_right', 0.9, 0.88],
      ['center', 0.5, 0.5],
    ];
    for (const [name, fx, fy] of cursorTargets) {
      await consolePage.evaluate(() => window.__kf.keep());
      const point = at(fx, fy);
      await consolePage.mouse.move(point.x, point.y, { steps: 6 });
      moves += 1;
      await consolePage.waitForTimeout(500);
      const delta = await consolePage.evaluate((target) => {
        const measured = window.__kf.diff();
        const args = window.__moveArgs || [];
        const frames = window.__sentFrames || [];
        const lastArgs = args.length ? args[args.length - 1] : null;
        const recent = frames.slice(-4).map((frame) => frame.b);
        if (!measured.bbox) return { ...measured, target, hit: false, lastArgs, recent };
        const [x, y, w, h] = measured.bbox;
        const tolerance = 30;
        const hit = target[0] >= x - tolerance && target[0] <= x + w + tolerance
          && target[1] >= y - tolerance && target[1] <= y + h + tolerance;
        return { ...measured, target, hit, lastArgs, recent };
      }, [Math.round(fx * canvasDims.width), Math.round(fy * canvasDims.height)]);
      if (SHOTS) {
        await consolePage.screenshot({ path: SHOTS + '/cursor-' + name + '.png' }).catch(() => {});
      }
      result.cursor_steps.push({ spot: name, ...delta });
    }
    result.cursor_hits = result.cursor_steps.filter((step) => step.hit).length;
    result.steps.push('cursor_tracked');

    result.hover = [];
    let bestHover = { spot: null, pixels: 0 };
    for (const [name, fx, fy] of HOVER_SPOTS) {
      if (moves >= MAX_MOVES) break;
      await consolePage.evaluate(() => window.__kf.keep());
      const point = at(fx, fy);
      await consolePage.mouse.move(point.x, point.y, { steps: 4 });
      moves += 1;
      await consolePage.waitForTimeout(650);
      const delta = await consolePage.evaluate(() => window.__kf.diff());
      result.hover.push({ spot: name, ...delta });
      if ((delta.pixels || 0) > bestHover.pixels) bestHover = { spot: name, pixels: delta.pixels || 0 };
    }
    result.best_hover = bestHover;
    result.steps.push('hover_swept');

    if (rightClicks < MAX_RIGHT_CLICKS) {
      await consolePage.evaluate(() => window.__kf.keep());
      const point = at(0.5, 0.62);
      await consolePage.mouse.move(point.x, point.y, { steps: 4 });
      moves += 1;
      await consolePage.waitForTimeout(300);
      await consolePage.evaluate(() => window.__kf.keep());
      await consolePage.mouse.click(point.x, point.y, { button: 'right' });
      rightClicks += 1;
      await consolePage.waitForTimeout(900);
      result.canvas_menu = await consolePage.evaluate(() => window.__kf.diff());
      if (SHOTS) {
        await consolePage.screenshot({ path: SHOTS + '/pointer-menu.png' }).catch(() => {});
      }
      result.steps.push('context_menu_requested');

      await consolePage.keyboard.press('Escape');
      await consolePage.waitForTimeout(900);
      result.canvas_menu_dismissed = await consolePage.evaluate(() => window.__kf.diff());
      result.steps.push('context_menu_dismissed');
    }

    result.moves = moves;
    result.right_clicks = rightClicks;
    result.state_after_input = await consolePage.evaluate(() => window.__kvm._rfb_state);
    result.desktop_name = await consolePage.title();

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
