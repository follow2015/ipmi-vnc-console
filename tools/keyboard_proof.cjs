'use strict';
const PW = process.env.KVM_PLAYWRIGHT;
const CHROME = process.env.KVM_CHROMIUM;
const BASE = process.env.KVM_BASE;
const TOKEN = process.env.KVM_TOKEN;
const ASSET = process.env.KVM_ASSET || 'real-1';
const SHOTS = process.env.KVM_SHOTS;
const { chromium } = require(PW);

const TEXT = 'kvmprobe';
const MAX_KEYS = 24;
const PIXEL_DELTA = 24;
const KEY_HOLD_MS = Math.max(0, Number(process.env.KVM_KEY_HOLD_MS || 0) || 0);

async function pressKey(page, key) {
  if (!KEY_HOLD_MS) {
    await page.keyboard.press(key);
    return;
  }
  await page.keyboard.down(key);
  await page.waitForTimeout(KEY_HOLD_MS);
  await page.keyboard.up(key);
}

const FORBIDDEN = new Set([
  'Enter', 'NumpadEnter', 'Tab', 'Escape', 'Delete',
  'ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'Home', 'End',
  'PageUp', 'PageDown', 'Insert', 'Space', 'F1', 'F2', 'F3', 'F4', 'F5',
  'F6', 'F7', 'F8', 'F9', 'F10', 'F11', 'F12',
]);

let keyEvents = 0;

function guardKey(name) {
  if (FORBIDDEN.has(name)) throw new Error('forbidden key rejected by probe policy: ' + name);
  if (/^[a-z]$/.test(name) || name === 'Backspace') return;
  throw new Error('key outside probe whitelist: ' + name);
}

function guardCombo(combo) {
  if (combo !== 'Control+u') throw new Error('combo outside probe whitelist: ' + combo);
}

(async () => {
  const result = { steps: [], errors: [], console_errors: [], http_404: [], keys_sent: 0 };
  let browser;
  try {
    browser = await chromium.launch({ executablePath: CHROME, headless: true });
    const context = await browser.newContext({ ignoreHTTPSErrors: true });
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
      const read = () => {
        const ctx = canvas.getContext('2d');
        return ctx.getImageData(0, 0, canvas.width, canvas.height);
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
        mark() { this.base = read(); this.previous = this.base; return this.base.width * this.base.height; },
        keep() { this.previous = read(); },
        diff() { return compare(this.previous); },
        diffBase() { return compare(this.base); },
      };
      window.__kf.mark();
    }, PIXEL_DELTA);

    await consolePage.waitForTimeout(1500);
    result.canvas_idle = await consolePage.evaluate(() => window.__kf.diff());
    await consolePage.evaluate(() => window.__kf.keep());

    await consolePage.locator('#screen').click({ position: { x: 40, y: 40 } }).catch(() => {});
    await consolePage.evaluate(() => document.getElementById('screen').focus());

    for (const character of TEXT) {
      if (keyEvents >= MAX_KEYS) throw new Error('key budget exhausted');
      guardKey(character);
      await pressKey(consolePage, character);
      keyEvents += 1;
    }
    result.steps.push('letters_typed');
    await consolePage.waitForTimeout(900);
    result.canvas_typed = await consolePage.evaluate(() => window.__kf.diffBase());
    if (SHOTS) {
      await consolePage.screenshot({ path: SHOTS + '/keyboard-typed.png' }).catch(() => {});
    }

    await consolePage.evaluate(() => window.__kf.keep());
    for (let index = 0; index < TEXT.length; index += 1) {
      if (keyEvents >= MAX_KEYS) throw new Error('key budget exhausted');
      guardKey('Backspace');
      await pressKey(consolePage, 'Backspace');
      keyEvents += 1;
    }
    result.steps.push('letters_erased');
    await consolePage.waitForTimeout(900);
    result.canvas_erase_change = await consolePage.evaluate(() => window.__kf.diff());
    result.canvas_restored = await consolePage.evaluate(() => window.__kf.diffBase());
    if (SHOTS) {
      await consolePage.screenshot({ path: SHOTS + '/keyboard-erased.png' }).catch(() => {});
    }

    guardCombo('Control+u');
    await consolePage.keyboard.press('Control+u');
    keyEvents += 1;
    result.steps.push('line_cleared');

    result.keys_sent = keyEvents;
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
