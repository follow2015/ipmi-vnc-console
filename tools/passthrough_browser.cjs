'use strict';
const PW = process.env.KVM_PLAYWRIGHT;
const CHROME = process.env.KVM_CHROMIUM;
const BASE = process.env.KVM_BASE;
const TOKEN = process.env.KVM_TOKEN;
const ASSET = process.env.KVM_ASSET || 'real-1';
const SCRIPT = (() => {
  try {
    const parsed = JSON.parse(process.env.KVM_SCRIPT || '[]');
    return Array.isArray(parsed) ? parsed : [];
  } catch (_) {
    return [];
  }
})();
const SECRET = process.env.KVM_SECRET || '';
const SHOT_DIR = process.env.KVM_SHOT_DIR || '';
const REVOKE = process.env.KVM_REVOKE_MODE === '1';
const REVOKE_TIMEOUT = Number(process.env.KVM_REVOKE_TIMEOUT_MS || 20000);
const SECOND_TAB = process.env.KVM_SECOND_TAB === '1';
const MODIFIERS = (() => {
  try {
    const parsed = JSON.parse(process.env.KVM_MODIFIERS || '[]');
    return Array.isArray(parsed) ? parsed.filter((name) => typeof name === 'string') : [];
  } catch (_) {
    return [];
  }
})();

const SHIFTED = {
  '!': '1', '@': '2', '#': '3', '$': '4', '%': '5', '^': '6', '&': '7', '*': '8',
  '(': '9', ')': '0', '_': '-', '+': '=', '{': '[', '}': ']', '|': '\\',
  ':': ';', '"': "'", '<': ',', '>': '.', '?': '/', '~': '`',
};

async function typeText(page, text, delay) {
  for (const char of text) {
    const base = char.toUpperCase() === char && char.toLowerCase() !== char
      ? char.toLowerCase()
      : SHIFTED[char];
    if (base) {
      await page.keyboard.down('Shift');
      await page.keyboard.press(base);
      await page.keyboard.up('Shift');
    } else {
      await page.keyboard.press(char === ' ' ? 'Space' : char);
    }
    await page.waitForTimeout(delay || 40);
  }
}

const { chromium } = require(PW);

(async () => {
  const result = { steps: [], errors: [], console_errors: [], http_404: [] };
  let browser;
  try {
    browser = await chromium.launch({ executablePath: CHROME, headless: true });
    const context = await browser.newContext({ ignoreHTTPSErrors: true });
    const page = await context.newPage();
    page.on('pageerror', (error) => result.console_errors.push(String(error.message).slice(0, 200)));
    page.on('response', (response) => {
      if (response.status() === 404) result.http_404.push(new URL(response.url()).pathname);
    });

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

    const canvasStats = () => consolePage.evaluate(() => {
      const canvas = document.getElementById('screen');
      const context2d = canvas.getContext('2d');
      const pixels = context2d.getImageData(0, 0, canvas.width, canvas.height).data;
      let nonBlack = 0;
      let hash = 2166136261;
      for (let i = 0, pixel = 0; i < pixels.length; i += 4, pixel += 1) {
        if (pixels[i] + pixels[i + 1] + pixels[i + 2] > 24) nonBlack += 1;
        if (pixel % 97 === 0) {
          hash ^= pixels[i] + (pixels[i + 1] << 8) + (pixels[i + 2] << 16);
          hash = Math.imul(hash, 16777619) >>> 0;
        }
      }
      return {
        width: canvas.width, height: canvas.height,
        total: canvas.width * canvas.height,
        non_black: nonBlack,
        ratio: canvas.width * canvas.height ? nonBlack / (canvas.width * canvas.height) : 0,
        fingerprint: hash,
      };
    });

    await consolePage.waitForTimeout(1500);
    result.canvas_initial = await canvasStats();

    await consolePage.evaluate(() => {
      const sock = window.__kvm._sock;
      window.__kvmSent = 0;
      if (!sock.__counted) {
        const original = sock.send.bind(sock);
        sock.send = function (data) {
          window.__kvmSent += (data && data.length) || 0;
          return original(data);
        };
        sock.__counted = true;
      }
    });
    let sentBefore = await consolePage.evaluate(() => window.__kvmSent);
    let carriedBytes = 0;

    const box = await consolePage.locator('#screen').boundingBox();
    if (box) {
      await consolePage.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
      await consolePage.mouse.move(box.x + box.width / 2 + 30, box.y + box.height / 2 + 18);
      result.steps.push('pointer_sent');
    }

    const releaseModifiers = async () => {
      for (const name of MODIFIERS) {
        await consolePage.keyboard.down(name).catch(() => {});
        await consolePage.keyboard.up(name).catch(() => {});
      }
      if (MODIFIERS.length) result.modifiers_cleared = MODIFIERS.slice();
    };

    if (SCRIPT.length === 0) {
      await releaseModifiers();
      sentBefore = await consolePage.evaluate(() => window.__kvmSent);
      await consolePage.keyboard.press('Shift');
      result.steps.push('shift_sent');
    } else {
      if (box) await consolePage.mouse.click(box.x + 20, box.y + 20);
      await releaseModifiers();
      sentBefore = await consolePage.evaluate(() => window.__kvmSent);
      result.step_samples = [];
      for (const step of SCRIPT) {
        const secret = step.text === '@secret';
        const text = secret ? SECRET : String(step.text);
        if (secret && !text) {
          result.errors.push('secret_not_provided');
          break;
        }
        if (step.reload) {
          const beforeReload = await canvasStats();
          carriedBytes += await consolePage.evaluate(() => window.__kvmSent || 0);
          await consolePage.reload({ waitUntil: 'domcontentloaded' });
          await consolePage.waitForFunction(
            () => window.__kvm && window.__kvm._rfb_state === 'normal',
            null, { timeout: 25000 }).catch(() => {});
          await consolePage.waitForTimeout(step.wait || 3000);
          if (SHOT_DIR && step.shot) {
            await consolePage.screenshot({ path: `${SHOT_DIR}/${step.shot}.png` }).catch(() => {});
          }
          const state = await consolePage.evaluate(() => window.__kvm && window.__kvm._rfb_state);
          const canvas = await canvasStats();
          result.step_samples.push({ label: step.label, reload: true, state, canvas,
                                     fingerprint_before: beforeReload.fingerprint });
          if (state !== 'normal') result.errors.push(`step_state_${step.label}:${state}`);
          continue;
        }
        if (SHOT_DIR && step.shot_before) {
          await consolePage.screenshot({ path: `${SHOT_DIR}/${step.shot_before}.png` }).catch(() => {});
        }
        await consolePage.waitForTimeout(200);
        const before = await canvasStats();
        if (step.keys) {
          await consolePage.keyboard.press(step.keys);
        } else {
          await typeText(consolePage, text, step.delay || 55);
          if (step.enter !== false) await consolePage.keyboard.press('Enter');
        }
        await consolePage.waitForTimeout(step.wait || 1200);
        if (SHOT_DIR && step.shot) {
          await consolePage.screenshot({ path: `${SHOT_DIR}/${step.shot}.png` }).catch(() => {});
        }
        const state = await consolePage.evaluate(() => window.__kvm._rfb_state);
        const canvas = await canvasStats();
        if (step.label === 'probe_echo') {
          result.probe = { before: before.fingerprint, after: canvas.fingerprint,
                           changed: before.fingerprint !== canvas.fingerprint };
        }
        result.step_samples.push({
          label: step.label, secret, chars: secret ? null : text.length, state, canvas,
          fingerprint_before: before.fingerprint,
        });
        if (state !== 'normal') {
          result.errors.push(`step_state_${step.label}:${state}`);
          break;
        }
      }
      result.steps.push('script_typed');
    }

    await consolePage.waitForTimeout(1500);
    result.canvas_after_input = await canvasStats();
    result.client_bytes_before = sentBefore;
    result.client_bytes_after = carriedBytes + await consolePage.evaluate(() => window.__kvmSent || 0);
    result.state_after_input = await consolePage.evaluate(() => window.__kvm._rfb_state);
    result.desktop_name = await consolePage.title();

    if (process.env.KVM_SCREENSHOT) {
      await consolePage.screenshot({ path: process.env.KVM_SCREENSHOT }).catch(() => {});
      result.screenshot = true;
    }

    if (SECOND_TAB) {
      const consoleUrl = consolePage.url();
      const startedAt = Date.now();
      const second = await context.newPage();
      second.on('pageerror', (error) => result.console_errors.push(String(error.message).slice(0, 200)));
      await second.goto(consoleUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });
      let statusText = '';
      const seen = [];
      const deadline = Date.now() + 12000;
      while (Date.now() < deadline) {
        const sample = await second.evaluate(() => {
          const node = document.getElementById('status');
          const rfb = window.__kvm;
          const sock = rfb && rfb._sock;
          return {
            text: node ? node.textContent : '',
            state: (rfb && rfb._rfb_state) || null,
            socket: sock && sock._websocket ? sock._websocket.readyState : null,
          };
        }).catch(() => null);
        if (sample) {
          statusText = sample.text;
          const last = seen[seen.length - 1];
          const changed = !last || last.text !== sample.text || last.state !== sample.state
            || last.socket !== sample.socket;
          if (changed && seen.length < 24) {
            seen.push({ t: Date.now() - startedAt, text: sample.text, state: sample.state,
                        socket: sample.socket });
          }
        }
        if (statusText && (statusText.includes('上限') || statusText.includes('会话已结束'))) break;
        await second.waitForTimeout(250);
      }
      const state = await second.evaluate(
        () => (window.__kvm && window.__kvm._rfb_state) || null).catch(() => null);
      const limits = await second.evaluate(async () => {
        try {
          const response = await fetch('/_platform/limits', { cache: 'no-store' });
          return { status: response.status, body: response.ok ? await response.json() : null };
        } catch (error) { return { status: null, body: null }; }
      }).catch(() => null);
      const statusLog = await second.evaluate(
        () => (window.__kvmStatusLog || []).slice(-20)).catch(() => []);
      if (statusLog.length) {
        const base = statusLog[0][0];
        statusLog.forEach((entry) => { entry[0] = entry[0] - base; });
      }
      result.second_tab = { status_text: statusText, state, states: seen, limits,
                            status_log: statusLog };
      result.steps.push('second_tab_refused');
      await second.close().catch(() => {});
      result.state_after_second_tab = await consolePage.evaluate(
        () => window.__kvm && window.__kvm._rfb_state);
      result.canvas_after_second_tab = await canvasStats();
    } else if (REVOKE) {
      const consoleTraffic = [];
      consolePage.on('request', (request) => {
        if (request.url().includes('/console')) consoleTraffic.push(Date.now());
      });
      consolePage.on('websocket', (socket) => {
        if (socket.url().includes('/console')) consoleTraffic.push(Date.now());
      });
      const readyAt = Date.now();
      const readyState = await consolePage.evaluate(() => window.__kvm._rfb_state);
      const sidMatch = consolePage.url().match(/w1-([0-9a-f]{32})\./);
      process.stdout.write('READY ' + JSON.stringify({
        at: readyAt, state: readyState, sid: sidMatch ? sidMatch[1] : null,
        canvas: result.canvas_after_input, client_bytes: result.client_bytes_after,
      }) + '\n');

      let finalState = null;
      let timedOut = true;
      const deadline = Date.now() + REVOKE_TIMEOUT;
      while (Date.now() < deadline) {
        const socket = await consolePage.evaluate(() => {
          const inner = window.__kvm && window.__kvm._sock;
          return { state: window.__kvm && window.__kvm._rfb_state,
                   readyState: inner ? inner.readyState : null };
        });
        if ((socket.state && socket.state !== 'normal') || socket.readyState === 3) {
          finalState = socket.state || 'socket_closed';
          timedOut = false;
          break;
        }
        await consolePage.waitForTimeout(200);
      }
      const closedAt = Date.now();
      result.cut = { ready_at: readyAt, closed_at: closedAt,
                        waited_ms: closedAt - readyAt, final_state: finalState,
                        timeout: timedOut };
      result.canvas_after_cut = await canvasStats();
      await consolePage.waitForTimeout(1500);
      result.canvas_after_cut_settled = await canvasStats();
      result.cut.requests_after_ready =
        consoleTraffic.filter((at) => at >= readyAt).length;
      result.steps.push('cut_observed');
    } else {
      await consolePage.click('#close');
      await consolePage.waitForTimeout(1500);
      result.steps.push('close_requested');
    }
  } catch (error) {
    result.errors.push(String((error && error.message) || error).slice(0, 300));
  } finally {
    if (browser) await browser.close().catch(() => {});
  }
  process.stdout.write('RESULT ' + JSON.stringify(result) + '\n');
})();
