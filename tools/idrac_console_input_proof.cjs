'use strict';
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const STUB = process.env.KVM_STUB === '1' || process.argv.includes('--stub');
const STUB_ORIGIN = 'https://kvm-stub.invalid';
const BASE = (process.env.KVM_BASE || (STUB ? STUB_ORIGIN : '')).replace(/\/$/, '');
const ASSET = process.env.KVM_ASSET || '96df7f56-9cb0-4532-9d51-fa22045fad6f';
const ASSET_HINT = process.env.KVM_ASSET_HINT || '192.0.2.84';
const USER = process.env.KVM_USER || '';
const PASSWORD = process.env.KVM_PASSWORD || '';
const TENANT = process.env.KVM_TENANT || '';
const SHOTS = process.env.KVM_SHOTS || '';
const EXPECT_PROTOCOL = process.env.KVM_EXPECT_PROTOCOL || 'standard8';

const TEXT = 'abc';                 // only lowercase letters, no Enter
const MAX_KEYS = 24;                // per entry
const PIXEL_DELTA = 24;             // summed RGB difference threshold
const SETTLE_TRIES = 40;
const SETTLE_MS = 250;

function resolvePlaywright() {
  if (process.env.KVM_PLAYWRIGHT) return process.env.KVM_PLAYWRIGHT;
  const local = path.join(ROOT, '.local-playwright', 'node_modules', 'playwright-core');
  if (fs.existsSync(path.join(local, 'package.json'))) return local;
  return 'playwright-core';
}
function resolveChromium() {
  if (process.env.KVM_CHROMIUM) return process.env.KVM_CHROMIUM;
  const bases = [];
  if (process.env.PLAYWRIGHT_BROWSERS_PATH) bases.push(process.env.PLAYWRIGHT_BROWSERS_PATH);
  if (process.env.LOCALAPPDATA) bases.push(path.join(process.env.LOCALAPPDATA, 'ms-playwright'));
  bases.push(path.join(process.env.HOME || process.env.USERPROFILE || '', '.cache', 'ms-playwright'));
  const patterns = ['chrome-win64/chrome.exe', 'chrome-win/chrome.exe', 'chrome-linux/chrome',
    'chrome-mac/Chromium.app/Contents/MacOS/Chromium'];
  for (const base of bases) {
    try {
      for (const dir of fs.readdirSync(base).filter((d) => /^chromium-\d+$/.test(d)).sort().reverse()) {
        for (const pattern of patterns) {
          const exe = path.join(base, dir, pattern);
          if (fs.existsSync(exe)) return exe;
        }
      }
    } catch (error) { /* keep looking */ }
  }
  return undefined;
}

const PW = resolvePlaywright();
const CHROME = resolveChromium();
let chromium;
try { ({ chromium } = require(PW)); } catch (error) { /* reported in RESULT */ }

function redact(value) {
  let text = String(value == null ? '' : value).slice(0, 400);
  for (const secret of [PASSWORD, TENANT, USER, process.env.KVM_TOKEN || '']) {
    if (secret) text = text.split(secret).join('[redacted]');
  }
  text = text.replace(/([?&](?:ticket|token|csrf|challenge|password|pwd|secret|t)=)[^&\s"'<>]+/gi,
    '$1[redacted]');
  text = text.replace(/https?:\/\/[^\s"'<>]+/g, (raw) => {
    try { const url = new URL(raw); return url.origin + url.pathname; } catch (error) { return '[url]'; }
  });
  return text;
}

const FORBIDDEN_KEYS = new Set([
  'Enter', 'NumpadEnter', 'Tab', 'Escape', 'Delete', 'Space', ' ',
  'ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'Home', 'End',
  'PageUp', 'PageDown', 'Insert', 'Backquote',
  'F1', 'F2', 'F3', 'F4', 'F5', 'F6', 'F7', 'F8', 'F9', 'F10', 'F11', 'F12',
]);

function guardPhysicalKey(key) {
  if (FORBIDDEN_KEYS.has(key)) throw new Error('forbidden key rejected by policy: ' + key);
  if (/^[a-z]$/.test(key) || key === 'Backspace') return;
  throw new Error('key outside whitelist: ' + key);
}
function guardCombo(combo) {
  if (combo !== 'Control+u') throw new Error('combo outside whitelist: ' + combo);
}
function guardSoftToken(token) {
  if (/^[a-z]$/.test(token) || token === 'bksp') return;
  throw new Error('softkey token outside whitelist: ' + token);
}
function guardText(text) {
  if (!/^[a-z]{1,24}$/.test(text)) throw new Error('paste text outside whitelist');
}

function selfTestGuards(result) {
  const rejects = (fn) => { try { fn(); return false; } catch (error) { return true; } };
  const checks = {
    enter_key_rejected: rejects(() => guardPhysicalKey('Enter')),
    tab_key_rejected: rejects(() => guardPhysicalKey('Tab')),
    function_key_rejected: rejects(() => guardPhysicalKey('F5')),
    space_key_rejected: rejects(() => guardPhysicalKey(' ')),
    other_combo_rejected: rejects(() => guardCombo('Control+Alt+Delete')),
    soft_enter_rejected: rejects(() => guardSoftToken('enter')),
    soft_modifier_rejected: rejects(() => guardSoftToken('lctrl')),
    paste_command_rejected: rejects(() => guardText('rm -rf /')),
    paste_uppercase_rejected: rejects(() => guardText('Abc')),
    lowercase_allowed: (() => {
      try {
        guardPhysicalKey('a'); guardPhysicalKey('Backspace'); guardSoftToken('bksp');
        guardCombo('Control+u'); guardText('abc'); return true;
      } catch (error) { return false; }
    })(),
  };
  result.guard_checks = checks;
  if (Object.keys(checks).some((name) => !checks[name])) throw new Error('guard self-test failed');
  result.steps.push('guards_self_checked');
}

function makeBudget(result, entry) {
  let used = 0;
  return {
    spend(n) {
      used += (n || 1);
      if (used > MAX_KEYS) throw new Error('key budget exhausted for ' + entry);
      result.entries[entry].keys = used;
    },
    get used() { return used; },
  };
}

async function installProbe(page, delta) {
  await page.evaluate((pixelDelta) => {
    const canvas = document.getElementById('screen');
    if (!canvas) throw new Error('no #screen canvas');
    const read = () => canvas.getContext('2d').getImageData(0, 0, canvas.width, canvas.height);
    let base = null;
    let control = null;
    let mask = null;
    function changed(a, b, p) {
      const i = p * 4;
      return Math.abs(a.data[i] - b.data[i]) + Math.abs(a.data[i + 1] - b.data[i + 1])
        + Math.abs(a.data[i + 2] - b.data[i + 2]) > pixelDelta;
    }
    function scan(a, b, applyMask) {
      if (!a || !b || a.width !== b.width || a.height !== b.height) {
        return { resized: true, pixels: -1, width: b.width, height: b.height, bbox: null };
      }
      const W = a.width, H = a.height;
      let pixels = 0, x0 = 1e9, y0 = 1e9, x1 = -1, y1 = -1;
      for (let y = 0; y < H; y += 1) {
        for (let x = 0; x < W; x += 1) {
          const p = y * W + x;
          if (applyMask && mask && mask[p]) continue;
          if (!changed(a, b, p)) continue;
          pixels += 1;
          if (x < x0) x0 = x;
          if (x > x1) x1 = x;
          if (y < y0) y0 = y;
          if (y > y1) y1 = y;
        }
      }
      return { pixels, width: W, height: H,
        bbox: pixels ? [x0, y0, x1 - x0 + 1, y1 - y0 + 1] : null };
    }
    function addNoise(a, b) {
      if (!a || !b || !mask || a.width !== b.width || a.height !== b.height) return;
      for (let p = 0; p < mask.length; p += 1) if (changed(a, b, p)) mask[p] = 1;
    }
    function maskCount() {
      let total = 0;
      for (let p = 0; p < mask.length; p += 1) if (mask[p]) total += 1;
      return total;
    }
    window.__kf = {
      mark() {
        base = read(); control = null;
        mask = new Uint8Array(base.width * base.height);
        return base.width * base.height;
      },
      controlFrame() {
        const frame = read();
        const raw = scan(base, frame, false);
        addNoise(base, frame);
        if (control) addNoise(control, frame);
        control = frame;
        raw.mask_pixels = maskCount();
        return raw;
      },
      diffBase() { return scan(base, read(), true); },
      diffControl() { return scan(control, read(), true); },
      maskCount() { return maskCount(); },
    };
    window.__kf.mark();
  }, delta);
}

async function settleCanvas(page, result) {
  let last = '';
  let stable = 0;
  for (let attempt = 0; attempt < SETTLE_TRIES && stable < 3; attempt += 1) {
    const size = await page.evaluate(() => {
      const c = document.getElementById('screen');
      return c.width + 'x' + c.height;
    });
    if (size === last) stable += 1;
    else { last = size; stable = 0; }
    if (stable < 3) await page.waitForTimeout(SETTLE_MS);
  }
  result.canvas_size = last;
  result.canvas_size_stable = stable >= 3;
}

function fromWorkerSource(name) {
  const file = path.join(ROOT, 'kvmhub', 'worker.py');
  const source = fs.readFileSync(file, 'utf8');
  const match = source.match(new RegExp('^' + name + ' = """([\\s\\S]*?)"""', 'm'));
  if (!match) throw new Error('cannot extract ' + name + ' from worker.py');
  return match[1].replace(/\\\\/g, '\\');
}

function stubKeymap() {
  const plain = { a: 4, b: 5, c: 6, u: 18 };
  const charKeysym = { a: 0x61, b: 0x62, c: 0x63, u: 0x75 };
  const keys = { bksp: 0xff08, lctrl: 0xffe3, rctrl: 0xffe4, lshift: 0xffe1, rshift: 0xffe2,
    lalt: 0xffe9, ralt: 0xffea, lwin: 0xffeb, enter: 0xff0d, tab: 0xff09, esc: 0xff1b };
  const keyKeysym = Object.assign({}, keys);
  const reliability = { a: 'verified', b: 'verified', c: 'verified', u: 'verified' };
  return {
    plain, shifted: {}, reliability, known_broken: {}, keys,
    modifiers: ['lctrl', 'rctrl', 'lshift', 'rshift', 'lalt', 'ralt', 'lwin'],
    macros: [], key_reliability: { bksp: 'verified' }, left_shift: 0xffe1, max_chars: 256,
    frame_styles: ['insyde18', 'standard8'], char_keysym: charKeysym, key_keysym: keyKeysym,
    left_shift_keysym: 0xffe1,
    levels: { verified: 'verified', unverified: 'unverified', known_broken: 'known_broken',
      unsupported: 'unsupported' },
    note: 'local stub',
  };
}

function stubInitScript() {
  window.__stubEcho = '';
  window.__stubKeyLog = [];
  function draw() {
    const canvas = document.getElementById('screen');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    ctx.fillStyle = '#000';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = '#fff';
    ctx.font = '28px monospace';
    ctx.fillText(window.__stubEcho, 24, 48);
    if (window.__stubBlink) {
      const width = ctx.measureText(window.__stubEcho).width;
      ctx.fillRect(24 + Math.round(width), 28, 12, 26);
    }
  }
  window.__stubBlink = false;
  setInterval(() => { window.__stubBlink = !window.__stubBlink; draw(); }, 300);
  function inject(frame) {
    const f = Array.from(frame);
    if (f[0] !== 4 || f[1] !== 1) return;            // KeyEvent, key down only
    const ks = (((f[4] << 24) | (f[5] << 16) | (f[6] << 8) | f[7]) >>> 0);
    if (ks === 0x15) window.__stubEcho = '';
    else if (ks >= 0x61 && ks <= 0x7a) window.__stubEcho += String.fromCharCode(ks);
    else if (ks === 0xff08) window.__stubEcho = window.__stubEcho.slice(0, -1);
    draw();
  }
  window.RFB = class StubRFB {
    constructor(opts) {
      this.options = opts;
      this._rfb_state = 'connecting';
      this._sock = { send: inject };
      this._websocket = null;
      window.addEventListener('keydown', (event) => {
        const canvas = document.getElementById('screen');
        if (!canvas || document.activeElement !== canvas) return;
        window.__stubKeyLog.push(event.key);
        if (event.ctrlKey && (event.key === 'u' || event.key === 'U')) {
          inject([4, 1, 0, 0, 0, 0, 0, 0x15]);
          event.preventDefault();
          return;
        }
        if (/^[a-z]$/.test(event.key)) inject([4, 1, 0, 0, 0, 0, 0, event.key.charCodeAt(0)]);
        else if (event.key === 'Backspace') inject([4, 1, 0, 0, 0, 0, 0xff, 0x08]);
      });
    }
    connect() {
      this._rfb_state = 'normal';
      this.options.onUpdateState(this, 'normal', 'connecting', '');
      draw();
    }
    disconnect() { this._rfb_state = 'disconnected'; }
    sendKey() {}
  };
  document.addEventListener('DOMContentLoaded', draw);
}

async function installStubRoutes(context, html, js, keymapJson) {
  const sid = 'a'.repeat(32);
  await context.route('**/*', async (route) => {
    const url = new URL(route.request().url());
    const p = url.pathname;
    const json = (body) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
    const page = (body) => route.fulfill({ status: 200, contentType: 'text/html; charset=utf-8', body });
    if (p === '/login') {
      return page('<!doctype html><html><body><form name="login">' +
        '<input name="tenant"/><input name="username" autocomplete="username"/>' +
        '<input name="password" autocomplete="current-password" type="password"/>' +
        '<button type="submit">登录</button></form><script>' +
        'document.querySelector("form").onsubmit=function(e){e.preventDefault();location.href="/assets";};' +
        '</script></body></html>');
    }
    if (p === '/assets') {
      return page('<!doctype html><html><body><h1>资产与控制台</h1>' +
        '<table><tr data-asset-id="' + ASSET + '"><td>' + ASSET + '</td><td>192.0.2.84</td>' +
        '<td><button type="button" onclick="window.open(\'/s/' + sid +
        '/\',\'kvm-' + sid + '\')">连接 VNC</button></td></tr></table></body></html>');
    }
    if (/^\/s\/[0-9a-f]{32}\/?$/.test(p)) return page(html);
    if (p === '/_platform/console.js') {
      return route.fulfill({ status: 200, contentType: 'application/javascript', body: js });
    }
    if (p === '/_platform/meta') {
      return json({ address: '192.0.2.84', asset_id: ASSET, input_protocol: EXPECT_PROTOCOL });
    }
    if (p === '/_platform/keymap') {
      return route.fulfill({ status: 200, contentType: 'application/json', body: keymapJson });
    }
    if (p === '/_platform/limits') return json({ connections: 0, opening: 0, limit: 4 });
    if (p === '/_platform/stats') return json({ recovery: {}, machine: {}, session: {} });
    if (p === '/_platform/close') return json({ ok: true });
    if (p.indexOf('/novnc/include/') === 0) {
      return route.fulfill({ status: 200, contentType: 'application/javascript', body: '/* stub */' });
    }
    return route.fulfill({ status: 404, contentType: 'text/plain', body: 'stub 404' });
  });
}

async function waitForAny(page, selectors, timeout) {
  const deadline = Date.now() + (timeout || 20000);
  while (Date.now() < deadline) {
    for (const selector of selectors) {
      if (await page.locator(selector).first().count()) return selector;
    }
    await page.waitForTimeout(250);
  }
  throw new Error('no selector appeared among: ' + selectors.join(' | '));
}

async function fillFirst(page, selectors, value) {
  await waitForAny(page, selectors, 20000);
  for (const selector of selectors) {
    const locator = page.locator(selector).first();
    if (await locator.count()) {
      await locator.fill(value);
      return selector;
    }
  }
  throw new Error('no matching field among: ' + selectors.join(' | '));
}

async function login(page, result) {
  if (!BASE) throw new Error('KVM_BASE is required');
  await page.goto(BASE + '/login', { waitUntil: 'domcontentloaded', timeout: 30000 });
  await waitForAny(page, ['input[autocomplete=username]', 'input[name=username]', '#username',
    'input[placeholder*="用户"]'], 25000);
  await fillFirst(page, ['input[autocomplete=username]', 'input[name=username]', '#username',
    'input[placeholder*="用户"]'], USER || 'probe');
  if (TENANT) {
    for (const selector of ['input[name=tenant]', 'input[autocomplete=organization]', '#tenant',
      'input[placeholder*="租户"]']) {
      const locator = page.locator(selector).first();
      if (await locator.count()) { await locator.fill(TENANT); break; }
    }
  }
  await fillFirst(page, ['input[name=password]', 'input[autocomplete=current-password]', '#password',
    'input[type=password]'], PASSWORD || 'probe');
  let clicked = false;
  for (const selector of ['button[type=submit]', 'button:has-text("登 录")', 'button:has-text("登录")']) {
    const locator = page.locator(selector).first();
    if (await locator.count()) { await locator.click(); clicked = true; break; }
  }
  if (!clicked) {
    const role = page.getByRole('button', { name: /登\s*录/ }).first();
    if (await role.count()) { await role.click(); clicked = true; }
  }
  if (!clicked) throw new Error('login button not found');
  await page.waitForURL(/\/(assets|dashboard|home)(\?|$)/, { timeout: 25000 }).catch(() => {});
  result.steps.push('login');
}

async function findAssetButton(page, assetId, hint) {
  return page.evaluate(({ id, addressHint }) => {
    const isHit = (node) => {
      const attrs = ['data-asset-id', 'data-id', 'data-asset', 'data-key', 'data-row-key'];
      for (const name of attrs) {
        const value = node.getAttribute && node.getAttribute(name);
        if (value && value.indexOf(id) >= 0) return true;
      }
      const text = node.textContent || '';
      return text.indexOf(id) >= 0 || (!!addressHint && text.indexOf(addressHint) >= 0);
    };
    const isConnectButton = (node) => {
      const text = (node.textContent || '') + ' ' + (node.getAttribute('aria-label') || '')
        + ' ' + (node.title || '');
      return /连接\s*VNC|VNC|连接|控制台/.test(text)
        && !/解绑|删除|移除|编辑|详情|停用/.test(text);
    };
    const seeds = Array.from(document.querySelectorAll(
      'tr, .ant-table-row, [role=row], li, .ant-list-item, td'))
      .concat(Array.from(document.querySelectorAll('*')).filter((n) => n.children.length < 8));
    const hits = seeds.filter(isHit);
    for (const node of hits) {
      let cursor = node;
      for (let level = 0; cursor && level < 6; level += 1) {
        const candidates = Array.from(cursor.querySelectorAll('button, a, [role=button]'))
          .filter(isConnectButton);
        if (candidates.length) {
          candidates[0].setAttribute('data-kvm-proof-target', '1');
          return { row: true, button: true,
            label: (candidates[0].textContent || '').trim().slice(0, 40) };
        }
        cursor = cursor.parentElement;
      }
    }
    return { row: hits.length > 0, button: false };
  }, { id: assetId, addressHint: hint });
}

function attachPageDiagnostics(page, result) {
  page.on('pageerror', (error) => result.console_errors.push(redact(error && error.message)));
  page.on('console', (message) => {
    if (message.type() === 'error') result.console_errors.push(redact(message.text()));
  });
}

async function assertConsoleWindow(page) {
  const ok = await page.evaluate(() => !!window.__kvm && !!document.getElementById('screen'));
  if (!ok) throw new Error('input target is not the console window');
  const url = page.url();
  if (!/\/s\/[0-9a-f]{32}\//.test(url) && !/kvm-stub\.invalid/.test(url)) {
    throw new Error('console window url unexpected');
  }
}

async function focusCanvas(page) {
  await page.locator('#screen').click({ position: { x: 16, y: 16 } }).catch(() => {});
  await page.locator('#screen').focus();
  let focused = await page.evaluate(() => document.activeElement && document.activeElement.id === 'screen');
  if (!focused) {
    await page.locator('#screen').click({ position: { x: 16, y: 16 } }).catch(() => {});
    await page.locator('#screen').focus();
    focused = await page.evaluate(() => document.activeElement && document.activeElement.id === 'screen');
  }
  if (!focused) throw new Error('cannot focus #screen');
}

async function safePress(page, key, budget) {
  guardPhysicalKey(key);
  budget.spend(1);
  await page.keyboard.press(key);
}
async function safeCombo(page, combo, budget) {
  guardCombo(combo);
  budget.spend(1);
  await page.keyboard.press(combo);
}

async function showKeysTab(page) {
  const pasteTab = await page.locator('#inputpanel').evaluate((el) => el.classList.contains('show-paste'));
  if (pasteTab) await page.locator('#tab-keys').click();
  const collapsed = await page.locator('#inputpanel').evaluate((el) => el.classList.contains('collapsed'));
  if (collapsed) await page.locator('#input-toggle').click();
  await page.locator('#sk-tabs [data-skpage="chars"]').click().catch(() => {});
  await page.waitForFunction(() => {
    const a = document.querySelector('#softkey [data-send="a"]');
    const b = document.querySelector('#softkey [data-send="bksp"]');
    return !!a && !!b && !a.disabled && !b.disabled;
  }, null, { timeout: 25000 });
}

async function showPasteTab(page) {
  const keysTab = await page.locator('#inputpanel').evaluate((el) => el.classList.contains('show-keys'));
  if (keysTab) await page.locator('#tab-paste').click();
  await page.waitForSelector('#paste-text', { timeout: 10000 });
}

async function runEntry(page, result, name, typeLetters, erase) {
  const entry = { keys: 0 };
  result.entries[name] = entry;
  const budget = makeBudget(result, name);
  await assertConsoleWindow(page);
  await installProbe(page, PIXEL_DELTA);
  for (let sample = 0; sample < 3; sample += 1) {
    await page.waitForTimeout(400);
    const frame = await page.evaluate(() => window.__kf.controlFrame());
    if (!entry.idle || frame.pixels > entry.idle.pixels) entry.idle = frame;
  }
  entry.idle.mask_pixels = await page.evaluate(() => window.__kf.maskCount());
  result.steps.push(name + '_idle_control');

  await typeLetters(budget);
  result.steps.push(name + '_letters_sent');
  await page.waitForTimeout(800);
  entry.typed = await page.evaluate(() => window.__kf.diffBase());

  await erase(budget);
  result.steps.push(name + '_erased');
  await page.waitForTimeout(800);
  entry.restored = await page.evaluate(() => window.__kf.diffBase());
  entry.erase_change = await page.evaluate(() => window.__kf.diffControl());

  await focusCanvas(page);
  await safeCombo(page, 'Control+u', budget);
  await page.waitForTimeout(500);
  entry.clean = await page.evaluate(() => window.__kf.diffBase());
  result.steps.push(name + '_cleaned');

  const idlePixels = entry.idle.pixels;
  const maskPixels = entry.idle.mask_pixels || 0;
  const residualIdle = Math.max(0, idlePixels - maskPixels);
  const threshold = Math.max(40, residualIdle * 4);
  const restoreLimit = Math.max(residualIdle * 3, 80);
  const settled = result.canvas_size_stable === true && idlePixels >= 0;
  entry.verdict = {
    control_valid: settled,
    cursor_band_excluded: maskPixels > 0,
    threshold,
    visible: settled && entry.typed.pixels > threshold && !!entry.typed.bbox,
    reversible: settled && entry.restored.pixels >= 0 && entry.restored.pixels < entry.typed.pixels
      && entry.restored.pixels <= restoreLimit,
    clean_ok: settled && entry.clean.pixels <= restoreLimit,
    budget_ok: budget.used <= MAX_KEYS,
  };
  result.entry_verdicts[name] = entry.verdict;
  result.keys_total += budget.used;
  return entry;
}

async function main() {
  const result = {
    steps: [], errors: [], console_errors: [], mode: STUB ? 'stub' : 'production',
    entries: {}, entry_verdicts: {}, keys_total: 0,
  };
  let browser = null;
  let context = null;
  try {
    selfTestGuards(result);
    if (!chromium) throw new Error('playwright-core/chromium unavailable: ' + PW);
    if (!STUB && !BASE) throw new Error('KVM_BASE is required outside stub mode');

    let stubHtml = '', stubJs = '', stubKeymapJson = '';
    if (STUB) {
      stubHtml = fromWorkerSource('REAL_CONSOLE_HTML');
      stubJs = fromWorkerSource('REAL_CONSOLE_JS');
      stubKeymapJson = JSON.stringify(stubKeymap());
    }

    browser = await chromium.launch({
      executablePath: CHROME, headless: true,
      args: ['--ignore-certificate-errors'],
    });
    context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 1000 } });
    if (STUB) {
      await context.addInitScript(stubInitScript);
      await installStubRoutes(context, stubHtml, stubJs, stubKeymapJson);
    }

    const page = await context.newPage();
    attachPageDiagnostics(page, result);
    await login(page, result);

    if (!/\/assets(\?|$)/.test(page.url())) {
      await page.goto(BASE + '/assets', { waitUntil: 'domcontentloaded', timeout: 30000 });
    }
    let located = { row: false, button: false };
    const findDeadline = Date.now() + 25000;
    while (Date.now() < findDeadline) {
      await waitForAny(page, ['.ant-table-row', '[role=row]', 'tr[data-row-key]', 'table tr'], 8000)
        .catch(() => {});
      located = await findAssetButton(page, ASSET, ASSET_HINT);
      if (located.button) break;
      await page.waitForTimeout(400);
    }
    result.asset_row_found = located.row;
    result.asset_button_found = located.button;
    if (!located.button) throw new Error('connect-VNC button not found for target asset');

    const popupPromise = context.waitForEvent('page', { timeout: 40000 });
    await page.locator('[data-kvm-proof-target="1"]').click();
    const consolePage = await popupPromise;
    attachPageDiagnostics(consolePage, result);
    result.steps.push('console_popup_captured');
    await consolePage.waitForLoadState('domcontentloaded').catch(() => {});
    if (!STUB) {
      await consolePage.waitForURL(/\/s\/[0-9a-f]{32}\//, { timeout: 40000 }).catch(() => {});
    }

    let meta = null;
    consolePage.on('response', async (response) => {
      if (response.url().indexOf('/_platform/meta') < 0) return;
      try {
        const body = await response.json();
        meta = { input_protocol: body.input_protocol, asset_id_match: body.asset_id === ASSET };
      } catch (error) { /* ignore */ }
    });
    await consolePage.waitForFunction(() => !!window.__kvm && !!window.__kvm_health
      && window.__kvm_health.state === 'normal', null, { timeout: 90000 });
    result.steps.push('rfb_normal');
    await settleCanvas(consolePage, result);
    result.steps.push('framebuffer_settled');
    if (!result.canvas_size_stable) throw new Error('framebuffer size did not settle');

    if (!meta) {
      meta = await consolePage.evaluate(async (assetId) => {
        const prefix = (location.pathname.match(/\/s\/[0-9a-f]{32}\//) || [''])[0];
        try {
          const response = await fetch(prefix + '_platform/meta', { cache: 'no-store' });
          if (!response.ok) return null;
          const body = await response.json();
          return { input_protocol: body.input_protocol, asset_id_match: body.asset_id === assetId };
        } catch (error) { return null; }
      }, ASSET);
    }
    result.input_protocol = meta && meta.input_protocol || 'unknown';
    result.meta_asset_id_match = !!(meta && meta.asset_id_match);
    result.protocol_expected = EXPECT_PROTOCOL;

    await runEntry(consolePage, result, 'physical', async (budget) => {
      await focusCanvas(consolePage);
      for (const character of TEXT) await safePress(consolePage, character, budget);
    }, async (budget) => {
      await focusCanvas(consolePage);
      for (let i = 0; i < TEXT.length; i += 1) await safePress(consolePage, 'Backspace', budget);
    });

    await runEntry(consolePage, result, 'softkey', async (budget) => {
      await showKeysTab(consolePage);
      for (const character of TEXT) {
        guardSoftToken(character);
        budget.spend(1);
        await consolePage.locator('#softkey .sk[data-send="' + character + '"]').click();
      }
    }, async (budget) => {
      await showKeysTab(consolePage);
      for (let i = 0; i < TEXT.length; i += 1) {
        guardSoftToken('bksp');
        budget.spend(1);
        await consolePage.locator('#softkey .sk[data-send="bksp"]').click();
      }
    });

    await runEntry(consolePage, result, 'paste', async (budget) => {
      guardText(TEXT);
      await showPasteTab(consolePage);
      await consolePage.locator('#paste-text').fill(TEXT);
      await consolePage.locator('#paste-preview').click();
      let enabled = false;
      for (let attempt = 0; attempt < 8 && !enabled; attempt += 1) {
        enabled = await consolePage.locator('#paste-send').isEnabled().catch(() => false);
        if (!enabled) {
          await consolePage.waitForTimeout(500);
          await consolePage.locator('#paste-preview').click().catch(() => {});
        }
      }
      if (!enabled) throw new Error('paste-send stayed disabled');
      const danger = (await consolePage.locator('#paste-danger').innerText().catch(() => '')).trim();
      if (danger) throw new Error('paste text hit dangerous-command confirmation');
      budget.spend(TEXT.length);
      await consolePage.locator('#paste-send').click();
    }, async (budget) => {
      await showKeysTab(consolePage);
      for (let i = 0; i < TEXT.length; i += 1) {
        guardSoftToken('bksp');
        budget.spend(1);
        await consolePage.locator('#softkey .sk[data-send="bksp"]').click();
      }
      await showPasteTab(consolePage);
      await consolePage.locator('#paste-clear').click().catch(() => {});
    });

    if (STUB) {
      const keyLog = await consolePage.evaluate(() => window.__stubKeyLog || []);
      result.no_enter_sent = !keyLog.some((key) => /^(Enter|NumpadEnter)$/i.test(key));
      result.stub_key_count = keyLog.length;
    }
    result.state_after_input = await consolePage.evaluate(() => {
      const health = window.__kvm_health || {};
      return health.state || 'unknown';
    });
    await consolePage.locator('#close').click().catch(() => {});
    result.steps.push('close_requested');
    if (SHOTS) {
      await consolePage.screenshot({ path: path.join(SHOTS, 'idrac-input-proof.png') }).catch(() => {});
    }
  } catch (error) {
    result.errors.push(redact((error && error.message) || error));
  } finally {
    if (context) await context.close().catch(() => {});
    if (browser) await browser.close().catch(() => {});
  }
  process.stdout.write('RESULT ' + JSON.stringify(result) + '\n');
}

main().catch((error) => {
  process.stdout.write('RESULT ' + JSON.stringify({ steps: [], errors: [redact((error && error.message) || error)] }) + '\n');
});
