'use strict';
const PW = process.env.KVM_PLAYWRIGHT;
const CHROME = process.env.KVM_CHROMIUM;
const BASE = process.env.KVM_BASE;
const TOKEN = process.env.KVM_TOKEN;
const ASSET = process.env.KVM_ASSET || 'real-1';
const SHOTS = process.env.KVM_SHOTS;
const ACTIONS = JSON.parse(process.env.KVM_ACTIONS || '[]');
const HEALTH_EVERY = Math.max(1, Number(process.env.KVM_HEALTH_EVERY) || 20);
const RECOVER_MS = Math.max(1000, Number(process.env.KVM_RECOVER_MS) || 12000);
const ATTEMPT = Math.max(1, Number(process.env.KVM_ATTEMPT) || 1);
const { chromium } = require(PW);

const MAX_ACTIONS = 2000;
const MAX_WAIT_MS = 600000;

const shot = async (page, name) => {
  if (!SHOTS) return;
  const file = (ATTEMPT > 1 ? 'a' + ATTEMPT + '-' : '') + name;
  await page.screenshot({ path: SHOTS + '/' + file + '.png' }).catch(() => {});
  const canvas = page.locator('#screen');
  if (await canvas.count()) {
    await canvas.screenshot({ path: SHOTS + '/' + file + '-screen.png' }).catch(() => {});
  }
};

(async () => {
  const result = { steps: [], action_log: [], errors: [], console_errors: [],
                   attempt: ATTEMPT, health_checks: 0, recovered: 0,
                   server_recoveries: 0, health: null, server_stats: null,
                   resume: null };
  let browser;
  let page;
  let consolePage;
  let steps = 0;
  let lastHealth = null;
  const cursor = { top: 0, repeat: null };

  const readHealth = async () => consolePage.evaluate(async () => {
    const client = window.__kvm;
    const health = window.__kvm_health;
    const canvas = document.getElementById('screen');
    let server = null;
    try {
      const stats = window.__kvm_stats ? await window.__kvm_stats() : null;
      if (stats) server = { session: stats.session, recent_ended: stats.recent_ended };
    } catch (error) {
      server = null;
    }
    return {
      rfb_state: client ? client._rfb_state : null,
      health_state: health ? health.state : null,
      exhausted: health ? !!health.exhausted : false,
      attempts: health ? health.attempts : 0,
      total_attempts: health ? health.total_attempts : 0,
      recovered: health ? health.recovered : 0,
      canvas: canvas ? canvas.width + 'x' + canvas.height : 'none',
      server: server
    };
  });

  const serverState = (health) => (health && health.server && health.server.session
                                   ? health.server.session.state : null);

  const waitServerRecovery = async () => {
    const deadline = Date.now() + RECOVER_MS;
    while (Date.now() < deadline) {
      const health = await readHealth();
      lastHealth = health;
      if (serverState(health) !== 'recovering') return true;
      await consolePage.waitForTimeout(200);
    }
    throw new Error('vnc_session_lost:recovering:' + JSON.stringify(lastHealth || {}));
  };

  const waitHealthy = async () => {
    const deadline = Date.now() + RECOVER_MS;
    let reason = 'timeout';
    while (Date.now() < deadline) {
      try {
        lastHealth = await readHealth();
        if (lastHealth && lastHealth.exhausted) { reason = 'exhausted'; break; }
        if (lastHealth && lastHealth.rfb_state === 'normal') return true;
      } catch (error) {
        reason = 'navigation';
      }
      await consolePage.waitForTimeout(200);
    }
    throw new Error('vnc_session_lost:' + reason + ':' +
                    JSON.stringify(lastHealth || {}));
  };

  const ensureHealthy = async () => {
    result.health_checks += 1;
    let health;
    const before = lastHealth ? lastHealth.recovered : 0;
    try {
      health = await readHealth();
    } catch (error) {
      await waitHealthy();
      result.recovered += Math.max(0, (lastHealth ? lastHealth.recovered : 0) - before);
      return;
    }
    lastHealth = health;
    if (health && health.server) result.server_stats = health.server;
    if (health && health.exhausted) {
      throw new Error('vnc_session_lost:exhausted:' + JSON.stringify(health));
    }
    if (health && health.server && health.server.session) {
      result.server_recoveries = health.server.session.recoveries || 0;
      if (serverState(health) === 'recovering') await waitServerRecovery();
    }
    if (!health || health.rfb_state !== 'normal') {
      const seen = health ? health.recovered : before;
      await waitHealthy();
      result.recovered += Math.max(0, (lastHealth ? lastHealth.recovered : 0) - seen);
    }
  };

  const makeResume = () => {
    const rest = ACTIONS.slice(cursor.top);
    if (!rest.length) return null;
    const done = cursor.repeat;
    if (done && rest[0] && rest[0].repeat) {
      const remaining = Number(rest[0].repeat.count) - (done.index - 1);
      if (remaining <= 0) return ACTIONS.slice(cursor.top + 1);
      rest[0] = { repeat: Object.assign({}, rest[0].repeat, { count: remaining }) };
    }
    return rest;
  };

  try {
    if (!Array.isArray(ACTIONS) || ACTIONS.length === 0) throw new Error('KVM_ACTIONS is empty');
    if (ACTIONS.length > MAX_ACTIONS) throw new Error('too many actions');

    browser = await chromium.launch({ executablePath: CHROME, headless: true });
    const context = await browser.newContext({
      ignoreHTTPSErrors: true, viewport: { width: 1280, height: 900 },
    });
    page = await context.newPage();
    page.on('pageerror', (error) => result.console_errors.push(String(error.message).slice(0, 200)));

    await page.goto(BASE, { waitUntil: 'domcontentloaded', timeout: 30000 });
    await page.fill('input[name=token]', TOKEN);
    await page.click('button');
    await page.waitForSelector(`[data-open="${ASSET}"]`, { timeout: 20000 });
    result.steps.push('manager_login');

    const opened = await Promise.all([
      context.waitForEvent('page', { timeout: 20000 }),
      page.click(`[data-open="${ASSET}"]`),
    ]);
    consolePage = opened[0];
    consolePage.on('pageerror', (error) => result.console_errors.push(String(error.message).slice(0, 200)));
    consolePage.on('console', (message) => {
      if (message.type() === 'error') result.console_errors.push(message.text().slice(0, 200));
    });
    await consolePage.waitForURL(/w1-[0-9a-f]{32}\.kvm\.localhost/, { timeout: 30000 });
    await consolePage.waitForLoadState('domcontentloaded');
    result.steps.push('console_opened');

    await consolePage.waitForFunction(
      () => window.__kvm && window.__kvm._rfb_state === 'normal', null, { timeout: 45000 });
    result.steps.push('rfb_normal');

    await consolePage.locator('#screen').click({ position: { x: 8, y: 8 } }).catch(() => {});
    await consolePage.evaluate(() => document.getElementById('screen').focus());
    await ensureHealthy();

    let quiet = false;
    const note = (entry) => { if (!quiet) result.action_log.push(entry); };

    const dispatch = async (action) => {
      const label = JSON.stringify(action).slice(0, 120);
      steps += 1;
      if (steps % HEALTH_EVERY === 0) await ensureHealthy();
      if (action.wait !== undefined) {
        const ms = Math.min(Number(action.wait) || 0, MAX_WAIT_MS);
        await consolePage.waitForTimeout(ms);
        note({ action: label, waited_ms: ms });
      } else if (action.key !== undefined) {
        await consolePage.keyboard.press(String(action.key));
        note({ action: label });
      } else if (action.combo !== undefined) {
        await consolePage.keyboard.press(String(action.combo));
        note({ action: label });
      } else if (action.text !== undefined) {
        await consolePage.keyboard.type(String(action.text));
        note({ action: label });
      } else if (action.slowtext !== undefined) {
        const spec = action.slowtext;
        const delay = Math.min(Number(spec.delay) || 90, 2000);
        for (const character of String(spec.text)) {
          await consolePage.keyboard.press(character === ' ' ? 'Space' : character);
          await consolePage.waitForTimeout(delay);
        }
        note({ action: label, delay_ms: delay });
      } else if (action.hold !== undefined) {
        const ms = Math.min(Number(action.ms) || 1000, 20000);
        await consolePage.keyboard.down(String(action.hold));
        await consolePage.waitForTimeout(ms);
        await consolePage.keyboard.up(String(action.hold));
        note({ action: label, held_ms: ms });
      } else if (action.click !== undefined) {
        const [x, y] = action.click.map(Number);
        await consolePage.locator('#screen').click({ position: { x, y } });
        note({ action: label });
      } else if (action.shot !== undefined) {
        await shot(consolePage, String(action.shot));
        const size = await consolePage.evaluate(() => {
          const canvas = document.getElementById('screen');
          return canvas ? canvas.width + 'x' + canvas.height : 'none';
        });
        note({ action: label, canvas: size });
      } else if (action.eval !== undefined) {
        const value = await consolePage.evaluate(String(action.eval));
        note({ action: label, result: String(JSON.stringify(value)).slice(0, 200) });
      } else if (action.repeat !== undefined) {
        const spec = action.repeat;
        const count = Math.min(Number(spec.count) || 0, MAX_ACTIONS);
        const inner = Array.isArray(spec.actions) ? spec.actions : [];
        if (!inner.length) throw new Error('repeat needs a non-empty actions list');
        const shotEvery = Number(spec.shot_every) || 0;
        const prefix = String(spec.shot_prefix || 'r');
        for (let index = 1; index <= count; index += 1) {
          cursor.repeat = { index, count };
          quiet = true;
          try {
            for (const step of inner) await dispatch(step);
          } finally {
            quiet = false;
          }
          if (shotEvery && index % shotEvery === 0) {
            await shot(consolePage, prefix + String(index).padStart(3, '0'));
            result.action_log.push({ action: 'repeat-shot', index });
          }
        }
        note({ action: label, iterations: count });
      } else {
        throw new Error('unknown action: ' + label);
      }
    };

    for (let index = 0; index < ACTIONS.length; index += 1) {
      cursor.top = index;
      cursor.repeat = null;
      await dispatch(ACTIONS[index]);
    }

    try {
      lastHealth = await readHealth();
      result.canvas_size = lastHealth.canvas;
      result.state_after = lastHealth.rfb_state;
    } catch (error) {
      result.canvas_size = null;
      result.state_after = null;
    }
    await shot(consolePage, 'final');

    await consolePage.click('#close').catch(() => {});
    await consolePage.waitForTimeout(1200);
    result.steps.push('close_requested');
  } catch (error) {
    const message = String((error && error.message) || error).slice(0, 300);
    result.errors.push(message);
    if (message.startsWith('vnc_session_lost:')) {
      result.resume = makeResume();
    }
    if (consolePage && SHOTS) await shot(consolePage, 'error').catch(() => {});
    if (page && SHOTS) await shot(page, 'error-manager').catch(() => {});
  } finally {
    result.health = lastHealth;
    if (browser) await browser.close().catch(() => {});
  }
  process.stdout.write('RESULT ' + JSON.stringify(result) + '\n');
})();
