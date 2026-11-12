'use strict';
const PW = process.env.KVM_PLAYWRIGHT;
const CHROME = process.env.KVM_CHROMIUM;
const BASE = process.env.KVM_BASE;
const TOKEN = process.env.KVM_TOKEN;
const ASSET = process.env.KVM_ASSET || 'real-1';
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
      for (let i = 0; i < pixels.length; i += 4) {
        if (pixels[i] + pixels[i + 1] + pixels[i + 2] > 24) nonBlack += 1;
      }
      return {
        width: canvas.width, height: canvas.height,
        total: canvas.width * canvas.height,
        non_black: nonBlack,
        ratio: canvas.width * canvas.height ? nonBlack / (canvas.width * canvas.height) : 0,
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
    const sentBefore = await consolePage.evaluate(() => window.__kvmSent);

    const box = await consolePage.locator('#screen').boundingBox();
    if (box) {
      await consolePage.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
      await consolePage.mouse.move(box.x + box.width / 2 + 30, box.y + box.height / 2 + 18);
      result.steps.push('pointer_sent');
    }
    await consolePage.keyboard.press('Shift');
    result.steps.push('shift_sent');

    await consolePage.waitForTimeout(1500);
    result.canvas_after_input = await canvasStats();
    result.client_bytes_before = sentBefore;
    result.client_bytes_after = await consolePage.evaluate(() => window.__kvmSent);
    result.state_after_input = await consolePage.evaluate(() => window.__kvm._rfb_state);
    result.desktop_name = await consolePage.title();

    if (process.env.KVM_SCREENSHOT) {
      await consolePage.screenshot({ path: process.env.KVM_SCREENSHOT }).catch(() => {});
      result.screenshot = true;
    }

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
