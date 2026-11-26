const { chromium } = require(process.env.KVM_PLAYWRIGHT);
(async () => {
  const browser = await chromium.launch({executablePath: process.env.KVM_CHROMIUM, headless: true});
  try {
    const page = await browser.newPage();
    const errors = [];
    const dialogs = [];
    page.on('pageerror', e => errors.push(e.message));
    page.on('dialog', async dialog => { dialogs.push(dialog.message()); await dialog.accept(); });
    await page.goto(process.argv[2]);
    await page.waitForFunction(() => {
      const canvas = document.querySelector('#v2-screen canvas');
      return canvas && canvas.width === 64 && canvas.height === 64;
    }, null, {timeout: 10000});
    const screenBefore = await page.locator('#v2-screen').boundingBox();
    await page.click('#v2-sk-toggle');
    if (await page.getAttribute('#v2-sk-panel', 'open') === null) throw Error('floating panel did not open');
    await page.waitForFunction(() => {
      const row = document.querySelector('#v2-sk-body [data-v2page="chars"]');
      return row && row.querySelectorAll('button[data-v2-key]').length >= 40;
    }, null, {timeout: 10000});
    const screenAfter = await page.locator('#v2-screen').boundingBox();
    if (Math.abs(screenAfter.height - screenBefore.height) > 1) {
      throw Error(`floating panel squeezed the RFB viewport: ${screenBefore.height} -> ${screenAfter.height}`);
    }

    const head = await page.locator('#v2-sk-head').boundingBox();
    const panelBefore = await page.locator('#v2-sk-panel').boundingBox();
    await page.mouse.move(head.x + head.width / 2, head.y + head.height / 2);
    await page.mouse.down();
    await page.mouse.move(head.x + head.width / 2 - 120, head.y + head.height / 2 - 80, {steps: 8});
    await page.mouse.up();
    const panelAfter = await page.locator('#v2-sk-panel').boundingBox();
    if (Math.abs((panelAfter.x - panelBefore.x) + 120) > 3 ||
        Math.abs((panelAfter.y - panelBefore.y) + 80) > 3) {
      throw Error(`panel did not follow drag: ${JSON.stringify(panelBefore)} -> ${JSON.stringify(panelAfter)}`);
    }
    const screenAfterDrag = await page.locator('#v2-screen').boundingBox();
    if (Math.abs(screenAfterDrag.height - screenBefore.height) > 1) {
      throw Error('dragging the panel resized the RFB viewport');
    }

    await page.click('#v2-sk-tabs button[data-v2page="func"]');
    if (await page.getAttribute('#v2-sk-body', 'data-page') !== 'func') throw Error('tab did not switch to func');
    await page.click('#v2-sk-body [data-v2page="func"] button[data-v2-key="f12"]');
    await page.waitForTimeout(120);
    if ((await page.textContent('#v2-sk-status')).trim()) throw Error('normal key press printed a status message');

    await page.click('#v2-sk-tabs button[data-v2page="chars"]');
    await page.click('#v2-sk-body [data-v2page="chars"] button[data-v2-key="lctrl"][data-mod]');
    if (!(await page.getAttribute('#v2-sk-body [data-v2page="chars"] button[data-v2-key="lctrl"]', 'class')).includes('on')) throw Error('modifier did not latch');
    await page.click('#v2-sk-body [data-v2page="chars"] button[data-v2-key="c"]');
    await page.waitForTimeout(120);
    if ((await page.textContent('#v2-sk-status')).trim()) throw Error('chord printed a status message');

    await page.click('#v2-sk-tabs button[data-v2page="macros"]');
    await page.waitForFunction(() => document.querySelectorAll('#v2-sk-body [data-v2page="macros"] button[data-v2-macro]').length > 0, null, {timeout: 5000});
    await page.click('#v2-sk-body [data-v2page="macros"] button[data-v2-macro]');
    await page.waitForTimeout(100);

    await page.fill('#v2-text', 'rm -rf /');
    await page.click('#v2-text-send');
    await page.waitForFunction(() => document.getElementById('v2-danger').textContent.includes('危险命令'), null, {timeout: 5000});
    if (!dialogs.some(text => text.includes('危险命令'))) throw Error('dangerous command dialog missing');
    await page.waitForFunction(() => document.getElementById('v2-input-status').textContent.includes('发送完成'), null, {timeout: 10000});

    await page.fill('#v2-text', '中');
    await page.click('#v2-text-send');
    await page.waitForFunction(() => document.getElementById('v2-input-status').textContent.includes('未发送'), null, {timeout: 5000});

    await page.click('#v2-sk-toggle');
    if (await page.getAttribute('#v2-sk-panel', 'open') !== null) throw Error('floating panel did not close');

    await page.click('#v2-close');
    await page.waitForFunction(() => document.getElementById('v2-status').textContent === '会话已结束', null, {timeout: 5000});
    if (errors.length) throw Error(JSON.stringify(errors));
    console.log(JSON.stringify({tabs: true, keys: true, modifiers: true, macros: true, danger: true, text_preflight: true, floating: true, draggable: true, closed: true}));
  } finally {
    await browser.close();
  }
})().catch(e => { console.error(e.stack); process.exit(1); });
