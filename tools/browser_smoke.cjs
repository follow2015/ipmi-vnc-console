const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { chromium } = require(process.env.KVM_PLAYWRIGHT || 'playwright');
const uiPort = process.env.KVMHUB_UI_PORT || '8443';
const workerPort = process.env.KVMHUB_WORKER_PORT || '9443';

(async () => {
  const directory = path.resolve(process.env.KVM_DIRECTORY || '.local-demo');
  const cert = new crypto.X509Certificate(fs.readFileSync(path.join(directory, 'server.pem')));
  const spki = crypto.createHash('sha256').update(cert.publicKey.export({type:'spki',format:'der'})).digest('base64');
  const browser = await chromium.launch({
    executablePath: process.env.KVM_CHROMIUM,
    args: [`--ignore-certificate-errors-spki-list=${spki}`], // Only this generated local test identity.
  });
  const context = await browser.newContext();
  await context.addInitScript(() => {
    const Native = window.WebSocket;
    window.WebSocket = class extends Native {
      constructor(...args) {
        super(...args);
        this.addEventListener('message', e => {
          if (e.data instanceof ArrayBuffer && new TextDecoder().decode(e.data).startsWith('INPUT ACK')) window.__inputAcknowledged = true;
        });
      }
    };
  });
  const errors = [];
  const observations = [];
  const sessionRequestHeaders = [];
  const requestReads = [];
  context.on('request', request => {
    if (request.url().includes(`.kvm.localhost:${workerPort}/`)) {
      requestReads.push(request.allHeaders().then(h => sessionRequestHeaders.push(h)));
    }
  });
  const passed = name => observations.push({name,passed:true});
  context.on('page', p => {
    p.on('pageerror', e => errors.push(e.message));
    p.on('console', m => { if(m.type()==='error') errors.push(m.text()); });
  });
  try {
    const manager = await context.newPage();
    await manager.goto(`https://localhost:${uiPort}`);
    await manager.locator('input[name=token]').fill(fs.readFileSync(path.join(directory,'login-token'),'utf8').trim());
    await manager.getByRole('button',{name:'登录',exact:true}).click();
    await manager.getByRole('button',{name:'打开控制台'}).first().waitFor();
    passed('login');
    const popupReady = manager.waitForEvent('popup');
    await manager.getByRole('button',{name:'打开控制台'}).first().click();
    const popup = await popupReady;
    await popup.waitForURL(/w1-[a-f0-9]+\.kvm\.localhost/);
    try {
      await popup.locator('#status').filter({hasText:'已连接模拟设备'}).waitFor({timeout:10000});
    } catch (e) {
      console.error('Popup diagnostics:', await popup.locator('body').innerText(), errors);
      throw e;
    }
    passed('ticket POST popup');
    passed('binary console');
    await popup.locator('canvas').click();
    await popup.keyboard.press('A');
    await popup.waitForFunction(() => window.__inputAcknowledged === true);
    passed('keyboard acknowledgement');
    await popup.screenshot({path:path.join(directory,'console.png')});
    const cookies = await context.cookies(popup.url());
    const session = cookies.find(c=>c.name==='__Host-kvm_sid');
    if (!session || !session.httpOnly || !session.secure || cookies.some(c=>c.name==='UPSTREAM_SECRET')) throw Error('cookie isolation failed');
    if (session.domain.startsWith('.') || session.sameSite !== 'Strict') throw Error('cookie host binding failed');
    passed('host-only secure Strict Cookie');
    await Promise.all(requestReads);
    if (!sessionRequestHeaders.length) throw Error('no session requests were observed');
    if (sessionRequestHeaders.some(h=>/UPSTREAM_SECRET|__Host-manager_sid/.test(h.cookie||''))) throw Error('cross-origin cookie leaked in request headers');
    if (!sessionRequestHeaders.some(h=>(h.cookie||'').includes('__Host-kvm_sid'))) throw Error('session cookie missing on request headers');
    passed('request-header cookie isolation');
    await popup.getByRole('button',{name:'结束会话'}).click();
    await popup.locator('#status').filter({hasText:'会话已结束'}).waitFor();
    await manager.goto(`https://localhost:${uiPort}`);
    const sid = new URL(popup.url()).hostname.match(/^w1-([a-f0-9]{32})\./)[1];
    const state = await manager.evaluate(async id => {
      const r=await fetch('/api/sessions/'+id);if(!r.ok)throw Error('status query failed');return await r.json();
    },sid);
    if (state.id!==sid || state.status!=='closed' || state.cleanup!=='confirmed') throw Error('session cleanup missing');
    passed('close and cleanup for exact session');
    if (errors.length) throw Error(JSON.stringify(errors));
    const result={result:'passed',recorded_at:new Date().toISOString(),synthetic_only:true,checks:observations,screenshot:path.join(directory,'console.png')};
    fs.writeFileSync(path.join(directory,'browser-smoke.json'),JSON.stringify(result,null,2)+'\n');
    console.log(JSON.stringify(result));
  } finally {
    await context.close();
    await browser.close();
  }
})().catch(e=>{
  const directory=path.resolve(process.env.KVM_DIRECTORY||'.local-demo');
  try{fs.writeFileSync(path.join(directory,'browser-smoke.json'),JSON.stringify({result:'failed',error:String(e&&e.message||e)},null,2)+'\n');}catch(_){}
  console.error(e);process.exitCode=1;
});
