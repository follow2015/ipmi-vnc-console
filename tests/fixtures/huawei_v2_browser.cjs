const { chromium } = require(process.env.KVM_PLAYWRIGHT);
(async () => {
  const browser = await chromium.launch({executablePath:process.env.KVM_CHROMIUM,headless:true});
  try {
    const page = await browser.newPage();
    const errors=[];
    page.on('pageerror', e=>errors.push(e.message));
    await page.goto(process.argv[2]);
    await page.waitForFunction(()=>{
      const c=document.querySelector('#v2-screen canvas');
      if(!c || c.width!==64 || c.height!==64) return false;
      const p=c.getContext('2d').getImageData(0,0,1,1).data;
      return p[0]>180 && p[2]<50;
    },null,{timeout:10000});
    await page.waitForFunction(()=>{
      const p=document.querySelector('#v2-screen canvas').getContext('2d').getImageData(0,0,1,1).data;
      return p[2]>180 && p[0]<50;
    },null,{timeout:10000});
    await page.click('#v2-escape');
    await page.click('#v2-fit');
    await page.click('#v2-input summary');
    await page.waitForFunction(()=>!document.getElementById('v2-text-send').disabled);
    await page.fill('#v2-text', '中');
    await page.click('#v2-text-send');
    if(!(await page.textContent('#v2-input-status')).includes('未发送')) throw Error('unmappable text was not refused');
    page.on('dialog', dialog=>dialog.accept());
    await page.fill('#v2-text', 'abc');
    await page.click('#v2-text-send');
    await page.waitForFunction(()=>document.getElementById('v2-input-status').textContent.includes('发送完成'));
    await page.click('#v2-sk-tabs button[data-v2page="func"]');
    await page.click('#v2-sk-body [data-v2page="func"] button[data-v2-key="f12"]');
    await page.waitForFunction(()=>document.getElementById('v2-sk-status').textContent.includes('F12'));
    await page.click('#v2-close');
    await page.waitForFunction(()=>document.getElementById('v2-status').textContent==='会话已结束');
    if(errors.length) throw Error(JSON.stringify(errors));
    console.log(JSON.stringify({first_screen:true,incremental:true,input:true,text_preflight:true,text_keys:true,softkey:true,closed:true}));
  } finally {await browser.close();}
})().catch(e=>{console.error(e.stack);process.exit(1)});
