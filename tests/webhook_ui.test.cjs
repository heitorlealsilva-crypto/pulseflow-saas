const {chromium,request}=require('playwright');
const assert=require('node:assert/strict');

(async()=>{
 const launchOptions={headless:true};
 if(process.platform==='win32'&&!process.env.CI)launchOptions.channel='msedge';
 const browser=await chromium.launch(launchOptions);
 const page=await browser.newPage({viewport:{width:1280,height:900}}),errors=[];
 page.on('pageerror',error=>errors.push(error.message));
 await page.goto('http://127.0.0.1:8788');
 await page.locator('[name=email]').fill('seller@example.test');
 await page.locator('[name=password]').fill('PulseFlow-local-2026!');
 await page.locator('#auth-form button[type=submit]').click();
 await page.locator('.sidebar').waitFor();
 if(await page.locator('#business-form').count()){
  await page.locator('#business-form [name=businessName]').fill('Empresa webhook QA');
  await page.locator('#business-form [name=number]').fill('11912345678');
  await page.locator('#business-form button[type=submit]').click();
  await page.locator('#modal').waitFor({state:'detached'});
 }

 await page.locator('.sidebar [data-page=settings]').click();
 let loaded=page.waitForResponse(response=>response.url().includes('action=webhooks'));
 await page.locator('[data-settings=security]').click();
 await loaded;
 assert.equal(await page.locator('#outbound-webhooks-panel').count(),0,'Plano Base sem destinos não deve exibir webhooks avançados.');

 const me=await page.evaluate(()=>fetch('/api/auth?action=me').then(response=>response.json()));
 const adminApi=await request.newContext({baseURL:'http://127.0.0.1:8788'});
 await adminApi.post('/api/auth?action=login',{headers:{Origin:'http://127.0.0.1:8788'},data:{email:'admin@example.test',password:'PulseFlow-local-2026!'}});
 const upgrade=await adminApi.post('/api/auth?action=admin-account',{headers:{Origin:'http://127.0.0.1:8788'},data:{organization_id:me.account.id,plan:'Equipe'}});
 assert.equal(upgrade.status(),200);
 await adminApi.dispose();

 await page.reload();
 await page.locator('.sidebar').waitFor();
 await page.locator('.sidebar [data-page=settings]').click();
 loaded=page.waitForResponse(response=>response.url().includes('action=webhooks'));
 await page.locator('[data-settings=security]').click();
 await loaded;
 const panel=page.locator('#outbound-webhooks-panel');
 await panel.waitFor();
 assert.equal(await panel.getAttribute('open'),null,'O painel deve iniciar recolhido.');
 await panel.locator('summary').click();
 await panel.locator('[data-action=outbound-webhook]').click();
 assert.equal(await page.locator('#outbound-webhook-form [name=event_types]').count(),6);
 assert((await page.locator('#outbound-webhook-form').innerText()).includes('somente IDs e horário'));
 await page.locator('#outbound-webhook-form [name=name]').fill('ERP financeiro');
 await page.locator('#outbound-webhook-form [name=url]').fill('https://hooks.example.test/pulseflow/clientes');
 await page.locator('#outbound-webhook-form button[type=submit]').click();
 const secretField=page.locator('#outbound-webhook-secret');
 await secretField.waitFor();
 const secret=await secretField.inputValue();
 assert.match(secret,/^whsec_/);
 await page.keyboard.press('Escape');
 assert(await secretField.isVisible(),'O segredo one-time não pode sumir com Escape.');
 await page.getByRole('button',{name:'Já copiei e salvei',exact:true}).click();
 await page.locator('#modal').waitFor({state:'detached'});
 assert.equal((await page.content()).includes(secret),false,'O segredo não deve permanecer no DOM.');
 assert((await panel.innerText()).includes('ERP financeiro'));
 assert((await panel.innerText()).includes('hooks.example.test'));
 assert.equal((await panel.innerText()).includes('/pulseflow/clientes'),false,'O caminho completo do destino não deve ser exibido.');

 await panel.locator('[data-test-webhook]').click();
 await page.waitForFunction(()=>document.body.innerText.includes('Teste colocado na fila de entrega.'));
 assert(await panel.getAttribute('open')!==null);
 page.once('dialog',dialog=>dialog.accept());
 await panel.locator('[data-revoke-webhook]').click();
 await page.waitForFunction(()=>document.querySelectorAll('[data-revoke-webhook]').length===0);
 assert((await panel.innerText()).includes('Nenhum webhook cadastrado.'));

 await page.setViewportSize({width:390,height:844});
 await panel.locator('summary').click();
 assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),'Webhooks não devem causar overflow no mobile.');
 assert.deepEqual(errors,[]);
 console.log('PASS: webhooks de saída ocultos no Base, criação segura, segredo one-time, teste enfileirado, revogação e mobile.');
 await browser.close();
})().catch(error=>{console.error(error);process.exit(1)});
