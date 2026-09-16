const {chromium}=require('C:/Users/heito/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright');
const assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch({headless:true,channel:'msedge'});
 const context=await browser.newContext({viewport:{width:1440,height:1000}});
 const page=await context.newPage();const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto('http://127.0.0.1:8788');
 await page.locator('[data-auth-switch=true]').click();await page.locator('[name=name]').fill('Vendedor QA');await page.locator('[name=company]').fill('Empresa QA '+Date.now());await page.locator('[name=email]').fill('qa-'+Date.now()+'@example.test');await page.locator('[name=password]').fill('PulseFlow-local-2026!');await page.locator('#auth-form button[type=submit]').click();
 await page.locator('.sidebar').waitFor();
 if(await page.locator('#modal').count()){await page.locator('#modal [name=number]').fill('11912345678');await page.locator('#modal [name=niche]').selectOption('Barbearia');await page.locator('#modal button[type=submit]').click();await page.locator('#modal').waitFor({state:'detached'})}
 await page.screenshot({path:'tests/desktop.png',fullPage:true});
 for(let i=0;i<10;i++){await page.locator('[data-action=lead]').first().click();assert(await page.locator('#modal').isVisible());if(i%2)await page.getByRole('button',{name:'Cancelar',exact:true}).click();else await page.getByRole('button',{name:'Fechar janela'}).click();await page.locator('#modal').waitFor({state:'detached'});}
 await page.locator('[data-action=lead]').first().click();await page.locator('#lead-form [name=name]').fill('Contato QA');await page.locator('#lead-form [name=phone]').fill('11923456789');await page.locator('[name=consentConfirmed]').check();await page.locator('#lead-form button[type=submit]').click();await page.locator('#modal').waitFor({state:'detached'});
 await page.locator('.sidebar [data-page=conversations]').click();assert(await page.locator('#message-input').isDisabled());await page.locator('[data-action=call]').first().click();await page.locator('#call-form [name=note]').fill('Quer um corte na sexta-feira.');await page.locator('#call-form button[type=submit]').click();await page.locator('#modal').waitFor({state:'detached'});assert(await page.locator('#message-input').isEnabled());
 await page.locator('[data-template="0"]').click();assert((await page.locator('#message-input').inputValue()).includes('corte'));
 await page.screenshot({path:'tests/conversation.png',fullPage:true});
 await context.route('https://wa.me/**',route=>route.fulfill({status:200,body:'External WhatsApp suppressed in local test.'}));
 await page.locator('#composer button[type=submit]').click();await page.locator('.manual-confirm').waitFor();assert.equal(await page.locator('.messages .outgoing').count(),0);await page.locator('[data-action=confirm-manual]').click();assert.equal(await page.locator('.messages .outgoing').count(),1);assert((await page.locator('.messages').innerText()).includes('Envio confirmado por você'));
 await page.locator('[data-action=schedule]').click();await page.locator('#schedule-form [name=nextDate]').fill('2026-10-01T14:00');await page.locator('#schedule-form button[type=submit]').click();await page.locator('#modal').waitFor({state:'detached'});await page.reload();await page.locator('.sidebar').waitFor();
 for(const pageName of ['home','leads','conversations','agenda','settings']){await page.locator('.sidebar [data-page='+pageName+']').click();assert(await page.locator('.page').isVisible());}
 await page.locator('[data-settings=plan]').click();assert((await page.locator('.plans').innerText()).includes('9,90'));
 await page.locator('[data-settings=operation]').click();await page.locator('[data-action=cadence]').click();assert.equal(await page.locator('#cadence-form textarea').count(),10);
 await page.setViewportSize({width:390,height:844});await page.locator('.mobile-nav [data-page=home]').click();await page.screenshot({path:'tests/mobile.png',fullPage:true});
 for(const width of [360,390,430]){await page.setViewportSize({width,height:844});for(const pageName of ['home','leads','conversations','agenda']){await page.locator('.mobile-nav [data-page='+pageName+']').click();assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),'Overflow '+pageName+' '+width);}}
 await page.screenshot({path:'tests/mobile-agenda.png',fullPage:true});
 await page.setViewportSize({width:1440,height:1000});await page.locator('[data-action=logout]').click();await page.locator('[name=email]').fill('admin@example.test');await page.locator('[name=password]').fill('PulseFlow-local-2026!');await page.locator('#auth-form button[type=submit]').click();await page.locator('[data-support]').first().waitFor();await page.screenshot({path:'tests/admin.png',fullPage:true});await page.locator('[data-support]').first().click();await page.locator('.support-banner').waitFor();await page.locator('.support-banner [data-action=exit-support]').click();await page.locator('[data-support]').first().waitFor();
 assert.deepEqual(errors,[]);console.log('PASS: login, onboarding, 10 closes, lead, call-first, templates, agenda persistence, five pages, plans, cadence, 390px navigation, admin/support.');await browser.close();
})().catch(e=>{console.error(e);process.exit(1)});
