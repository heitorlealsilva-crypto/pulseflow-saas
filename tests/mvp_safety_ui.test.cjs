const { chromium } = require('playwright');
const assert = require('node:assert/strict');

(async () => {
  const browser = await chromium.launch(process.platform === 'win32' && !process.env.CI
    ? { headless: true, channel: 'msedge' } : { headless: true });
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto('http://127.0.0.1:8788');
  await page.locator('[data-auth-switch=true]').click();
  await page.locator('#auth-form [name=name]').fill('Segurança QA');
  await page.locator('#auth-form [name=company]').fill('Segurança QA');
  await page.locator('#auth-form [name=email]').fill(`seguranca-${Date.now()}@example.test`);
  await page.locator('#auth-form [name=password]').fill('PulseFlow-local-2026!');
  await page.locator('#auth-form [name=legal_accepted]').check();
  await page.locator('#auth-form button[type=submit]').click();
  await page.locator('#business-form').waitFor();
  await page.locator('#business-form [name=number]').fill('11912345678');
  await page.locator('#business-form button[type=submit]').click();
  await page.locator('#modal').waitFor({ state: 'detached' });
  await page.waitForFunction(() => document.querySelector('#save-state')?.textContent === 'Salvo na nuvem');

  async function workspace() {
    return page.evaluate(async () => {
      const me = await fetch('/api/auth?action=me').then(response => response.json());
      return fetch('/api/auth?action=workspace&organization_id=' + encodeURIComponent(me.account.id))
        .then(response => response.json());
    });
  }
  async function save(state) {
    const result = await page.evaluate(async state => {
      const me = await fetch('/api/auth?action=me').then(response => response.json());
      const current = await fetch('/api/auth?action=workspace&organization_id=' + encodeURIComponent(me.account.id))
        .then(response => response.json());
      const response = await fetch('/api/auth?action=workspace', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ organization_id: me.account.id, revision: current.revision, state }),
      });
      return response.status;
    }, state);
    assert.equal(result, 200);
  }

  const data = await workspace();
  const state = data.workspace;
  const entered = Date.now() - 48 * 3600000;
  state.ai.enabled = true;
  state.automations = [{ id: 'stage-qa', name: 'Prazo da etapa', enabled: true,
    trigger: 'stage_timeout', board: 'Principal', delay: 24, action: 'prepare_followup', instructions: 'Revisar' }];
  state.leads = [{ id: 'lead-qa', name: 'Contato de segurança', phone: '5511987654321',
    board: 'Principal', stage: 'service', entered, consentConfirmed: true,
    calls: [{ id: 'call-qa', at: new Date(entered).toISOString(), outcome: 'Não atendeu' }],
    messages: [], notes: '' }];
  await save(state);
  await page.reload();
  await page.locator('.sidebar').waitFor();
  await page.locator('.sidebar [data-page=automations]').click();
  assert.equal(await page.locator('.approval-list article').count(), 1);
  await page.reload();
  await page.locator('.sidebar').waitFor();
  await page.locator('.sidebar [data-page=automations]').click();
  assert.equal(await page.locator('.approval-list article').count(), 1,
    'prazo sem mudança não pode gerar outra aprovação a cada dia ou abertura');
  await page.waitForFunction(() => document.querySelector('#save-state')?.textContent === 'Salvo na nuvem');

  const legacy = await workspace();
  legacy.workspace.automationRuns = [{ key: `stage-qa:lead-qa:${new Date().toISOString().slice(0, 10)}`,
    ruleId: 'stage-qa', leadId: 'lead-qa', at: new Date().toISOString() }];
  await save(legacy.workspace);
  await page.reload();
  await page.locator('.sidebar').waitFor();
  await page.locator('.sidebar [data-page=automations]').click();
  assert.equal(await page.locator('.approval-list article').count(), 1,
    'revisões antigas não devem criar uma nova cópia na migração');

  const blocked = await workspace();
  blocked.workspace.leads[0].opt_out = true;
  blocked.workspace.leads[0].optOut = false;
  await save(blocked.workspace);
  await page.reload();
  await page.locator('.sidebar').waitFor();
  await page.locator('.sidebar [data-page=leads]').click();
  assert((await page.locator('.lead-card').innerText()).includes('Não contatar'));
  await page.locator('.sidebar [data-page=conversations]').click();
  assert.equal(await page.locator('#composer').count(), 0,
    'bloqueio de integração deve impedir preparo e envio manual');
  assert.deepEqual(errors, []);
  await browser.close();
  console.log('PASS: opt-out importado bloqueia interface e regra de etapa não duplica revisões.');
})().catch(error => { console.error(error); process.exit(1); });
