// HTTP contract checks against tests/serve_test.py only, never production.
const assert=require('node:assert/strict');
const origin='http://127.0.0.1:8788';
async function call(action,payload,cookie=''){const r=await fetch(origin+'/api/auth?action='+action,{method:payload?'POST':'GET',headers:{Origin:origin,'Content-Type':'application/json',Cookie:cookie},body:payload?JSON.stringify(payload):undefined});return {status:r.status,data:await r.json(),cookie:r.headers.get('set-cookie')?.split(';')[0]}}
(async()=>{
 assert.equal((await call('me')).status,401);
 const nonce=Date.now(),password='Fixture-only-Password!';
 const a=await call('register',{name:'Teste A',company:'Tenant A '+nonce,email:'a'+nonce+'@example.test',password});
 const b=await call('register',{name:'Teste B',company:'Tenant B '+nonce,email:'b'+nonce+'@example.test',password});
 assert.equal(a.status,200);assert.equal(b.status,200);
 assert.equal((await call('admin',undefined,a.cookie)).status,403);
 const org=a.data.user.organization_id,other=b.data.user.organization_id;
 assert.equal((await call('workspace&organization_id='+other,undefined,a.cookie)).status,403);
 const state={leads:[{id:'a1',name:'Only tenant A',notes:'isolated'}]};
 const first=await call('workspace',{organization_id:org,revision:0,state},a.cookie);assert.equal(first.status,200);assert.equal(first.data.revision,1);
 assert.equal((await call('workspace',{organization_id:org,revision:0,state:{leads:[]}},a.cookie)).status,409);
 assert.equal((await call('workspace&organization_id='+org,undefined,a.cookie)).data.workspace.leads[0].notes,'isolated');
 assert.equal((await call('workspace',{organization_id:other,revision:0,state},a.cookie)).status,403);
 const untouched=await call('workspace&organization_id='+other,undefined,b.cookie);assert.equal(untouched.data.revision,0);
 const admin=await call('login',{email:'admin@example.test',password:'PulseFlow-local-2026!'});assert.equal(admin.status,200);
 assert.equal((await call('admin-account',{organization_id:org,permissions:{workspace_write:false}},admin.cookie)).status,200);
 assert.equal((await call('workspace',{organization_id:org,revision:1,state},a.cookie)).status,403);
 assert.equal((await call('admin-account',{organization_id:org,status:'suspended'},admin.cookie)).status,200);
 assert.equal((await call('me',undefined,a.cookie)).status,401);
 assert.equal((await call('workspace&organization_id='+org,undefined,admin.cookie)).status,200);
 console.log('PASS: isolated HTTP contracts: sessions, tenants, CAS, permissions, suspension and admin support.');
})().catch(e=>{console.error(e);process.exit(1)});
