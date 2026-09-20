// HTTP contract checks against tests/serve_test.py only, never production.
const assert=require('node:assert/strict');
const origin='http://127.0.0.1:8788';
async function call(action,payload,cookie=''){const r=await fetch(origin+'/api/auth?action='+action,{method:payload?'POST':'GET',headers:{Origin:origin,'Content-Type':'application/json',Cookie:cookie},body:payload?JSON.stringify(payload):undefined});return {status:r.status,data:await r.json(),cookie:r.headers.get('set-cookie')?.split(';')[0]}}
(async()=>{
 assert.equal((await call('me')).status,401);
 const nonce=Date.now(),password='Fixture-only-Password!';
 assert.equal((await call('register',{name:'Sem aceite',company:'Inválida',email:'no-legal'+nonce+'@example.test',password})).status,400);
 const legal={legal_accepted:true,legal_version:'2026-09-20'},a=await call('register',{name:'Teste A',company:'Tenant A '+nonce,email:'a'+nonce+'@example.test',password,...legal});
 const b=await call('register',{name:'Teste B',company:'Tenant B '+nonce,email:'b'+nonce+'@example.test',password,...legal});
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
 assert.equal((await call('admin-account',{organization_id:org,plan:'Equipe'},admin.cookie)).status,200);
 const team=await call('team&organization_id='+org,undefined,a.cookie);assert.equal(team.status,200);assert.equal(team.data.members.length,1);assert.equal(team.data.limit,3);
 const teammateEmail='member'+nonce+'@example.test',teammatePassword='Member-only-Password!';const invitation=await call('team-invite',{organization_id:org,operation:'create',name:'Vendedor B',email:teammateEmail},a.cookie);assert.equal(invitation.status,200);assert.match(invitation.data.invite_path,/^\/#invite=/);assert.equal((await call('team&organization_id='+org,undefined,a.cookie)).data.invites.length,1);
 const inviteToken=new URL(origin+invitation.data.invite_path).hash.slice(1).split('=')[1];assert.equal((await call('accept-invite',{token:inviteToken,password:teammatePassword})).status,400);const teammate=await call('accept-invite',{token:inviteToken,password:teammatePassword,...legal});assert.equal(teammate.status,200);assert.equal(teammate.data.user.organization_id,org);assert.equal((await call('accept-invite',{token:inviteToken,password:teammatePassword,...legal})).status,410);assert.equal((await call('team&organization_id='+org,undefined,teammate.cookie)).status,200);assert.equal((await call('team-invite',{organization_id:org,operation:'create',name:'Inválido',email:'invalid@example.test'},teammate.cookie)).status,403);
 assert.equal((await call('admin-password-reset',{user_id:admin.data.user.id},admin.cookie)).status,403);assert.equal((await call('admin-password-reset',{user_id:teammate.data.user.id},a.cookie)).status,403);
 const reset=await call('admin-password-reset',{user_id:teammate.data.user.id},admin.cookie);assert.equal(reset.status,200);assert.equal(reset.data.expires_in_minutes,30);assert.match(reset.data.reset_path,/^\/#reset=/);assert.equal('token' in reset.data,false);
 const resetToken=new URL(origin+reset.data.reset_path).hash.slice(1).split('=')[1],resetPassword='Reset-member-Password!';assert.equal((await call('accept-password-reset',{token:resetToken,password:'curta'})).status,400);
 const resetAccepted=await call('accept-password-reset',{token:resetToken,password:resetPassword});assert.equal(resetAccepted.status,200);assert.equal(resetAccepted.data.user.id,teammate.data.user.id);assert.equal((await call('me',undefined,teammate.cookie)).status,401);assert.equal((await call('accept-password-reset',{token:resetToken,password:resetPassword})).status,410);assert.equal((await call('login',{email:teammateEmail,password:teammatePassword})).status,401);assert.equal((await call('login',{email:teammateEmail,password:resetPassword})).status,200);assert.equal((await call('team&organization_id='+org,undefined,resetAccepted.cookie)).status,200);
 assert.equal((await call('team-user',{organization_id:org,operation:'status',user_id:teammate.data.user.id,status:'suspended'},a.cookie)).status,200);assert.equal((await call('me',undefined,resetAccepted.cookie)).status,401);assert.equal((await call('admin-password-reset',{user_id:teammate.data.user.id},admin.cookie)).status,409);
 const changedPassword='Changed-owner-Password!';assert.equal((await call('change-password',{current_password:password,new_password:changedPassword},a.cookie)).status,200);assert.equal((await call('login',{email:a.data.user.email,password})).status,401);assert.equal((await call('login',{email:a.data.user.email,password:changedPassword})).status,200);
 assert.equal((await call('admin-account',{organization_id:org,permissions:{workspace_write:false}},admin.cookie)).status,200);
 assert.equal((await call('workspace',{organization_id:org,revision:1,state},a.cookie)).status,403);
 assert.equal((await call('admin-account',{organization_id:org,status:'suspended'},admin.cookie)).status,200);
 assert.equal((await call('me',undefined,a.cookie)).status,401);
 assert.equal((await call('workspace&organization_id='+org,undefined,admin.cookie)).status,200);
 console.log('PASS: isolated HTTP contracts: sessions, tenants, team access, password reset, CAS, permissions, suspension and admin support.');
})().catch(e=>{console.error(e);process.exit(1)});
