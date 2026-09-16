"""Deterministic handler tests. No credentials, database or provider network used."""
import hashlib
import hmac
import importlib
import io
import json
import sys
import types
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
try:
    import psycopg
except ImportError:
    stub = types.ModuleType('psycopg')
    stub.errors = types.SimpleNamespace(UniqueViolation=type('UniqueViolation', (Exception,), {}))
    stub.rows = types.ModuleType('psycopg.rows')
    stub.rows.dict_row = None
    sys.modules['psycopg'] = stub
    sys.modules['psycopg.rows'] = stub.rows
auth = importlib.import_module('api.auth')
wa = importlib.import_module('api.whatsapp')

class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now(timezone.utc)
        self.lead = {'id':'l1','phone':'11912345678','board':'Principal','consentConfirmed':True,
            'calls':[{'id':'c1','at':(self.now-timedelta(hours=1)).isoformat(),'outcome':'Não atendeu'}]}
        self.workspace = {'leads':[self.lead]}
        self.payload = {'lead_id':'l1','approval':True,'request_id':str(uuid.uuid4()),'text':'Olá, Ana.'}
        self.org, self.other = str(uuid.uuid4()), str(uuid.uuid4())
        self.owner = {'id':str(uuid.uuid4()),'role':'owner','organization_id':self.org}
        self.handler = auth.handler.__new__(auth.handler)

    def reject_send(self, code):
        with self.assertRaises(wa.IntegrationError) as caught:
            wa.send_guard(self.workspace,self.payload,self.now,now=self.now)
        self.assertEqual(caught.exception.code,code)

    def test_password_hash_and_wrong_password(self):
        value=auth.password_hash('test-only-Password!')
        self.assertTrue(auth.password_valid('test-only-Password!',value))
        self.assertFalse(auth.password_valid('wrong',value))
        self.assertFalse(auth.password_valid('x','malformed'))
    def test_password_salts_are_independent(self):
        self.assertNotEqual(auth.password_hash('test-pass'),auth.password_hash('test-pass'))
    def test_secrets_and_auth_fields_do_not_persist(self):
        value=auth.clean_workspace({'user':{'role':'super_admin'},'plan':'Premium','officialWhatsappConnected':True,
            'ai':{'api_key':'secret','instructions':'ok'},'leads':[{'id':'l','access_token':'secret'}]})
        self.assertEqual(value,{'ai':{'instructions':'ok'},'leads':[{'id':'l'}]})
    def test_workspace_types_rejected(self):
        for value in [None,[],{'leads':{}},{'schemaVersion':True}]:
            with self.assertRaises(auth.RequestError): auth.clean_workspace(value)
    def test_nested_object_limit(self):
        value={}
        for _ in range(20): value={'nested':value}
        with self.assertRaises(auth.RequestError):auth.clean_workspace({'settings':value})
    def test_origin_validation(self):
        for headers in [{'Host':'app.example','Origin':'https://evil.example'}, {'Host':'app.example'},
                {'Host':'app.example','Origin':'https://app.example','Sec-Fetch-Site':'cross-site'}]:
            self.handler.headers=headers
            with self.assertRaises(auth.RequestError):self.handler.check_origin()
        self.handler.headers={'Host':'app.example','Origin':'https://app.example'}
        self.handler.check_origin()
    def test_nonlocal_http_origin_is_invalid(self):
        self.assertIsNone(auth.normalized_origin('http://app.example'))
        self.assertIsNotNone(auth.normalized_origin('http://127.0.0.1:8788'))
    def test_body_validation(self):
        for raw in [b'[]',b'null',b'{"x":NaN}',b'{bad']:
            self.handler.headers={'Content-Type':'application/json','Content-Length':str(len(raw))}
            self.handler.rfile=io.BytesIO(raw)
            with self.assertRaises(auth.RequestError): self.handler.body()
    def test_large_body_rejected_before_reading(self):
        self.handler.headers={'Content-Type':'application/json','Content-Length':'2000001'}
        self.handler.rfile=MagicMock()
        with self.assertRaises(auth.RequestError):self.handler.body()
        self.handler.rfile.read.assert_not_called()
    def test_workspace_tenant_boundary(self):
        self.assertEqual(self.handler.allowed_organization(self.owner,''),self.org)
        self.assertIsNone(self.handler.allowed_organization(self.owner,self.other))
        self.assertEqual(self.handler.allowed_organization({'role':'super_admin'},self.other),self.other)
    def test_permissions_enforced_and_admin_exception(self):
        account=auth.public_account({'id':self.org,'status':'active','permissions':{'workspace_write':False}})
        with self.assertRaises(auth.RequestError):auth.require_permission(self.owner,account,'workspace_write')
        auth.require_permission({'role':'super_admin'},account,'workspace_write')
    def test_workspace_revision_required(self):
        with self.assertRaises(auth.RequestError) as caught:self.handler.save_workspace(MagicMock(),self.owner,{'organization_id':self.org,'state':{}})
        self.assertEqual(caught.exception.status,428)
    def test_stale_workspace_revision_cannot_overwrite(self):
        db=MagicMock();db.execute.return_value.fetchone.return_value={'state':{},'revision':4}
        self.handler.account=lambda *a,**k:auth.public_account({'id':self.org,'status':'active','permissions':{}})
        with self.assertRaises(auth.RequestError) as caught:self.handler.save_workspace(db,self.owner,{'organization_id':self.org,'revision':3,'state':{}})
        self.assertEqual(caught.exception.status,409);db.commit.assert_not_called()
        self.assertFalse(any('INSERT INTO tenant_workspaces' in str(c) for c in db.execute.call_args_list))
    def test_invalid_account_status_and_plan(self):
        self.handler.account=lambda *a,**k:auth.public_account({'id':self.org,'status':'active','permissions':{}})
        for value in [{'status':'deleted'},{'plan':'FreeEverything'},{'permissions':{'workspace_read':'yes'}}]:
            with self.assertRaises(auth.RequestError):self.handler.update_account(MagicMock(),self.owner,{'organization_id':self.org,**value})
    def test_whatsapp_tenant_boundary(self):
        self.assertEqual(wa.allowed_org(self.owner,''),self.org)
        self.assertIsNone(wa.allowed_org(self.owner,self.other))
    def test_webhook_signature_mandatory_and_exact(self):
        raw=b'{"test":true}';signature='sha256='+hmac.new(b'secret',raw,hashlib.sha256).hexdigest()
        self.assertTrue(wa.valid_signature('secret',raw,signature))
        for value in ['',None,'sha256=bad',signature.upper()]:self.assertFalse(wa.valid_signature('secret',raw,value))
        self.assertFalse(wa.valid_signature('secret',b'tampered',signature))
    def test_configured_does_not_mean_connected(self):
        self.assertFalse(wa.connection_payload({'status':'active'},self.org)['ready'])
        self.assertFalse(wa.connection_payload({'meta_verified_at':self.now},self.org)['ready'])
        self.assertTrue(wa.connection_payload({'meta_verified_at':self.now,'webhook_verified_at':self.now},self.org)['ready'])
    def test_connection_hides_credentials(self):
        value=wa.connection_payload({'access_token_enc':'secret','verify_token_hash':'secret'},self.org)
        self.assertNotIn('secret',json.dumps(value,default=str))
    def test_sender_requires_explicit_approval(self):
        self.payload['approval']=False;self.reject_send('approval_required')
    def test_sender_disallows_background_flag(self):
        self.payload['automatic']=True;self.reject_send('approval_required')
    def test_sender_requires_request_uuid(self):
        self.payload['request_id']='bad';self.reject_send('invalid_request_id')
    def test_sender_uses_saved_destination(self):
        self.payload['to']='5511999999999'
        _,destination,_,_=wa.send_guard(self.workspace,self.payload,self.now,now=self.now)
        self.assertEqual(destination,'5511912345678')
    def test_client_call_flag_cannot_bypass_rule(self):
        self.lead['calls']=[];self.lead['callDone']=True;self.payload['callDone']=True;self.reject_send('call_required')
    def test_future_or_planned_call_is_not_evidence(self):
        self.lead['calls'][0]['at']=(self.now+timedelta(days=1)).isoformat();self.reject_send('call_required')
        self.lead['calls'][0]['at']=self.now.isoformat();self.lead['calls'][0]['outcome']='agendada';self.reject_send('call_required')
    def test_client_consent_flag_cannot_bypass_rule(self):
        self.lead['consentConfirmed']=False;self.payload['consentConfirmed']=True;self.reject_send('consent_required')
    def test_optout_is_respected(self):
        self.lead['optOut']=True;self.reject_send('opted_out')
    def test_closed_lead_is_respected(self):
        self.lead['stage']='closed';self.reject_send('lead_closed')
    def test_postsale_is_observer_only(self):
        self.lead['board']='Pós-venda';self.reject_send('observation_only')
    def test_outside_window_requires_approved_template(self):
        for inbound in [None,self.now-timedelta(hours=24),self.now+timedelta(seconds=1)]:
            with self.assertRaises(wa.IntegrationError) as caught:wa.send_guard(self.workspace,self.payload,inbound,now=self.now)
            self.assertEqual(caught.exception.code,'template_required')
    def test_template_shape_validation(self):
        self.payload['template']={'name':'invalid spaces','language':'pt_BR'};self.reject_send('invalid_template')
    def test_template_must_be_approved_in_meta(self):
        with patch.object(wa,'graph_call',return_value={'data':[]}):
            with self.assertRaises(wa.IntegrationError) as caught:wa.template_payload({'waba_id':'12345'},{'name':'hello','language':'pt_BR'})
            self.assertEqual(caught.exception.code,'template_not_approved')
    def test_cipher_roundtrip(self):
        with patch.dict('os.environ',{'PULSEFLOW_ENCRYPTION_KEY':'test-only-key-not-for-production-12345'}):
            encrypted=wa.cipher().encrypt(b'test-token').decode()
            self.assertNotIn('test-token',encrypted);self.assertEqual(wa.decrypt(encrypted),'test-token')
    def test_missing_encryption_key_fails_closed(self):
        with patch.dict('os.environ',{'PULSEFLOW_ENCRYPTION_KEY':''}):
            with self.assertRaises(wa.IntegrationError):wa.cipher()

if __name__=='__main__':unittest.main()
