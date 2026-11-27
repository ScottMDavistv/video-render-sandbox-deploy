"""Execute the exact embedded Python with synthetic data and denied networking."""
import ast
import base64
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import unittest
from unittest.mock import patch
import urllib.request
import yaml

ROOT = Path(__file__).resolve().parents[1]
PATH = '.github/workflows/oidc-proof-reusable.yml'
BASE = 'a05dc9b04fe5bfedb99e8fc8d0f093e5e8efa60c'
GUID = '00000000-0000-0000-0000-000000000000'
ROUTE = '/_apis/distributedtask/hubs/Actions/plans/' + GUID + '/jobs/' + GUID + '/idtoken'
ROOT_URL = 'https://pipelines.actions.githubusercontent.com' + ROUTE + '?api-version=2.0'
REGIONAL = 'https://pipelinesghubtest1.actions.githubusercontent.com/SyntheticScope_1/' + GUID + ROUTE + '?api-version=2.0'
NOW = 1800000000


def source(raw):
    job = yaml.safe_load(raw)['jobs']['claim-proof']
    lines = job['steps'][0]['run'].splitlines()
    if lines[0] != "/usr/bin/python3 -I -B - <<'CLAIM_RECEIPT_PY'" or lines[-1] != 'CLAIM_RECEIPT_PY':
        raise ValueError('Unexpected entry point')
    return '\n'.join(lines[1:-1]) + '\n'


def load(raw):
    ns = {'__name__': 'synthetic_offline_fixture'}
    exec(compile(source(raw), 'exact_embedded_claim_receipt', 'exec'), ns)
    return ns


def environment(ns, url=REGIONAL):
    return {'GITHUB_ACTIONS':'true', 'RUNNER_ENVIRONMENT':'github-hosted',
            'GITHUB_REPOSITORY':ns['REPO'], 'GITHUB_REPOSITORY_ID':ns['REPO_ID'],
            'GITHUB_REPOSITORY_OWNER_ID':ns['OWNER_ID'], 'GITHUB_ACTOR_ID':ns['ACTOR_ID'],
            'GITHUB_REF':'refs/heads/main', 'GITHUB_REF_TYPE':'branch',
            'GITHUB_EVENT_NAME':'workflow_dispatch', 'GITHUB_RUN_ATTEMPT':'1',
            'GITHUB_WORKFLOW_REF':ns['CALLER'], 'GITHUB_RUN_ID':'123456',
            'GITHUB_SHA':'1'*40, 'ACTIONS_ID_TOKEN_REQUEST_URL':url,
            'ACTIONS_ID_TOKEN_REQUEST_TOKEN':'SYNTHETIC-NOT-A-CREDENTIAL'}


def claims(ns):
    return {'iss':ns['ISSUER'], 'aud':ns['AUDIENCE'],
            'sub':f"repo:ScottMDavistv@{ns['OWNER_ID']}/video-render-sandbox-deploy@{ns['REPO_ID']}:environment:{ns['ENVIRONMENT']}",
            'repository':ns['REPO'], 'repository_id':ns['REPO_ID'], 'repository_owner_id':ns['OWNER_ID'],
            'environment':ns['ENVIRONMENT'], 'ref':'refs/heads/main', 'ref_type':'branch',
            'event_name':'workflow_dispatch', 'actor_id':ns['ACTOR_ID'], 'run_id':'123456',
            'run_attempt':'1', 'workflow_ref':ns['CALLER'], 'workflow_sha':'1'*40,
            'job_workflow_ref':ns['CALLEE']+'2'*40, 'job_workflow_sha':'2'*40,
            'runner_environment':'github-hosted', 'iat':NOW-1, 'nbf':NOW-1, 'exp':NOW+60}


def body(c):
    def enc(v):return base64.urlsafe_b64encode(json.dumps(v).encode()).decode().rstrip('=')
    return json.dumps({'value':enc({'alg':'RS256','kid':'synthetic'})+'.'+enc(c)+'.synthetic'}).encode()


class OfflineCheckerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.before = subprocess.check_output(['git','show',BASE+':'+PATH], cwd=ROOT)
        cls.after = (ROOT/PATH).read_bytes()

    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.dict(os.environ, {}, clear=True))
        for target in ('socket.socket.connect','socket.socket.connect_ex','socket.create_connection','socket.getaddrinfo','urllib.request.urlopen'):
            self.stack.enter_context(patch(target, side_effect=RuntimeError('NETWORK_DENIED')))
        self.ns = load(self.after)

    def main(self, env=None, fetch=None, ns=None):
        ns = ns or self.ns
        env = environment(ns) if env is None else env
        fetch = (lambda *_:body(claims(ns))) if fetch is None else fetch
        # Supply synthetic transport and clock to the unchanged function boundary.
        ns['collect'].__defaults__ = (fetch, lambda:NOW)
        out, err = io.StringIO(), io.StringIO()
        with patch.dict(os.environ,env,clear=True), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = ns['main']()
        return code,out.getvalue(),err.getvalue()

    def refused(self, stage, **kwargs):
        code,out,err = self.main(**kwargs)
        self.assertEqual(code,78)
        self.assertEqual(out,'')
        self.assertEqual(err,'STOP: claim proof refused stage='+stage+'\n')

    def test_baseline_identity_and_unchanged_workflow_controls(self):
        self.assertEqual(hashlib.sha1(b'blob '+str(len(self.before)).encode()+b'\0'+self.before).hexdigest(),'4f731befafbee6633b319083678186a82f16c274')
        a,b=yaml.safe_load(self.before),yaml.safe_load(self.after)
        a['jobs']['claim-proof']['steps'][0]['run']='EMBEDDED'
        b['jobs']['claim-proof']['steps'][0]['run']='EMBEDDED'
        self.assertEqual(a,b)
        caller=(ROOT/'.github/workflows/oidc-proof-caller.yml').read_bytes()
        self.assertEqual(hashlib.sha1(b'blob '+str(len(caller)).encode()+b'\0'+caller).hexdigest(),'3a8ddaa802d35783754aea631ba753649106f389')
        old,new=ast.parse(source(self.before)),ast.parse(source(self.after))
        funcs=lambda t:{n.name:ast.dump(n,include_attributes=False) for n in t.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
        for name,node in funcs(old).items():
            if name not in ('provider_url','collect','main'):self.assertEqual(node,funcs(new)[name],name)

    def test_old_rejects_regional_new_accepts_both(self):
        old=load(self.before)
        with self.assertRaises(old['Refused']):old['provider_url'](REGIONAL)
        for url in (ROOT_URL,REGIONAL):
            result=self.ns['provider_url'](url)
            self.assertEqual(result,url+'&audience=api%3A%2F%2FAzureADTokenExchange')
            code,out,err=self.main(env=environment(self.ns,url))
            self.assertEqual(code,0);self.assertEqual(err,'')
            self.assertEqual(json.loads(out.removeprefix('STORAGE_OIDC_RECEIPT '))['status'],'CLAIM_RECEIPT_ONLY')
            self.assertNotIn('SYNTHETIC-NOT-A-CREDENTIAL',out)

    def test_hostile_origin_authority_and_path(self):
        urls=[ROOT_URL.replace('https:','http:'), ROOT_URL.replace('pipelines.', 'user@pipelines.'),
              ROOT_URL.replace('.com/', '.com:443/'),ROOT_URL.replace('.com/', '.com.evil.invalid/'),
              ROOT_URL.replace('pipelines.','PIPELINES.'),ROOT_URL+'#fragment', ROOT_URL+'\n',
              ROOT_URL.replace('/_apis/', '//_apis/'), ROOT_URL.replace('/_apis/', '/%5fapis/'),
              ROOT_URL.replace('/_apis/', '/x/../_apis/'),ROOT_URL.replace('/idtoken','/idtoken/extra'),
              ROOT_URL.replace('/idtoken','/idtoken%2f'),ROOT_URL.replace('/hubs/Actions','/hubs/Other'),
              ROOT_URL.replace('/plans/', '/plans/%2e%2e/'),ROOT_URL.replace('/_apis/', '/_apis\\'),
              REGIONAL.replace('pipelinesghubtest1','other'),REGIONAL.replace('/SyntheticScope_1/', '/x/y/'),
              REGIONAL.replace('/SyntheticScope_1/', '/./'),REGIONAL.replace('/SyntheticScope_1/', '/%41/'),
              ROOT_URL.replace('/_apis/', '/prefix/_apis/'),ROOT_URL.replace(GUID,'bad')]
        for url in urls:
            with self.subTest(url=urls.index(url)):
                self.refused('PROVIDER_URL',env=environment(self.ns,url))

    def test_query_fail_closed(self):
        for q in ('audience=x','Audience=x','%61udience=x','api-version=2.0&api-version=2.0',
                  'api-version=2.0&token=SECRET','api-version=2.0&','api-version=%32.0',
                  'api-version=3.0','api-version=2.0;audience=x','api-version=2.0&x=%ZZ'):
            self.refused('PROVIDER_URL',env=environment(self.ns,ROOT_URL.split('?')[0]+'?'+q))

    def test_stage_redaction_all_boundaries(self):
        self.ns['RELEASED']=False;self.refused('GATE');self.ns['RELEASED']=True
        e=environment(self.ns);e['GITHUB_ACTOR_ID']='SECRET';self.refused('CONTEXT',env=e)
        e=environment(self.ns);e['ACTIONS_ID_TOKEN_REQUEST_TOKEN']='SECRET\n';self.refused('REQUEST_CREDENTIAL',env=e)
        def bad(*_):raise RuntimeError('SECRET token URL claims headers')
        self.refused('TRANSPORT',fetch=bad)
        for raw in (b'SECRET',b'x'*32769,b'{"value":"SECRET"}',b'{"value":1,"value":2}'):
            self.refused('ASSERTION',fetch=lambda *_,r=raw:r)
        c=claims(self.ns);c['aud']='SECRET';self.refused('CLAIMS',fetch=lambda *_:body(c))
        self.ns['collect']=bad;self.refused('INTERNAL')

    def test_existing_context_claims_and_time_guards(self):
        for key in ('GITHUB_REPOSITORY_ID','GITHUB_REPOSITORY_OWNER_ID','GITHUB_REF','GITHUB_RUN_ATTEMPT','GITHUB_WORKFLOW_REF'):
            e=environment(self.ns);e[key]='wrong';self.refused('CONTEXT',env=e)
        for key in ('sub','environment','job_workflow_ref','workflow_sha','actor_id','run_id','run_attempt','iss'):
            c=claims(self.ns);c[key]='wrong';self.refused('CLAIMS',fetch=lambda *_,c=c:body(c))
        c=claims(self.ns);c['exp']=NOW-1;self.refused('CLAIMS',fetch=lambda *_:body(c))

    def test_exact_transport_no_proxy_no_redirect_single_get_bounded(self):
        seen=[]
        class Response:
            status=200
            def __enter__(self):return self
            def __exit__(self,*a):pass
            def read(self,n):seen.append(n);return body(claims(self.ns))
        response=Response();response.ns=self.ns
        class Opener:
            def open(self,req,timeout):seen.append((req.get_method(),timeout));return response
        def build(*handlers):
            self.assertEqual(handlers[0].proxies,{})
            self.assertIsNone(handlers[-1].redirect_request(None,None,None,None,None,None))
            return Opener()
        with patch.dict(os.environ,{'HTTPS_PROXY':'http://invalid.invalid','ALL_PROXY':'http://invalid.invalid'},clear=True), patch('urllib.request.build_opener',side_effect=build) as opener:
            raw=self.ns['tls_fetch'](self.ns['provider_url'](REGIONAL),'SYNTHETIC-NOT-A-CREDENTIAL')
        self.assertEqual(raw,body(claims(self.ns)))
        self.assertEqual(seen,[('GET',8),32769]);self.assertEqual(opener.call_count,1)

    def test_full_embedded_main_entrypoint_with_only_mock_transport(self):
        ns=self.ns
        class Response:
            status=200
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self,n):return body(claims(ns))
        class Opener:
            def open(self,*args,**kwargs):return Response()
        out,err=io.StringIO(),io.StringIO()
        with patch.dict(os.environ,environment(ns),clear=True), patch('time.time',return_value=NOW), patch('urllib.request.build_opener',return_value=Opener()) as transport, contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            with self.assertRaises(SystemExit) as result:
                exec(compile(source(self.after),'exact_embedded_main','exec'),{'__name__':'__main__'})
        self.assertEqual(result.exception.code,0)
        self.assertEqual(transport.call_count,1)
        self.assertEqual(err.getvalue(),'')
        self.assertEqual(json.loads(out.getvalue().removeprefix('STORAGE_OIDC_RECEIPT '))['status'],'CLAIM_RECEIPT_ONLY')

    def test_redirect_and_transport_failures_never_emit_response(self):
        import urllib.error
        for error in (urllib.error.HTTPError('https://synthetic.invalid',302,'SECRET',{},None),RuntimeError('SECRET')):
            def build(*_,e=error):
                class Opener:
                    def open(self,*a,**k):raise e
                return Opener()
            with patch('urllib.request.build_opener',side_effect=build):
                self.refused('TRANSPORT',fetch=self.ns['tls_fetch'])


if __name__=='__main__':unittest.main()
