"""Security regressions from Claude's review of eb3c4b9; synthetic files only."""
import contextlib
import io
import json
import os
import tempfile
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel.config import validate_policy
from sentinel.hermes_adapter import SentinelHook, normalize
from sentinel.engine import evaluate
from sentinel.settings import resolve_settings

KEY = b'R'*32


def rules(effect='allow', tools=None):
    return {'version':1, 'rules':[{'id':'named','effect':effect,
            'operations':['unknown'],'tools':tools or ['read_file','write_file','patch','secret_request']}]}


class Review8Tests(unittest.TestCase):
    def test_unknown_execution_approvals_cannot_be_blind(self):
        for names in (None, ['terminal'], ['execute_code'], ['TERMINAL'], ['read_file','execute_code']):
            policy = rules('require_approval')
            if names is None: del policy['rules'][0]['tools']
            else: policy['rules'][0]['tools'] = names
            with self.subTest(names=names), self.assertRaises(ValueError): validate_policy(policy)

    def test_whole_tool_prompt_does_not_claim_to_show_exact_arguments(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'policy.json';p.write_text(json.dumps(rules('require_approval',['secret_request'])))
            h=SentinelHook(str(p),str(Path(d)/'audit.jsonl'),KEY,'enforce')
            r=h('secret_request',{'name':'PRIVATE_CANARY'})
            self.assertEqual(r['action'],'approve')
            self.assertIn('any operation',r['message'])
            self.assertNotIn('exact request',r['message'])
            self.assertNotIn('PRIVATE_CANARY',r['message'])

    def setup_profile(self, root, mode='enforce', policy=None):
        home=root/'profile'; home.mkdir()
        state=home/'sentinel';state.mkdir(mode=0o700)
        p=state/'policy.json';p.write_text(json.dumps(policy or rules()));p.chmod(0o600)
        values={'mode':mode,'policy_path':'sentinel/policy.json'}
        h=SentinelHook('',str(state/'audit.jsonl'),KEY,
            binding_resolver=lambda:resolve_settings(home,lambda k,default=None:values.get(k,default),{}))
        return home,p,values,h

    def test_file_writes_cannot_modify_governance_even_when_allowed(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d).resolve();home,p,values,h=self.setup_profile(root)
            plugin=Path(__file__).resolve().parents[1]
            (home/'config.yaml').write_text('synthetic: true')
            alias=root/'alias';alias.symlink_to(home/'sentinel',target_is_directory=True)
            hard=root/'hard';os.link(home/'config.yaml',hard)
            for target in (home/'config.yaml',p,home/'sentinel/audit.key',plugin/'__init__.py',
                           alias/'policy.json',hard,home/'sentinel'):
                for tool in ('write_file','patch'):
                    with self.subTest(target=target,tool=tool):
                        self.assertEqual((h(tool,{'path':str(target),'content':'PRIVATE_CONTENT'}) or {}).get('action'),'block')
            ordinary=root/'notes.txt'
            self.assertIsNone(h('write_file',{'path':str(ordinary),'content':'synthetic'}))
            self.assertIsNone(h('patch',{'path':str(ordinary),'old_string':'old','new_string':'new'}))
            for target in ('notes.txt','',None):
                self.assertEqual(h('write_file',{'path':target})['action'],'block')
            self.assertNotIn('PRIVATE_CONTENT',(home/'sentinel/audit.jsonl').read_text())

    def test_all_patch_headers_and_move_endpoints_are_protected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d).resolve();home,p,values,h=self.setup_profile(root)
            good=root/'notes.txt'
            for content in (f'*** Begin Patch\n***Update File: {p}\n@@\n-old\n+new\n*** End Patch',
                            f'*** Begin Patch\n*** Add File: {good}\n+ok\n*** Delete File: {p}\n*** End Patch',
                            f'*** Begin Patch\n*** Move File: {good} -> {p}\n*** End Patch',
                            f'*** Begin Patch\n*** Move File: {p} -> {good}\n*** End Patch'):
                self.assertEqual((h('patch',{'mode':'patch','patch':content}) or {}).get('action'),'block')
            self.assertIsNone(h('patch',{'mode':'patch','patch':f'*** Begin Patch\n*** Add File: {good}\n+ok\n*** End Patch'}))

    def test_credential_read_beats_whole_tool_allow_without_secret_guard(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d).resolve();home,p,values,h=self.setup_profile(root)
            sensitive=root/'.env';sensitive.write_text('SYNTHETIC_ONLY')
            (root/'alias.txt').symlink_to(sensitive)
            os.link(sensitive,root/'hard.txt')
            for target in (sensitive,root/'alias.txt',root/'hard.txt',root/'.ssh/id_ed25519',root/'token.json',
                           root/'private.pem',home/'config.yaml'):
                with self.subTest(target=target):
                    self.assertEqual((h('read_file',{'path':str(target)}) or {}).get('action'),'block')
            ordinary=root/'notes.txt';ordinary.write_text('synthetic')
            self.assertIsNone(h('read_file',{'path':str(ordinary)}))
            self.assertIsNone(h('secret_request',{'name':'synthetic-empty-registry'}))

    def test_case_alias_cannot_bypass_governance_protection(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d).resolve();home,p,values,h=self.setup_profile(root)
            alias=home/'SENTINEL'/'POLICY.JSON'
            if not alias.exists(): self.skipTest('Case-sensitive filesystem')
            self.assertEqual((h('write_file',{'path':str(alias)}) or {}).get('action'),'block')

    def test_enforce_latches_and_mode_change_is_signed(self):
        from sentinel.audit import verify_control_event
        with tempfile.TemporaryDirectory() as d:
            root=Path(d).resolve();home,p,values,h=self.setup_profile(root,policy={'version':1,'rules':[]})
            self.assertEqual(h('unlisted',{})['action'],'block')
            values.clear()
            self.assertEqual(h('unlisted',{})['action'],'block')
            path=home/'sentinel/audit.jsonl'
            rows=[json.loads(line) for line in path.read_text().splitlines()]
            controls=[r for r in rows if r.get('event_type')=='mode_change']
            self.assertEqual(len(controls),1)
            self.assertEqual((controls[0]['previous_mode'],controls[0]['requested_mode'],controls[0]['enforcement_mode']),('enforce','audit','enforce'))
            self.assertTrue(verify_control_event(controls[0],KEY))
            controls[0]['requested_mode']='enforce'
            self.assertFalse(verify_control_event(controls[0],KEY))
            replacement=SentinelHook('',str(path),KEY,binding_resolver=lambda:resolve_settings(home,lambda k,default=None:values.get(k,default),{}))
            self.assertEqual(replacement('unlisted',{})['action'],'block')
            from sentinel.report import summarize
            key_path=home/'sentinel/audit.key';key_path.write_bytes(KEY);key_path.chmod(0o600)
            summary=summarize(path)
            self.assertEqual((summary['total'],summary['counts']['mode_change']),(3,1))
            with path.open('a') as stream: stream.write(json.dumps(controls[0])+'\n')
            summary=summarize(path)
            self.assertEqual((summary['total'],summary['invalid_rows']),(3,1))

    def test_policy_failure_is_visible_once_and_does_not_inflate_proposals(self):
        from sentinel.report import summarize
        from sentinel.cli import main
        with tempfile.TemporaryDirectory() as d:
            root=Path(d).resolve();home,p,values,h=self.setup_profile(root,'audit')
            p.chmod(0o622)
            for _ in range(3): self.assertIsNone(h('unlisted',{}))
            path=home/'sentinel/audit.jsonl'
            rows=[json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual(len([r for r in rows if r.get('event_type')=='policy_load_failure']),1)
            (home/'sentinel/audit.key').write_bytes(KEY);(home/'sentinel/audit.key').chmod(0o600)
            self.assertEqual(summarize(path)['total'],0)
            (home/'config.yaml').write_text(json.dumps({'plugins':{'entries':{'sentinel-governance':{'settings':values}}}}))
            out=io.StringIO()
            with patch('sentinel.settings.current_home',return_value=home), patch.dict(os.environ,{},clear=True), contextlib.redirect_stdout(out):
                self.assertEqual(main(['report','--journal',str(path)]),0)
            self.assertIn('Policy health: unavailable',out.getvalue())
            self.assertIn('unsafe_permissions',out.getvalue())
            self.assertNotIn(str(home),out.getvalue())

    def test_process_restart_can_explicitly_return_to_audit(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d).resolve();home,p,values,h=self.setup_profile(root,policy={'version':1,'rules':[]})
            h.preflight()  # Enforce is latched before the first proposal.
            values['mode']='audit'
            self.assertEqual(h('unlisted',{})['action'],'block')
            script='''from pathlib import Path
import sys
from sentinel.hermes_adapter import SentinelHook
from sentinel.settings import resolve_settings
home=Path(sys.argv[1])
h=SentinelHook('',str(home/'sentinel/audit.jsonl'),b'R'*32,binding_resolver=lambda:resolve_settings(home,lambda k,d=None:'audit' if k=='mode' else d,{}))
assert h('unlisted',{}) is None
print('restart_audit')
'''
            env=dict(os.environ)
            env['PYTHONPATH']=str(Path(__file__).resolve().parents[1])+os.pathsep+env.get('PYTHONPATH','')
            result=subprocess.run([sys.executable,'-c',script,str(home)],env=env,capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn('restart_audit',result.stdout)
