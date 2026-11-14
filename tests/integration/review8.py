"""PR8 review reproductions through pinned Hermes; isolated files and spied effects."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from unittest.mock import patch

home = Path(os.environ['HERMES_HOME']).resolve()
home.mkdir(parents=True, exist_ok=True)
assert not (home/'sentinel/audit.jsonl').exists(), 'Use a fresh disposable home'
source = Path(sys.argv[1]).resolve()
plugin = home/'plugins/sentinel-governance'
plugin.parent.mkdir(); shutil.copytree(source, plugin)
os.environ.pop('SENTINEL_GOVERNANCE_MODE', None)
os.environ.pop('HERMES_SENTINEL_MODE', None)
audit_case = len(sys.argv)>2 and sys.argv[2]=='audit'
policy = home/'policy.json'
policy.write_text(json.dumps({'version':1,'rules':[
    {'id':'allow-files','effect':'allow','operations':['unknown'],'tools':['read_file','search_files','write_file','patch']},
    {'id':'approve-secret','effect':'require_approval','operations':['unknown'],'tools':['secret_request']}]}))
policy.chmod(0o600)
config = home/'config.yaml'
configuration = {'plugins':{'enabled':['sentinel-governance'],'entries':{'sentinel-governance':{
    'settings':{'mode':'audit' if audit_case else 'enforce','policy_path':'policy.json'}}}}}
config.write_text(json.dumps(configuration))
if audit_case: policy.chmod(0o622)

from hermes_cli.plugins import discover_plugins
from model_tools import handle_function_call
from tools.registry import registry
from sentinel.audit import read_key, verify_control_event
discover_plugins()

if audit_case:
    with patch.object(registry,'dispatch',return_value='synthetic pass'):
        for _ in range(3): assert handle_function_call('read_file',{'path':str(home/'ordinary.txt')})=='synthetic pass'
    journal=home/'sentinel/audit.jsonl'
    rows=[json.loads(line) for line in journal.read_text().splitlines()]
    assert len(rows)==1 and rows[0]['event_type']=='policy_load_failure'
    assert verify_control_event(rows[0],read_key(home/'sentinel/audit.key'))
    report=subprocess.run([sys.executable,'-m','sentinel.cli','report'],capture_output=True,text=True,timeout=10)
    assert report.returncode==0 and 'Policy health: unavailable (unsafe_permissions)' in report.stdout, report.stdout+report.stderr
    assert str(home) not in report.stdout+report.stderr
    assert 'Observed proposals' in report.stdout and 'Signed policy-load failures' in report.stdout
    print('PR8 audit policy failure: one signed event, continued synthetic dispatch, visible sanitized report health.')
    raise SystemExit(0)

ordinary=home/'ordinary.txt'; ordinary.write_text('SYNTHETIC_ONLY')
secret=home/'.env'; secret.write_text('SYNTHETIC_ONLY')
alias=home/'alias.txt';alias.symlink_to(secret)
hard=home/'hard.txt';os.link(secret,hard)
with patch.object(registry,'dispatch',return_value='synthetic pass') as effect, \
     patch('tools.approval.request_tool_approval',return_value={'approved':False,'message':'Synthetic denied'}) as approval:
    for name in ('read_file','search_files','write_file','patch'):
        assert handle_function_call(name,{'path':str(ordinary),'content':'SYNTHETIC_ONLY','pattern':'synthetic'})=='synthetic pass'
    assert effect.call_count==4
    approval.assert_not_called()
    for target in (secret,alias,hard):
        assert 'blocked' in str(handle_function_call('read_file',{'path':str(target)})).lower()
    for args in ({'path':str(secret),'pattern':'SYNTHETIC_ONLY'},
                 {'path':str(home),'pattern':'SYNTHETIC_ONLY'},
                 {'path':str(home),'pattern':'.env','target':'files'},
                 {'pattern':'SYNTHETIC_ONLY'}, {'path':'.','pattern':'SYNTHETIC_ONLY'}):
        assert 'blocked' in str(handle_function_call('search_files',args)).lower()
    for target in (config,policy,home/'sentinel/audit.key',plugin/'__init__.py'):
        for name in ('write_file','patch'):
            assert 'blocked' in str(handle_function_call(name,{'path':str(target),'content':'SYNTHETIC_ONLY'})).lower()
    payload=f'*** Begin Patch\n*** Add File: {home/"out.txt"}\n+ok\n*** Move File: {ordinary} -> {policy}\n*** End Patch'
    assert 'blocked' in str(handle_function_call('patch',{'mode':'patch','patch':payload})).lower()
    assert effect.call_count==4
    approval.assert_not_called()
    # Operator-side config edits, not tool effects, reproduce loss/downgrade.
    config.write_text('')
    assert 'blocked' in str(handle_function_call('terminal',{'command':'echo SYNTHETIC_ONLY'})).lower()
    config.write_text(json.dumps({'plugins':{'enabled':['sentinel-governance']}}))
    assert 'blocked' in str(handle_function_call('terminal',{'command':'echo SYNTHETIC_ONLY'})).lower()
    config.write_text(json.dumps(configuration))
    assert 'blocked' in str(handle_function_call('terminal',{'command':'echo SYNTHETIC_ONLY'})).lower()
    invalid=json.loads(json.dumps(configuration))
    invalid['plugins']['entries']['sentinel-governance']['settings']['mode']='invalid'
    config.write_text(json.dumps(invalid))
    assert 'blocked' in str(handle_function_call('terminal',{'command':'echo SYNTHETIC_ONLY'})).lower()
    config.write_text(json.dumps(configuration))
    handle_function_call('secret_request',{'name':'PRIVATE_APPROVAL_CANARY'})
    approval.assert_called_once()
    assert 'PRIVATE_APPROVAL_CANARY' not in str(approval.call_args)
    assert 'any operation' in str(approval.call_args)
    assert effect.call_count==4

journal=home/'sentinel/audit.jsonl'
rows=[json.loads(line) for line in journal.read_text().splitlines()]
controls=[row for row in rows if row.get('event_type')=='mode_change']
assert [row['requested_mode'] for row in controls]==['audit','enforce','invalid','enforce']
assert all(row['enforcement_mode'] in ('enforce','invalid') and verify_control_event(row,read_key(home/'sentinel/audit.key')) for row in controls)
assert 'PRIVATE_APPROVAL_CANARY' not in journal.read_text()

from hermes_state import SessionDB
db=SessionDB(home/'state.db'); db.create_session('synthetic','cli')
calls=[('read_file',{'path':str(ordinary)}),('read_file',{'path':str(secret)}),
       ('write_file',{'path':str(policy)}),('write_file',{'path':str(ordinary)}),('secret_request',{}),
       ('search_files',{'path':str(ordinary),'pattern':'synthetic'}),
       ('search_files',{'path':str(secret),'pattern':'SYNTHETIC_ONLY'}),
       ('search_files',{'path':str(home),'pattern':'SYNTHETIC_ONLY'}),
       ('search_files',{'pattern':'SYNTHETIC_ONLY'})]
db.append_message('synthetic','assistant',timestamp=time.time(),tool_calls=[
    {'id':str(i),'type':'function','function':{'name':name,'arguments':json.dumps(args)}} for i,(name,args) in enumerate(calls)])
db.close()
replay=subprocess.run([sys.executable,'-m','sentinel.cli','replay'],capture_output=True,text=True,timeout=10)
assert replay.returncode==0, replay.stderr
for expected in ('Allowed: 3\n','Blocked: 5\n','Approval candidates: 1\n'):
    assert expected in replay.stdout,replay.stdout

child_env=dict(os.environ,HERMES_HOME=str(home/'audit-child'))
child=subprocess.run([sys.executable,__file__,str(source),'audit'],env=child_env,capture_output=True,text=True,timeout=20)
assert child.returncode==0,child.stdout+child.stderr
print(child.stdout.strip())
print('PR8 real dispatch: pre-rule self/credential protections, ordinary alternatives without approval, sticky enforce and signed mode changes, truthful approval, real replay parity passed.')
