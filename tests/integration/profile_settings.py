"""Settings-only enforcement through actual Hermes dispatch; no live secrets/tools."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from unittest.mock import patch

home = Path(os.environ['HERMES_HOME'])
installed = home/'plugins'/'sentinel-governance'
assert installed.is_dir()
assert not (home/'sentinel'/'audit.jsonl').exists(), 'Use a fresh disposable home'
os.environ.pop('SENTINEL_GOVERNANCE_MODE', None)
os.environ.pop('HERMES_SENTINEL_MODE', None)

# Only this disposable profile is configured. Clear environment is intentional.
config = home/'config.yaml'
config.write_text('plugins:\n  enabled: [sentinel-governance]\n  entries:\n    sentinel-governance:\n      settings:\n        mode: enforce\n')
from hermes_cli.plugins import discover_plugins
from model_tools import handle_function_call
from tools.registry import registry
discover_plugins()

with patch.object(registry, 'dispatch', return_value='synthetic effect') as execute, \
     patch('tools.approval.request_tool_approval') as approval:
    result = handle_function_call('terminal', {'command':'echo PRIVATE_DEFAULT_DENY'})
    assert 'blocked' in str(result).lower(), result
    execute.assert_not_called()
    approval.assert_not_called()

policy_path = home/'sentinel'/'policy.json'
policy = {'version':1, 'rules':[
    {'id':'allow-read-tools','effect':'allow','operations':['unknown'],
     'tools':['read_file','secret_request']},
    {'id':'approve-writes','effect':'require_approval','operations':['unknown'],
     'tools':['write_file']}]}
policy_path.write_text(json.dumps(policy)); policy_path.chmod(0o600)
original_policy = policy_path.read_bytes()
with config.open('a') as stream: stream.write('        policy_path: sentinel/policy.json\n')

# A directory replacement represents plugin update without touching operator policy.
replacement = home/'replacement-plugin'; shutil.copytree(installed, replacement)
previous = home/'previous-plugin'; installed.rename(previous); replacement.rename(installed)
assert policy_path.read_bytes() == original_policy

# The actual hook/middleware/approval path runs; the final registry effect is a
# synthetic spy. In particular, secret_request never reaches a credential store.
with patch.object(registry, 'dispatch', return_value='synthetic effect') as execute, \
     patch('tools.approval.request_tool_approval', return_value={'approved':False,'message':'Synthetic denied'}) as approval:
    for name in ('read_file','secret_request'):
        assert handle_function_call(name, {'path':'PRIVATE_ARGUMENT'}) == 'synthetic effect'
    assert execute.call_count == 2
    approval.assert_not_called()
    result = handle_function_call('terminal', {'command':'echo PRIVATE_ARGUMENT'})
    assert 'blocked' in str(result).lower()
    assert execute.call_count == 2
    result = handle_function_call('write_file', {'path':'PRIVATE_ARGUMENT'})
    approval.assert_called_once()
    assert execute.call_count == 2

events = [json.loads(line) for line in (home/'sentinel'/'audit.jsonl').read_text().splitlines()]
assert [event['policy_verdict'] for event in events] == ['blocked','allowed','allowed','blocked','pending']
assert all(event['enforcement_mode']=='enforce' for event in events)
assert 'PRIVATE_' not in (home/'sentinel'/'audit.jsonl').read_text()

# Real SessionDB and spawned replay must use exactly the current profile policy.
from hermes_state import SessionDB
db = SessionDB(home/'state.db'); db.create_session('synthetic', 'cli')
db.append_message('synthetic', 'assistant', timestamp=time.time(), tool_calls=[
    {'id':str(i),'type':'function','function':{'name':name,'arguments':'{}'}}
    for i,name in enumerate(('read_file','secret_request','terminal','write_file'))])
db.close()
run = subprocess.run([sys.executable,'-m','sentinel.cli','replay'],capture_output=True,text=True,timeout=10)
assert run.returncode == 0, run.stderr
for expected in ('Allowed: 2\n','Blocked: 1\n','Approval candidates: 1\n'):
    assert expected in run.stdout, run.stdout
assert 'PRIVATE_' not in run.stdout + run.stderr
print('Settings-only enforce: real dispatch blocks default deny, named tools proceed without approval, writes request approval, custom policy survives plugin replacement, real replay counts agree.')
