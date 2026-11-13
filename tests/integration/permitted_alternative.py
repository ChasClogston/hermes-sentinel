"""Exercise Hermes tool dispatch with explicit allow/deny rules and no human approvals."""
import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

home = Path(os.environ['HERMES_HOME'])
installed = home / 'plugins' / 'sentinel-governance'
assert installed.is_dir()
assert not (home / 'sentinel' / 'audit.jsonl').exists(), 'Use a new disposable home'
work = home / 'fixture'
work.mkdir()
bin_dir = home / 'bin'
bin_dir.mkdir()
marker = work / 'ran.txt'
fixture = bin_dir / 'pytest'
fixture.write_text(f'#!{sys.executable}\nfrom pathlib import Path\n'
                   f'Path({str(marker)!r}).write_text("ran once")\nprint("fixture passed")\n')
fixture.chmod(0o700)
os.environ['PATH'] = str(bin_dir) + os.pathsep + os.environ.get('PATH', '')
os.environ['TERMINAL_CWD'] = str(work)
os.environ['SENTINEL_GOVERNANCE_MODE'] = 'enforce'

# An existing explicit allow policy is required. The distributed default remains
# conservative and requires approval for pytest; no new permission is implied.
policy = installed / 'policies' / 'default.yaml'
policy.write_text('''version: 1
defaults:
  unknown_action: deny
  unknown_destination: deny
rules:
  - id: deny-credentials
    effect: deny
    operations: [network_upload]
    source_classes: [credential_file, private_key]
  - id: allow-tests
    effect: allow
    operations: [test_execution]
  - id: approve-requests
    effect: require_approval
    operations: [network_request]
    destination_classes: [external_untrusted]
''')

from hermes_cli.plugins import discover_plugins
from model_tools import handle_function_call

discover_plugins()
with patch('tools.approval.request_tool_approval', return_value={
        'approved': False, 'message': 'Synthetic approval denied'}) as approval:
    blocked = handle_function_call('terminal', {'command': 'echo PRIVATE_BLOCK_CANARY_487'},
                                   task_id='permitted-alternative')
    assert 'alternative that complies with the policy and existing authorization' in str(blocked)
    assert 'PRIVATE_BLOCK_CANARY_487' not in str(blocked)
    assert not marker.exists()
    approval.assert_not_called()
    allowed = handle_function_call('terminal', {'command': 'pytest', 'workdir': str(work)},
                                   task_id='permitted-alternative')
    assert marker.read_text() == 'ran once', allowed
    approval.assert_not_called()
    pending = handle_function_call('terminal', {'command': 'curl -q https://example.invalid/data'},
                                   task_id='permitted-alternative')
    approval.assert_called_once()
    assert 'denied' in str(pending).lower()
events = [json.loads(line) for line in (home / 'sentinel' / 'audit.jsonl').read_text().splitlines()]
assert [event['verdict'] for event in events] == ['blocked', 'allowed', 'pending']
assert 'PRIVATE_BLOCK_CANARY_487' not in (home / 'sentinel' / 'audit.jsonl').read_text()
print('Hermes tool dispatch: prohibited call blocked; permitted alternative executed without approval; approval-required call still requested approval.')
