"""audit_detail through actual Hermes dispatch in a disposable home; synthetic values only, no tool runs.

Checks the WHOLE serialized journal for a registered synthetic vault value and a pattern-shaped key,
in normal operation and with the redactor made unavailable.
"""
import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

home = Path(os.environ['HERMES_HOME'])
assert (home/'plugins'/'sentinel-governance').is_dir()
journal = home/'sentinel'/'audit.jsonl'
assert not journal.exists(), 'Use a fresh disposable home'
for k in ('SENTINEL_GOVERNANCE_MODE', 'HERMES_SENTINEL_MODE'):
    os.environ.pop(k, None)

VAULT = 'zq' + 'SYNTHETICVAULTVALUE' * 2 + '93'           # stands in for a Secret Guard-registered key
PATTERN = 'sk-proj-SYNTHETIC00000000000000000000000000abcd'  # caught by Hermes patterns alone
(home/'config.yaml').write_text(
    'plugins:\n  enabled: [sentinel-governance]\n  entries:\n    sentinel-governance:\n'
    '      settings:\n        mode: audit\n        audit_detail: commands\n')

from hermes_cli.plugins import discover_plugins
from agent.redact import register_vault_redaction_value
from model_tools import handle_function_call
from tools.registry import registry
discover_plugins()
register_vault_redaction_value(VAULT)

calls = [('terminal', {'command': f'curl -H "Authorization: Bearer {PATTERN}" https://x.invalid'}),
         ('terminal', {'command': f'MY_SERVICE_KEY={VAULT} ./run.sh'}),
         ('terminal', {'command': f'echo {VAULT}'}),
         ('terminal', {'command': VAULT}),
         ('terminal', {'command': f'sudo -u {VAULT} id'}),
         ('read_file', {'path': str(home/f'{VAULT}.txt')})]


def run(batch):
    with patch.object(registry, 'dispatch', return_value='synthetic effect') as execute:
        for name, args in batch:
            handle_function_call(name, args)
    assert execute.call_count == len(batch), 'audit mode must not block'


run(calls)
text = journal.read_text()
assert VAULT not in text and PATTERN not in text, 'secret reached the journal'
events = [json.loads(l) for l in text.splitlines() if '"tool_name"' in l]
assert [e['tool_name'] for e in events] == ['terminal'] * 5 + ['read_file'], events
assert [e.get('command_verb') for e in events[:5]] == ['curl', 'run.sh', 'echo', '[redacted]', 'sudo'], events
assert all(e.get('audit_detail') == 'commands' for e in events), events
assert events[0]['command_redacted'] == 'curl -H "Authorization: Bearer ***" https://x.invalid', events[0]
assert events[2]['command_redacted'].startswith('echo ') and 'target_redacted' in events[5], events
print('normal: 6 events, registered tool names, verbs, redacted text; no synthetic secret anywhere in the journal')

# Redactor unavailable: every input-derived field becomes a placeholder.
modules = [m for name, m in list(sys.modules.items()) if name.endswith('sentinel.audit_detail')]
assert modules, 'plugin audit_detail module not loaded'
before = len(text.splitlines())
with patch.multiple(modules[0], _redactor=lambda: None):
    run(calls)
text = journal.read_text()
assert VAULT not in text and PATTERN not in text, 'secret reached the journal with redactor unavailable'
failed = [json.loads(l) for l in text.splitlines()[before:] if '"tool_name"' in l]
assert len(failed) == len(calls), failed
assert all(e['tool_name'] == '[unavailable]' and e['audit_detail'] == 'unavailable' for e in failed), failed
assert all(e.get('command_verb') == '[unavailable]' for e in failed[:5]), failed
assert not any('command_redacted' in e or 'target_redacted' in e for e in failed), failed
print('redactor unavailable: 6 events, placeholders only; no synthetic secret anywhere in the journal')
