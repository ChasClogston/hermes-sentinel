"""audit_detail through actual Hermes dispatch in a disposable home; synthetic values only, no tool runs."""
import json
import os
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


def configure(detail):
    (home/'config.yaml').write_text(
        'plugins:\n  enabled: [sentinel-governance]\n  entries:\n    sentinel-governance:\n'
        f'      settings:\n        mode: audit\n        audit_detail: {detail}\n')


def run(calls):
    from model_tools import handle_function_call
    from tools.registry import registry
    with patch.object(registry, 'dispatch', return_value='synthetic effect') as execute:
        for name, args in calls:
            handle_function_call(name, args)
    return execute.call_count


configure('commands')
from hermes_cli.plugins import discover_plugins
from agent.redact import register_vault_redaction_value
discover_plugins()
register_vault_redaction_value(VAULT)
calls = [('terminal', {'command': f'curl -H "Authorization: Bearer {PATTERN}" https://x.invalid'}),
         ('terminal', {'command': f'MY_SERVICE_KEY={VAULT} ./run.sh'}),
         ('terminal', {'command': f'echo {VAULT}'}),
         ('read_file', {'path': str(home/'notes.txt')})]
assert run(calls) == len(calls), 'audit mode must not block'
events = [json.loads(l) for l in journal.read_text().splitlines() if '"tool_name"' in l]
text = journal.read_text()
assert VAULT not in text and PATTERN not in text, 'secret reached the journal'
assert [e['tool_name'] for e in events] == ['terminal', 'terminal', 'terminal', 'read_file'], events
assert [e.get('command_verb') for e in events[:3]] == ['curl', 'run.sh', 'echo'], events
assert all(e.get('audit_detail') == 'commands' for e in events), events
assert all('command_redacted' in e for e in events[:3]) and 'target_redacted' in events[3], events
assert events[2]['command_redacted'].startswith('echo ') and len(events[2]['command_redacted']) > 5, events[2]
print('commands level: 4 events, tool names + verbs + redacted text, no synthetic secret in journal')
for e in events:
    print('  ', e['tool_name'], e.get('command_verb'), '|', (e.get('command_redacted') or e.get('target_redacted'))[:90])
