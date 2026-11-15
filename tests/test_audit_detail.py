"""Audit detail: real tool names and command verbs always; redacted commands only on opt-in."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel import audit_detail
from sentinel.audit import append_event
from sentinel.audit_detail import command_verb, detail_fields, detail_level, redacted, safe_tool_name
from sentinel.hermes_adapter import SentinelHook
from sentinel.settings import ProfileSettings, resolve_settings

CANARY = 'sk-SYNTHETICCANARY0123456789abcdef'


def fake_redactor(text, force=False, redact_url_credentials=False):
    assert force and redact_url_credentials
    return text.replace(CANARY, '***')


class DetailUnitTests(unittest.TestCase):
    def test_tool_names(self):
        self.assertEqual(safe_tool_name('read_file'), 'read_file')
        self.assertEqual(safe_tool_name('mcp_omi:search'), 'mcp_omi:search')
        for bad in ('', 'x' * 97, 'has space', 'semi;colon', None, 3):
            with self.subTest(bad=bad):
                self.assertEqual(safe_tool_name(bad), '[redacted]')

    def test_command_verb_never_records_assignments(self):
        cases = {'git status': 'git', '/usr/bin/curl -q https://x.invalid': 'curl',
                 f'TOKEN={CANARY} curl -H x https://x.invalid': 'curl',
                 f'env A={CANARY} B=2 python3 -c 1': 'python3', 'sudo -n ls': 'ls',
                 'nohup ./run.sh &': 'run.sh', "echo 'unterminated": 'echo',
                 '': '[none]', '   ': '[none]', f'X={CANARY}': '[none]', None: '[none]',
                 '$(whoami)': '[complex]'}
        for cmd, verb in cases.items():
            with self.subTest(cmd=cmd):
                self.assertEqual(command_verb(cmd), verb)
                self.assertNotIn(CANARY, command_verb(cmd))

    def test_detail_level(self):
        self.assertEqual(detail_level('commands'), 'commands')
        self.assertEqual(detail_level(' Commands '), 'commands')
        for bad in (None, '', 'all', 'raw', True, 1, ['commands']):
            with self.subTest(bad=bad):
                self.assertEqual(detail_level(bad), 'basic')

    def test_basic_records_no_text(self):
        fields = detail_fields('terminal', {'command': f'curl -H "Authorization: Bearer {CANARY}" https://x.invalid'}, 'basic', fake_redactor)
        self.assertEqual(fields, {'tool_name': 'terminal', 'command_verb': 'curl'})
        self.assertEqual(detail_fields('read_file', {'path': f'/tmp/{CANARY}'}, 'basic', fake_redactor), {'tool_name': 'read_file'})

    def test_commands_level_redacts_escapes_caps(self):
        fields = detail_fields('terminal', {'command': f'echo {CANARY}\nrm -rf /tmp/x'}, 'commands', fake_redactor)
        self.assertEqual(fields['audit_detail'], 'commands')
        self.assertNotIn(CANARY, fields['command_redacted'])
        self.assertIn('\\x0a', fields['command_redacted'])
        self.assertFalse(any(ord(c) < 32 for c in fields['command_redacted']))
        long = detail_fields('terminal', {'command': 'a' * 5000}, 'commands', fake_redactor)['command_redacted']
        self.assertLessEqual(len(long), audit_detail.MAX_DETAIL_CHARS)
        self.assertTrue(long.endswith('…[truncated]'))
        target = detail_fields('read_file', {'path': f'/tmp/{CANARY}.txt'}, 'commands', fake_redactor)
        self.assertEqual(target['target_redacted'], '/tmp/***.txt')
        self.assertEqual(detail_fields('todo', {'items': []}, 'commands', fake_redactor), {'tool_name': 'todo', 'audit_detail': 'commands'})

    def test_redactor_missing_or_failing_records_nothing_extra(self):
        def boom(*a, **k): raise RuntimeError('x')
        for fn in (boom, lambda *a, **k: None, lambda *a, **k: 5):
            fields = detail_fields('terminal', {'command': f'echo {CANARY}'}, 'commands', fn)
            self.assertEqual(fields['audit_detail'], 'unavailable')
            self.assertNotIn('command_redacted', fields)
        with patch.object(audit_detail, '_redactor', return_value=None):
            fields = detail_fields('terminal', {'command': f'echo {CANARY}'}, 'commands')
            self.assertEqual((fields['audit_detail'], 'command_redacted' in fields), ('unavailable', False))
        self.assertIsNone(redacted(None, fake_redactor))

    def test_journal_schema_accepts_detail_and_rejects_raw_control_chars(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'audit.jsonl'
            base = {'verdict': 'unclassified', 'tool_name': 'terminal'}
            append_event(str(p), {**base, 'command_verb': 'git', 'command_redacted': 'git log ' + 'x' * 1500, 'audit_detail': 'commands'})
            for bad in ({'command_redacted': 'a\nb'}, {'command_redacted': 'x' * 2001}, {'command_verb': 'x' * 129},
                        {'target_redacted': 'a\x7fb'}, {'command_raw': 'git'}):
                with self.subTest(bad=bad), self.assertRaises(ValueError):
                    append_event(str(p), {**base, **bad})
            self.assertEqual(len(p.read_text().splitlines()), 1)


class SettingsTests(unittest.TestCase):
    def test_setting_only_from_profile_settings(self):
        values = {'audit_detail': 'commands'}
        b = resolve_settings(Path('/unused'), lambda k, d=None: values.get(k, d), {})
        self.assertEqual(b.audit_detail, 'commands')
        b = resolve_settings(Path('/unused'), lambda k, d=None: None, {'SENTINEL_AUDIT_DETAIL': 'commands'})
        self.assertEqual(b.audit_detail, 'basic')
        b = resolve_settings(Path('/unused'), lambda k, d=None: {'audit_detail': 'raw'}.get(k, d), {})
        self.assertEqual(b.audit_detail, 'basic')


class HookTests(unittest.TestCase):
    def run_hook(self, level, tool, args):
        with tempfile.TemporaryDirectory() as d:
            home = Path(d) / 'home'; home.mkdir()
            journal = Path(d) / 'audit.jsonl'
            binding = ProfileSettings(home, 'audit', 'settings', None, level)
            hook = SentinelHook('', str(journal), b'x' * 32, binding_resolver=lambda: binding)
            with patch.object(audit_detail, '_redactor', return_value=fake_redactor):
                self.assertIsNone(hook(tool, args))
            return [json.loads(l) for l in journal.read_text().splitlines()]

    def test_basic_hook_records_name_and_verb_only(self):
        [e] = self.run_hook('basic', 'terminal', {'command': f'curl -H "X: {CANARY}" https://x.invalid'})
        self.assertEqual((e['tool_name'], e['command_verb']), ('terminal', 'curl'))
        self.assertNotIn('command_redacted', e)
        self.assertNotIn(CANARY, json.dumps(e))
        [e] = self.run_hook('basic', 'web_search', {'query': CANARY})
        self.assertEqual(e['tool_name'], 'web_search')
        self.assertNotIn(CANARY, json.dumps(e))

    def test_commands_hook_records_redacted_command(self):
        [e] = self.run_hook('commands', 'terminal', {'command': f'curl -H "X: {CANARY}" https://x.invalid'})
        self.assertEqual(e['audit_detail'], 'commands')
        self.assertIn('curl -H "X: ***" https://x.invalid', e['command_redacted'])
        self.assertNotIn(CANARY, json.dumps(e))
        self.assertEqual(e['enforcement_mode'], 'audit')


HERMES_AGENT = Path(os.environ.get('HERMES_AGENT_DIR', Path.home() / '.hermes' / 'hermes-agent'))


@unittest.skipUnless((HERMES_AGENT / 'agent' / 'redact.py').is_file(), 'Hermes source not available')
class RealHermesRedactorTests(unittest.TestCase):
    """Runs against the installed Hermes redactor with synthetic values only."""
    def setUp(self):
        sys.path.insert(0, str(HERMES_AGENT))
        try:
            from agent import redact
        except Exception as exc:
            self.skipTest(f'Hermes redactor not importable: {type(exc).__name__}')
        self.redact = redact
        redact.clear_vault_redaction_values()

    def tearDown(self):
        self.redact.clear_vault_redaction_values()
        sys.path.remove(str(HERMES_AGENT))

    def test_registered_vault_value_and_patterns_are_scrubbed(self):
        vault = 'zq' + 'SYNTHETICVAULTVALUE' * 2 + '93'
        self.redact.register_vault_redaction_value(vault)
        cmds = [f'echo {vault}', f'MY_SERVICE_KEY={vault} ./run.sh',
                'curl -H "Authorization: Bearer sk-proj-SYNTHETIC00000000000000000000000000abcd" https://x.invalid',
                'curl https://user:SyntheticPassw0rd@x.invalid/path']
        for cmd in cmds:
            with self.subTest(cmd=cmd[:30]):
                out = detail_fields('terminal', {'command': cmd}, 'commands')
                self.assertEqual(out['audit_detail'], 'commands')
                for secret in (vault, 'sk-proj-SYNTHETIC00000000000000000000000000abcd', 'SyntheticPassw0rd'):
                    self.assertNotIn(secret, out['command_redacted'])


if __name__ == '__main__':
    unittest.main()
