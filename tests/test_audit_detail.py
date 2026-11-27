"""Audit detail: every input-derived journal field passes the redaction gate; whole records are checked."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel import audit_detail
from sentinel.audit import append_event
from sentinel.audit_detail import _Gate, command_verb, detail_fields, detail_level, tool_name_field
from sentinel.hermes_adapter import SentinelHook
from sentinel.settings import ProfileSettings, resolve_settings

CANARY = 'zqSYNTHETICVAULTVALUE93'
KNOWN_TOOLS = {'terminal', 'read_file', 'web_search', 'secret_request'}


def fake_redactor(text, force=False, redact_url_credentials=False):
    assert force and redact_url_credentials
    return text.replace(CANARY, '***')


def known(name):
    return name in KNOWN_TOOLS | {CANARY}   # the canary is "registered" to prove redaction, not syntax, protects it


def boom(*a, **k):
    raise RuntimeError('synthetic')


FAILURES = {'missing': None, 'raises': boom, 'nonstring': lambda *a, **k: 7}

# (label, tool, args) — every case carries the canary somewhere in its input.
CASES = [
    ('echo', 'terminal', {'command': f'echo {CANARY}'}),
    ('first-word', 'terminal', {'command': CANARY}),
    ('first-word-path', 'terminal', {'command': f'/tmp/{CANARY} --run'}),
    ('wrapper-option-value', 'terminal', {'command': f'sudo -u {CANARY} id'}),
    ('env-assignment', 'terminal', {'command': f'env TOKEN={CANARY} python3 -c 1'}),
    ('leading-assignment', 'terminal', {'command': f'TOKEN={CANARY} curl https://x.invalid'}),
    ('malformed-quoting', 'terminal', {'command': f"{CANARY} 'unterminated"}),
    ('tool-name', CANARY, {'command': 'true'}),
    ('target-path', 'read_file', {'path': f'/tmp/{CANARY}.txt'}),
    ('url-target', 'web_search', {'url': f'https://x.invalid/?k={CANARY}'}),
]


def journal_for(level, tool, args, redactor=fake_redactor, registry=known):
    with tempfile.TemporaryDirectory() as d:
        home = Path(d) / 'home'; home.mkdir()
        journal = Path(d) / 'audit.jsonl'
        binding = ProfileSettings(home, 'audit', 'settings', None, level)
        hook = SentinelHook('', str(journal), b'x' * 32, binding_resolver=lambda: binding)
        with patch.object(audit_detail, '_redactor', return_value=redactor), \
             patch.object(audit_detail, '_registry_lookup', return_value=registry):
            assert hook(tool, args) is None
        text = journal.read_text()
        return text, [json.loads(line) for line in text.splitlines()]


class WholeJournalTests(unittest.TestCase):
    def test_no_case_leaks_at_any_level_or_failure(self):
        for level in ('basic', 'commands'):
            for failure, fn in [('ok', fake_redactor), *FAILURES.items()]:
                for label, tool, args in CASES:
                    with self.subTest(level=level, failure=failure, case=label):
                        text, events = journal_for(level, tool, args, fn)
                        self.assertEqual(len(events), 1)
                        self.assertNotIn(CANARY, text)

    def test_failure_makes_every_input_field_a_placeholder(self):
        for failure, fn in FAILURES.items():
            with self.subTest(failure=failure):
                _, [e] = journal_for('commands', 'terminal', {'command': 'git status'}, fn)
                self.assertEqual((e['tool_name'], e['command_verb'], e['audit_detail']),
                                 ('[unavailable]', '[unavailable]', 'unavailable'))
                self.assertNotIn('command_redacted', e)
                _, [e] = journal_for('basic', 'read_file', {'path': '/tmp/x'}, fn)
                self.assertEqual(e['tool_name'], '[unavailable]')
                self.assertNotIn('audit_detail', e)

    def test_useful_detail_survives_when_safe(self):
        _, [e] = journal_for('basic', 'terminal', {'command': 'git status'})
        self.assertEqual((e['tool_name'], e['command_verb']), ('terminal', 'git'))
        self.assertNotIn('command_redacted', e)
        _, [e] = journal_for('commands', 'terminal', {'command': f'curl -H "X: {CANARY}" https://x.invalid'})
        self.assertEqual((e['command_verb'], e['audit_detail']), ('curl', 'commands'))
        self.assertEqual(e['command_redacted'], 'curl -H "X: ***" https://x.invalid')
        _, [e] = journal_for('basic', 'web_search', {'query': 'weather'})
        self.assertEqual(e['tool_name'], 'web_search')

    def test_wrappers_record_only_themselves(self):
        for cmd, verb in ((f'sudo -u {CANARY} id', 'sudo'), (f'env A={CANARY} python3', 'env'),
                          ('nohup ./run.sh', 'nohup'), ('time make', 'time')):
            with self.subTest(cmd=cmd):
                _, [e] = journal_for('basic', 'terminal', {'command': cmd})
                self.assertEqual(e['command_verb'], verb)


class FieldUnitTests(unittest.TestCase):
    def test_tool_name_provenance(self):
        g = _Gate(fake_redactor)
        self.assertEqual(tool_name_field('read_file', g, known), 'read_file')
        self.assertEqual(tool_name_field('not_registered', g, known), '[unregistered]')
        self.assertEqual(tool_name_field('read_file', g, None), '[unverified]')
        self.assertEqual(tool_name_field(CANARY, g, known), '[redacted]')
        for missing in ('', None):
            self.assertEqual(tool_name_field(missing, g, known), '[missing]')
        for bad in ('x' * 97, 'has space', 3):
            self.assertEqual(tool_name_field(bad, g, known), '[redacted]')
        self.assertEqual(tool_name_field('read_file', _Gate(None), known), '[unavailable]')

    def test_command_verb_shapes(self):
        g = _Gate(fake_redactor)
        cases = {'git status': 'git', '/usr/bin/curl -q x': 'curl', "echo 'unterminated": '[unparsed]',
                 '': '[none]', '  ': '[none]', 'X=1': '[none]', None: '[none]', '$(whoami)': '[redacted]',
                 'sk-proj-abcdEFGH1234ijklMNOP': '[redacted]', 'a' * 41: '[redacted]',
                 'my-very-long-script-name.sh': 'my-very-long-script-name.sh'}
        for cmd, verb in cases.items():
            with self.subTest(cmd=cmd):
                self.assertEqual(command_verb(cmd, g), verb)

    def test_detail_level(self):
        self.assertEqual(detail_level(' Commands '), 'commands')
        for bad in (None, '', 'all', 'raw', True, 1, ['commands']):
            self.assertEqual(detail_level(bad), 'basic')

    def test_long_text_escaped_and_capped(self):
        f = detail_fields('terminal', {'command': 'echo a\nb' + 'c' * 5000}, 'commands', fake_redactor, known)
        self.assertIn('\\x0a', f['command_redacted'])
        self.assertLessEqual(len(f['command_redacted']), audit_detail.MAX_DETAIL_CHARS)
        self.assertTrue(f['command_redacted'].endswith('…[truncated]'))

    def test_journal_schema(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'audit.jsonl'
            base = {'verdict': 'unclassified', 'tool_name': 'terminal'}
            append_event(str(p), {**base, 'command_verb': 'git', 'command_redacted': 'git log ' + 'x' * 1500, 'audit_detail': 'commands'})
            for bad in ({'command_redacted': 'a\nb'}, {'command_redacted': 'x' * 2001}, {'command_verb': 'x' * 129},
                        {'target_redacted': 'a\x7fb'}, {'command_raw': 'git'}):
                with self.subTest(bad=bad), self.assertRaises(ValueError):
                    append_event(str(p), {**base, **bad})
            self.assertEqual(len(p.read_text().splitlines()), 1)

    def test_setting_only_from_profile_settings(self):
        get = lambda values: (lambda k, d=None: values.get(k, d))
        self.assertEqual(resolve_settings(Path('/u'), get({'audit_detail': 'commands'}), {}).audit_detail, 'commands')
        self.assertEqual(resolve_settings(Path('/u'), get({}), {'SENTINEL_AUDIT_DETAIL': 'commands'}).audit_detail, 'basic')
        self.assertEqual(resolve_settings(Path('/u'), get({'audit_detail': 'raw'}), {}).audit_detail, 'basic')


HERMES_AGENT = Path(os.environ.get('HERMES_AGENT_DIR', Path.home() / '.hermes' / 'hermes-agent'))
REQUIRE_REAL = os.environ.get('SENTINEL_REQUIRE_REAL_REDACTOR') == '1'


class RealHermesRedactorTests(unittest.TestCase):
    """Same whole-journal cases against the real Hermes redactor and a registered synthetic vault value.
    CI sets SENTINEL_REQUIRE_REAL_REDACTOR=1 in the lifecycle job so this cannot silently skip there."""
    def setUp(self):
        added = str(HERMES_AGENT) not in sys.path
        if added:
            sys.path.insert(0, str(HERMES_AGENT))
        self.addCleanup(lambda: added and sys.path.remove(str(HERMES_AGENT)))
        try:
            from agent import redact
        except Exception as exc:
            if REQUIRE_REAL:
                raise
            self.skipTest(f'Hermes redactor not importable: {type(exc).__name__}')
        self.redact = redact
        redact.clear_vault_redaction_values()
        redact.register_vault_redaction_value(CANARY)
        self.addCleanup(redact.clear_vault_redaction_values)

    def test_real_redactor_whole_journal(self):
        for level in ('basic', 'commands'):
            for label, tool, args in CASES:
                with self.subTest(level=level, case=label):
                    text, _ = journal_for(level, tool, args, self.redact.redact_sensitive_text)
                    self.assertNotIn(CANARY, text)
        for cmd, secret in (('curl -H "Authorization: Bearer sk-proj-SYNTHETIC00000000000000000000000000abcd" https://x.invalid',
                             'sk-proj-SYNTHETIC00000000000000000000000000abcd'),
                            ('curl https://user:SyntheticPassw0rd@x.invalid/path', 'SyntheticPassw0rd')):
            text, [e] = journal_for('commands', 'terminal', {'command': cmd}, self.redact.redact_sensitive_text)
            self.assertNotIn(secret, text)
            self.assertEqual((e['command_verb'], e['audit_detail']), ('curl', 'commands'))

    def test_real_redactor_keeps_ordinary_names(self):
        _, [e] = journal_for('basic', 'terminal', {'command': 'git status'}, self.redact.redact_sensitive_text)
        self.assertEqual((e['tool_name'], e['command_verb']), ('terminal', 'git'))
        _, [e] = journal_for('basic', 'secret_request', {}, self.redact.redact_sensitive_text)
        self.assertIn(e['tool_name'], ('secret_request', '[redacted]'))


if __name__ == '__main__':
    unittest.main()
