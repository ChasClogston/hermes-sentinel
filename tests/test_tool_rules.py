"""Exact tool rules grant only the named capability and preserve policy ordering."""
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
import sys
import types

from sentinel.config import load_policy
from sentinel.engine import evaluate
from sentinel.engine import Action
from sentinel.hermes_adapter import SentinelHook, normalize
from sentinel.replay import _scan
from test_replay import FakeDB


class ToolRuleTests(unittest.TestCase):
    def policy(self, rules):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/'p.json'; p.write_text(json.dumps({'version': 1, 'rules': rules}))
            return load_policy(p)

    def rule(self, effect='allow', name='a', tools=None):
        return dict(id=name, effect=effect, operations=['unknown'], tools=tools or ['read_file', 'secret_request'])

    def test_exact_tool_identity_and_ordering(self):
        action = normalize('read_file', {'path': '/any/host/permitted/path'})
        self.assertEqual((action.tool, action.tool_name), ('other', 'read_file'))
        allow = self.rule()
        self.assertEqual(evaluate(action, self.policy([allow]), b'x'*32).verdict, 'allowed')
        for name in ('Read_file', 'write_file', 'terminal', 'execute_code', 'mcp__read_file'):
            self.assertEqual(evaluate(normalize(name, {}), self.policy([allow]), b'x'*32).verdict, 'blocked')
        for rules, verdict in (([allow, self.rule('deny', 'deny')], 'blocked'),
                               ([allow, self.rule('require_approval', 'z-approve')], 'pending')):
            self.assertEqual(evaluate(action, self.policy(rules), b'x'*32).verdict, verdict)

    def test_loader_rejects_broad_and_execution_unknown_allows(self):
        for tools in (None, [], ['terminal'], ['execute_code'], ['read_file', 'terminal'],
                      ['TERMINAL'], ['*'], [1], 'read_file'):
            rule = self.rule(); rule['tools'] = tools
            if tools is None: del rule['tools']
            with self.subTest(tools=tools), self.assertRaises(ValueError): self.policy([rule])

    def test_named_rule_cannot_allow_invalid_destination(self):
        rule = self.rule(tools=['read_file'])
        decision = evaluate(Action('other', 'unknown', 'https://example.invalid:0',
                                   tool_name='read_file'), self.policy([rule]), b'x'*32)
        self.assertEqual((decision.verdict, decision.rule_id), ('blocked', 'invalid-destination'))

    def test_whole_tool_allow_has_no_approval_and_journal_stays_private(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'p.json'; path.write_text(json.dumps({'version':1,'rules':[self.rule()]}))
            hook = SentinelHook(str(path), str(Path(d)/'audit.jsonl'), b'x'*32, 'enforce')
            self.assertIsNone(hook('read_file', {'path': 'PRIVATE_CANARY'}))
            self.assertIsNone(hook('secret_request', {'anything': 'PRIVATE_CANARY'}))
            self.assertEqual(hook('write_file', {})['action'], 'block')
            path.write_text(json.dumps({'version':1,'rules':[self.rule('require_approval')]}))
            result = hook('read_file', {'path': 'PRIVATE_CANARY'})
            self.assertEqual(result['action'], 'approve')
            self.assertIn('whole tool', result['message'])
            self.assertNotIn('PRIVATE_CANARY', result['message'])
            journal = (Path(d)/'audit.jsonl').read_text()
            self.assertNotIn('PRIVATE_CANARY', journal)
            self.assertNotIn('secret_request', journal)

    def test_replay_matches_live_named_calls(self):
        policy = self.policy([self.rule(), self.rule('require_approval', 'write', ['write_file'])])
        names = ['read_file', 'secret_request', 'write_file', 'unlisted', 'terminal']
        verdicts = [evaluate(normalize(name, {}), policy, b'x'*32).verdict for name in names]
        now = time.time()
        FakeDB.messages = [{'timestamp':now,'tool_calls':[{'function':{'name':name,'arguments':'{}'}} for name in names]}]
        FakeDB.sessions = [{'id':'synthetic'}]
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'state.db'; path.touch()
            with patch.dict(sys.modules, {'hermes_state':types.SimpleNamespace(SessionDB=FakeDB)}):
                result = _scan([path], policy, now-10, now+10, lambda value:None, time.monotonic()+2)
        for verdict in ('allowed', 'pending', 'blocked'):
            self.assertEqual(result[verdict], verdicts.count(verdict))
