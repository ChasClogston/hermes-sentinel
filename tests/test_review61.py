"""Regressions for the independent v0.6.0 review."""
import json
import tempfile
import unittest
from pathlib import Path

from sentinel.config import load_policy
from sentinel.engine import Action, evaluate
from sentinel.hermes_adapter import BlockingHook, normalize
from sentinel.replay import _parse_call


class Review61Tests(unittest.TestCase):
    def test_approval_wins_equal_priority_regardless_of_rule_names(self):
        for allow_name in ('a-allow', 'z-allow'):
            rules = [
                {'id': allow_name, 'effect': 'allow', 'operations': ['network_request']},
                {'id': 'm-approve', 'effect': 'require_approval', 'operations': ['network_request']},
            ]
            result = evaluate(Action('terminal', 'network_request', 'https://example.invalid/x'),
                              {'rules': rules}, b'x' * 32)
            self.assertEqual(result.verdict, 'pending')

    def test_broad_unknown_allow_is_rejected(self):
        policy = {'version': 1, 'defaults': {'unknown_action': 'deny'}, 'rules': [
            {'id': 'unsafe-allow', 'effect': 'allow', 'operations': ['unknown']}]}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'policy.json'
            path.write_text(json.dumps(policy))
            with self.assertRaises(ValueError):
                load_policy(path)

    def test_failure_guidance_stops_instead_of_suggesting_alternatives(self):
        result = BlockingHook()('terminal', {})
        self.assertIn('Stop and tell the user', result['message'])
        self.assertNotIn('alternative', result['message'])

    def test_stored_shapes_match_the_live_classifier(self):
        cases = [
            ('write_file', json.dumps({'content': 'PRIVATE_CANARY_61' * 5000}), {}, False),
            ('terminal', '', {}, False),
            ('terminal', {'command': 'pytest'}, {'command': 'pytest'}, False),
            ('terminal', json.dumps(['pytest']), ['pytest'], False),
            ('terminal', json.dumps({'command': 'pytest'}), {'command': 'pytest'}, True),
        ]
        policy = {'rules': [{'id': 'approve-tests', 'effect': 'require_approval',
                             'operations': ['test_execution']}]}
        for tool, raw, live_args, flat in cases:
            with self.subTest(tool=tool, flat=flat, argument_type=type(raw).__name__):
                function = {'name': tool, 'arguments': raw}
                parsed = _parse_call(function if flat else {'function': function})
                self.assertIsNotNone(parsed)
                observed = evaluate(normalize(*parsed), policy, b'x' * 32).verdict
                expected = evaluate(normalize(tool, live_args), policy, b'x' * 32).verdict
                self.assertEqual(observed, expected)
