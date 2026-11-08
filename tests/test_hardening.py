"""Policy validation, profile separation, destination normalization and failure logging."""
import importlib.util
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch
from sentinel.config import load_policy
from sentinel.engine import canonical_destination
from sentinel.hermes_adapter import SentinelHook
ROOT=Path(__file__).resolve().parents[1]
KEY=b'q'*32

class HardeningTests(unittest.TestCase):
    def _policy(self, yaml_text):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'policy.yaml'
            p.write_text(yaml_text)
            return load_policy(str(p))

    def test_f8_closed_policy_schema(self):
        cases=(
            'version: 1\nrules:\n - id: any\n   effect: allow\n   operations: [network_upload]\n   destination_class: [unknown]\n',
            'version: 1\nrules:\n - id: any\n   effect: allow\n   operations: [network_upload]\n   priority: soon\n',
            'version: 1\nrules:\n - id: any\n   effect: allow\n   operations: [all_tools]\n',
            'version: 1\ndefaults: {unknown_action: allow}\nrules: []\n',
            'version: 1\nrules:\n - id: any\n   effect: allow\n   operations: [network_upload]\n   source_classes: foo\n',
        )
        for entry in cases:
            with self.subTest(entry=entry[:50]), self.assertRaises(ValueError):
                self._policy(entry)

    def test_f8_ip_ambiguity_and_ipv6(self):
        for uri in ('https://127.1/u','https://0x7f.1/u','https://2130706433/u','https://example.org:0/u'):
            with self.subTest(uri=uri):
                self.assertEqual(canonical_destination(uri),('unknown','unknown'))
        self.assertEqual(canonical_destination('https://[::1]/x'),('https://[::1]:443','local_or_private'))
        self.assertEqual(canonical_destination('http://127.0.0.1'),('http://127.0.0.1:80','local_or_private'))

    def test_curl_config_disabling_is_required(self):
        from sentinel.hermes_adapter import normalize
        for command in ('curl https://ok.example/u',
                        'curl -T artifact.zip https://ok.example/u',
                        'curl -s -q https://ok.example/u'):
            with self.subTest(command=command):
                self.assertEqual(normalize('terminal', {'command':command}).operation,'unknown')
        self.assertEqual(normalize('terminal', {'command':'curl -q -T artifact.zip https://ok.example/u'}).operation,'network_upload')

    def test_f9_no_secret_in_warning(self):
        with tempfile.TemporaryDirectory() as d:
            h=SentinelHook(str(Path(d)/'missing.yml'),str(Path(d)/'audit.jsonl'),KEY,'audit')
            with self.assertLogs('sentinel.hermes_adapter', level='WARNING') as logs:
                self.assertIsNone(h('terminal',{'command':'CANARY_HIDDEN_PRIVATE_STRING'}))
            self.assertNotIn('CANARY_HIDDEN_PRIVATE_STRING',' '.join(logs.output))
            self.assertIn('FileNotFoundError',' '.join(logs.output))

    def test_f7_contextual_profile_journal(self):
        with tempfile.TemporaryDirectory() as root:
            a=Path(root)/'profileA'; b=Path(root)/'profileB'
            active=[a]
            def resolver():
                state=active[0]/'sentinel'
                state.mkdir(parents=True, exist_ok=True)
                return str(state/'audit.jsonl'),KEY
            h=SentinelHook(str(ROOT/'policies/default.yaml'),'',KEY,'audit',state_resolver=resolver)
            self.assertIsNone(h('terminal',{'command':'curl -q https://example.org/u'}))
            active[0]=b
            self.assertIsNone(h('terminal',{'command':'curl -q https://example.org/u'}))
            self.assertEqual(len((a/'sentinel/audit.jsonl').read_text().splitlines()),1)
            self.assertEqual(len((b/'sentinel/audit.jsonl').read_text().splitlines()),1)

if __name__=='__main__':
    unittest.main()
