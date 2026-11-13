import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel.hermes_adapter import BlockingHook, SentinelHook

ROOT = Path(__file__).resolve().parents[1]


class RefusalTests(unittest.TestCase):
    def test_blocks_preserve_permitted_alternatives_without_a_blanket_ask(self):
        with tempfile.TemporaryDirectory() as directory:
            hook = SentinelHook(str(ROOT / 'policies/default.yaml'),
                                str(Path(directory) / 'audit.jsonl'), b'x' * 32, mode='enforce')
            blocked = hook('terminal', {'command': 'echo PRIVATE_CANARY_487'})
            with patch('sentinel.hermes_adapter.load_policy', side_effect=ValueError('PRIVATE_CANARY_487')):
                failed = hook('terminal', {'command': 'pytest'})
            for result in (blocked, failed, BlockingHook()('terminal', {})):
                self.assertEqual(result['action'], 'block')
                self.assertIn('alternative that complies with the policy and existing authorization', result['message'])
                self.assertIn('requires an exception or additional authorization', result['message'])
                self.assertNotIn('PRIVATE_CANARY_487', result['message'])
                self.assertNotIn('Do not reach the same result', result['message'])
            self.assertNotIn('PRIVATE_CANARY_487', (Path(directory) / 'audit.jsonl').read_text())
