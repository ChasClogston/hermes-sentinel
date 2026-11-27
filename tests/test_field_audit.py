"""Regression coverage for safe classifications added after the field audit."""
from pathlib import Path
import tempfile
import unittest

from sentinel.config import load_policy
from sentinel.engine import evaluate
from sentinel.hermes_adapter import normalize


class FieldAuditTests(unittest.TestCase):
    def test_ordinary_hermes_paths_and_credentials(self):
        policy = load_policy(str(Path(__file__).resolve().parents[1] / 'policies/default.yaml'))
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve() / '.hermes'
            for relative, verdict in (
                ('cache/scratch/example/notes.txt', 'allowed'),
                ('skills/example/SKILL.md', 'pending'),
                ('plugins/example/main.py', 'pending'),
                ('profiles/example/auth.json', 'blocked'),
                ('cache/scratch/example/.env.local', 'blocked'),
                ('state.db', 'blocked'),
                ('state.db-wal', 'blocked'),
                ('state.db-shm', 'blocked'),
                ('config.yaml.bak-20261127', 'blocked'),
                ('sessions/example.json', 'blocked'),
                ('logs/gateway.log', 'blocked'),
                ('whatsapp/session/creds.json', 'blocked'),
                ('pairing/example.json', 'blocked'),
                ('cron/jobs.json', 'blocked'),
                ('gateway_state.json', 'blocked'),
                ('plugins/.install-metadata.json', 'blocked'),
                ('sentinel/audit.key', 'blocked'),
                ('sentinel/audit.jsonl', 'blocked'),
                ('sentinel/archive/audit.jsonl', 'blocked'),
                ('profiles/other/cache/scratch/notes.txt', 'blocked'),
                ('../outside/notes.txt', 'blocked'),
            ):
                with self.subTest(relative=relative):
                    action = normalize('read_file', {'path': str(home / relative)}, profile_home=home)
                    self.assertEqual(evaluate(action, policy, b'x' * 32).verdict, verdict)

            outside = home.parent / 'Documents' / 'report.txt'
            action = normalize('read_file', {'path': str(outside)}, profile_home=home)
            self.assertEqual(evaluate(action, policy, b'x' * 32).verdict, 'pending')

    def test_curl_keeps_configuration_and_file_boundaries(self):
        url = 'https://example.org/feed'
        for arguments, expected in (
            ('-q -sS --max-time 30', 'network_request'),
            ('-q --connect-timeout 1.5 --fail', 'network_request'),
            ('-sS --max-time 30', 'unknown'),
            ('-q -L', 'unknown'),
            ('-q -o output.txt', 'unknown'),
            ('-q --data @payload', 'unknown'),
        ):
            with self.subTest(arguments=arguments):
                self.assertEqual(normalize('terminal', {'command': f'curl {arguments} {url}'}).operation,
                                 expected)
