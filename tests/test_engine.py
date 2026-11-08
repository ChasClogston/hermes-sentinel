import tempfile
import unittest
from pathlib import Path
from sentinel.engine import Action, evaluate, canonical_destination, action_digest
from sentinel.audit import append_event
from sentinel.config import load_policy

ROOT=Path(__file__).resolve().parents[1]
class EngineTests(unittest.TestCase):
    def setUp(self):
        self.policy=load_policy(ROOT/'policies/default.yaml')
        self.key=b'x'*32
    def test_deny_credential(self):
        self.assertEqual(evaluate(Action('terminal','network_upload','https://evil.example/x','credential_file'),self.policy,self.key).verdict,'blocked')
    def test_approve_external(self):
        self.assertEqual(evaluate(Action('terminal','network_upload','https://safe.example/path'),self.policy,self.key).verdict,'pending')
    def test_allow_local(self):
        self.assertEqual(evaluate(Action('terminal','test_execution'),self.policy,self.key).verdict,'pending')
    def test_unknown_denied(self):
        self.assertEqual(evaluate(Action('terminal','shell_unknown'),self.policy,self.key).verdict,'blocked')
    def test_credentials_in_uri_denied(self):
        self.assertEqual(canonical_destination('https://user:password@example.com'),('unknown','unknown'))
    def test_invalid_port_denied(self):
        self.assertEqual(canonical_destination('https://example.com:bad'),('unknown','unknown'))
    def test_audit_rejects_raw_arguments(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):append_event(d+'/audit.jsonl',{'verdict':'blocked','raw_args':'SECRET_CANARY'})
            self.assertFalse(Path(d+'/audit.jsonl').exists())
    def test_audit_canary_not_present(self):
        with tempfile.TemporaryDirectory() as d:
            p=d+'/audit.jsonl';append_event(p,{'verdict':'blocked','tool_name':'terminal','target_hmac_sha256':'a'*64})
            self.assertNotIn('SECRET_CANARY',Path(p).read_text())
if __name__=='__main__':unittest.main()
