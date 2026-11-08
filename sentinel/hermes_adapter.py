"""Hermes pre_tool_call integration. Never log tool arguments or exception text."""
from __future__ import annotations
import os
import re
import secrets
import shlex
from pathlib import Path
from .engine import Action, evaluate
from .config import load_policy
from .audit import append_event

URL = re.compile(r'https?://[^\s\'"<>]+', re.I)
NETWORK = {'curl', 'wget', 'http', 'httpie'}
TEST = {'pytest', 'python -m pytest', 'python3 -m pytest', 'go test', 'cargo test', 'npm test'}

def _sensitive_path(path: str) -> bool:
    """Conservative filename indicator, not a complete data-classification system."""
    p = Path(path.lstrip('@')).name.lower()
    return (p in {'.env', 'id_rsa', 'id_ed25519', 'credentials.json', 'auth.json'}
            or p.endswith(('.pem', '.key', '.p12', '.pfx'))
            or p.startswith('.env.') or any(t in p for t in ('secret', 'credential', 'token')))


def _transfer_source_class(tokens: list[str]) -> str:
    """Recognize visible source-path flags; dynamic or opaque inputs remain unknown."""
    for index, token in enumerate(tokens):
        if token in {'-T', '--upload-file', '-d', '--data', '--data-binary', '--data-raw', '--data-urlencode', '-F', '--form', '--post-file'}:
            if index + 1 < len(tokens):
                value = tokens[index + 1]
                if _sensitive_path(value):
                    return 'credential_file'
        if token.startswith(('--upload-file=', '--post-file=')) and _sensitive_path(token.split('=', 1)[1]):
            return 'credential_file'
        if token.startswith('@') and _sensitive_path(token):
            return 'credential_file'
    return 'unknown'


def normalize(tool_name: str, args: dict) -> Action:
    """Conservatively classify a small, known set of command forms.

    This is NOT a shell parser, network firewall, or guarantee against redirects.
    """
    if not isinstance(args, dict) or tool_name != 'terminal':
        return Action('other', 'unknown')
    command = args.get('command')
    if not isinstance(command, str) or not command.strip() or len(command) > 16384:
        return Action('terminal', 'unknown')
    try:
        tokens = shlex.split(command)
    except ValueError:
        return Action('terminal', 'unknown')
    if not tokens:
        return Action('terminal', 'unknown')
    # No shell chaining, substitution, expansion or redirection can be safely summarized.
    if re.search(r'[;&|`<>\n\r]|\$|\\\n', command):
        return Action('terminal', 'unknown')
    if command.strip() in TEST or tokens in [['python', '-m', 'pytest'], ['python3', '-m', 'pytest']]:
        return Action('terminal', 'test_execution')
    executable = Path(tokens[0]).name.lower()
    if executable not in NETWORK or tokens[0].startswith(('.', '~')):
        return Action('terminal', 'unknown')
    # A single explicit HTTP(S) destination is necessary, not sufficient, to permit approval.
    urls = URL.findall(command)
    if len(urls) != 1:
        return Action('terminal', 'unknown')
    # Prevent the regex from extracting a harmless URL out of a larger opaque protocol string.
    if re.search(r'(?i)(?:file|ftp|sftp|scp|gopher|dict)://', command):
        return Action('terminal', 'unknown')
    # Treat URLs in payload text as ambiguous. The URI must appear as its own argument.
    uri = urls[0].rstrip('),')
    if uri not in tokens:
        return Action('terminal', 'unknown')
    # Respect explicit `--` and reject option values that may themselves invoke commands.
    if any(t.startswith(('--config', '-K', '--proxy', '--preproxy', '--resolve', '--connect-to', '--next', '--url-query', '--libcurl', '--write-out')) for t in tokens[1:]):
        return Action('terminal', 'unknown')
    return Action('terminal', 'network_upload', uri, _transfer_source_class(tokens))

class SentinelHook:
    def __init__(self, policy_path: str, audit_path: str, audit_key: bytes, mode: str = "audit"):
        if mode not in {"audit", "enforce"}:
            raise ValueError("invalid Sentinel mode")
        self.mode = mode
        self.policy_path, self.audit_path, self.audit_key = policy_path, audit_path, audit_key

    def __call__(self, tool_name: str, args: dict, task_id: str = '', **kwargs):
        try:
            action = normalize(tool_name, args)
            decision = evaluate(action, load_policy(self.policy_path), self.audit_key)
            # IDs are random and not derived from arguments or user-supplied text.
            event_id = secrets.token_hex(12)
            append_event(self.audit_path, {
                'event_id': event_id, 'action_id': event_id,
                'tool_name': 'terminal' if tool_name == 'terminal' else 'other',
                'operation': decision.operation,
                'target_hmac_sha256': decision.target_digest,
                'verdict': decision.verdict,
                'policy_id': decision.rule_id,
                'reason_code': 'policy_decision',
                'execution_status': 'not_executed' if decision.verdict != 'allowed' else 'pending_execution',
            })
            # Audit mode observes without changing the tool execution decision.
            if self.mode == 'audit':
                return None
            if decision.verdict == 'allowed':
                return None
            if decision.verdict == 'pending':
                # Hermes approval gate owns the human interaction and execution continuation.
                return {'action': 'approve', 'message': f'Sentinel authorization required (event {event_id}).'}
            return {'action': 'block', 'message': f'Sentinel policy blocked this action (event {event_id}).'}
        except Exception:
            # Audit-only mode must not return a policy veto on evaluation/journal errors.
            # The host may still independently fail closed on hook timeout.
            if self.mode == 'audit':
                return None
            return {'action': 'block', 'message': 'Sentinel policy evaluation unavailable; action blocked.'}
