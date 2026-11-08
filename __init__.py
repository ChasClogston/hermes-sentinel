"""Hermes Sentinel plugin entry point."""
from __future__ import annotations
import os
from pathlib import Path
from .sentinel.hermes_adapter import SentinelHook


def register(ctx):
    mode = os.environ.get("HERMES_SENTINEL_MODE", "audit").strip().lower()
    if mode not in {"audit", "enforce"}:
        raise ValueError("HERMES_SENTINEL_MODE must be audit or enforce")
    root = Path(os.environ.get('HERMES_HOME', str(Path.home() / '.hermes')))
    state = root / 'sentinel'
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    key_path = state / 'audit.key'
    if not key_path.exists():
        import secrets
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as out:
            out.write(secrets.token_bytes(32))
    key = key_path.read_bytes()
    if len(key) != 32:
        raise ValueError('Sentinel audit key invalid')
    policy_path = str(Path(__file__).parent / 'policies' / 'default.yaml')
    ctx.register_hook('pre_tool_call', SentinelHook(policy_path, str(state / 'audit.jsonl'), key, mode=mode))
