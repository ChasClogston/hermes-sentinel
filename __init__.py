"""Sentinel Governance registration through public plugin APIs only."""
from __future__ import annotations
import os
import logging
import secrets
import tempfile
import time
from pathlib import Path
from .sentinel.hermes_adapter import SentinelHook, BlockingHook


def _audit_key(state: Path) -> bytes:
    """Install a complete key atomically without replacing another process's key."""
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    key_path = state / 'audit.key'
    # mkstemp creates 0600, and hard-link publication is atomic.
    if not key_path.exists():
        fd, temporary = tempfile.mkstemp(prefix='.audit-key-', dir=state)
        try:
            with os.fdopen(fd, 'wb') as out:
                out.write(secrets.token_bytes(32))
                out.flush()
                os.fsync(out.fileno())
            try:
                os.link(temporary, key_path)
            except FileExistsError:
                pass  # Another process published a complete key first.
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
    # The publishing process briefly has two hard links (temp + final).
    # Never accept a multiply-linked key: retry until its temp link is gone.
    for attempt in range(40):
        fd = os.open(key_path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        try:
            st = os.fstat(fd)
            if st.st_mode & 0o077:
                raise ValueError('unsafe audit key permissions')
            if st.st_nlink == 1:
                with os.fdopen(fd, 'rb', closefd=False) as f:
                    key = f.read(33)
                if len(key) != 32:
                    raise ValueError('invalid audit key length')
                return key
        finally:
            os.close(fd)
        # Clean only stale siblings hard-linked to the exact key inode.
        # Never delete an active publisher's temporary key.
        if attempt >= 20:
            try:
                key_stat = key_path.stat()
                for sibling in state.glob('.audit-key-*'):
                    info = sibling.lstat()
                    if (info.st_ino == key_stat.st_ino
                            and info.st_dev == key_stat.st_dev
                            and time.time() - info.st_mtime > 5):
                        sibling.unlink()
            except OSError:
                pass
        time.sleep(0.01)
    raise ValueError('audit key still multiply linked')


def register(ctx):
    """Audit startup failures observe only; enforce failures register a veto."""
    mode = os.environ.get('SENTINEL_GOVERNANCE_MODE',
                          os.environ.get('HERMES_SENTINEL_MODE', 'audit')).strip().lower()
    try:
        if mode not in {'audit', 'enforce'}:
            raise ValueError('invalid Sentinel mode')
        # Hermes constants honor multiplex context-local profile overrides.
        from hermes_constants import get_hermes_home
        state = get_hermes_home() / 'sentinel'
        key = _audit_key(state)
        policy_path = str(Path(__file__).parent / 'policies' / 'default.yaml')
        def resolve_current_profile():
            current = get_hermes_home() / 'sentinel'
            return str(current / 'audit.jsonl'), _audit_key(current)
        handler = SentinelHook(policy_path, str(state / 'audit.jsonl'), key,
                               mode=mode, state_resolver=resolve_current_profile)
    except Exception as exc:
        logging.getLogger(__name__).warning(
            'Sentinel Governance initialization failure: %s', type(exc).__name__)
        # Audit must not turn a damaged journal into an agent-wide denial.
        # Invalid mode cannot be trusted as audit and remains fail-closed.
        if mode == 'audit':
            from .sentinel.hermes_adapter import ObservingFailureHook
            handler = ObservingFailureHook()
        else:
            handler = BlockingHook()
    ctx.register_hook('pre_tool_call', handler)
