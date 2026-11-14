"""Per-profile enforcement latches survive hook re-registration until process exit."""
from __future__ import annotations
import logging
import secrets
import sys
import threading
import types
from pathlib import Path
from .audit import append_event

_LOG = logging.getLogger(__name__)
# Hermes may unload scoped plugin packages. Keep only opaque in-memory state in
# a process-owned namespace outside those packages; no disk persistence/reset API.
_new = types.ModuleType('_sentinel_governance_process_state_v1')
_new.lock = threading.RLock()
_new.profiles = {}
_process = sys.modules.setdefault(_new.__name__, _new)


class ProfileState:
    def __init__(self):
        self.lock = threading.RLock()
        self.enforced = False
        self.requested = None
        self.pending = []
        self.policy_failure_recorded = False

    def mode(self, requested, source):
        if requested == 'enforce':
            self.enforced = True
        effective = ('invalid' if requested == 'invalid' else
                     'enforce' if self.enforced else 'audit')
        if self.requested is not None and requested != self.requested:
            self.pending.append({'event_type':'mode_change','previous_mode':self.requested,
                                 'requested_mode':requested,'enforcement_mode':effective,
                                 'mode_source':source,'reason_code':'mode_changed'})
            _LOG.warning('Sentinel Governance mode change: requested=%s effective=%s; enforce latches until restart',
                         requested, effective)
        self.requested = requested
        return effective

    def flush(self, path, key):
        while self.pending:
            append_event(path, {'event_id':secrets.token_hex(12), 'verdict':'configuration',
                               'execution_status':'configuration_event', **self.pending[0]}, signing_key=key)
            self.pending.pop(0)

    def policy_failure(self, path, key, mode, reason):
        if not self.policy_failure_recorded:
            _LOG.warning('Sentinel Governance policy unavailable: %s mode=%s', reason, mode)
            append_event(path, {'event_id':secrets.token_hex(12), 'event_type':'policy_load_failure',
                         'verdict':'configuration', 'enforcement_mode':mode, 'reason_code':reason,
                         'execution_status':'configuration_event'}, signing_key=key)
            self.policy_failure_recorded = True


def profile_state(home) -> ProfileState:
    identity = str(Path(home).resolve())
    with _process.lock:
        if identity not in _process.profiles:
            _process.profiles[identity] = ProfileState()
        return _process.profiles[identity]
