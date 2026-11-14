"""Conservative Hermes action-governance hook.

Approved grammar is deliberately tiny. Unknown actions block in enforcement mode.
No proposed shell commands are executed or serialized by this module.
"""
from __future__ import annotations

import logging
import re
import secrets
import shlex
from dataclasses import replace
from pathlib import Path
from urllib.parse import urlsplit
from .audit import append_event
from .config import load_policy
from .engine import Action, evaluate
from .source_policy import safe_source, safe_url_path
from .runtime_state import ProfileState, profile_state
from .settings import policy_failure_reason

_LOG = logging.getLogger(__name__)
_REFUSAL_GUIDANCE = (
    'Continue with an alternative that complies with the policy and existing authorization. '
    'Preserve the restriction expressed by this rule. '
    'Ask the user if completing the task requires an exception or additional authorization.'
)
_FAILURE_GUIDANCE = (
    'Stop and tell the user that Sentinel Governance needs attention before tool execution can continue.'
)
_SHELL_META = re.compile(r'[;&|`<>\n\r$*?\[\]{}]')
_SENSITIVE = {'.env', '.netrc', '.npmrc', '.pgpass', 'id_rsa',
              'id_dsa', 'id_ecdsa', 'id_ed25519', 'credentials.json',
              'auth.json', 'config.yaml', 'hosts.yml'}
_PRIVATE_DIRS = {'.ssh', '.aws', '.kube', '.docker', '.gnupg'}
_TEST_COMMANDS = {
    ('pytest',): 'pytest',
    ('python', '-m', 'pytest'): 'python -m pytest',
    ('python3', '-m', 'pytest'): 'python3 -m pytest',
}


def _sensitive_path(raw: str) -> bool:
    p = raw.strip().lstrip('@').lower()
    components = set(Path(p).parts)
    leaf = Path(p).name
    return (
        bool(components.intersection(_PRIVATE_DIRS))
        or leaf in _SENSITIVE
        or leaf.startswith('.env.')
        or leaf.endswith(('.pem', '.key', '.p12', '.pfx'))
        or any(x in leaf for x in ('secret', 'credential', 'token'))
        or '/.config/gh/' in ('/' + p.lstrip('/') + '/')
    )


def normalize(tool_name: str, args: dict, **file_context) -> Action:
    from .file_guards import file_restriction
    return replace(_normalize(tool_name, args), tool_name=tool_name,
                   file_restriction=file_restriction(tool_name, args, **file_context))


def _normalize(tool_name: str, args: dict) -> Action:
    """Recognize only single-destination, option-restricted curl proposals.

    Other network clients and arbitrary commands cannot safely be classified.
    Classification is NOT a shell sandbox or network boundary.
    """
    if tool_name != 'terminal' or not isinstance(args, dict):
        return Action('other', 'unknown')
    cmd = args.get('command')
    if not isinstance(cmd, str) or not cmd.strip() or len(cmd) > 16384:
        return Action('terminal', 'unknown')
    if _SHELL_META.search(cmd) or '\\' in cmd:
        return Action('terminal', 'unknown')
    try:
        tok = shlex.split(cmd, posix=True)
    except ValueError:
        return Action('terminal', 'unknown')
    if not tok:
        return Action('terminal', 'unknown')
    if tuple(tok) in _TEST_COMMANDS:
        return Action('terminal', 'test_execution')

    # Do not approve a different binary simply because its basename is "curl".
    # curl -q MUST be its first option; otherwise ~/.curlrc can silently add
    # proxies, destinations, file outputs, and other uninspected behavior.
    if tok[0] != 'curl' or len(tok) < 3 or tok[1] != '-q':
        return Action('terminal', 'unknown')
    tok = [tok[0], *tok[2:]]
    # V0.5 grammar: curl -q [--upload-file SOURCE | -T SOURCE] URI
    #              or curl -q URI. Any extra option, attached flag, host, config,
    #              redirect, proxy or data argument is treated as unknown.
    if len(tok) == 2:
        uri = tok[1]
        source = None
    elif len(tok) == 4 and tok[1] in ('-T', '--upload-file'):
        source, uri = tok[2], tok[3]
    else:
        return Action('terminal', 'unknown')
    try:
        parsed = urlsplit(uri)
        if (parsed.scheme.lower() not in {'http', 'https'}
                or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.fragment):
            return Action('terminal', 'unknown')
        if parsed.port == 0:
            return Action('terminal', 'unknown')
    except ValueError:
        return Action('terminal', 'unknown')
    path_ok, _ = safe_url_path(uri)
    if source is None:
        return Action('terminal', 'network_request', uri,
                      'none' if path_ok else 'credential_file')
    source_class, _ = safe_source(source, args.get('workdir'))
    if not path_ok:
        source_class = 'credential_file'
    return Action('terminal', 'network_upload', uri, source_class)


class SentinelHook:
    def __init__(self, policy_path: str, audit_path: str, audit_key: bytes,
                 mode: str = 'audit', state_resolver=None, binding_resolver=None):
        if mode not in {'audit', 'enforce'}:
            raise ValueError('invalid Sentinel mode')
        self.policy_path = policy_path
        self.audit_path = audit_path
        self.audit_key = audit_key
        self.mode = mode
        self.state_resolver = state_resolver
        self.binding_resolver = binding_resolver
        self._state = ProfileState()

    def __call__(self, tool_name: str, args: dict, task_id: str = '',
                 session_id: str = '', tool_call_id: str = '', **kwargs):
        return self._invoke(tool_name, args, session_id, tool_call_id)

    def preflight(self):
        return self._invoke('', {}, '', '', health_only=True)

    def _invoke(self, tool_name, args, session_id, tool_call_id, health_only=False):
        try:
            binding = self.binding_resolver() if self.binding_resolver is not None else None
            state = profile_state(binding.home) if binding is not None else self._state
            # Linearize a profile's resolution through its decision. Other
            # profiles have independent locks and cannot inherit its mode.
            with state.lock:
                return self._execute(binding, state, tool_name, args, session_id, tool_call_id, health_only)
        except Exception as exc:
            return self._failure('invalid' if self.binding_resolver is not None else self.mode, exc)

    def _failure(self, mode, exc):
        _LOG.warning('Sentinel Governance hook failure: %s', type(exc).__name__)
        if mode == 'audit':
            return None
        return {'action':'block', 'message':(
            'Sentinel Governance evaluation unavailable; tool call blocked. ' + _FAILURE_GUIDANCE)}

    def _execute(self, binding, state, tool_name, args, session_id, tool_call_id, health_only):
        mode = 'invalid' if binding is not None else self.mode
        try:
            mode = state.mode(binding.mode, binding.mode_source) if binding is not None else self.mode
            audit_path, audit_key = (self.state_resolver() if self.state_resolver is not None
                                     else (self.audit_path, self.audit_key))
            state.flush(audit_path, audit_key)
            if health_only and binding is not None:
                _LOG.info('Sentinel Governance effective mode=%s mode_source=%s policy_source=%s; enforce latched per profile until restart',
                          mode, binding.mode_source, binding.policy_source)
            if mode == 'invalid':
                raise ValueError('invalid Sentinel mode')
            try:
                policy = binding.load_policy() if binding is not None else load_policy(self.policy_path)
            except Exception as exc:
                state.policy_failure(audit_path, audit_key, mode, policy_failure_reason(exc))
                raise
            if health_only:
                return None
            file_context = ({'profile_home': binding.home, 'policy_path': binding.policy_path}
                            if binding is not None else {})
            action = normalize(tool_name, args, **file_context)
            decision = evaluate(action, policy, audit_key)
            event_id = secrets.token_hex(12)
            entry = {
                'event_id': event_id,
                'action_id': event_id,
                'tool_name': 'terminal' if tool_name == 'terminal' else 'other',
                'operation': decision.operation,
                'target_hmac_sha256': decision.target_digest,
                'verdict': ('unclassified' if mode == 'audit'
                            and decision.rule_id == 'default-deny' else decision.verdict),
                'policy_verdict': decision.verdict,
                'classification': ('unclassified' if decision.rule_id == 'default-deny'
                                   else 'matched'),
                'enforcement_mode': mode,
                'policy_id': decision.rule_id,
                'reason_code': 'policy_decision',
                'execution_status': ('not_enforced' if mode == 'audit'
                                     else 'blocked_by_sentinel' if decision.verdict == 'blocked'
                                     else 'approval_requested' if decision.verdict == 'pending'
                                     else 'not_observed'),
            }
            # Keep opaque host-provided IDs only when they meet strict token syntax.
            for k, value in (('session_id', session_id), ('tool_call_id', tool_call_id)):
                if isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_.:-]{1,96}', value):
                    entry[k] = value
            append_event(audit_path, entry)
            if mode == 'audit':
                return None
            if decision.verdict == 'allowed':
                return None
            if decision.verdict == 'pending':
                # One approval key PER EVENT. Persistent/"always" approval grants
                # from Hermes cannot authorize subsequent Sentinel decisions.
                base = args.get('workdir') if isinstance(args, dict) else None
                workspace = Path(base).name if isinstance(base, str) and base else Path.cwd().name
                if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,40}',workspace):
                    workspace = '[redacted]'
                if action.operation == 'test_execution':
                    label = _TEST_COMMANDS[tuple(shlex.split(args['command']))]
                    context = f'command={label}, workspace={workspace}'
                elif action.operation == 'unknown':
                    name = action.tool_name
                    label = name if isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9_.:-]{1,160}', name) else '[redacted]'
                    context = f'tool={label}, scope=whole tool; arguments are not inspected'
                else:
                    host = urlsplit(action.destination).hostname or 'unknown'
                    _, ui_path = safe_url_path(action.destination) if action.destination else (True, '[none]')
                    if action.operation == 'network_upload':
                        _, ui_source = safe_source(shlex.split(args['command'])[3], args.get('workdir'))
                    else:
                        ui_source = '[not applicable]'
                    context = (f'destination={host}, path={ui_path}, source={ui_source}, '
                               f'workspace={workspace}, source_class={action.source_class}')
                return {
                    'action': 'approve',
                    'rule_key': f'sentinel:{event_id}',
                    'message': (
                        f'Sentinel Governance approval required: operation={decision.operation}, '
                        f'{context}, '
                        f'policy={decision.rule_id}, event={event_id}. '
                        + ('Authorize one invocation of this whole tool; it may perform any operation '
                         'the tool permits. Arguments are not shown or approved individually.'
                         if action.operation == 'unknown' else 'Approve this exact request only.')
                    ),
                }
            return {
                'action': 'block',
                'message': (f'Sentinel Governance policy blocked this tool call (event {event_id}). '
                            + _REFUSAL_GUIDANCE)
            }
        except Exception as exc:
            return self._failure(mode, exc)


class BlockingHook:
    """Emergency fallback when Sentinel initialization is misconfigured."""
    def __call__(self, tool_name: str, args: dict, **kwargs):
        return {'action': 'block',
                'message': ('Sentinel Governance startup health check failed; execution blocked. '
                            + _FAILURE_GUIDANCE)}


class ObservingFailureHook:
    """Audit-mode startup fallback: never issue vetoes."""
    def __call__(self, tool_name: str, args: dict, **kwargs):
        return None

