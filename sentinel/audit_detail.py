"""Audit detail for policy review.

Every input-derived journal field in this module passes the same confidentiality gate:
Hermes's own redactor (`agent.redact.redact_sensitive_text`, forced, which also applies every vault
value registered for the active profile; Secret Guard registers its keys there). A value the
redactor changes is replaced by a fixed placeholder. If the redactor is missing or fails, every
input-derived field becomes a fixed placeholder; no input text is written.

Fields:
- `tool_name`: the real tool name only when Hermes's tool registry knows it, it matches token
  syntax, and redaction leaves it unchanged. Otherwise `[unregistered]`, `[unverified]`,
  `[redacted]` or `[unavailable]`.
- `command_verb` (terminal only): the first program word. Leading `VAR=value` assignments are
  skipped. A wrapper (`sudo`, `env`, `nohup`, ...) is recorded as itself; its options and target
  are never guessed. Unparseable quoting gives `[unparsed]`; long or token-like words give
  `[redacted]`.
- With profile setting `audit_detail: commands` only: `command_redacted` (terminal) or
  `target_redacted` (first of path/file_path/filepath/target/url/uri), after redaction.

Limits: redaction is pattern- and registry-based. A credential that Hermes does not recognise and
that is not registered for the active profile can still appear in `command_redacted` or
`target_redacted`, and also in `command_verb` at either level when it is supplied as the program
word itself. `basic` metadata is therefore not guaranteed secret-free. `commands` detail is for
review windows only.
"""
from __future__ import annotations

import os
import re
import shlex

DETAIL_LEVELS = frozenset({'basic', 'commands'})
MAX_DETAIL_CHARS = 2000
MAX_VERB_CHARS = 40
_TOOL_NAME = re.compile(r'[A-Za-z0-9_.:-]{1,96}')
_VERB = re.compile(r'[A-Za-z0-9_.+-]{1,%d}' % MAX_VERB_CHARS)
_ASSIGNMENT = re.compile(r'[A-Za-z_][A-Za-z0-9_]*=')
_TARGET_KEYS = ('path', 'file_path', 'filepath', 'target', 'url', 'uri')
_UNAVAILABLE = '[unavailable]'


def detail_level(raw) -> str:
    """Unknown or malformed values fall back to the more private level."""
    if isinstance(raw, str) and raw.strip().lower() in DETAIL_LEVELS:
        return raw.strip().lower()
    return 'basic'


def _redactor():
    try:
        from agent.redact import redact_sensitive_text
    except Exception:
        return None
    return redact_sensitive_text


def _registry_lookup():
    """Return a callable name -> bool for Hermes's tool registry, or None if it cannot be read."""
    try:
        from tools.registry import registry
    except Exception:
        return None
    def known(name):
        try:
            return registry.get_entry(name) is not None
        except Exception:
            return False
    return known


class _Gate:
    """One redaction gate per record. `ok` is False once the redactor is missing or has failed."""
    def __init__(self, redactor):
        self.fn = redactor
        self.ok = redactor is not None

    def text(self, value):
        if not self.ok or not isinstance(value, str):
            return None
        try:
            clean = self.fn(value, force=True, redact_url_credentials=True)
        except Exception:
            self.ok = False
            return None
        if not isinstance(clean, str):
            self.ok = False
            return None
        return clean

    def token(self, value):
        """A short identifier: kept only if redaction leaves it byte-identical."""
        clean = self.text(value)
        if clean is None:
            return _UNAVAILABLE
        return value if clean == value else '[redacted]'


def _token_like(word: str) -> bool:
    """Opaque credential shape: long, mixed classes, no path or extension structure."""
    if len(word) < 20:
        return False
    classes = sum(bool(re.search(p, word)) for p in (r'[a-z]', r'[A-Z]', r'[0-9]'))
    return classes >= 2 and not re.search(r'[./]', word)


def tool_name_field(name, gate: _Gate, known=None) -> str:
    if not isinstance(name, str) or not _TOOL_NAME.fullmatch(name):
        return '[redacted]'
    if known is None:
        return '[unverified]'
    if not known(name):
        return '[unregistered]'
    return gate.token(name)


def command_verb(command, gate: _Gate) -> str:
    if not isinstance(command, str) or not command.strip():
        return '[none]'
    try:
        words = shlex.split(command, posix=True)
    except ValueError:
        return '[unparsed]'
    word = next((w for w in words if not _ASSIGNMENT.match(w)), None)
    if word is None:
        return '[none]'
    base = os.path.basename(word)
    if not _VERB.fullmatch(base) or _token_like(base):
        return '[redacted]'
    return gate.token(base)


def _escape(text: str) -> str:
    out = ''.join(c if 32 <= ord(c) != 127 else '\\x%02x' % ord(c) for c in text)
    if len(out) > MAX_DETAIL_CHARS:
        out = out[:MAX_DETAIL_CHARS - 13] + '…[truncated]'
    return out


def detail_fields(tool_name, args, level: str, redactor=None, known=None) -> dict:
    """Journal fields derived from tool input. `redactor`/`known` default to Hermes's own."""
    gate = _Gate(redactor if redactor is not None else _redactor())
    known = known if known is not None else _registry_lookup()
    fields = {'tool_name': tool_name_field(tool_name, gate, known)}
    command = args.get('command') if isinstance(args, dict) else None
    if tool_name == 'terminal':
        fields['command_verb'] = command_verb(command, gate)
    if level == 'commands':
        if tool_name == 'terminal':
            value, key = command, 'command_redacted'
        else:
            value = next((args.get(k) for k in _TARGET_KEYS
                          if isinstance(args, dict) and isinstance(args.get(k), str)), None)
            key = 'target_redacted'
        if value is not None:
            clean = gate.text(value)
            if clean is not None:
                fields[key] = _escape(clean)
    if not gate.ok:
        # Fail closed for the whole record: no input-derived text survives a missing or failed redactor.
        fields = {k: _UNAVAILABLE for k in fields if k in ('tool_name', 'command_verb')}
        if level == 'commands':
            fields['audit_detail'] = 'unavailable'
    elif level == 'commands':
        fields['audit_detail'] = 'commands'
    return fields
