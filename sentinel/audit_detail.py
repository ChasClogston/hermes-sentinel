"""Audit detail for policy review: real tool names, command verbs and, when enabled, redacted commands.

Default detail ('basic') records the tool name and, for terminal calls, the first program word only.
Neither can hold a credential. Detail 'commands' (profile setting `audit_detail: commands`) also
records the terminal command or a file/URL target, AFTER Hermes's own redaction (pattern-based plus
every vault value registered for the active profile, which is where Secret Guard registers its keys).
If Hermes's redactor cannot be imported, nothing beyond 'basic' is recorded.
"""
from __future__ import annotations

import os
import re
import shlex

DETAIL_LEVELS = frozenset({'basic', 'commands'})
MAX_DETAIL_CHARS = 2000
_TOOL_NAME = re.compile(r'[A-Za-z0-9_.:-]{1,96}')
_VERB = re.compile(r'[A-Za-z0-9_.+-]{1,64}')
_ASSIGNMENT = re.compile(r'[A-Za-z_][A-Za-z0-9_]*=')
_TARGET_KEYS = ('path', 'file_path', 'filepath', 'target', 'url', 'uri')


def detail_level(raw) -> str:
    """Unknown or malformed values fall back to the more private level."""
    if isinstance(raw, str) and raw.strip().lower() in DETAIL_LEVELS:
        return raw.strip().lower()
    return 'basic'


def safe_tool_name(name) -> str:
    return name if isinstance(name, str) and _TOOL_NAME.fullmatch(name) else '[redacted]'


def command_verb(command) -> str:
    """First program word of a shell command, skipping leading VAR=value assignments (never recorded)."""
    if not isinstance(command, str) or not command.strip():
        return '[none]'
    try:
        words = shlex.split(command, posix=True)
    except ValueError:
        words = command.split()
    wrapped = False
    for word in words:
        if _ASSIGNMENT.match(word):
            continue
        if word in ('sudo', 'env', 'command', 'exec', 'nohup', 'time'):
            wrapped = True
            continue
        if wrapped and word.startswith('-'):
            continue
        base = os.path.basename(word)
        return base if _VERB.fullmatch(base) else '[complex]'
    return '[none]'


def _escape(text: str) -> str:
    out = ''.join(c if 32 <= ord(c) != 127 else '\\x%02x' % ord(c) for c in text)
    if len(out) > MAX_DETAIL_CHARS:
        out = out[:MAX_DETAIL_CHARS - 13] + '…[truncated]'
    return out


def _redactor():
    try:
        from agent.redact import redact_sensitive_text
    except Exception:
        return None
    return redact_sensitive_text


def redacted(text, redactor=None):
    """Redact with Hermes, then escape and cap. Returns None when redaction is unavailable or fails."""
    if not isinstance(text, str):
        return None
    fn = redactor if redactor is not None else _redactor()
    if fn is None:
        return None
    try:
        clean = fn(text, force=True, redact_url_credentials=True)
    except Exception:
        return None
    return _escape(clean) if isinstance(clean, str) else None


def detail_fields(tool_name, args, level: str, redactor=None) -> dict:
    fields = {'tool_name': safe_tool_name(tool_name)}
    command = args.get('command') if isinstance(args, dict) else None
    if tool_name == 'terminal':
        fields['command_verb'] = command_verb(command)
    if level != 'commands':
        return fields
    if tool_name == 'terminal':
        value, key = command, 'command_redacted'
    else:
        value = next((args.get(k) for k in _TARGET_KEYS
                      if isinstance(args, dict) and isinstance(args.get(k), str)), None)
        key = 'target_redacted'
    if value is None:
        fields['audit_detail'] = 'commands'
        return fields
    clean = redacted(value, redactor)
    if clean is None:
        fields['audit_detail'] = 'unavailable'
    else:
        fields['audit_detail'] = 'commands'
        fields[key] = clean
    return fields
