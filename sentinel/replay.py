"""Bounded, read-only policy estimates over Hermes history; aggregate output only."""
from __future__ import annotations

import contextlib
import json
import logging
import math
import multiprocessing
import os
import time
from pathlib import Path

from .engine import evaluate
from .hermes_adapter import normalize

MAX_CALLS = 2_000
MAX_MESSAGES = 2_000
MAX_SESSIONS = 200
MAX_SECONDS = 2.0
_PAGE_SIZE = 32
_FIELDS = ('allowed', 'pending', 'blocked', 'unclassified', 'network_request',
           'network_upload', 'test_execution', 'unknown', 'skipped', 'outside_window',
           'examined', 'messages', 'sessions', 'databases_skipped', 'limited',
           'complete', 'finished')


def discover_databases(all_profiles: bool = False) -> list[Path]:
    from hermes_constants import get_hermes_home

    current = get_hermes_home().resolve()
    homes = [current]
    if all_profiles:
        from hermes_constants import get_default_hermes_root, named_profile_is_live

        root = get_default_hermes_root().resolve()
        homes.append(root)
        for home in sorted((root / 'profiles').glob('*')):
            if home.is_dir() and not home.is_symlink() and named_profile_is_live(home):
                homes.append(home.resolve())
    return [home / 'state.db' for home in dict.fromkeys(homes)]


def _empty() -> dict[str, int]:
    return dict.fromkeys(_FIELDS, 0)


def _snapshot(result: dict[str, int]) -> tuple[int, ...]:
    # Only fixed-position integers cross the worker boundary. No history or paths.
    return tuple(result[field] for field in _FIELDS)


def _parse_call(call) -> tuple[str, dict] | None:
    function = call.get('function') if isinstance(call, dict) else None
    if not isinstance(function, dict) or not isinstance(function.get('name'), str):
        return None
    raw = function.get('arguments')
    if not isinstance(raw, str) or len(raw) > 65_536:
        return None
    try:
        args = json.loads(raw)
    except (ValueError, TypeError):
        return None
    return (function['name'], args) if isinstance(args, dict) else None


def _scan(paths, policy, cutoff, now, emit, deadline) -> dict[str, int]:
    from hermes_state import SessionDB

    result = _empty()
    key = os.urandom(32)
    for path in paths:
        db = None
        try:
            if path.is_symlink() or not path.is_file():
                result['databases_skipped'] += 1
                continue
            db = SessionDB(path, read_only=True)
            remaining = MAX_SESSIONS - result['sessions']
            sessions = db.list_sessions_rich(limit=remaining, order_by_last_active=True)
            for session in sessions:
                result['sessions'] += 1
                offset = 0
                while True:
                    if time.monotonic() >= deadline:
                        result['limited'] = 1
                        return result
                    remaining = MAX_MESSAGES - result['messages']
                    messages = db.get_messages(session['id'], latest=True,
                                               limit=min(_PAGE_SIZE, remaining), offset=offset)
                    if not messages:
                        break
                    offset += len(messages)
                    for message in reversed(messages):
                        result['messages'] += 1
                        timestamp = message.get('timestamp')
                        valid_time = (type(timestamp) in (int, float) and math.isfinite(timestamp)
                                      and cutoff <= timestamp <= now)
                        calls = message.get('tool_calls')
                        if not isinstance(calls, list):
                            calls = []
                        for call in reversed(calls):
                            if time.monotonic() >= deadline:
                                result['limited'] = 1
                                return result
                            result['examined'] += 1
                            parsed = _parse_call(call) if valid_time else None
                            if not valid_time:
                                result['outside_window'] += 1
                            elif parsed is None:
                                result['skipped'] += 1
                            else:
                                tool, args = parsed
                                action = normalize(tool, args)
                                decision = evaluate(action, policy, key)
                                result[decision.verdict] += 1
                                result[action.operation] += 1
                                result['unclassified'] += int(decision.rule_id == 'default-deny')
                            emit(_snapshot(result))
                            if result['examined'] >= MAX_CALLS:
                                result['limited'] = 1
                                return result
                        if result['messages'] >= MAX_MESSAGES:
                            result['limited'] = 1
                            return result
                    emit(_snapshot(result))
                if result['sessions'] >= MAX_SESSIONS:
                    result['limited'] = 1
                    return result
        except Exception:
            # Database, JSON and policy errors must never include the original payload.
            result['databases_skipped'] += 1
        finally:
            if db is not None:
                with contextlib.suppress(Exception):
                    db.close()
            emit(_snapshot(result))
    return result


def _worker(paths, policy, cutoff, now, connection, deadline):
    # Hermes can log database paths or malformed stored messages. Keep all worker
    # diagnostics private and send only aggregate integers to the CLI process.
    with open(os.devnull, 'w') as null:
        os.dup2(null.fileno(), 1)
        os.dup2(null.fileno(), 2)
        logging.disable(logging.CRITICAL)
        try:
            result = _scan(paths, policy, cutoff, now, connection.send, deadline)
        except Exception:
            result = _empty()
            result['databases_skipped'] = len(paths)
        result['complete'] = int(not result['limited'] and not result['databases_skipped'])
        result['finished'] = 1
        try:
            connection.send(_snapshot(result))
        finally:
            connection.close()


def summarize_replay(paths, policy, days: int = 14, seconds: float = MAX_SECONDS,
                     now: float | None = None) -> dict[str, int]:
    if type(days) is not int or not 1 <= days <= 3650:
        raise ValueError('invalid replay window')
    if not 0 < seconds <= MAX_SECONDS:
        raise ValueError('invalid replay budget')
    now = time.time() if now is None else now
    result = _empty()
    deadline = time.monotonic() + seconds
    context = multiprocessing.get_context('spawn')
    reader, writer = context.Pipe(duplex=False)
    process = context.Process(target=_worker,
        args=(paths, policy, now - days * 86400, now, writer, deadline))
    try:
        process.start()
        writer.close()
        while time.monotonic() < deadline:
            if not reader.poll(max(0, deadline - time.monotonic())):
                break
            try:
                snapshot = reader.recv()
            except EOFError:
                break
            if (not isinstance(snapshot, tuple) or len(snapshot) != len(_FIELDS)
                    or any(type(value) is not int or value < 0 for value in snapshot)):
                raise ValueError('invalid replay result')
            result = dict(zip(_FIELDS, snapshot))
            if result['finished']:
                break
        if not result['finished']:
            result['limited'] = 1
    finally:
        writer.close()
        reader.close()
        if process.pid is not None:
            if process.is_alive():
                process.terminate()
            process.join(timeout=0.1)
            if process.is_alive():
                process.kill()
                process.join(timeout=0.1)
            process.close()
    return result


def display_replay(result: dict[str, int], days: int = 14) -> str:
    rows = [('Allowed', 'allowed'), ('Approval candidates', 'pending'),
            ('Blocked', 'blocked'), ('Of those, unclassified', 'unclassified'),
            ('Network requests', 'network_request'), ('Network uploads', 'network_upload'),
            ('Test executions', 'test_execution'), ('Unknown operations', 'unknown'),
            ('Malformed calls skipped', 'skipped'), ('Outside window or undated', 'outside_window'),
            ('Databases skipped', 'databases_skipped')]
    lines = ['SENTINEL GOVERNANCE // HISTORY REPLAY',
             f'Window: last {days} days.',
             'Estimated decisions under this policy in enforce mode.']
    lines.extend(f'{label}: {result[field]}' for label, field in rows)
    lines.append('Incomplete bounded sample.' if not result['complete'] else 'Selected history scan complete.')
    lines.append('Historical paths are evaluated against the current filesystem.')
    return '\n'.join(lines)
