"""Bounded, read-only policy estimates over Hermes history; aggregate output only."""
from __future__ import annotations

import contextlib
from collections import deque
import json
import logging
import math
import multiprocessing
import os
import stat
import tempfile
import time
from pathlib import Path

from .engine import evaluate
from .hermes_adapter import normalize

MAX_CALLS = 2_000
MAX_MESSAGES = 20_000
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


def _parse_call(call) -> tuple[str, object] | None:
    if not isinstance(call, dict):
        return None
    function = call.get('function', call)
    if not isinstance(function, dict) or not isinstance(function.get('name'), str):
        return None
    name, args = function['name'], function.get('arguments', {})
    if not name:
        return None
    if isinstance(args, str):
        try:
            args = json.loads(args) if args else {}
        except ValueError:
            # A recognizable tool with undecodable arguments is unclassified,
            # just as missing arguments are at the live hook; never silently omit it.
            args = {}
    return name, args


def _scan(paths, policy, cutoff, now, emit, deadline) -> dict[str, int]:
    from hermes_state import SessionDB

    result = _empty()
    key = os.urandom(32)
    databases = []
    queue = deque()
    try:
        for path in paths:
            if time.monotonic() >= deadline:
                result['limited'] = 1
                break
            db = None
            try:
                if path.is_symlink() or not path.is_file():
                    raise ValueError('unavailable database')
                db = SessionDB(path, read_only=True)
                remaining = MAX_SESSIONS - result['sessions']
                sessions = db.list_sessions_rich(limit=remaining + 1,
                    order_by_last_active=True, include_archived=True,
                    include_children=True, include_hidden=True, include_subagents=True)
                if len(sessions) > remaining:
                    result['limited'] = 1
                selected = sessions[:remaining]
                result['sessions'] += len(selected)
                queue.extend((db, session['id'], 0) for session in selected)
                databases.append(db)
            except Exception:
                result['databases_skipped'] += 1
                if db is not None:
                    with contextlib.suppress(Exception):
                        db.close()
        # One page per session per round prevents a long/old session starving
        # all other selected sessions. Each physical session is read once;
        # ancestor expansion would count rotation parents multiple times.
        while queue:
            if time.monotonic() >= deadline:
                result['limited'] = 1
                return result
            db, session_id, offset = queue.popleft()
            try:
                messages = db.get_messages(session_id, latest=True,
                    limit=_PAGE_SIZE, offset=offset, include_compacted=True)
            except Exception:
                result['databases_skipped'] += 1
                continue
            if not messages:
                continue
            queue.append((db, session_id, offset + len(messages)))
            for message in reversed(messages):
                if result['messages'] >= MAX_MESSAGES:
                    result['limited'] = 1
                    return result
                result['messages'] += 1
                timestamp = message.get('timestamp')
                valid_time = (type(timestamp) in (int, float) and math.isfinite(timestamp)
                              and cutoff <= timestamp <= now)
                calls = message.get('tool_calls')
                if not isinstance(calls, list):
                    result['skipped'] += int(bool(calls))
                    calls = []
                for call in reversed(calls):
                    if time.monotonic() >= deadline:
                        result['limited'] = 1
                        return result
                    if not valid_time:
                        result['outside_window'] += 1
                        continue
                    # Only in-window calls consume the call budget. Look for an
                    # actual extra call before declaring an exact-boundary scan limited.
                    if result['examined'] >= MAX_CALLS:
                        result['limited'] = 1
                        return result
                    result['examined'] += 1
                    parsed = _parse_call(call)
                    if parsed is None:
                        result['skipped'] += 1
                    else:
                        tool, args = parsed
                        action = normalize(tool, args)
                        decision = evaluate(action, policy, key)
                        result[decision.verdict] += 1
                        result[action.operation] += 1
                        result['unclassified'] += int(decision.rule_id == 'default-deny')
                    emit(_snapshot(result))
            emit(_snapshot(result))
    finally:
        for db in databases:
            with contextlib.suppress(Exception):
                db.close()
        emit(_snapshot(result))
    return result


def _identity(path):
    try:
        value = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(value.st_mode):
        raise ValueError('unsafe database component')
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _copy_database(source, directory, deadline):
    # Copy without opening SQLite on the source. WAL is needed for committed
    # uncheckpointed rows; SHM is rebuilt only in the private snapshot directory.
    components = [source, Path(str(source) + '-wal'), Path(str(source) + '-journal')]
    before = [_identity(path) for path in components]
    if before[0] is None:
        raise ValueError('missing database')
    directory.mkdir(mode=0o700)
    destination = directory / 'state.db'
    for index, (path, expected) in enumerate(zip(components, before)):
        if expected is None:
            continue
        if time.monotonic() >= deadline:
            raise TimeoutError
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as original:
            value = os.fstat(original.fileno())
            observed = (value.st_dev, value.st_ino, value.st_size,
                        value.st_mtime_ns, value.st_ctime_ns)
            if not stat.S_ISREG(value.st_mode) or observed != expected:
                raise ValueError('changed database component')
            target = destination if index == 0 else Path(str(destination) + ('-wal' if index == 1 else '-journal'))
            with os.fdopen(os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as copy:
                while chunk := original.read(1024 * 1024):
                    if time.monotonic() >= deadline:
                        raise TimeoutError
                    copy.write(chunk)
    if before != [_identity(path) for path in components]:
        raise ValueError('database changed during snapshot')
    return destination


def _worker(paths, policy, cutoff, now, connection, deadline, scratch, skipped):
    # No provider/config initialization may discover the real home or credentials.
    # This runs before importing Hermes's history API in the spawned process.
    os.environ.clear()
    os.environ.update(HOME=str(scratch / 'home'), HERMES_HOME=str(scratch / 'hermes'),
                      TMPDIR=str(scratch), PATH='/usr/bin:/bin',
                      PYTHONDONTWRITEBYTECODE='1', HERMES_NO_AUTO_INSTALL='1')
    os.umask(0o077)
    with open(os.devnull, 'w') as null:
        os.dup2(null.fileno(), 1)
        os.dup2(null.fileno(), 2)
        logging.disable(logging.CRITICAL)
        result = _empty()
        snapshots = []
        try:
            for index, path in enumerate(paths):
                try:
                    snapshots.append(_copy_database(path, scratch / str(index), deadline))
                except TimeoutError:
                    result['limited'] = 1
                    break
                except Exception:
                    skipped += 1
            if not result['limited'] and snapshots:
                def emit(value):
                    counts = dict(zip(_FIELDS, value))
                    counts['databases_skipped'] += skipped
                    connection.send(_snapshot(counts))
                result = _scan(snapshots, policy, cutoff, now, emit, deadline)
        except Exception:
            skipped += len(snapshots) or 1
        result['databases_skipped'] += skipped
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
    usable = []
    for path in dict.fromkeys(map(Path, paths)):
        try:
            if _identity(path) is not None:
                usable.append(path)
            else:
                result['databases_skipped'] += 1
        except OSError:
            result['databases_skipped'] += 1
        except ValueError:
            result['databases_skipped'] += 1
    if not usable:
        result['finished'] = 1
        return result
    deadline = time.monotonic() + seconds
    context = multiprocessing.get_context('spawn')
    # Explicit /tmp avoids a caller's TMPDIR placing the copy inside a profile.
    # The parent owns cleanup so it also runs after a killed/timed-out worker.
    with tempfile.TemporaryDirectory(prefix='sentinel-replay-', dir='/tmp') as directory:
        scratch = Path(directory)
        reader, writer = context.Pipe(duplex=False)
        process = context.Process(target=_worker, args=(usable, policy,
            now - days * 86400, now, writer, deadline, scratch, result['databases_skipped']))
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
    lines.append('Incomplete bounded sample.' if not result['complete'] else 'Selected retained history scanned.')
    lines.append('Includes hidden, child, subagent, archived and rotated sessions; retained compaction history is deduplicated by Hermes.')
    lines.append('Excludes rewound calls and malformed data omitted by the Hermes API.')
    lines.append('Historical paths use the current filesystem; missing workdir uses the invocation directory.')
    return '\n'.join(lines)
