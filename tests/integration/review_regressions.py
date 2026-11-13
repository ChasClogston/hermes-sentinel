"""Real pinned-Hermes regression fixtures; use only a disposable HERMES_HOME."""
import hashlib
import json
import os
import sqlite3
import stat
import subprocess
import sys
import time
from pathlib import Path

from hermes_state import SessionDB

ROOT = Path(os.environ['HERMES_HOME'])
ROOT.mkdir(parents=True, exist_ok=True)
NOW = time.time()
CANARY = 'PRIVATE_REVIEW61_CANARY'


def tool(index, name='terminal', arguments=None, flat=False):
    function = {'name': name, 'arguments': json.dumps({'command': 'pytest'}) if arguments is None else arguments}
    return dict(id=str(index), type='function', **(function if flat else {'function': function}))


def add(db, session, count, **kwargs):
    for index in range(count):
        db.append_message(session, 'assistant', timestamp=NOW,
                          tool_calls=[tool(session + str(index))], **kwargs)


def fingerprint(home):
    if not home.exists():
        return None
    return {str(p.relative_to(home)): (stat.S_IMODE(p.stat().st_mode),
        hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None)
        for p in home.rglob('*')}


def replay(home, pending, blocked=0, outside=0):
    before = fingerprint(home)
    scratch = set(Path('/tmp').glob('sentinel-replay-*'))
    env = dict(os.environ, HERMES_HOME=str(home), TMPDIR=str(home / 'must-not-create'))
    result = subprocess.run([sys.executable, '-m', 'sentinel.cli', 'replay'],
                            env=env, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    for expected in (f'Approval candidates: {pending}\n', f'Blocked: {blocked}\n',
                     f'Outside window or undated: {outside}\n'):
        assert expected in result.stdout, (home.name, result.stdout)
    assert ('Selected retained history scanned.' if before is not None else 'Incomplete bounded sample.') in result.stdout, result.stdout
    assert 'Excludes rewound calls' in result.stdout
    for private in (CANARY, str(home), 'pytest', 'example.invalid'):
        assert private not in result.stdout + result.stderr, result.stdout
    assert before == fingerprint(home), f'Original profile changed: {home.name}'
    assert set(Path('/tmp').glob('sentinel-replay-*')) == scratch, 'Temporary snapshot residue'


def make(name):
    home = ROOT / name
    home.mkdir()
    return home, SessionDB(home / 'state.db')


def main():
    replay(ROOT / 'nonexistent-profile', 0)
    for archived in (False, True):
        home, db = make('archived-rotation' if archived else 'rotation')
        db.create_session('parent', 'cli')
        add(db, 'parent', 3)
        db.end_session('parent', 'compression')
        db.create_session('continuation', 'cli', parent_session_id='parent')
        add(db, 'continuation', 1)
        if archived:
            db.set_session_archived('parent', True, notify=False)
        db.close()
        replay(home, 4)

    home, db = make('delegates')
    db.create_session('parent', 'cli')
    add(db, 'parent', 1)
    db.create_session('delegate', 'subagent', parent_session_id='parent',
                      model_config={'_delegate_from': 'parent'})
    add(db, 'delegate', 2)
    db.close()
    replay(home, 3)

    home, db = make('hidden')
    db.create_session('visible', 'cli')
    db.create_session('hidden', 'cli')
    add(db, 'visible', 1)
    add(db, 'hidden', 2)
    db.set_session_hidden('hidden', True)
    db.close()
    replay(home, 3)

    home, db = make('children')
    db.create_session('parent', 'cli')
    add(db, 'parent', 1)
    for name, source, count in (('tool-child', 'tool', 2), ('plain-child', 'cli', 4)):
        db.create_session(name, source, parent_session_id='parent')
        add(db, name, count)
    db.close()
    replay(home, 7)

    home, db = make('rewound')
    db.create_session('rewound', 'cli')
    add(db, 'rewound', 3)
    db.close()
    with sqlite3.connect(home / 'state.db') as con:
        con.execute('UPDATE messages SET active=0, compacted=0 WHERE id IN (SELECT id FROM messages ORDER BY id LIMIT 2)')
    replay(home, 1)

    home, db = make('compaction')
    db.create_session('compacted', 'cli')
    add(db, 'compacted', 3)
    messages = db.get_messages('compacted')
    db.archive_and_compact('compacted', [dict(role='system', content='Synthetic summary'), messages[-1]], tail_count=1)
    db.close()
    replay(home, 3)

    home, db = make('argument-shapes')
    db.create_session('shapes', 'cli')
    calls = [tool('large', 'write_file', json.dumps({'content': CANARY * 5000})),
             tool('empty', arguments=''), tool('dictionary', arguments={'command': 'pytest'}),
             tool('array', arguments='["pytest"]'), tool('flat', flat=True)]
    db.append_message('shapes', 'assistant', timestamp=NOW, tool_calls=calls)
    db.close()
    replay(home, 2, 3)

    home, db = make('out-of-window')
    db.create_session('old', 'cli')
    add(db, 'old', 1)
    db.append_message('old', 'assistant', timestamp=NOW - 30 * 86400,
                      tool_calls=[tool(i) for i in range(2001)])
    db.close()
    replay(home, 1, outside=2001)

    home, db = make('plain-messages')
    db.create_session('chat', 'cli')
    db.append_message('chat', 'assistant', timestamp=NOW, tool_calls=[tool(i) for i in range(50)])
    for _ in range(2000):
        db.append_message('chat', 'user', content='Synthetic plain text', timestamp=NOW)
    db.close()
    replay(home, 50)

    # An open WAL source must retain its bytes and sidecar names unchanged.
    home, db = make('open-wal')
    db.create_session('wal', 'cli')
    add(db, 'wal', 2)
    db.close()
    # Some Hermes runtimes intentionally choose DELETE for their bundled SQLite.
    # Force WAL only on this synthetic fixture using one quiescent writer, so
    # source snapshot coverage does not depend on Hermes's platform preference.
    with sqlite3.connect(home / 'state.db') as writer:
        assert writer.execute('PRAGMA journal_mode=WAL').fetchone()[0] == 'wal'
        writer.execute('UPDATE messages SET content=?', (CANARY,))
        writer.commit()
        assert Path(str(home / 'state.db') + '-wal').exists()
        replay(home, 2)
    writer.close()

    env = dict(os.environ, HERMES_HOME=str(ROOT / 'invalid-days'))
    result = subprocess.run([sys.executable, '-m', 'sentinel.cli', 'replay', '--days', '0'],
                            env=env, capture_output=True, text=True)
    assert result.returncode == 2 and '1 to 3650' in result.stderr
    assert not (ROOT / 'invalid-days').exists()
    print('v0.6.1 real-Hermes regressions: session coverage, compaction deduplication, named rewind exclusion, argument shapes, budgets, WAL snapshots, profile immutability and cleanup passed.')


if __name__ == '__main__':
    main()
