"""Signal real replay copies of synthetic Hermes history on both supported OSes."""
import hashlib
import os
import signal
import sqlite3
import sys
from pathlib import Path
import unittest

from hermes_state import SessionDB

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from replay_process_probe import run_signal_case
from test_replay_cleanup import ReplayCleanupTests, ReplayErrorCountingTests


def main():
    home = Path(os.environ['HERMES_HOME'])
    home.mkdir(parents=True, exist_ok=True)
    assert not (home / 'state.db').exists(), 'Use a new disposable Hermes home'
    source = home / 'state.db'
    db = SessionDB(source)
    db.create_session('signal-fixture', 'cli')
    db.append_message('signal-fixture', 'user', content='PRIVATE_SIGNAL_CANARY')
    db.close()
    with sqlite3.connect(source) as connection:
        connection.execute('CREATE TABLE signal_fixture_padding (content BLOB)')
        connection.execute('INSERT INTO signal_fixture_padding VALUES (zeroblob(?))', (32*1024*1024,))
    connection.close()
    def fingerprint():
        return {str(p.relative_to(home)): (p.stat().st_mode & 0o777,
            hashlib.sha256(p.read_bytes()).digest() if p.is_file() else None)
            for p in home.rglob('*')}
    before = fingerprint()
    controls = home.parent / (home.name + '-controls')
    controls.mkdir()
    for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGKILL):
        run_signal_case(controls / str(sig), source, sig)
    run_signal_case(controls / 'early-kill', source,
                    signal.SIGKILL, scenario='before-copy')
    assert before == fingerprint(), 'Original Hermes profile changed'
    names = ('test_later_copy_timeout_preserves_first_database_counts',
             'test_source_changed_once_retries_and_counts',
             'test_persistent_source_change_is_skipped_after_one_retry',
             'test_stale_sweep_preserves_fresh_active_unmarked_and_symlinked_directories',
             'test_exclusively_leased_stale_snapshot_does_not_block_startup',
             'test_global_call_budget_is_not_reset_for_each_database',
             'test_stale_age_is_rechecked_after_ownership_lease')
    suite = unittest.TestSuite(ReplayCleanupTests(name) for name in names)
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(ReplayErrorCountingTests))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    assert result.wasSuccessful(), 'Replay lifetime regression failed'
    print('Replay cleanup: SIGTERM/SIGHUP, parent SIGKILL during/before copy, source integrity, leased stale sweep, partial counts, global budgets and one-change retry passed.')


if __name__ == '__main__':
    main()
