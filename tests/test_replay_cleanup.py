import fcntl
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel.replay import summarize_replay
from test_replay import FakeDB
import test_replay as replay_tests
from replay_process_probe import probe_environment, run_signal_case


class ReplayCleanupTests(unittest.TestCase):
    def signal_case(self, signum):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'state.db'
            with source.open('wb') as file:
                file.write(b'PRIVATE_SIGNAL_CANARY')
                file.truncate(32 * 1024 * 1024)
            run_signal_case(root / 'control', source, signum)
            self.assertEqual(source.stat().st_size, 32 * 1024 * 1024)

    def test_sigterm_removes_snapshot(self):
        self.signal_case(signal.SIGTERM)

    def test_sighup_removes_snapshot(self):
        self.signal_case(signal.SIGHUP)

    def test_parent_sigkill_stops_orphan_and_removes_snapshot(self):
        self.signal_case(signal.SIGKILL)

    def scenario(self, name, files=1):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = []
            for index in range(files):
                path = root / f'{index}.db'
                path.write_bytes(b'SYNTHETIC_HISTORY')
                paths.append(str(path))
            run = subprocess.run([sys.executable, str(Path(__file__).with_name('replay_process_probe.py')),
                                  name, str(root), *paths], capture_output=True, timeout=10, env=probe_environment())
            self.assertEqual(run.returncode, 0, run.stderr.decode())
            return json.loads((root / 'result.json').read_text()), int((root / 'attempts').read_text())

    def test_later_copy_timeout_preserves_first_database_counts(self):
        result, _ = self.scenario('second-timeout', 2)
        self.assertEqual(result['pending'], 1)
        self.assertEqual(result['limited'], 1)
        self.assertEqual(result['databases_skipped'], 0)
        self.assertEqual(result['complete'], 0)

    def test_source_changed_once_retries_and_counts(self):
        result, attempts = self.scenario('retry-once')
        self.assertEqual(result['pending'], 1)
        self.assertEqual(attempts, 2)
        self.assertEqual(result['complete'], 1)

    def test_persistent_source_change_is_skipped_after_one_retry(self):
        result, attempts = self.scenario('retry-always')
        self.assertEqual(attempts, 2)
        self.assertEqual(result['pending'], 0)
        self.assertEqual(result['databases_skipped'], 1)
        self.assertEqual(result['complete'], 0)

    def test_stale_sweep_preserves_fresh_active_unmarked_and_symlinked_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            directories = {}
            for label in ('stale', 'fresh', 'active', 'unmarked', 'unsafe'):
                path = root / ('sentinel-replay-' + label)
                path.mkdir(mode=0o700)
                (path / 'history').write_bytes(b'SYNTHETIC_PRIVATE_HISTORY')
                if label != 'unmarked':
                    marker = path / '.sentinel-replay-v1'
                    marker.write_bytes(b'sentinel-governance-replay-v1\n')
                    marker.chmod(0o600)
                if label != 'fresh':
                    os.utime(path, (time.time() - 120, time.time() - 120))
                if label == 'unsafe':
                    path.chmod(0o755)
                directories[label] = path
            (root / 'sentinel-replay-link').symlink_to(directories['unmarked'], target_is_directory=True)
            with (directories['active'] / '.sentinel-replay-v1').open('rb') as lock:
                fcntl.flock(lock, fcntl.LOCK_SH)
                with patch('sentinel.replay._temp_root', return_value=root, create=True):
                    summarize_replay([root / 'missing.db'], {'rules': []})
            self.assertFalse(directories['stale'].exists())
            for label in ('fresh', 'active', 'unmarked', 'unsafe'):
                self.assertTrue(directories[label].exists(), label)
            self.assertTrue((root / 'sentinel-replay-link').is_symlink())

    def test_exclusively_leased_stale_snapshot_does_not_block_startup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / 'sentinel-replay-active'
            active.mkdir(mode=0o700)
            marker = active / '.sentinel-replay-v1'
            marker.write_bytes(b'sentinel-governance-replay-v1\n')
            marker.chmod(0o600)
            os.utime(active, (time.time()-120, time.time()-120))
            with marker.open('rb') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                try:
                    result = subprocess.run([sys.executable, str(Path(__file__).with_name('replay_process_probe.py')),
                        'sweep', str(root)], capture_output=True, timeout=2, env=probe_environment())
                except subprocess.TimeoutExpired:
                    self.fail('Startup blocked on another replay lease')
            self.assertEqual(result.returncode, 0)
            self.assertTrue(active.exists())

    def test_signal_handlers_are_restored(self):
        before = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
        summarize_replay([], {'rules': []})
        self.assertEqual(before, {sig: signal.getsignal(sig) for sig in before})

    def test_parent_killed_before_copy_still_triggers_worker_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'state.db'
            source.write_bytes(b'SYNTHETIC_HISTORY')
            run_signal_case(root / 'control', source, signal.SIGKILL, scenario='before-copy')

    def test_global_call_budget_is_not_reset_for_each_database(self):
        result, attempts = self.scenario('global-budget', 3)
        self.assertEqual(result['pending'], 1)
        self.assertEqual(result['examined'], 1)
        self.assertEqual(result['limited'], 1)
        self.assertEqual(attempts, 2)

    def test_linux_temp_root_ignores_xdg_and_tmpdir(self):
        from sentinel.replay_temp import temp_root
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home, runtime, profile = root/'home', root/'runtime', root/'profile'
            for path in (home, runtime, profile):
                path.mkdir(mode=0o700)
            with patch('sentinel.replay_temp.sys.platform', 'linux'):
                with patch.dict(os.environ, HOME=str(home), XDG_RUNTIME_DIR=str(runtime), TMPDIR=str(runtime)):
                    self.assertEqual(temp_root([profile/'state.db']), Path('/tmp'))
                with patch.dict(os.environ, HOME=str(home), XDG_RUNTIME_DIR='', TMPDIR=''):
                    self.assertEqual(temp_root([profile/'state.db']), Path('/tmp'))

    def test_macos_uses_system_private_temp_not_environment(self):
        from sentinel.replay_temp import temp_root
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home, system, runtime, profile = (root/name for name in ('home','system','runtime','profile'))
            for path in (home,system,runtime,profile):
                path.mkdir(mode=0o700)
            with patch('sentinel.replay_temp.sys.platform', 'darwin'):
                with patch('sentinel.replay_temp.os.confstr', return_value=str(system)):
                    with patch.dict(os.environ, HOME=str(home), XDG_RUNTIME_DIR=str(runtime), TMPDIR=str(runtime)):
                        self.assertEqual(temp_root([profile/'state.db']), system.resolve())

    def test_non_main_thread_replay_is_rejected_before_creating_files(self):
        import threading
        errors = []
        def run():
            try:
                summarize_replay([], {'rules': []})
            except ValueError:
                errors.append('rejected')
        thread = threading.Thread(target=run)
        thread.start()
        thread.join(timeout=2)
        self.assertEqual(errors, ['rejected'])

    def test_private_scratch_is_usable_with_a_restrictive_umask(self):
        from sentinel.replay_temp import scratch_directory
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous = os.umask(0o777)
            try:
                try:
                    with scratch_directory(root) as scratch:
                        self.assertEqual(scratch.stat().st_mode & 0o777, 0o700)
                        (scratch / 'history').touch()
                except OSError:
                    self.fail('Private scratch could not be used with restrictive umask')
            finally:
                os.umask(previous)
                for path in root.glob('sentinel-replay-*'):
                    path.chmod(0o700)
            self.assertEqual(list(root.iterdir()), [])

    def test_stale_age_is_rechecked_after_ownership_lease(self):
        import sentinel.replay_temp as temp
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot = root / 'sentinel-replay-refreshed'
            snapshot.mkdir(mode=0o700)
            marker = snapshot / '.sentinel-replay-v1'
            marker.write_bytes(b'sentinel-governance-replay-v1\n')
            marker.chmod(0o600)
            os.utime(snapshot, (time.time()-120, time.time()-120))
            original = temp.lease
            def refreshed(path, **kwargs):
                os.utime(path, None)
                return original(path, **kwargs)
            with patch('sentinel.replay._temp_root', return_value=root):
                with patch.object(temp, 'lease', side_effect=refreshed):
                    summarize_replay([], {'rules': []})
            self.assertTrue(snapshot.exists())

    def test_shared_temp_fallback_cannot_be_inside_selected_profile(self):
        from sentinel.replay_temp import temp_root
        with patch('sentinel.replay_temp.sys.platform', 'linux'):
            with patch.dict(os.environ, XDG_RUNTIME_DIR=''):
                with self.assertRaises(ValueError):
                    temp_root([Path('/tmp/state.db')])


class ReplayErrorCountingTests(unittest.TestCase):
    setUp = replay_tests.ReplayTests.setUp
    scan = replay_tests.ReplayTests.scan
    def test_multiple_failing_pages_count_one_database(self):
        FakeDB.sessions = [{'id': str(index)} for index in range(3)]
        with patch.object(FakeDB, 'get_messages', side_effect=ValueError('synthetic read failure')):
            result = self.scan([])
        self.assertEqual(result['databases_skipped'], 1)
