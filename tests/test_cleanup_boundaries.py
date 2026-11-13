import contextlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import sentinel.replay as replay
import sentinel.replay_temp as temp


def marker_first(original):
    @contextlib.contextmanager
    def ordered(path):
        with original(path) as iterator:
            entries = sorted(iterator, key=lambda entry: entry.name != '.sentinel-replay-v1')
        yield iter(entries)
    return ordered


class CleanupBoundaryTests(unittest.TestCase):
    def boundary(self, mode, sig):
        with tempfile.TemporaryDirectory() as directory:
            control = Path(directory)
            env = dict(os.environ)
            package = str(Path(replay.__file__).resolve().parents[1])
            env['PYTHONPATH'] = package + os.pathsep + env.get('PYTHONPATH', '')
            run = subprocess.run([sys.executable, str(Path(__file__).with_name('cleanup_boundary_probe.py')),
                                  mode, directory, str(sig)], env=env, capture_output=True, timeout=6)
            ready = control / 'ready.json'
            scratch, worker = None, None
            if ready.exists():
                data = json.loads(ready.read_text())
                scratch = Path(data['scratch'])
                worker = data.get('worker')
            try:
                self.assertEqual(run.returncode, 128 + sig, run.stderr.decode())
                if mode == 'worker-stop':
                    self.assertTrue((control/'terminated').exists(), 'Signal interrupted worker termination')
                    self.assertTrue((control/'closed').exists(), 'Worker was not joined/closed')
                self.assertIsNotNone(scratch, run.stderr.decode())
                self.assertFalse(scratch.exists(), 'Signal interrupted snapshot removal')
            finally:
                if worker and not (control/'worker-finished').exists():
                    try:
                        os.kill(worker, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                if scratch and scratch.exists():
                    shutil.rmtree(scratch)

    def test_signal_during_removal_finishes_cleanup_before_exit(self):
        for stage in ('remove-entry', 'remove'):
            for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
                with self.subTest(stage=stage, signal=sig):
                    self.boundary(stage, sig)

    def test_signal_during_worker_shutdown_completes_shutdown(self):
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            with self.subTest(signal=sig):
                self.boundary('worker-stop', sig)

    def test_marker_is_removed_only_after_all_history(self):
        with tempfile.TemporaryDirectory() as directory:
            with temp.scratch_directory(Path(directory)) as path:
                (path/'history').write_bytes(b'SYNTHETIC_HISTORY')
                (path/'scaffold').mkdir()
                (path/'scaffold'/'data').touch()
                info = path.stat()
                unlink, scandir = os.unlink, os.scandir
                def checked(name, *args, **kwargs):
                    if Path(name).name == '.sentinel-replay-v1':
                        self.assertEqual(sorted(p.name for p in path.iterdir()), ['.sentinel-replay-v1'])
                    return unlink(name, *args, **kwargs)
                with patch.object(temp.os, 'scandir', marker_first(scandir)):
                    with patch.object(temp.os, 'unlink', checked):
                        temp.remove_scratch(path, (info.st_dev, info.st_ino))
                self.assertFalse(path.exists())

    def test_deletion_error_preserves_marker_and_signal_mask(self):
        with tempfile.TemporaryDirectory() as directory:
            with temp.scratch_directory(Path(directory)) as path:
                (path/'history').write_bytes(b'SYNTHETIC_HISTORY')
                info = path.stat()
                unlink, scandir = os.unlink, os.scandir
                before = signal.pthread_sigmask(signal.SIG_BLOCK, set())
                def failing(name, *args, **kwargs):
                    if Path(name).name == 'history':
                        raise OSError('synthetic deletion failure')
                    return unlink(name, *args, **kwargs)
                with patch.object(temp.os, 'scandir', marker_first(scandir)):
                    with patch.object(temp.os, 'unlink', failing):
                        with self.assertRaises(OSError):
                            temp.remove_scratch(path, (info.st_dev, info.st_ino))
                self.assertTrue((path/'.sentinel-replay-v1').exists())
                self.assertTrue((path/'history').exists())
                self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, set()), before)
