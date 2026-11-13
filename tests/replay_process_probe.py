"""Subprocess fixtures for real replay lifetime/copy behavior; synthetic inputs only."""
import functools
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import patch

import sentinel.replay as replay


def probe_environment():
    # Preserve the package selected by the calling test (including a historical
    # source for regression checks), even without an editable installation.
    env = dict(os.environ)
    package = str(Path(replay.__file__).resolve().parents[1])
    env['PYTHONPATH'] = package + os.pathsep + env.get('PYTHONPATH', '')
    return env


class Reader:
    def __init__(self, stream, callback):
        self.stream, self.callback = stream, callback
    def __enter__(self):
        self.stream.__enter__()
        return self
    def __exit__(self, *args):
        return self.stream.__exit__(*args)
    def __getattr__(self, name):
        return getattr(self.stream, name)
    def read(self, size=-1):
        result = self.stream.read(size)
        self.callback()
        return result


def ready_info(control, scratch):
    temporary = control / 'ready.tmp'
    temporary.write_text(json.dumps({'scratch': str(scratch), 'worker': os.getpid()}))
    temporary.replace(control / 'ready.json')


def probe_worker(*args, control, scenario):
    control = Path(control)
    if scenario != 'signals':
        import types
        from test_replay import FakeDB, call
        FakeDB.messages = [{'timestamp': time.time() - 1, 'tool_calls': [call('pytest')]}]
        sys.modules['hermes_state'] = types.SimpleNamespace(SessionDB=FakeDB)
    if scenario == 'global-budget':
        replay.MAX_CALLS = 1
    if scenario == 'before-copy':
        ready_info(control, args[-2])
        time.sleep(0.2)
    real_copy, real_fdopen = replay._copy_database, os.fdopen
    attempts = 0

    def copy(source, directory, deadline, *extra, **kwargs):
        nonlocal attempts
        attempts += 1
        (control / 'attempts').write_text(str(attempts))
        if scenario == 'second-timeout' and attempts == 2:
            raise TimeoutError
        touched = False
        def on_read():
            nonlocal touched
            if scenario == 'signals':
                ready = control / 'ready.json'
                if not ready.exists():
                    ready_info(control, directory.parent)
                time.sleep(0.06)
            elif scenario in ('retry-once', 'retry-always') and not touched:
                touched = True
                if attempts == 1 or scenario == 'retry-always':
                    value = source.stat()
                    os.utime(source, ns=(value.st_atime_ns, value.st_mtime_ns + 1_000_000))
        def fdopen(fd, mode='r', *a, **k):
            stream = real_fdopen(fd, mode, *a, **k)
            return Reader(stream, on_read) if mode == 'rb' else stream
        with patch.object(replay.os, 'fdopen', fdopen):
            return real_copy(source, directory, deadline, *extra, **kwargs)

    try:
        with patch.object(replay, '_copy_database', copy):
            replay._worker(*args)
    finally:
        (control / 'worker-finished').touch()


def run_signal_case(control, source, signum, scenario='signals'):
    """Signal the parent during actual copying; verify cleanup and worker stop."""
    control.mkdir()
    process = subprocess.Popen([sys.executable, __file__, scenario, str(control), str(source)],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=probe_environment())
    scratch, worker = None, None
    try:
        ready = control / 'ready.json'
        end = time.monotonic() + 10
        while not ready.exists() and time.monotonic() < end and process.poll() is None:
            time.sleep(0.01)
        assert ready.exists(), 'Replay did not reach copying'
        data = json.loads(ready.read_text())
        scratch, worker = Path(data['scratch']), data['worker']
        process.send_signal(signum)
        stdout, stderr = process.communicate(timeout=5)
        end = time.monotonic() + 5
        while scratch.exists() and time.monotonic() < end:
            time.sleep(0.02)
        assert not scratch.exists(), f'Snapshot remained after signal {signum}'
        assert b'PRIVATE_SIGNAL_CANARY' not in stdout + stderr
        if signum == signal.SIGKILL:
            assert (control / 'worker-finished').exists(), 'Orphaned worker did not stop'
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        if worker:
            try:
                os.kill(worker, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if scratch and scratch.exists():
            import shutil
            shutil.rmtree(scratch)


def main():
    scenario, control, *paths = sys.argv[1:]
    control = Path(control)
    policy = {'rules': [{'id': 'approve-tests', 'effect': 'require_approval',
                         'operations': ['test_execution']}]}
    if scenario == 'sweep':
        with patch.object(replay, '_temp_root', return_value=control, create=True):
            result = replay.summarize_replay([control / 'missing.db'], policy)
    else:
        with patch.object(replay, '_worker', functools.partial(probe_worker, control=str(control), scenario=scenario)):
            result = replay.summarize_replay(list(map(Path, paths)), policy)
    (control / 'result.json').write_text(json.dumps(result))


if __name__ == '__main__':
    main()
