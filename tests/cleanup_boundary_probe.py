"""Inject ordinary signals at real deletion/worker-stop boundaries."""
import functools
import json
import multiprocessing.process
import os
from pathlib import Path
import signal
import sys
import time
from unittest.mock import patch

import sentinel.replay as replay
import sentinel.replay_temp as temp
from replay_process_probe import ready_info


def shutdown_worker(*args, control, start_delay=0):
    """Keep a known synthetic snapshot live until parent shutdown stops us."""
    control = Path(control)
    time.sleep(start_delay)
    scratch = Path(args[-2])
    (scratch / 'synthetic-worker-history').write_bytes(b'SYNTHETIC_HISTORY')
    ready_info(control, scratch)
    try:
        time.sleep(30)
    finally:
        (control / 'worker-finished').touch()


def main():
    mode, directory, value = sys.argv[1:]
    control, sig = Path(directory), int(value)
    sent = False
    def interrupt():
        nonlocal sent
        if not sent:
            sent = True
            os.kill(os.getpid(), sig)
    if mode in ('remove', 'remove-entry'):
        owner = temp.shutil if mode == 'remove' else temp
        target = 'rmtree' if mode == 'remove' else 'remove_scratch'
        original = getattr(owner, target)
        def remove(*args, **kwargs):
            interrupt()
            return original(*args, **kwargs)
        with patch.object(owner, target, remove):
            with temp.termination_handlers():
                with temp.scratch_directory(control) as path:
                    (control / 'ready.json').write_text(json.dumps({'scratch': str(path)}))
                    (path / 'scaffold').mkdir()
                    (path / 'scaffold' / 'history').write_bytes(b'SYNTHETIC_HISTORY')
    elif mode in ('worker-stop', 'worker-stop-slow-start'):
        source = control / 'state.db'
        with source.open('wb') as file:
            file.write(b'SYNTHETIC_HISTORY')
            file.truncate(32 * 1024 * 1024)
        process = multiprocessing.process.BaseProcess
        start, terminate, close = process.start, process.terminate, process.close
        def started(self):
            start(self)
            # Synchronize the fixture, not production replay: shutdown must
            # begin with a known live worker/snapshot, even on a loaded runner.
            deadline = time.monotonic() + 4
            while not (control / 'ready.json').exists():
                if not self.is_alive() or time.monotonic() >= deadline:
                    raise RuntimeError('cleanup probe worker never became ready')
                time.sleep(0.01)
        def terminate_with_signal(self):
            interrupt()
            terminate(self)
            (control / 'terminated').touch()
        def closed(self):
            close(self)
            (control / 'closed').touch()
        with patch.object(process, 'start', started), patch.object(process, 'terminate', terminate_with_signal):
            with patch.object(process, 'close', closed):
                delay = 0.6 if mode == 'worker-stop-slow-start' else 0
                with patch.object(replay, '_worker', functools.partial(shutdown_worker,
                                  control=str(control), start_delay=delay)):
                    replay.summarize_replay([source], {'rules': []}, seconds=0.4)


if __name__ == '__main__':
    main()
