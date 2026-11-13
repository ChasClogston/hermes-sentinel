"""Inject ordinary signals at real deletion/worker-stop boundaries."""
import functools
import json
import multiprocessing.process
import os
from pathlib import Path
import signal
import sys
from unittest.mock import patch

import sentinel.replay as replay
import sentinel.replay_temp as temp
from replay_process_probe import probe_worker


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
    elif mode == 'worker-stop':
        source = control / 'state.db'
        with source.open('wb') as file:
            file.write(b'SYNTHETIC_HISTORY')
            file.truncate(32 * 1024 * 1024)
        process = multiprocessing.process.BaseProcess
        terminate, close = process.terminate, process.close
        def terminate_with_signal(self):
            interrupt()
            terminate(self)
            (control / 'terminated').touch()
        def closed(self):
            close(self)
            (control / 'closed').touch()
        with patch.object(process, 'terminate', terminate_with_signal):
            with patch.object(process, 'close', closed):
                with patch.object(replay, '_worker', functools.partial(probe_worker,
                                  control=str(control), scenario='signals')):
                    replay.summarize_replay([source], {'rules': []}, seconds=0.4)


if __name__ == '__main__':
    main()
