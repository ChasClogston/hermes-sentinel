"""Private replay scratch ownership, leases, and scoped CLI signal handling."""
from __future__ import annotations

import contextlib
import fcntl
import os
from pathlib import Path
import shutil
import signal
import stat
import sys
import tempfile
import threading
import time

_PREFIX = 'sentinel-replay-'
_MARKER = '.sentinel-replay-v1'
_CONTENT = b'sentinel-governance-replay-v1\n'
_STALE_SECONDS = 60
_TERMINATION_SIGNALS = {signal.SIGINT, signal.SIGTERM, signal.SIGHUP}


def temp_root(paths):
    """Use the macOS system private root or stable /tmp; ignore env temp roots."""
    excluded = [Path.home().resolve(), *(Path(p).parent.resolve() for p in paths)]
    candidates = []
    if sys.platform == 'darwin':
        with contextlib.suppress(ValueError, OSError):
            candidates.append(os.confstr('CS_DARWIN_USER_TEMP_DIR'))
    for raw in candidates:
        if not raw:
            continue
        with contextlib.suppress(OSError):
            path = Path(raw).resolve(strict=True)
            info = path.stat()
            if (stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                    and not info.st_mode & 0o077
                    and not any(path.is_relative_to(home) for home in excluded)):
                return path
    # Caller-controlled TMPDIR may be inside a profile. Each scratch directory
    # under the fallback shared root is still private, with owner-only files.
    if any(Path('/tmp').resolve().is_relative_to(home) for home in excluded):
        raise ValueError('no temporary root outside home and profiles')
    return Path('/tmp')


@contextlib.contextmanager
def cleanup_signals():
    """Finish destructive cleanup before delivering ordinary pending signals."""
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, _TERMINATION_SIGNALS)
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def remove_scratch(path, identity):
    """Remove this invocation's exact private directory, ownership marker last."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700
            or (info.st_dev, info.st_ino) != identity):
        return
    with cleanup_signals():
        try:
            directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return
        try:
            current = os.fstat(directory)
            if ((current.st_dev, current.st_ino) != identity
                    or current.st_uid != os.getuid()
                    or stat.S_IMODE(current.st_mode) != 0o700):
                return
            # Work relative to the verified directory descriptor. Never follow
            # child symlinks, and leave the marker if any data removal fails.
            with os.scandir(directory) as entries:
                for entry in entries:
                    if entry.name == _MARKER:
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        shutil.rmtree(entry.name, dir_fd=directory)
                    else:
                        os.unlink(entry.name, dir_fd=directory)
            with contextlib.suppress(FileNotFoundError):
                os.unlink(_MARKER, dir_fd=directory)
            with contextlib.suppress(FileNotFoundError):
                value = path.lstat()
                if (value.st_dev, value.st_ino) == identity:
                    path.rmdir()
        finally:
            os.close(directory)


@contextlib.contextmanager
def lease(path, exclusive=False):
    """Shared leases in parent and worker exclude startup sweeping of live work."""
    directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    marker = None
    try:
        info = os.fstat(directory)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('unsafe replay directory')
        marker = os.open(_MARKER, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        value = os.fstat(marker)
        if (not stat.S_ISREG(value.st_mode) or value.st_uid != os.getuid()
                or stat.S_IMODE(value.st_mode) != 0o600 or value.st_nlink != 1
                or os.read(marker, len(_CONTENT) + 1) != _CONTENT):
            raise ValueError('invalid replay ownership marker')
        fcntl.flock(marker, (fcntl.LOCK_EX | fcntl.LOCK_NB) if exclusive else fcntl.LOCK_SH)
        yield (info.st_dev, info.st_ino), marker
    finally:
        if marker is not None:
            os.close(marker)
        os.close(directory)


def sweep_stale(root):
    """Best effort; never sweep a fresh, unmarked, unsafe, or leased directory."""
    for path in root.glob(_PREFIX + '*'):
        try:
            info = path.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o700
                    or time.time() - info.st_mtime <= _STALE_SECONDS):
                continue
            with lease(path, exclusive=True) as (identity, _):
                # Ownership/age can change between enumeration and locking.
                if time.time() - path.lstat().st_mtime > _STALE_SECONDS:
                    remove_scratch(path, identity)
        except (OSError, ValueError):
            continue


@contextlib.contextmanager
def scratch_directory(root):
    path = Path(tempfile.mkdtemp(prefix=_PREFIX, dir=root))
    info = path.lstat()
    identity = (info.st_dev, info.st_ino)
    try:
        path.chmod(0o700)
        fd = os.open(path / _MARKER, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as out:
            os.fchmod(out.fileno(), 0o600)
            out.write(_CONTENT)
            out.flush()
            os.fsync(out.fileno())
        directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        with lease(path):
            yield path
    finally:
        remove_scratch(path, identity)


@contextlib.contextmanager
def termination_handlers():
    if threading.current_thread() is not threading.main_thread():
        raise ValueError('history replay requires the main thread')
    previous = {}
    requested = None
    def stop(signum, frame):
        nonlocal requested
        # Never inject an asynchronous exception into a finally block. The
        # parent observes this request, cleans up, then exits with signal status.
        if requested is None:
            requested = signum
    try:
        for sig in _TERMINATION_SIGNALS:
            previous[sig] = signal.signal(sig, stop)
        yield lambda: requested is not None
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        if requested is not None:
            raise SystemExit(128 + requested)
