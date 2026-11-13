import os
import stat
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel.replay import _copy_database, _identity, _temp_root, summarize_replay


def writing_worker(*args):
    (args[-2] / 'raw-history').write_text('SYNTHETIC_PRIVATE_CANARY')
    time.sleep(30)


class SnapshotTests(unittest.TestCase):
    def test_owner_only_snapshot_and_source_untouched(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            source = root / 'state.db'
            source.write_bytes(b'SYNTHETIC_PRIVATE_CANARY')
            wal = Path(str(source) + '-wal')
            wal.write_bytes(b'SYNTHETIC_WAL')
            before = (_identity(source), _identity(wal))
            target = _copy_database(source, root / 'private', time.monotonic() + 2)
            self.assertEqual(source.read_bytes(), target.read_bytes())
            self.assertEqual(wal.read_bytes(), Path(str(target) + '-wal').read_bytes())
            self.assertEqual(stat.S_IMODE(target.parent.stat().st_mode), 0o700)
            for path in target.parent.iterdir():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(before, (_identity(source), _identity(wal)))

    def test_concurrent_changes_and_symlink_sidecars_are_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            source = root / 'state.db'
            source.write_bytes(b'SYNTHETIC_HISTORY')
            identity = _identity(source)
            changed = (*identity[:-1], identity[-1] + 1)
            with patch('sentinel.replay._identity', side_effect=[identity, None, None, changed, None, None]):
                with self.assertRaises(ValueError):
                    _copy_database(source, root / 'changed', time.monotonic() + 2)
            Path(str(source) + '-wal').symlink_to(source)
            with self.assertRaises(ValueError):
                _copy_database(source, root / 'symlinked', time.monotonic() + 2)

    def test_missing_profile_never_starts_reader_or_creates_files(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / 'missing' / 'state.db'
            with patch('sentinel.replay._worker') as worker:
                result = summarize_replay([source], {'rules': []})
            worker.assert_not_called()
            self.assertFalse(source.parent.exists())
            self.assertEqual(result['databases_skipped'], 1)
            self.assertEqual(result['complete'], 0)

    def test_timeout_cleans_raw_snapshot_owned_by_parent(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / 'state.db'
            source.touch()
            temp = _temp_root([source])
            before = set(temp.glob('sentinel-replay-*'))
            with patch('sentinel.replay._worker', writing_worker):
                result = summarize_replay([source], {'rules': []}, seconds=0.4)
            self.assertEqual(result['limited'], 1)
            self.assertEqual(list(Path(root).iterdir()), [source])
        self.assertEqual(set(temp.glob('sentinel-replay-*')), before)
