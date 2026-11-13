"""Profile settings cannot silently loosen enforcement or select unsafe policy files."""
import contextlib
import io
import json
import os
import tempfile
import unittest
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from sentinel.settings import resolve_settings, read_profile_setting
from sentinel.hermes_adapter import SentinelHook


class SettingsTests(unittest.TestCase):
    def resolve(self, home, setting=None, env=None, path=None):
        values = {'mode': setting, 'policy_path': path}
        return resolve_settings(home, lambda key, default=None: values.get(key, default), env or {})

    def test_mode_precedence_and_provenance(self):
        cases = [(None, None, 'audit', 'default'),
                 ('enforce', None, 'enforce', 'settings'),
                 (None, 'enforce', 'enforce', 'environment'),
                 ('audit', 'enforce', 'enforce', 'settings+environment'),
                 ('enforce', 'audit', 'enforce', 'settings+environment'),
                 ('audit', 'audit', 'audit', 'settings+environment'),
                 ('enforce', 'enforce', 'enforce', 'settings+environment')]
        for setting, env, mode, source in cases:
            with self.subTest(setting=setting, env=env):
                binding = self.resolve(Path('/unused'), setting,
                    {} if env is None else {'SENTINEL_GOVERNANCE_MODE': env})
                self.assertEqual((binding.mode, binding.mode_source), (mode, source))
        self.assertEqual(self.resolve(Path('/unused'), env={'HERMES_SENTINEL_MODE': 'enforce'}).mode, 'enforce')
        self.assertEqual(self.resolve(Path('/unused'), env={'HERMES_SENTINEL_MODE': 'bad',
                         'SENTINEL_GOVERNANCE_MODE': 'audit'}).mode, 'audit')

    def test_invalid_modes_fail_closed(self):
        for bad in ('', 'bad', False, 1, [], {}):
            for field in ('settings', 'environment'):
                with self.subTest(bad=bad, field=field), self.assertRaises(ValueError):
                    self.resolve(Path('/unused'), bad if field == 'settings' else 'audit',
                        {'SENTINEL_GOVERNANCE_MODE': bad} if field == 'environment' else {})

    def test_policy_paths_and_mode_failure_behavior(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); home = root/'profile'; home.mkdir()
            good = home/'policy.json'; good.write_text('{"version":1,"rules":[]}'); good.chmod(0o600)
            outside = root/'outside.json'; outside.write_text(good.read_text())
            (home/'link').symlink_to(good)
            (home/'parent').symlink_to(home, target_is_directory=True)
            bad = home/'bad'; bad.write_text('not: [valid'); bad.chmod(0o600)
            writable = home/'writable'; writable.write_text(good.read_text()); writable.chmod(0o620)
            fifo = home/'fifo'; os.mkfifo(fifo)
            paths = [None, 'policy.json', str(good), 'link', 'parent/policy.json',
                     str(outside), '../outside.json', 'writable', 'bad', 'fifo', '.', '', 7]
            for mode in ('audit', 'enforce'):
                for path in paths:
                    with self.subTest(mode=mode, path=path):
                        binding = self.resolve(home, mode, path=path)
                        valid = path in (None, 'policy.json', str(good))
                        if valid:
                            self.assertEqual(binding.load_policy()['version'], 1)
                        else:
                            with self.assertRaises((ValueError, OSError)):
                                binding.load_policy()
                        hook = SentinelHook('', str(home/'audit.jsonl'), b'x'*32,
                                            binding_resolver=lambda: binding)
                        result = hook('unlisted', {'PRIVATE_CANARY': d})
                        self.assertEqual(result is None, mode == 'audit')
                        if result: self.assertNotIn(d, str(result))

    def test_binding_is_read_per_call_without_mutating_other_profiles(self):
        with tempfile.TemporaryDirectory() as d:
            home = Path(d); values = {'mode': 'audit'}
            def resolver():
                return resolve_settings(home, lambda k, default=None: values.get(k, default), {})
            hook = SentinelHook('', str(home/'audit.jsonl'), b'x'*32, binding_resolver=resolver)
            self.assertIsNone(hook('unlisted', {}))
            values['mode'] = 'enforce'
            self.assertEqual(hook('unlisted', {})['action'], 'block')
            values['mode'] = 'bad'
            self.assertEqual(hook('unlisted', {})['action'], 'block')
            values['mode'] = 'audit'
            self.assertIsNone(hook('unlisted', {}))

    def test_readonly_cli_settings_and_report(self):
        from sentinel.cli import main
        with tempfile.TemporaryDirectory() as d:
            home = Path(d)/'missing'
            self.assertIsNone(read_profile_setting(home, 'mode'))
            self.assertFalse(home.exists())
            home.mkdir()
            (home/'config.yaml').write_text('plugins:\n  entries:\n    sentinel-governance:\n      settings:\n        mode: enforce\n        policy_path: PRIVATE_PATH\n')
            self.assertEqual(read_profile_setting(home, 'mode'), 'enforce')
            with patch('sentinel.settings.current_home', return_value=home), patch.dict(os.environ, {}, clear=True):
                out = io.StringIO()
                with contextlib.redirect_stdout(out): self.assertEqual(main(['report']), 0)
            self.assertIn('Effective mode: enforce', out.getvalue())
            self.assertIn('Mode source: settings', out.getvalue())
            self.assertIn('Policy source: profile', out.getvalue())
            self.assertNotIn('PRIVATE_PATH', out.getvalue())
            self.assertFalse((home/'sentinel').exists())

    def test_concurrent_profile_modes_do_not_leak(self):
        with tempfile.TemporaryDirectory() as d:
            home = Path(d)
            local = threading.local(); barrier = threading.Barrier(2)
            def resolver():
                binding = self.resolve(home, local.mode)
                barrier.wait(timeout=3)
                return binding
            hook = SentinelHook('', str(home/'audit.jsonl'), b'x'*32, binding_resolver=resolver)
            def run(mode):
                local.mode = mode
                return [hook('unlisted', {}) for _ in range(10)]
            with ThreadPoolExecutor(max_workers=2) as pool:
                audit = pool.submit(run, 'audit'); enforce = pool.submit(run, 'enforce')
                self.assertEqual(audit.result(), [None]*10)
                self.assertTrue(all(value['action']=='block' for value in enforce.result()))

    def test_registered_hook_resolves_profile_policy_and_journal_together(self):
        import importlib.util
        import sys
        name = 'settings_registration_test'
        root = Path(__file__).resolve().parents[1]
        spec = importlib.util.spec_from_file_location(name, root/'__init__.py', submodule_search_locations=[str(root)])
        module = importlib.util.module_from_spec(spec); sys.modules[name] = module
        try:
            spec.loader.exec_module(module)
            with tempfile.TemporaryDirectory() as d:
                a = Path(d)/'a'; b = Path(d)/'b'; a.mkdir(); b.mkdir(); active = [a]
                for home, mode in ((a,'audit'),(b,'enforce')):
                    (home/'config.yaml').write_text(json.dumps({'plugins':{'entries':{'sentinel-governance':{'settings':{'mode':mode}}}}}))
                class Ctx:
                    def get_config(self, key, default=None):
                        return read_profile_setting(active[0], key, default)
                    def register_hook(self, name, handler): self.handler = handler
                ctx = Ctx()
                import importlib
                settings_module = importlib.import_module(name+'.sentinel.settings')
                with patch.object(settings_module, 'current_home', side_effect=lambda: active[0]), \
                     patch.dict(os.environ, {}, clear=True):
                    module.register(ctx)
                    self.assertIsNone(ctx.handler('unlisted', {}))
                    active[0] = b
                    self.assertEqual(ctx.handler('unlisted', {})['action'], 'block')
                    self.assertEqual(json.loads((a/'sentinel/audit.jsonl').read_text())['enforcement_mode'], 'audit')
                    self.assertEqual(json.loads((b/'sentinel/audit.jsonl').read_text())['enforcement_mode'], 'enforce')
        finally:
            for key in list(sys.modules):
                if key == name or key.startswith(name+'.'): sys.modules.pop(key, None)
