"""Profile-scoped settings and descriptor-verified custom policy reads."""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import stat
import hermes_yaml as yaml
from .config import load_policy, validate_policy

_BUNDLED = Path(__file__).resolve().parent.parent / 'policies' / 'default.yaml'


def current_home() -> Path:
    try:
        from hermes_constants import get_hermes_home
        return Path(get_hermes_home())
    except ImportError:
        return Path(os.environ.get('HERMES_HOME', str(Path.home() / '.hermes')))


def read_profile_setting(home: Path, key: str, default=None):
    """CLI-only read: never invoke configuration code that creates a profile."""
    try:
        with (home / 'config.yaml').open(encoding='utf-8') as stream:
            config = yaml.safe_load(stream)
    except FileNotFoundError:
        return default
    if config is None:
        return default
    if not isinstance(config, dict):
        raise ValueError('invalid profile configuration')
    node = config
    for name in ('plugins', 'entries', 'sentinel-governance'):
        node = node.get(name, {})
        if not isinstance(node, dict):
            raise ValueError('invalid plugin configuration')
    for name in ('settings', 'config'):
        subtree = node.get(name, {})
        if not isinstance(subtree, dict):
            raise ValueError('invalid plugin settings')
        if key in subtree:
            return subtree[key]
    return default


def _custom_policy(home: Path, raw) -> dict:
    if not isinstance(raw, str) or not raw or '\x00' in raw:
        raise ValueError('invalid policy path')
    lexical_home = home.absolute()
    home = home.resolve(strict=True)
    path = Path(raw)
    # Reject traversal rather than normalizing across potentially symlinked parents.
    if '..' in path.parts:
        raise ValueError('policy path escapes profile')
    if path.is_absolute():
        for root in (lexical_home, home):
            try:
                path = path.relative_to(root)
                break
            except ValueError:
                continue
        else:
            raise ValueError('policy path escapes profile') from None
    if not path.parts:
        raise ValueError('policy must be a regular file')
    directory = os.open(home, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    file_fd = None
    try:
        if os.fstat(directory).st_mode & 0o022:
            raise ValueError('unsafe profile directory permissions')
        for part in path.parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
            if os.fstat(directory).st_mode & 0o022:
                raise ValueError('unsafe policy directory permissions')
        file_fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        info = os.fstat(file_fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022
                or info.st_uid not in {os.getuid(), 0} or info.st_nlink != 1):
            raise ValueError('unsafe policy file')
        with os.fdopen(file_fd, encoding='utf-8') as stream:
            file_fd = None
            try:
                parsed = yaml.safe_load(stream)
            except Exception:
                raise ValueError('unparsable profile policy') from None
            return validate_policy(parsed)
    finally:
        if file_fd is not None:
            os.close(file_fd)
        os.close(directory)


@dataclass(frozen=True)
class ProfileSettings:
    home: Path
    mode: str
    mode_source: str
    policy_path: object

    @property
    def policy_source(self) -> str:
        return 'bundled' if self.policy_path is None else 'profile'

    def load_policy(self) -> dict:
        return load_policy(_BUNDLED) if self.policy_path is None else _custom_policy(self.home, self.policy_path)


def resolve_settings(home: Path, getter=None, environ=None) -> ProfileSettings:
    """Selected environment override can tighten settings, never loosen them."""
    if getter is None:
        getter = lambda key, default=None: read_profile_setting(home, key, default)
    environ = os.environ if environ is None else environ
    setting = getter('mode', None)
    env = environ.get('SENTINEL_GOVERNANCE_MODE', environ.get('HERMES_SENTINEL_MODE'))
    selected = [value for value in (setting, env) if value is not None]
    if any(not isinstance(value, str) or value.strip().lower() not in {'audit', 'enforce'} for value in selected):
        raise ValueError('invalid Sentinel mode')
    mode = 'enforce' if any(value.strip().lower() == 'enforce' for value in selected) else 'audit'
    source = ('settings+environment' if setting is not None and env is not None else
              'settings' if setting is not None else 'environment' if env is not None else 'default')
    return ProfileSettings(Path(home), mode, source, getter('policy_path', None))
