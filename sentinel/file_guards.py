"""Pre-rule protections for known Hermes host file tools, without reading content."""
from __future__ import annotations
from pathlib import Path
import re
import stat

_READ = {'read_file', 'search_files'}
_WRITE = {'write_file', 'patch'}
_SENSITIVE = {'.env', '.netrc', '.npmrc', '.pgpass', 'config.yaml', 'config.yml',
              'credentials.json', 'auth.json', 'hosts.yml', 'state.db',
              'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519', 'login.keychain-db'}
_PRIVATE = {'.ssh', '.aws', '.kube', '.docker', '.gnupg', '.hermes', 'keychains', 'keyrings'}
_HINT = re.compile(r'secret|credential|token|password|auth', re.I)
_SINGLE = re.compile(r'^\*\*\*\s*(?:Update|Add|Delete)\s+File:\s*(.+)$')
_MOVE = re.compile(r'^\*\*\*\s*Move\s+File:\s*(.+?)\s*->\s*(.+)$')


def context(home=None, policy_path=None):
    if home is None:
        from .settings import current_home
        home = current_home()
    return {'profile_home': str(home), 'policy_path': policy_path}


def _paths(tool, args):
    if not isinstance(args, dict):
        raise ValueError('invalid file arguments')
    paths = []
    if tool == 'patch' and args.get('mode', 'replace') == 'patch':
        text = args.get('patch')
        if not isinstance(text, str) or not text or len(text) > 1_048_576:
            raise ValueError('unrecognized patch')
        for line in (value.removesuffix('\r') for value in text.split('\n')):
            single, move = _SINGLE.fullmatch(line), _MOVE.fullmatch(line)
            if single:
                paths.append(single.group(1).strip())
            elif move:
                paths.extend(value.strip() for value in move.groups())
            elif line.lstrip().startswith('***') and line not in ('*** Begin Patch', '*** End Patch', '*** End of File'):
                raise ValueError('unrecognized patch header')
        if args.get('path') is not None:
            paths.append(args['path'])
    else:
        if tool == 'patch' and args.get('mode', 'replace') != 'replace':
            raise ValueError('unrecognized patch mode')
        paths.append(args.get('path'))
    if not paths:
        raise ValueError('missing file target')
    return paths


def _sensitive(path):
    for part in path.parts:
        name = part.lower()
        if (name in _PRIVATE or name in _SENSITIVE or name.startswith('.env.')
                or name.endswith(('.pem', '.key', '.p12', '.pfx')) or _HINT.search(name)):
            return True
    return False


def _protected(path, targets):
    # Conservative case folding also protects not-yet-created names on common
    # case-insensitive Mac volumes. Inodes catch existing Unicode/path aliases.
    value = str(path).casefold()
    identities = set()
    for target in targets:
        name = str(target).casefold()
        if value == name or value.startswith(name + '/'):
            return True
        try:
            info = target.stat()
            identities.add((info.st_dev, info.st_ino))
        except FileNotFoundError:
            pass
    for ancestor in (path, *path.parents):
        try:
            info = ancestor.stat()
            if (info.st_dev, info.st_ino) in identities:
                return True
        except FileNotFoundError:
            pass
    return False


def file_restriction(tool, args, profile_home=None, policy_path=None):
    """Opaque pre-rule veto; require absolute host paths instead of guessing task cwd."""
    if tool not in _READ | _WRITE:
        return None
    try:
        if profile_home is None:
            from .settings import current_home
            profile_home = current_home()
        home = Path(profile_home).resolve()
        plugin = Path(__file__).resolve().parent.parent
        policy = Path(policy_path) if isinstance(policy_path, str) else None
        if policy is not None and not policy.is_absolute():
            policy = home / policy
        protected = [home / 'config.yaml', home / 'sentinel', plugin,
                     home / 'plugins' / 'sentinel-governance']
        if policy is not None:
            protected.append(policy.resolve())
        for raw in _paths(tool, args):
            if not isinstance(raw, str) or not raw or not raw.isprintable() or not Path(raw).is_absolute():
                return 'ambiguous-file-target'
            path = Path(raw)
            if '..' in path.parts:
                return 'ambiguous-file-target'
            for item in (path, *path.parents):
                if item.is_symlink():
                    return 'ambiguous-file-target'
            resolved = path.resolve()
            try:
                info = path.stat()
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    return 'ambiguous-file-target'
            except FileNotFoundError:
                pass
            if tool in _WRITE and _protected(resolved, protected):
                return 'governance-file-protected'
            if _sensitive(path) or _sensitive(resolved):
                return 'credential-file-protected'
        return None
    except (OSError, ValueError, RuntimeError):
        return 'ambiguous-file-target'
