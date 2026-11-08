"""Strict, contextual source validation and safe approval summaries.

Only regular, non-hidden files inside an explicit or current working directory
are eligible for upload approval. Never follow an untrusted path in the UI.
Not an OS sandbox: content can be sensitive even when a filename is ordinary.
"""
from __future__ import annotations
import os
import re
from pathlib import Path
from urllib.parse import urlsplit

_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SAFE_SEG = re.compile(r"^[A-Za-z0-9_.-]{1,24}$")
_SENSITIVE = {"config.yaml","state.db",".zsh_history",".bash_history",
              "login.keychain-db",".netrc",".npmrc",".pgpass","auth.json",
              "credentials.json","id_rsa","id_ecdsa","id_dsa","id_ed25519"}
_PRIVATE = {".ssh",".aws",".kube",".docker",".gnupg","keychains","keyrings",".hermes"}
_SECRET_HINT = re.compile(r"(secret|token|credential|key|password|auth|history|AKIA)", re.I)


def safe_source(raw: str, workdir: str | None) -> tuple[str, str]:
    """Return (classification, safe UI filename); no raw path in output."""
    if not isinstance(raw,str) or not raw or "\x00" in raw or raw.startswith(("-", "@")):
        return "credential_file", "[rejected]"
    if Path(raw).is_absolute() or raw.startswith("~"):
        return "credential_file", "[outside workspace]"
    try:
        base = Path(workdir if isinstance(workdir,str) and workdir else os.getcwd()).resolve(strict=True)
        candidate = base / raw
        # Reject symlinked inputs even if the resolved destination is benign.
        if candidate.is_symlink() or any((base / part).is_symlink() for part in candidate.relative_to(base).parents if part != Path('.')):
            return "credential_file", "[symlink]"
        target = candidate.resolve(strict=True)
        rel = target.relative_to(base)
        if (not base.is_dir() or not target.is_file()
                or any(x.startswith(".") for x in rel.parts)
                or any(x.lower() in _PRIVATE for x in (*base.parts, *target.parts))
                or any(x.lower() in _SENSITIVE for x in rel.parts)
                or _SECRET_HINT.search(raw) or _SECRET_HINT.search(target.name)):
            return "credential_file", "[protected]"
        # Allow ordinary single-file relative paths, not nested paths or hidden files.
        if len(rel.parts)!=1 or not _SAFE_NAME.fullmatch(target.name):
            return "credential_file", "[protected]"
        return "workspace_file", target.name
    except (OSError, ValueError, RuntimeError):
        return "credential_file", "[unresolved]"


def safe_url_path(uri: str) -> tuple[bool,str]:
    """Show short, unambiguous paths. Never copy arbitrary URLs into UI."""
    try:
        p=urlsplit(uri)
        if p.query or p.fragment:
            return False,"[redacted]"
        path=p.path or "/"
        if len(path)>80 or _SECRET_HINT.search(path):
            return False,"[redacted]"
        if path=="/":
            return True,"/"
        if any(x in (".", "..") or not _SAFE_SEG.fullmatch(x) for x in path.strip("/").split("/")):
            return False,"[redacted]"
        return True,path
    except ValueError:
        return False,"[redacted]"
