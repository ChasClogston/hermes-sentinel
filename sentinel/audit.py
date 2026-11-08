"""Strict allowlisted audit event serialization. No raw targets or arguments."""
import fcntl
import json
import os
from datetime import datetime, timezone
from pathlib import Path

FIELDS = frozenset({"event_id", "action_id", "session_id", "profile_id", "tool_name", "operation", "target_hmac_sha256", "verdict", "policy_id", "reason_code", "approval_id", "execution_status", "enforcement_mode", "tool_call_id", "classification", "policy_verdict"})
VERDICTS = frozenset({"allowed", "blocked", "pending", "approved", "denied", "unclassified"})

def append_event(path: str, event: dict) -> None:
    if not set(event).issubset(FIELDS):
        raise ValueError("audit schema rejected unsupported field")
    if event.get("verdict") not in VERDICTS:
        raise ValueError("audit schema rejected verdict")
    if not all(isinstance(v, str) or v is None for v in event.values()):
        raise ValueError("audit schema rejected field type")
    # Cap strings and reject control chars; tool arguments are not accepted as fields.
    if any(len(v)>128 or any(ord(c)<32 for c in v) for v in event.values() if isinstance(v,str)):
        raise ValueError("audit schema rejected field content")
    record = {"schema_version":"1.0", "timestamp":datetime.now(timezone.utc).isoformat(), **event}
    parent = Path(path).parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_APPEND|getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        if not os.path.isfile(path) or os.fstat(fd).st_nlink != 1:
            raise ValueError("unsafe audit journal target")
        os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        os.write(fd, (json.dumps(record, sort_keys=True, separators=(",", ":"))+"\n").encode())
        os.fsync(fd)
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
