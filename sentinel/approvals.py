"""Single-use action-bound approval records. SQLite transaction serializes consumption."""
import secrets
import sqlite3
import time
from pathlib import Path

class ApprovalStore:
    def __init__(self, path: str):
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self._connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS approvals (id TEXT PRIMARY KEY, session TEXT NOT NULL, action_digest TEXT NOT NULL, policy_version TEXT NOT NULL, expires REAL NOT NULL, status TEXT NOT NULL)")
    def _connect(self):
        return sqlite3.connect(self.path, timeout=10, isolation_level=None)
    def request(self, session: str, digest: str, policy_version: str, ttl: int = 120) -> str:
        approval_id = secrets.token_urlsafe(24)
        with self._connect() as db:
            db.execute("INSERT INTO approvals VALUES (?,?,?,?,?,?)", (approval_id, session, digest, policy_version, time.time()+ttl, "pending"))
        return approval_id
    def authorize(self, approval_id: str) -> bool:
        with self._connect() as db:
            cur = db.execute("UPDATE approvals SET status='approved' WHERE id=? AND status='pending' AND expires>?", (approval_id, time.time()))
            return cur.rowcount == 1
    def consume(self, approval_id: str, session: str, digest: str, policy_version: str) -> bool:
        with self._connect() as db:
            cur = db.execute("UPDATE approvals SET status='consumed' WHERE id=? AND session=? AND action_digest=? AND policy_version=? AND status='approved' AND expires>?", (approval_id, session, digest, policy_version, time.time()))
            return cur.rowcount == 1
