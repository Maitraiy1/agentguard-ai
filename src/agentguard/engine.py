"""SQLite-backed approval state machine. The host owns authentication and tools."""
from __future__ import annotations

import json
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator, TypeVar

from .core import Action, Decision, Policy, canonical, label

T = TypeVar("T")


class ApprovalError(PermissionError):
    """An action or state transition was rejected."""


class Engine:
    def __init__(self, database: str | Path, policy: Policy, *,
                 reviewers: set[str] | frozenset[str],
                 clock: Callable[[], float] = time.time):
        self.database = str(database)
        if self.database == ":memory:":
            raise ValueError("Use a file database; connections are transaction-scoped")
        self.policy = policy
        self.reviewers = frozenset(label(r, "reviewer") for r in reviewers)
        self.clock = clock
        with self._transaction() as db:
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, 1):
                raise ValueError("Unsupported database schema version")
            schema = """
                CREATE TABLE IF NOT EXISTS requests (
                    id TEXT PRIMARY KEY, action TEXT NOT NULL, digest TEXT NOT NULL,
                    policy TEXT NOT NULL, expires REAL NOT NULL,
                    status TEXT NOT NULL CHECK(status IN
                        ('pending','approved','denied','consumed')),
                    reviewer TEXT
                );
                CREATE TABLE IF NOT EXISTS audit (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL, event TEXT NOT NULL,
                    request_id TEXT, actor TEXT NOT NULL, digest TEXT NOT NULL
                );
            """
            for statement in schema.split(";"):
                if statement.strip():
                    db.execute(statement)
            db.execute("PRAGMA user_version=1")

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.database, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def _audit(self, db: sqlite3.Connection, event: str, actor: str,
               digest: str, request_id: str | None = None) -> None:
        db.execute("INSERT INTO audit(timestamp,event,request_id,actor,digest) VALUES(?,?,?,?,?)",
                   (self.clock(), event, request_id, actor, digest))

    def request(self, action: Action, *, ttl: int = 300) -> str:
        if type(ttl) is not int or not 1 <= ttl <= 3600:
            raise ValueError("ttl must be an integer between 1 and 3600 seconds")
        if self.policy.evaluate(action) != Decision.APPROVAL:
            raise ApprovalError("Policy does not permit an approval request")
        request_id = secrets.token_urlsafe(32)
        with self._transaction() as db:
            db.execute("INSERT INTO requests(id,action,digest,policy,expires,status,reviewer) VALUES(?,?,?,?,?,?,?)",
                       (request_id, canonical(action.as_dict()), action.digest,
                        self.policy.digest, self.clock() + ttl, "pending", None))
            self._audit(db, "requested", action.principal, action.digest, request_id)
        return request_id

    def _active(self, db: sqlite3.Connection, request_id: str) -> sqlite3.Row:
        row = db.execute("SELECT * FROM requests WHERE id=?", (request_id,)).fetchone()
        if row is None:
            raise ApprovalError("Unknown approval request")
        if self.clock() >= row["expires"]:
            raise ApprovalError("Approval request expired")
        if row["policy"] != self.policy.digest:
            raise ApprovalError("Policy changed; create a new request")
        return row

    def review(self, request_id: str, *, reviewer: str, approve: bool) -> None:
        if reviewer not in self.reviewers:
            raise ApprovalError("Reviewer is not authorized")
        if type(approve) is not bool:
            raise ValueError("approve must be a boolean")
        with self._transaction() as db:
            row = self._active(db, request_id)
            if row["status"] != "pending":
                raise ApprovalError("Only pending requests can be reviewed")
            action = Action.from_dict(json.loads(row["action"]))
            if reviewer == action.principal:
                raise ApprovalError("Self-approval is forbidden")
            status = "approved" if approve else "denied"
            db.execute("UPDATE requests SET status=?, reviewer=? WHERE id=?",
                       (status, reviewer, request_id))
            self._audit(db, status, reviewer, row["digest"], request_id)

    def execute(self, action: Action, handler: Callable[[Action], T], *,
                request_id: str | None = None) -> T:
        """Consume permission durably before invoking a trusted, synchronous handler.

        A crash or handler failure burns the approval. No automatic retries.
        """
        decision = self.policy.evaluate(action)
        if decision == Decision.DENY:
            with self._transaction() as db:
                self._audit(db, "blocked", action.principal, action.digest, request_id)
            raise ApprovalError("Action denied by policy")
        with self._transaction() as db:
            if decision == Decision.APPROVAL:
                if request_id is None:
                    raise ApprovalError("Approval is required")
                row = self._active(db, request_id)
                if row["status"] != "approved" or row["digest"] != action.digest:
                    raise ApprovalError("Approval is not valid for this exact action")
                if row["reviewer"] not in self.reviewers:
                    raise ApprovalError("Reviewer authorization was revoked")
                db.execute("UPDATE requests SET status='consumed' WHERE id=?", (request_id,))
            elif request_id is not None:
                raise ApprovalError("Unexpected approval ID for an allowed action")
            self._audit(db, "execution_started", action.principal, action.digest, request_id)
        try:
            result = handler(action)
        except BaseException:
            with self._transaction() as db:
                self._audit(db, "execution_failed", action.principal, action.digest, request_id)
            raise
        with self._transaction() as db:
            self._audit(db, "execution_succeeded", action.principal, action.digest, request_id)
        return result

    def inspect(self, request_id: str) -> dict[str, Any]:
        with self._transaction() as db:
            row = db.execute("SELECT * FROM requests WHERE id=?", (request_id,)).fetchone()
            if row is None:
                raise ApprovalError("Unknown approval request")
            result = dict(row)
            result["action"] = json.loads(result["action"])
            return result

    def audit(self, *, limit: int = 100) -> list[dict[str, Any]]:
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        with self._transaction() as db:
            return [dict(row) for row in db.execute(
                "SELECT * FROM audit ORDER BY sequence DESC LIMIT ?", (limit,))]
