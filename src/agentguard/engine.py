"""SQLite-backed approval state machine. The host owns authentication and tools."""
from __future__ import annotations

import json
import hashlib
import math
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
            if version not in (0, 1, 2):
                raise ValueError("Unsupported database schema version")
            schema = """
                CREATE TABLE IF NOT EXISTS requests (
                    id TEXT PRIMARY KEY, action TEXT NOT NULL, digest TEXT NOT NULL,
                    policy TEXT NOT NULL, expires REAL NOT NULL,
                    status TEXT NOT NULL CHECK(status IN
                        ('pending','approved','denied','consumed')),
                    reviewer TEXT, generation INTEGER NOT NULL DEFAULT 0
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
            columns = {row["name"] for row in db.execute("PRAGMA table_info(requests)")}
            if "generation" not in columns:
                db.execute("ALTER TABLE requests ADD COLUMN generation INTEGER NOT NULL DEFAULT 0")
            db.execute("CREATE TABLE IF NOT EXISTS revocations (request_id TEXT PRIMARY KEY, actor TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS policy_state (id INTEGER PRIMARY KEY CHECK(id=1), digest TEXT NOT NULL, generation INTEGER NOT NULL)")
            db.execute("INSERT OR IGNORE INTO policy_state VALUES(1,?,1)", (self.policy.digest,))
            db.execute("PRAGMA user_version=2")
            if version == 1:
                self._audit(db, "schema_migrated", "system", self.policy.digest)

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
        # Prefix prevents random leading hyphens from being parsed as CLI flags.
        request_id = "req_" + secrets.token_urlsafe(32)
        with self._transaction() as db:
            generation = self._current(db)
            db.execute("INSERT INTO requests(id,action,digest,policy,expires,status,reviewer,generation) VALUES(?,?,?,?,?,?,?,?)",
                       (request_id, canonical(action.as_dict()), action.digest,
                        self.policy.digest, self.clock() + ttl, "pending", None, generation))
            self._audit(db, "requested", action.principal, action.digest, request_id)
        return request_id

    def _active(self, db: sqlite3.Connection, request_id: str) -> sqlite3.Row:
        generation = self._current(db)
        row = db.execute("SELECT * FROM requests WHERE id=?", (request_id,)).fetchone()
        if row is None:
            raise ApprovalError("Unknown approval request")
        if db.execute("SELECT 1 FROM revocations WHERE request_id=?", (request_id,)).fetchone():
            raise ApprovalError("Approval request revoked")
        if row["generation"] != generation:
            raise ApprovalError("Approval invalidated by policy activation or upgrade")
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
            self._current(db)
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
            return self._decorate(db, result)

    def audit(self, *, limit: int = 100) -> list[dict[str, Any]]:
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        with self._transaction() as db:
            return [dict(row) for row in db.execute(
                "SELECT * FROM audit ORDER BY sequence DESC LIMIT ?", (limit,))]

    def list_requests(self, *, limit: int = 100) -> list[dict[str, Any]]:
        """Return newest requests for trusted reviewer interfaces; payloads are sensitive."""
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        with self._transaction() as db:
            rows = db.execute("SELECT * FROM requests ORDER BY rowid DESC LIMIT ?", (limit,))
            results = []
            for row in rows:
                item = dict(row)
                results.append(self._decorate(db, item))
            return results

    def _current(self, db: sqlite3.Connection) -> int:
        row = db.execute("SELECT digest,generation FROM policy_state WHERE id=1").fetchone()
        if row is None or row["digest"] != self.policy.digest:
            raise ApprovalError("Worker policy is not active; restart workers with the active policy")
        return row["generation"]

    def _decorate(self, db: sqlite3.Connection, result: dict[str, Any]) -> dict[str, Any]:
        result["action"] = json.loads(result["action"])
        state = db.execute("SELECT digest,generation FROM policy_state WHERE id=1").fetchone()
        result["policy_current"] = (state["digest"] == self.policy.digest == result["policy"]
                                    and state["generation"] == result["generation"])
        if db.execute("SELECT 1 FROM revocations WHERE request_id=?", (result["id"],)).fetchone():
            result["status"] = "revoked"
        return result

    def activate_policy(self, *, actor: str) -> int:
        """Privileged local administration: activate policy and invalidate all old approvals.

        The host must authenticate/authorize this operation. Never expose it to agents.
        Every activation increments the durable generation, even for identical content.
        """
        label(actor, "actor")
        with self._transaction() as db:
            db.execute("UPDATE policy_state SET digest=?,generation=generation+1 WHERE id=1", (self.policy.digest,))
            generation = self._current(db)
            self._audit(db, "policy_activated", actor, self.policy.digest)
            return generation

    def revoke(self, request_id: str, *, reviewer: str) -> None:
        if reviewer not in self.reviewers:
            raise ApprovalError("Reviewer is not authorized")
        with self._transaction() as db:
            self._current(db)
            row = db.execute("SELECT * FROM requests WHERE id=?", (request_id,)).fetchone()
            if row is None or row["status"] not in ("pending", "approved"):
                raise ApprovalError("Only pending or approved requests can be revoked")
            if db.execute("SELECT 1 FROM revocations WHERE request_id=?", (request_id,)).fetchone():
                raise ApprovalError("Request is already revoked")
            db.execute("INSERT INTO revocations VALUES(?,?)", (request_id, reviewer))
            self._audit(db, "revoked", reviewer, row["digest"], request_id)

    def prune(self, *, before: float, actor: str, apply: bool = False,
              audit_before: float | None = None) -> dict[str, int]:
        """Preview or delete old terminal/expired requests and optionally old audit events.

        Privileged local maintenance; export/backup first. Pending live requests are retained.
        """
        label(actor, "actor")
        if type(apply) is not bool:
            raise ValueError("apply must be a boolean")
        if before is None:
            raise ValueError("before is required")
        for cutoff in (before, audit_before):
            if cutoff is not None and (type(cutoff) not in (float, int) or not math.isfinite(cutoff)
                                      or cutoff < 0 or cutoff > self.clock()):
                raise ValueError("Cutoffs must be finite past Unix timestamps")
        condition = "expires < ? AND (status IN ('denied','consumed') OR expires <= ? OR id IN (SELECT request_id FROM revocations))"
        with self._transaction() as db:
            self._current(db)
            args = (before, self.clock())
            requests = db.execute("SELECT COUNT(*) FROM requests WHERE " + condition, args).fetchone()[0]
            audit = 0 if audit_before is None else db.execute("SELECT COUNT(*) FROM audit WHERE timestamp < ?", (audit_before,)).fetchone()[0]
            counts = {"requests": requests, "audit": audit}
            if apply:
                db.execute("DELETE FROM revocations WHERE request_id IN (SELECT id FROM requests WHERE " + condition + ")", args)
                db.execute("DELETE FROM requests WHERE " + condition, args)
                if audit_before is not None:
                    db.execute("DELETE FROM audit WHERE timestamp < ?", (audit_before,))
                digest = hashlib.sha256(canonical(counts).encode()).hexdigest()
                self._audit(db, "retention_applied", actor, digest)
            return counts
