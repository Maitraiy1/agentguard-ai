"""A trusted local tool runner that waits for a dashboard review before printing."""
from __future__ import annotations

import argparse
import json
import math
import sqlite3
import sys
import time
from collections.abc import Callable
from pathlib import Path

from .core import Action, Policy
from .engine import ApprovalError, Engine

DEMO_TEXT = "AgentGuard demo: your approval allowed this message to run."


def demo_action() -> Action:
    return Action("notes.publish", "notes/demo", "demo-agent", {"text": DEMO_TEXT})


def console_tool(action: Action) -> None:
    """A narrow, harmless stand-in for notes.publish; no shell, files or network."""
    if action.as_dict() != demo_action().as_dict():
        raise ValueError("The demo tool only accepts its fixed sample action")
    print(action.parameters["text"], flush=True)


def load_policy(path: Path) -> Policy:
    from .cli import load
    return Policy.from_dict(load(str(path)))


def wait_and_execute(engine: Engine, action: Action, request_id: str, *,
                     timeout: float = 300, interval: float = 0.5,
                     handler: Callable[[Action], None] = console_tool,
                     clock: Callable[[], float] = time.monotonic,
                     sleep: Callable[[float], None] = time.sleep,
                     current_policy: Callable[[], Policy] | None = None) -> str:
    """Observe a request, then let Engine atomically consume its exact approval.

    No retries or auto-approval. The configured policy is reloaded before every
    state check, including immediately before execution. The host remains trusted.
    """
    if (type(timeout) not in (int, float) or not math.isfinite(timeout)
            or not 0 < timeout <= 3600):
        raise ValueError("timeout must be greater than 0 and at most 3600 seconds")
    if (type(interval) not in (int, float) or not math.isfinite(interval)
            or not 0.05 <= interval <= 10):
        raise ValueError("interval must be between 0.05 and 10 seconds")
    deadline = clock() + timeout
    while True:
        if clock() >= deadline:
            return "timed out"
        if current_policy is not None and current_policy().digest != engine.policy.digest:
            raise ApprovalError("Policy changed; stop, reload the dashboard and create a new request")
        row = engine.inspect(request_id)
        if row["digest"] != action.digest or row["policy"] != engine.policy.digest:
            raise ApprovalError("Request does not match the action and policy")
        if row["status"] in ("denied", "revoked"):
            return row["status"]
        if not row.get("policy_current", True):
            raise ApprovalError("Request invalidated by policy activation or upgrade")
        if row["status"] == "consumed":
            return "already consumed"
        if engine.clock() >= row["expires"]:
            return "expired"
        if row["status"] == "approved":
            # The engine rechecks expiry, policy, reviewer and single-use status.
            # No side effect occurs unless its transaction commits successfully.
            if current_policy is not None and current_policy().digest != engine.policy.digest:
                raise ApprovalError("Policy changed before execution")
            engine.execute(action, handler, request_id=request_id)
            return "executed"
        if row["status"] != "pending":
            raise ApprovalError("Unexpected request state")
        sleep(min(interval, max(0.0, deadline - clock())))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Request dashboard approval, then print one demo message")
    parser.add_argument("--db", default=".agentguard/state.sqlite3")
    parser.add_argument("--policy", default="examples/policy.json")
    parser.add_argument("--reviewer", default="operator", help="Trusted reviewer allowlist identity")
    parser.add_argument("--ttl", type=int, default=300, help="Approval lifetime/wait in seconds (1–3600)")
    args = parser.parse_args(argv)
    try:
        if not 1 <= args.ttl <= 3600:
            raise ValueError("ttl must be between 1 and 3600 seconds")
        if not Path(args.db).parent.is_dir():
            raise ValueError("Set up and start the dashboard first; database directory is missing")
        policy_path = Path(args.policy)
        engine = Engine(args.db, load_policy(policy_path), reviewers={args.reviewer})
        action = demo_action()
        request_id = engine.request(action, ttl=args.ttl)
        print("Created request:", request_id, flush=True)
        print(json.dumps(action.as_dict(), indent=2), flush=True)
        print("Open the dashboard, refresh Requests and inspect this request ID.", flush=True)
        print(f"Waiting up to {args.ttl} seconds for your decision. No automatic approval.", flush=True)
        outcome = wait_and_execute(engine, action, request_id, timeout=args.ttl,
                                   current_policy=lambda: load_policy(policy_path))
        print("Result:", outcome, flush=True)
        if outcome == "executed":
            print("Refresh Audit history: execution_started and execution_succeeded are recorded.", flush=True)
            return 0
        print("This runner did not start the tool. Inspect audit history before retrying.", flush=True)
        return 2
    except KeyboardInterrupt:
        print("Runner stopped. Inspect audit history before retrying; the request may remain until expiry.",
              file=sys.stderr)
        return 130
    except (OSError, ValueError, TypeError, RecursionError, sqlite3.Error) as error:
        print(f"Demo error: {error}. Inspect audit history before retrying.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
