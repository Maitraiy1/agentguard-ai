"""Local trusted-operator CLI; deliberately exposes no shell execution endpoint."""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

from .core import Action, Policy, strict_json
from .engine import Engine


def load(path: str):
    with Path(path).open(encoding="utf-8") as stream:
        return strict_json(stream.read(65537))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AgentGuard local policy and approval CLI")
    parser.add_argument("--db", default=".agentguard/state.sqlite3")
    parser.add_argument("--policy", default="examples/policy.json")
    parser.add_argument("--reviewer", action="append", default=[],
                        help="Trusted reviewer identity; repeat as needed (not authentication)")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="Create private local state directory")
    check = commands.add_parser("check")
    check.add_argument("action")
    request = commands.add_parser("request")
    request.add_argument("action")
    request.add_argument("--ttl", type=int, default=300)
    inspect = commands.add_parser("inspect")
    inspect.add_argument("id")
    review = commands.add_parser("review")
    review.add_argument("id")
    review.add_argument("--as", dest="actor", required=True)
    review.add_argument("--approve", action="store_true", help="Omit to deny")
    audit = commands.add_parser("audit")
    audit.add_argument("--limit", type=int, default=100)
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            parent = Path(args.db).parent
            parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            print(json.dumps({"directory": str(parent), "status": "ready"}))
            return 0
        policy = Policy.from_dict(load(args.policy))
        if args.command == "check":
            decision = policy.evaluate(Action.from_dict(load(args.action)))
            print(json.dumps({"decision": decision.value}))
            return 0 if decision.value == "allow" else 2
        engine = Engine(args.db, policy, reviewers=set(args.reviewer))
        if args.command == "request":
            action = Action.from_dict(load(args.action))
            result = {"request_id": engine.request(action, ttl=args.ttl), "digest": action.digest}
        elif args.command == "inspect":
            result = engine.inspect(args.id)
        elif args.command == "review":
            engine.review(args.id, reviewer=args.actor, approve=args.approve)
            result = {"status": "approved" if args.approve else "denied"}
        else:
            result = engine.audit(limit=args.limit)
        print(json.dumps(result, indent=2))
        return 0
    except (ValueError, TypeError, RecursionError, OSError, sqlite3.Error) as error:
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
