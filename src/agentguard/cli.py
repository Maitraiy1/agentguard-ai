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
    revoke = commands.add_parser("revoke")
    revoke.add_argument("id")
    revoke.add_argument("--as", dest="actor", required=True)
    activate = commands.add_parser("activate-policy")
    activate.add_argument("--as", dest="actor", required=True)
    backup = commands.add_parser("backup")
    backup.add_argument("output")
    restore = commands.add_parser("restore")
    restore.add_argument("source")
    restore.add_argument("output")
    restore.add_argument("--as", dest="actor", required=True)
    export = commands.add_parser("export-audit")
    export.add_argument("output")
    prune = commands.add_parser("prune")
    prune.add_argument("--before", type=float, required=True)
    prune.add_argument("--audit-before", type=float)
    prune.add_argument("--as", dest="actor", required=True)
    prune.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            parent = Path(args.db).parent
            parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            print(json.dumps({"directory": str(parent), "status": "ready"}))
            return 0
        if args.command == "backup":
            from .maintenance import backup_database
            print(json.dumps(backup_database(args.db, args.output)))
            return 0
        policy = Policy.from_dict(load(args.policy))
        if args.command == "restore":
            from .maintenance import restore_database
            print(json.dumps(restore_database(args.source, args.output, policy, actor=args.actor)))
            return 0
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
        elif args.command == "revoke":
            engine.revoke(args.id, reviewer=args.actor)
            result = {"status": "revoked"}
        elif args.command == "activate-policy":
            result = {"generation": engine.activate_policy(actor=args.actor)}
        elif args.command == "export-audit":
            from .maintenance import export_audit
            result = export_audit(args.db, args.output)
        elif args.command == "prune":
            result = engine.prune(before=args.before, actor=args.actor, apply=args.apply,
                                  audit_before=args.audit_before)
        else:
            result = engine.audit(limit=args.limit)
        print(json.dumps(result, indent=2))
        return 0
    except (ValueError, TypeError, RecursionError, OSError, sqlite3.Error) as error:
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
