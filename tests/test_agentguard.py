import concurrent.futures
import contextlib
import io
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from agentguard import Action, ApprovalError, Decision, Engine, Policy, Rule
from agentguard.cli import main
from agentguard.core import strict_json


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.action = Action('publish', 'note/1', 'agent', {'text': 'hello'})

    def test_default_deny_and_exact_matches(self):
        self.assertEqual(Policy().evaluate(self.action), Decision.DENY)
        for field in ('tool', 'resource', 'principal'):
            values = dict(tool='publish', resource='note/1', principal='agent')
            values[field] += '*'
            policy = Policy((Rule(**values, decision=Decision.ALLOW),))
            self.assertEqual(policy.evaluate(self.action), Decision.DENY)

    def test_deny_and_approval_precedence(self):
        rules = [Rule('publish', 'note/1', 'agent', decision) for decision in Decision]
        for rows in (rules, list(reversed(rules))):
            self.assertEqual(Policy(tuple(rows)).evaluate(self.action), Decision.DENY)
        self.assertEqual(Policy(tuple(rules[:2])).evaluate(self.action), Decision.APPROVAL)

    def test_snapshot_and_canonical_hash(self):
        parameters = {'nested': [1, 2], 'b': 'x'}
        action = Action('x', 'r', 'p', parameters)
        digest = action.digest
        parameters['nested'].append(3)
        action.parameters['nested'].append(4)
        self.assertEqual(action.digest, digest)
        self.assertEqual(action.parameters['nested'], [1, 2])
        self.assertEqual(action.digest, Action('x', 'r', 'p', {'b': 'x', 'nested': [1, 2]}).digest)
        with self.assertRaises(AttributeError):
            action.tool = 'other'

    def test_strict_inputs(self):
        for value in ({1: 'x'}, {'x': float('nan')}, {'x': object()}, {'x': (1, 2)}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                Action('t', 'r', 'p', value)
        for value in ('', '\n', 42):
            with self.assertRaises(ValueError):
                Action(value, 'r', 'p')
        with self.assertRaises(ValueError):
            Action('t', 'r', 'p', {'x': 'a' * 65536})
        with self.assertRaises(ValueError):
            Action.from_dict({'tool': 'x'})

    def test_strict_json_and_policy(self):
        for raw in ('{"a":1,"a":2}', '{"x":NaN}', '{"x":Infinity}'):
            with self.assertRaises(ValueError):
                strict_json(raw)
        for data in ({'rules': [], 'typo': True}, {'rules': 'x'}, {'rules': [{}]}):
            with self.assertRaises(ValueError):
                Policy.from_dict(data)
        with self.assertRaises(ValueError):
            Rule('t', 'r', 'p', 'typo')
        with self.assertRaises(ValueError):
            Policy(('not-a-rule',))

    def test_policy_snapshot_hash_is_order_independent(self):
        rows = [Rule('a', 'r', 'p', Decision.ALLOW), Rule('b', 'r', 'p', Decision.DENY)]
        policy = Policy(rows)
        rows.clear()
        self.assertEqual(len(policy.rules), 2)
        self.assertEqual(policy.digest, Policy(tuple(reversed(policy.rules))).digest)


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.database = Path(self.temp.name) / 'state.sqlite3'
        self.now = 1000.0
        self.policy = Policy((Rule('publish', 'note/1', 'agent', Decision.APPROVAL),))
        self.action = Action('publish', 'note/1', 'agent', {'text': 'hello'})
        self.engine = Engine(self.database, self.policy, reviewers={'human', 'agent'},
                             clock=lambda: self.now)

    def approved(self):
        request_id = self.engine.request(self.action)
        self.engine.review(request_id, reviewer='human', approve=True)
        return request_id

    def test_happy_path_and_metadata_audit(self):
        request_id = self.approved()
        self.assertEqual(self.engine.inspect(request_id)['action'], self.action.as_dict())
        result = self.engine.execute(self.action, lambda a: a.parameters['text'], request_id=request_id)
        self.assertEqual(result, 'hello')
        self.assertEqual(self.engine.inspect(request_id)['status'], 'consumed')
        events = list(reversed(self.engine.audit()))
        self.assertEqual([r['event'] for r in events],
                         ['requested', 'approved', 'execution_started', 'execution_succeeded'])
        self.assertNotIn('hello', json.dumps(events))

    def test_missing_or_pending_approval_never_calls_handler(self):
        request_id = self.engine.request(self.action)
        calls = []
        for approval in (None, request_id, 'unknown'):
            with self.assertRaises(ApprovalError):
                self.engine.execute(self.action, calls.append, request_id=approval)
        self.assertEqual(calls, [])

    def test_replay_blocked(self):
        request_id = self.approved()
        calls = []
        self.engine.execute(self.action, calls.append, request_id=request_id)
        with self.assertRaises(ApprovalError):
            self.engine.execute(self.action, calls.append, request_id=request_id)
        self.assertEqual(len(calls), 1)

    def test_changed_parameters_blocked_without_burning_valid_request(self):
        request_id = self.approved()
        changed = Action('publish', 'note/1', 'agent', {'text': 'different'})
        with self.assertRaises(ApprovalError):
            self.engine.execute(changed, lambda _: self.fail('called'), request_id=request_id)
        self.assertEqual(self.engine.inspect(request_id)['status'], 'approved')

    def test_changed_principal_cannot_reuse_approval(self):
        both = Policy(self.policy.rules + (Rule('publish', 'note/1', 'other', Decision.APPROVAL),))
        engine = Engine(self.database, both, reviewers={'human'}, clock=lambda: self.now)
        request_id = engine.request(self.action)
        engine.review(request_id, reviewer='human', approve=True)
        with self.assertRaises(ApprovalError):
            engine.execute(Action('publish', 'note/1', 'other', self.action.parameters),
                           lambda _: self.fail('called'), request_id=request_id)

    def test_unknown_and_self_reviewer_blocked(self):
        request_id = self.engine.request(self.action)
        for reviewer in ('intruder', 'agent'):
            with self.assertRaises(ApprovalError):
                self.engine.review(request_id, reviewer=reviewer, approve=True)
        self.assertEqual(self.engine.inspect(request_id)['status'], 'pending')

    def test_denial_is_terminal(self):
        request_id = self.engine.request(self.action)
        self.engine.review(request_id, reviewer='human', approve=False)
        with self.assertRaises(ApprovalError):
            self.engine.review(request_id, reviewer='human', approve=True)
        with self.assertRaises(ApprovalError):
            self.engine.execute(self.action, lambda _: self.fail('called'), request_id=request_id)

    def test_expiration_boundary_for_review_and_execution(self):
        pending = self.engine.request(self.action, ttl=10)
        approved = self.approved()
        self.now += 10
        with self.assertRaises(ApprovalError):
            self.engine.review(pending, reviewer='human', approve=True)
        self.now += 290
        with self.assertRaises(ApprovalError):
            self.engine.execute(self.action, lambda _: self.fail('called'), request_id=approved)

    def test_policy_change_invalidates_review_and_execution(self):
        approved = self.approved()
        pending = self.engine.request(self.action)
        changed = Policy(self.policy.rules + (Rule('other', 'x', 'agent', Decision.DENY),))
        engine = Engine(self.database, changed, reviewers={'human'}, clock=lambda: self.now)
        with self.assertRaises(ApprovalError):
            engine.review(pending, reviewer='human', approve=True)
        with self.assertRaises(ApprovalError):
            engine.execute(self.action, lambda _: self.fail('called'), request_id=approved)

    def test_revoked_reviewer(self):
        request_id = self.approved()
        engine = Engine(self.database, self.policy, reviewers=set(), clock=lambda: self.now)
        with self.assertRaises(ApprovalError):
            engine.execute(self.action, lambda _: self.fail('called'), request_id=request_id)

    def test_handler_failure_burns_approval(self):
        request_id = self.approved()
        def broken(_):
            raise RuntimeError('sensitive detail')
        with self.assertRaises(RuntimeError):
            self.engine.execute(self.action, broken, request_id=request_id)
        self.assertEqual(self.engine.inspect(request_id)['status'], 'consumed')
        self.assertEqual(self.engine.audit()[0]['event'], 'execution_failed')
        self.assertNotIn('sensitive detail', json.dumps(self.engine.audit()))

    def test_state_survives_engine_restart(self):
        request_id = self.approved()
        restarted = Engine(self.database, self.policy, reviewers={'human'}, clock=lambda: self.now)
        restarted.execute(self.action, lambda _: None, request_id=request_id)
        self.assertEqual(self.engine.inspect(request_id)['status'], 'consumed')

    def test_concurrent_consumption_only_one_handler_runs(self):
        request_id = self.approved()
        def attempt(_):
            try:
                self.engine.execute(self.action, lambda _: None, request_id=request_id)
                return True
            except ApprovalError:
                return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(attempt, range(16)))
        self.assertEqual(sum(outcomes), 1)
        self.assertEqual(sum(r['event'] == 'execution_started' for r in self.engine.audit()), 1)

    def test_allowed_and_denied(self):
        allowed = Policy((Rule('publish', 'note/1', 'agent', Decision.ALLOW),))
        engine = Engine(self.database, allowed, reviewers=set())
        self.assertEqual(engine.execute(self.action, lambda _: 7), 7)
        with self.assertRaises(ApprovalError):
            engine.request(self.action)
        with self.assertRaises(ApprovalError):
            engine.execute(self.action, lambda _: None, request_id='unexpected')
        blocked = Engine(self.database, Policy(), reviewers=set())
        with self.assertRaises(ApprovalError):
            blocked.execute(self.action, lambda _: self.fail('called'))
        self.assertEqual(blocked.audit()[0]['event'], 'blocked')

    def test_invalid_ttl_and_review_type(self):
        for ttl in (0, -1, 3601, True, 1.5):
            with self.assertRaises(ValueError):
                self.engine.request(self.action, ttl=ttl)
        request_id = self.engine.request(self.action)
        with self.assertRaises(ValueError):
            self.engine.review(request_id, reviewer='human', approve='yes')
        with self.assertRaises(ApprovalError):
            self.engine.inspect('unknown')
        with self.assertRaises(ValueError):
            self.engine.audit(limit=1001)

    def test_storage_failure_prevents_handler_and_consumption(self):
        request_id = self.approved()
        with contextlib.closing(sqlite3.connect(self.database)) as db, db:
            db.execute("CREATE TRIGGER fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'unavailable'); END")
        with self.assertRaises(sqlite3.Error):
            self.engine.execute(self.action, lambda _: self.fail('called'), request_id=request_id)
        self.assertEqual(self.engine.inspect(request_id)['status'], 'approved')

    def test_unknown_schema_fails_closed(self):
        with contextlib.closing(sqlite3.connect(self.database)) as db, db:
            db.execute("PRAGMA user_version=99")
        with self.assertRaises(ValueError):
            Engine(self.database, self.policy, reviewers={'human'})

    def test_final_audit_failure_reports_error_after_side_effect(self):
        request_id = self.approved()
        calls = []
        def handler(_):
            calls.append('effect')
            with contextlib.closing(sqlite3.connect(self.database)) as db, db:
                db.execute("CREATE TRIGGER fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'unavailable'); END")
        with self.assertRaises(sqlite3.Error):
            self.engine.execute(self.action, handler, request_id=request_id)
        self.assertEqual(calls, ['effect'])
        self.assertEqual(self.engine.inspect(request_id)['status'], 'consumed')


class CLITests(unittest.TestCase):
    def test_cli_lifecycle_and_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            policy = folder / 'policy.json'
            action = folder / 'action.json'
            database = folder / 'private' / 'state.sqlite3'
            policy.write_text(json.dumps({'rules': [dict(tool='t', resource='r', principal='p', decision='approval')]}))
            action.write_text(json.dumps(Action('t', 'r', 'p').as_dict()))
            args = ['--db', str(database), '--policy', str(policy), '--reviewer', 'human']
            def run(extra):
                output, errors = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                    code = main(args + extra)
                return code, output.getvalue(), errors.getvalue()
            self.assertEqual(run(['init'])[0], 0)
            self.assertEqual(run(['check', str(action)])[0], 2)
            code, output, _ = run(['request', str(action)])
            self.assertEqual(code, 0)
            request_id = json.loads(output)['request_id']
            self.assertEqual(run(['inspect', request_id])[0], 0)
            self.assertEqual(run(['review', request_id, '--as', 'human', '--approve'])[0], 0)
            self.assertEqual(run(['audit'])[0], 0)
            self.assertEqual(run(['review', request_id, '--as', 'intruder', '--approve'])[0], 1)
            policy.write_text('{"rules":[],"rules":[]}')
            self.assertEqual(run(['check', str(action)])[0], 1)


if __name__ == '__main__':
    unittest.main()

