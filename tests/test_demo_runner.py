import contextlib
import io
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agentguard import Action, ApprovalError, Decision, Engine, Policy, Rule
from agentguard.demo_runner import DEMO_TEXT, console_tool, demo_action, main, wait_and_execute


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.policy = Policy((Rule('notes.publish', 'notes/demo', 'demo-agent', Decision.APPROVAL),))
        self.now = 1000.0
        self.engine = Engine(Path(self.temp.name) / 'state.sqlite3', self.policy,
                             reviewers={'operator'}, clock=lambda: self.now)
        self.action = demo_action()
        self.request_id = self.engine.request(self.action)
        self.calls = []

    def wait(self, sleep, **kwargs):
        return wait_and_execute(self.engine, self.action, self.request_id,
                                clock=lambda: self.now, sleep=sleep,
                                handler=self.calls.append, **kwargs)

    def test_approval_during_wait_then_execute_once(self):
        def approve(_):
            self.assertEqual(self.calls, [])
            self.engine.review(self.request_id, reviewer='operator', approve=True)
        self.assertEqual(self.wait(approve), 'executed')
        self.assertEqual(self.calls, [self.action])
        self.assertEqual(self.wait(lambda _: self.fail('slept')), 'already consumed')
        self.assertEqual(len(self.calls), 1)
        self.assertEqual([r['event'] for r in reversed(self.engine.audit())],
                         ['requested', 'approved', 'execution_started', 'execution_succeeded'])

    def test_denial_during_wait_never_executes(self):
        def deny(_):
            self.engine.review(self.request_id, reviewer='operator', approve=False)
        self.assertEqual(self.wait(deny), 'denied')
        self.assertEqual(self.calls, [])
        self.assertFalse(any(r['event'].startswith('execution') for r in self.engine.audit()))

    def test_timeout_never_executes(self):
        def advance(seconds):
            self.now += seconds
        self.assertEqual(self.wait(advance, timeout=1), 'timed out')
        self.assertEqual(self.calls, [])
        self.assertEqual(self.engine.inspect(self.request_id)['status'], 'pending')

    def test_expired_never_executes(self):
        self.now += 300
        self.assertEqual(self.wait(lambda _: None), 'expired')
        self.assertEqual(self.calls, [])

    def test_changed_policy_file_never_executes(self):
        self.engine.review(self.request_id, reviewer='operator', approve=True)
        with self.assertRaises(ApprovalError):
            self.wait(lambda _: None, current_policy=lambda: Policy())
        self.assertEqual(self.calls, [])

    def test_policy_change_between_inspection_and_execution(self):
        self.engine.review(self.request_id, reviewer='operator', approve=True)
        policies = iter([self.policy, Policy()])
        with self.assertRaises(ApprovalError):
            self.wait(lambda _: None, current_policy=lambda: next(policies))
        self.assertEqual(self.calls, [])

    def test_substituted_action_never_executes(self):
        other = Action('notes.publish', 'notes/demo', 'demo-agent', {'text': 'different'})
        with self.assertRaises(ApprovalError):
            wait_and_execute(self.engine, other, self.request_id, handler=self.calls.append)
        self.assertEqual(self.calls, [])

    def test_storage_failure_never_executes(self):
        self.engine.review(self.request_id, reviewer='operator', approve=True)
        with contextlib.closing(sqlite3.connect(self.engine.database)) as db, db:
            db.execute("CREATE TRIGGER fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'unavailable'); END")
        with self.assertRaises(sqlite3.Error):
            self.wait(lambda _: None)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.engine.inspect(self.request_id)['status'], 'approved')

    def test_handler_failure_burns_approval_without_retry(self):
        self.engine.review(self.request_id, reviewer='operator', approve=True)
        def fail(_):
            raise RuntimeError('failed')
        with self.assertRaises(RuntimeError):
            wait_and_execute(self.engine, self.action, self.request_id, handler=fail)
        self.assertEqual(self.engine.inspect(self.request_id)['status'], 'consumed')
        self.assertEqual(self.engine.audit()[0]['event'], 'execution_failed')

    def test_fixed_console_tool(self):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            console_tool(self.action)
        self.assertEqual(stream.getvalue(), DEMO_TEXT + '\n')
        with self.assertRaises(ValueError):
            console_tool(Action('shell.execute', 'host', 'demo-agent', {}))

    def test_invalid_wait_arguments(self):
        for kwargs in ({'timeout': 0}, {'timeout': True}, {'timeout': float('nan')},
                       {'timeout': 3601}, {'interval': 0}, {'interval': float('inf')}):
            with self.assertRaises(ValueError):
                self.wait(lambda _: None, **kwargs)

    def test_main_waits_for_human_and_reports_success(self):
        policy_file = Path(self.temp.name) / 'policy.json'
        policy_file.write_text('{"rules":[{"tool":"notes.publish","resource":"notes/demo",'
                               '"principal":"demo-agent","decision":"approval"}]}')
        original = wait_and_execute
        def human_approved(engine, action, request_id, **kwargs):
            self.assertEqual(engine.inspect(request_id)['status'], 'pending')
            engine.review(request_id, reviewer='operator', approve=True)
            return original(engine, action, request_id, **kwargs)
        stream = io.StringIO()
        with patch('agentguard.demo_runner.wait_and_execute', side_effect=human_approved), contextlib.redirect_stdout(stream):
            code = main(['--db', str(self.engine.database), '--policy', str(policy_file)])
        self.assertEqual(code, 0)
        self.assertIn('Result: executed', stream.getvalue())
        self.assertIn(DEMO_TEXT, stream.getvalue())


class EndToEndTests(unittest.TestCase):
    def test_http_dashboard_decisions_control_runner_execution(self):
        import concurrent.futures
        import http.client
        import threading
        from http.cookies import SimpleCookie
        from urllib.parse import urlencode
        from agentguard.dashboard import COOKIE, Credentials, Dashboard

        with tempfile.TemporaryDirectory() as directory:
            policy = Policy((Rule('notes.publish', 'notes/demo', 'demo-agent', Decision.APPROVAL),))
            engine = Engine(Path(directory) / 'state.sqlite3', policy, reviewers={'operator'})
            credentials = Credentials.create('operator', 'test-only-password-123!')
            with Dashboard(engine, credentials, port=0) as server:
                serving = threading.Thread(target=server.serve_forever, daemon=True)
                serving.start()
                try:
                    def post(path, form, cookie=None):
                        connection = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=5)
                        headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Origin': server.origin}
                        if cookie:
                            headers['Cookie'] = cookie
                        try:
                            connection.request('POST', path, urlencode(form), headers)
                            response = connection.getresponse()
                            response.read()
                            return response.status, response.getheader('Set-Cookie')
                        finally:
                            connection.close()
                    status, cookie_header = post('/login', {'password': 'test-only-password-123!'})
                    self.assertEqual(status, 303)
                    cookie = SimpleCookie()
                    cookie.load(cookie_header)
                    token = cookie[COOKIE].value
                    csrf = server.sessions[token].csrf
                    calls = []
                    for approve in (True, False):
                        action = demo_action()
                        request_id = engine.request(action)
                        started = threading.Event()
                        def run():
                            started.set()
                            return wait_and_execute(engine, action, request_id, handler=calls.append,
                                                    timeout=3, interval=0.05)
                        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                            future = pool.submit(run)
                            self.assertTrue(started.wait(timeout=1))
                            before = len(calls)
                            self.assertFalse(future.done())
                            status, _ = post('/review', {'csrf': csrf, 'request_id': request_id,
                                'decision': 'approve' if approve else 'deny'}, f'{COOKIE}={token}')
                            self.assertEqual(status, 303)
                            outcome = future.result(timeout=5)
                        self.assertEqual(outcome, 'executed' if approve else 'denied')
                        self.assertEqual(len(calls), before + int(approve))
                        events = [r['event'] for r in reversed(engine.audit()) if r['request_id'] == request_id]
                        self.assertEqual(events, ['requested', 'approved', 'execution_started', 'execution_succeeded']
                                         if approve else ['requested', 'denied'])
                finally:
                    server.shutdown()
                    serving.join(timeout=3)
