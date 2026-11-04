"""HTTP integration tests against a real ephemeral loopback server."""
import contextlib
import http.client
import json
import io
import tempfile
import threading
import unittest
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import urlencode
from unittest.mock import patch

from agentguard import Action, ApprovalError, Decision, Engine, Policy, Rule
from agentguard.dashboard import COOKIE, Credentials, Dashboard, main


class DashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.password = 'test-only-password-123!'
        cls.credentials = Credentials.create('operator', cls.password)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.now = 1000.0
        self.policy = Policy((Rule('notes.publish', 'notes/demo', 'agent', Decision.APPROVAL),))
        self.engine = Engine(Path(self.temp.name) / 'state.sqlite3', self.policy,
                             reviewers={'operator'})
        self.action = Action('notes.publish', 'notes/demo', 'agent', {'text': '<script>alert(1)</script>'})
        self.request_id = self.engine.request(self.action, ttl=3600)
        self.server = Dashboard(self.engine, self.credentials, port=0, clock=lambda: self.now)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop)

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def request(self, method, path, form=None, cookie=None, *, origin=True, host=None, raw=None, extra=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        headers = {'Host': host or self.server.host}
        if method == 'POST':
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
            if origin:
                headers['Origin'] = self.server.origin if origin is True else origin
        if cookie:
            headers['Cookie'] = cookie
        if extra:
            headers.update(extra)
        body = raw if raw is not None else (urlencode(form) if form is not None else None)
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read().decode()
        finally:
            connection.close()

    def login(self):
        status, headers, _ = self.request('POST', '/login', {'password': self.password})
        self.assertEqual(status, 303)
        cookie = SimpleCookie()
        cookie.load(headers['Set-Cookie'])
        token = cookie[COOKIE].value
        return f'{COOKIE}={token}', self.server.sessions[token].csrf

    def test_anonymous_pages_hide_payloads(self):
        for path in ('/', '/audit', '/request/' + self.request_id):
            status, headers, body = self.request('GET', path)
            self.assertEqual(status, 303)
            self.assertEqual(headers['Location'], '/login')
            self.assertNotIn('alert(1)', body)

    def test_login_cookie_and_security_headers(self):
        status, headers, body = self.request('GET', '/login')
        self.assertEqual(status, 200)
        self.assertIn('type="password"', body)
        self.assertEqual(headers['Cache-Control'], 'no-store')
        self.assertEqual(headers['Referrer-Policy'], 'same-origin')
        self.assertEqual(headers['X-Frame-Options'], 'DENY')
        self.assertIn("frame-ancestors 'none'", headers['Content-Security-Policy'])
        status, headers, _ = self.request('POST', '/login', {'password': self.password})
        self.assertEqual(status, 303)
        self.assertIn('HttpOnly', headers['Set-Cookie'])
        self.assertIn('SameSite=Strict', headers['Set-Cookie'])
        self.assertNotIn(self.password, headers['Set-Cookie'])

    def test_wrong_password_and_rate_limit(self):
        for _ in range(5):
            self.assertEqual(self.request('POST', '/login', {'password': 'wrong'})[0], 401)
        self.assertEqual(self.request('POST', '/login', {'password': self.password})[0], 429)
        self.now += 60
        self.assertEqual(self.request('POST', '/login', {'password': self.password})[0], 303)

    def test_host_and_origin_rejected(self):
        self.assertEqual(self.request('GET', '/login', host='evil.example')[0], 403)
        for origin in (False, 'null', 'http://evil.example'):
            self.assertEqual(self.request('POST', '/login', {'password': self.password}, origin=origin)[0], 403)

    def test_review_approves_exact_request_and_records_reviewer(self):
        cookie, csrf = self.login()
        status, _, home = self.request('GET', '/', cookie=cookie)
        self.assertEqual(status, 200)
        self.assertIn('notes.publish', home)
        status, _, detail = self.request('GET', '/request/' + self.request_id, cookie=cookie)
        self.assertEqual(status, 200)
        self.assertIn('&lt;script&gt;', detail)
        self.assertNotIn('<script>', detail)
        self.assertIn('Approve action', detail)
        status, headers, _ = self.request('POST', '/review',
            {'csrf': csrf, 'request_id': self.request_id, 'decision': 'approve'}, cookie)
        self.assertEqual(status, 303)
        self.assertEqual(headers['Location'], '/request/' + self.request_id)
        row = self.engine.inspect(self.request_id)
        self.assertEqual(row['status'], 'approved')
        self.assertEqual(row['reviewer'], 'operator')
        # Dashboard only changes approval state; no execution event is emitted.
        self.assertFalse(any(r['event'].startswith('execution') for r in self.engine.audit()))

    def test_deny_is_terminal(self):
        cookie, csrf = self.login()
        form = {'csrf': csrf, 'request_id': self.request_id, 'decision': 'deny'}
        self.assertEqual(self.request('POST', '/review', form, cookie)[0], 303)
        form['decision'] = 'approve'
        self.assertEqual(self.request('POST', '/review', form, cookie)[0], 409)
        self.assertEqual(self.engine.inspect(self.request_id)['status'], 'denied')

    def test_csrf_missing_wrong_and_non_ascii(self):
        cookie, _ = self.login()
        for token in ('', 'wrong', 'अ'):
            form = {'csrf': token, 'request_id': self.request_id, 'decision': 'approve'}
            self.assertEqual(self.request('POST', '/review', form, cookie)[0], 403)
        self.assertEqual(self.engine.inspect(self.request_id)['status'], 'pending')

    def test_identity_cannot_be_supplied_by_browser(self):
        cookie, csrf = self.login()
        form = {'csrf': csrf, 'request_id': self.request_id, 'decision': 'approve', 'reviewer': 'agent'}
        self.assertEqual(self.request('POST', '/review', form, cookie)[0], 400)
        self.assertEqual(self.engine.inspect(self.request_id)['status'], 'pending')

    def test_revoke_approved_request_from_dashboard(self):
        cookie, csrf = self.login()
        form = {'csrf': csrf, 'request_id': self.request_id, 'decision': 'approve'}
        self.assertEqual(self.request('POST', '/review', form, cookie)[0], 303)
        form['decision'] = 'revoke'
        self.assertEqual(self.request('POST', '/review', form, cookie)[0], 303)
        self.assertEqual(self.engine.inspect(self.request_id)['status'], 'revoked')
        with self.assertRaises(ApprovalError):
            self.engine.execute(self.action, lambda _: self.fail('called'), request_id=self.request_id)

    def test_unknown_decision_does_not_mutate(self):
        cookie, csrf = self.login()
        form = {'csrf': csrf, 'request_id': self.request_id, 'decision': 'maybe'}
        self.assertEqual(self.request('POST', '/review', form, cookie)[0], 400)
        self.assertEqual(self.engine.inspect(self.request_id)['status'], 'pending')

    def test_malformed_and_oversize_forms(self):
        self.assertEqual(self.request('POST', '/login', raw='password=x&password=y')[0], 400)
        self.assertEqual(self.request('POST', '/login', raw='a' * 8193)[0], 413)
        self.assertEqual(self.request('POST', '/login', raw='{}', extra={'Content-Type': 'application/json'})[0], 415)

    def test_logout_and_forged_cookie(self):
        cookie, csrf = self.login()
        self.assertEqual(self.request('POST', '/logout', {'csrf': csrf}, cookie)[0], 303)
        self.assertEqual(self.request('GET', '/', cookie=cookie)[0], 303)
        self.assertEqual(self.request('GET', '/', cookie=COOKIE + '=forged')[0], 303)

    def test_idle_and_absolute_session_expiry(self):
        cookie, _ = self.login()
        self.now += 900
        self.assertEqual(self.request('GET', '/', cookie=cookie)[0], 303)
        cookie, _ = self.login()
        for _ in range(2):
            self.now += 600
            self.assertEqual(self.request('GET', '/', cookie=cookie)[0], 200)
        self.now += 600
        self.assertEqual(self.request('GET', '/', cookie=cookie)[0], 303)

    def test_audit_page(self):
        cookie, _ = self.login()
        status, _, body = self.request('GET', '/audit', cookie=cookie)
        self.assertEqual(status, 200)
        self.assertIn('requested', body)
        self.assertNotIn('alert(1)', body)

    def test_expired_request_blocked_on_post(self):
        cookie, csrf = self.login()
        self.engine.clock = lambda: 10**12
        form = {'csrf': csrf, 'request_id': self.request_id, 'decision': 'approve'}
        self.assertEqual(self.request('POST', '/review', form, cookie)[0], 409)
        body = self.request('GET', '/request/' + self.request_id, cookie=cookie)[2]
        self.assertIn('expired', body)
        self.assertNotIn('Approve action', body)

    def test_engine_list_limits_and_order(self):
        other = self.engine.request(self.action)
        self.assertEqual(self.engine.list_requests(limit=1)[0]['id'], other)
        for limit in (0, True, 1001):
            with self.assertRaises(ValueError):
                self.engine.list_requests(limit=limit)

    def test_no_tool_execution_route(self):
        cookie, csrf = self.login()
        self.assertEqual(self.request('POST', '/execute', {'csrf': csrf}, cookie)[0], 400)
        self.assertEqual(self.request('GET', '/execute', cookie=cookie)[0], 404)


class CredentialTests(unittest.TestCase):
    def test_round_trip_and_no_plaintext(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'credentials.json'
            credentials = Credentials.create('operator', 'long-test-password')
            credentials.save(path)
            self.assertNotIn('long-test-password', path.read_text())
            loaded = Credentials.load(path)
            self.assertTrue(loaded.verify('long-test-password'))
            self.assertFalse(loaded.verify('wrong'))
            with self.assertRaises(FileExistsError):
                credentials.save(path)

    def test_short_password_and_bad_config(self):
        with self.assertRaises(ValueError):
            Credentials.create('operator', 'short')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'credentials.json'
            path.write_text(json.dumps({'version': 99, 'reviewer': 'a', 'salt': '00', 'digest': '00'}))
            with self.assertRaises(ValueError):
                Credentials.load(path)

    def test_init_prompts_for_password(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'credentials.json'
            with patch('agentguard.dashboard.getpass.getpass', return_value='long-test-password'), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(['--credentials', str(path), 'init']), 0)
            self.assertTrue(path.exists())
