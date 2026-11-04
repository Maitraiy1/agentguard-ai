"""Real Chromium form regression and note-creation walkthrough (CI/browser extra)."""
import concurrent.futures
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path

from playwright.sync_api import expect, sync_playwright
from agentguard import Action, ApprovalError, Engine, Policy
from agentguard.dashboard import Credentials, Dashboard
from agentguard.demo_runner import wait_and_execute
from agentguard.notes import NoteWriter


class BrowserFlow(unittest.TestCase):
    def test_login_notes_deny_revoke_audit_logout(self):
        artifacts = Path(os.environ.get('AGENTGUARD_ARTIFACTS', 'artifacts'))
        artifacts.mkdir(parents=True, exist_ok=True)
        policy_path = Path(__file__).resolve().parents[1] / 'examples/notes-policy.json'
        policy = Policy.from_dict(json.loads(policy_path.read_text()))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            engine = Engine(root / 'state.sqlite3', policy, reviewers={'operator'})
            writer = NoteWriter(root / 'notes')
            credentials = Credentials.create('operator', 'browser-test-password-only')
            action = Action('notes.create', 'local-notes', 'demo-agent',
                            {'filename': 'approved-note.txt', 'text': 'Created after a real browser approval.'})
            request_id = engine.request(action)
            with Dashboard(engine, credentials, port=0) as server:
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    with sync_playwright() as playwright:
                        browser = playwright.chromium.launch()
                        context = browser.new_context(viewport={'width': 1280, 'height': 900},
                                                      record_video_dir=str(artifacts / 'videos'))
                        page = context.new_page()
                        try:
                            page.goto(server.origin + '/audit')
                            expect(page).to_have_url(server.origin + '/login')
                            page.get_by_label('Password', exact=True).fill('browser-test-password-only')
                            page.get_by_role('button', name='Sign in', exact=True).click()
                            expect(page).to_have_url(server.origin + '/')
                            expect(page.get_by_role('heading', name='Approval requests')).to_be_visible()
                            page.screenshot(path=str(artifacts / 'dashboard.png'), full_page=True)
                            page.get_by_role('link', name='Inspect', exact=True).click()
                            expect(page.get_by_role('button', name='Approve action')).to_be_visible()
                            self.assertFalse((writer.root / 'approved-note.txt').exists())
                            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                                future = pool.submit(wait_and_execute, engine, action, request_id,
                                    timeout=15, interval=0.05, handler=writer)
                                page.get_by_role('button', name='Approve action', exact=True).click()
                                self.assertEqual(future.result(timeout=15), 'executed')
                            page.reload()
                            expect(page.get_by_text('consumed', exact=True)).to_be_visible()
                            self.assertEqual((writer.root / 'approved-note.txt').read_text(), action.parameters['text'])
                            page.screenshot(path=str(artifacts / 'approved.png'), full_page=True)
                            denied_action = Action('notes.create', 'local-notes', 'demo-agent',
                                {'filename': 'meeting-note.txt', 'text': 'This must never be written.'})
                            denied = engine.request(denied_action)
                            page.goto(server.origin + '/request/' + denied)
                            page.get_by_role('button', name='Deny action', exact=True).click()
                            expect(page.get_by_text('denied', exact=True)).to_be_visible()
                            self.assertEqual(wait_and_execute(engine, denied_action, denied, handler=writer), 'denied')
                            self.assertFalse((writer.root / 'meeting-note.txt').exists())
                            revoked = engine.request(denied_action)
                            page.goto(server.origin + '/request/' + revoked)
                            page.get_by_role('button', name='Approve action', exact=True).click()
                            page.get_by_role('button', name='Revoke permission', exact=True).click()
                            expect(page.get_by_text('revoked', exact=True)).to_be_visible()
                            with self.assertRaises(ApprovalError):
                                engine.execute(denied_action, writer, request_id=revoked)
                            bad = context.request.post(server.origin + '/review',
                                form={'csrf': 'invalid', 'request_id': revoked, 'decision': 'approve'},
                                headers={'Origin': 'http://evil.invalid'})
                            self.assertEqual(bad.status, 403)
                            page.get_by_role('link', name='Audit history', exact=True).click()
                            expect(page.get_by_role('cell', name='execution_succeeded', exact=True)).to_be_visible()
                            expect(page.get_by_role('cell', name='revoked', exact=True)).to_be_visible()
                            page.screenshot(path=str(artifacts / 'audit.png'), full_page=True)
                            page.get_by_role('button', name='Sign out', exact=True).click()
                            expect(page).to_have_url(server.origin + '/login')
                            page.goto(server.origin + '/audit')
                            expect(page).to_have_url(server.origin + '/login')
                        finally:
                            context.close()
                            browser.close()
                finally:
                    server.shutdown()
                    thread.join(timeout=5)


if __name__ == '__main__':
    unittest.main()
