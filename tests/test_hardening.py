import contextlib
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from agentguard import Action, ApprovalError, Decision, Engine, ParameterSchema, Policy, Rule
from agentguard.maintenance import backup_database, export_audit, restore_database
from agentguard.notes import NoteWriter


class ParameterTests(unittest.TestCase):
    def test_types_ranges_enums_and_exact_keys(self):
        schema = ParameterSchema({'dest': {'type': 'string', 'enum': ['local']},
            'count': {'type': 'integer', 'minimum': 1, 'maximum': 5},
            'text': {'type': 'string', 'max_length': 3}, 'enabled': {'type': 'boolean'}})
        good = dict(dest='local', count=2, text='hi', enabled=True)
        self.assertTrue(schema.accepts(good))
        for key, value in [('count', True), ('count', 1.0), ('count', 0), ('count', 6),
                           ('dest', 'external'), ('text', 'long'), ('enabled', 1)]:
            self.assertFalse(schema.accepts({**good, key: value}))
        self.assertFalse(schema.accepts({**good, 'extra': 'x'}))
        self.assertFalse(schema.accepts({'count': 2}))

    def test_invalid_schemas_and_immutable_snapshot(self):
        for fields in ({'a': {'type': 'unknown'}}, {'a': {'type': 'string', 'pattern': '.*'}},
            {'a': {'type': 'integer', 'enum': [True]}}, {'a': {'type': 'string', 'enum': []}},
            {'a': {'type': 'integer', 'minimum': 2, 'maximum': 1}},
            {'a': {'type': 'integer', 'max_length': 1}}, {'a': {'type': 'string', 'max_length': -1}}):
            with self.assertRaises(ValueError):
                ParameterSchema(fields)
        source = {'text': {'type': 'string', 'max_length': 3}}
        schema = ParameterSchema(source)
        source['text']['max_length'] = 100
        schema.as_dict()['text']['max_length'] = 100
        self.assertFalse(schema.accepts({'text': 'long'}))

    def test_constraints_cannot_be_bypassed(self):
        schema = ParameterSchema({'text': {'type': 'string', 'max_length': 3}})
        rows = (Rule('t', 'r', 'p', Decision.ALLOW), Rule('t', 'r', 'p', Decision.APPROVAL, schema))
        policy = Policy(rows)
        self.assertEqual(policy.evaluate(Action('t', 'r', 'p', {'text': 'ok'})), Decision.APPROVAL)
        self.assertEqual(policy.evaluate(Action('t', 'r', 'p', {'text': 'long'})), Decision.DENY)
        self.assertNotEqual(policy.digest, Policy(rows[:1]).digest)
        self.assertEqual(policy.digest, Policy(tuple(reversed(rows))).digest)
        with self.assertRaises(ValueError):
            Rule('t', 'r', 'p', Decision.DENY, schema)

    def test_json_policy(self):
        data = {'rules': [{'tool': 't', 'resource': 'r', 'principal': 'p', 'decision': 'approval',
                          'parameters': {'text': {'type': 'string', 'max_length': 4}}}]}
        policy = Policy.from_dict(data)
        self.assertEqual(policy.evaluate(Action('t', 'r', 'p', {'text': 'fine'})), Decision.APPROVAL)
        data['rules'][0]['parameters']['text']['typo'] = True
        with self.assertRaises(ValueError):
            Policy.from_dict(data)


class OperationalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.policy = Policy((Rule('t', 'r', 'p', Decision.APPROVAL),))
        self.action = Action('t', 'r', 'p', {'secret': 'payload-not-exported'})
        self.now = 1000.0
        self.engine = Engine(self.root / 'state.sqlite3', self.policy, reviewers={'human'}, clock=lambda: self.now)

    def approved(self):
        request = self.engine.request(self.action)
        self.engine.review(request, reviewer='human', approve=True)
        return request

    def test_revoked_approval_never_executes(self):
        request = self.approved()
        self.engine.revoke(request, reviewer='human')
        self.assertEqual(self.engine.inspect(request)['status'], 'revoked')
        self.assertEqual(self.engine.list_requests()[0]['status'], 'revoked')
        for callback in (lambda: self.engine.execute(self.action, lambda _: self.fail('called'), request_id=request),
                         lambda: self.engine.review(request, reviewer='human', approve=True),
                         lambda: self.engine.revoke(request, reviewer='human')):
            with self.assertRaises(ApprovalError):
                callback()
        self.assertEqual(self.engine.audit()[0]['event'], 'revoked')

    def test_unauthorized_revocation_and_consumed_state(self):
        request = self.approved()
        with self.assertRaises(ApprovalError):
            self.engine.revoke(request, reviewer='intruder')
        self.engine.execute(self.action, lambda _: None, request_id=request)
        with self.assertRaises(ApprovalError):
            self.engine.revoke(request, reviewer='human')

    def test_policy_revert_never_revives_old_approval(self):
        request = self.approved()
        changed = Policy(self.policy.rules + (Rule('other', 'r', 'p', Decision.ALLOW),))
        newer = Engine(self.engine.database, changed, reviewers={'human'})
        with self.assertRaises(ApprovalError):
            newer.request(self.action)
        self.assertEqual(newer.activate_policy(actor='admin'), 2)
        with self.assertRaises(ApprovalError):
            self.engine.execute(self.action, lambda _: self.fail('called'), request_id=request)
        reverted = Engine(self.engine.database, self.policy, reviewers={'human'})
        self.assertEqual(reverted.activate_policy(actor='admin'), 3)
        with self.assertRaises(ApprovalError):
            reverted.execute(self.action, lambda _: self.fail('called'), request_id=request)
        self.assertFalse(reverted.inspect(request)['policy_current'])
        fresh = reverted.request(self.action)
        reverted.review(fresh, reviewer='human', approve=True)
        reverted.execute(self.action, lambda _: None, request_id=fresh)

    def test_stale_allow_worker_cannot_execute(self):
        allowed = Policy((Rule('t', 'r', 'p', Decision.ALLOW),))
        worker = Engine(self.engine.database, allowed, reviewers=set())
        worker.activate_policy(actor='admin')
        self.assertEqual(worker.execute(self.action, lambda _: 7), 7)
        self.engine.activate_policy(actor='admin')
        with self.assertRaises(ApprovalError):
            worker.execute(self.action, lambda _: self.fail('called'))

    def test_unrecognized_database_is_not_modified(self):
        for version in (0, 1, 2):
            path = self.root / f'unrelated-{version}.sqlite3'
            with contextlib.closing(sqlite3.connect(path)) as db, db:
                db.execute('CREATE TABLE unrelated(value TEXT)')
                db.execute("INSERT INTO unrelated VALUES('keep')")
                db.execute(f'PRAGMA user_version={version}')
            with self.assertRaises(ValueError):
                Engine(path, self.policy, reviewers={'human'})
            with contextlib.closing(sqlite3.connect(path)) as db:
                self.assertEqual(db.execute('SELECT value FROM unrelated').fetchone()[0], 'keep')
                self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], version)
                self.assertIsNone(db.execute("SELECT name FROM sqlite_master WHERE name='requests'").fetchone())

    def test_migrate_v1_invalidates_legacy_requests(self):
        path = self.root / 'legacy.sqlite3'
        with contextlib.closing(sqlite3.connect(path)) as db, db:
            db.execute('CREATE TABLE requests(id TEXT PRIMARY KEY, action TEXT, digest TEXT, policy TEXT, expires REAL, status TEXT, reviewer TEXT)')
            db.execute('CREATE TABLE audit(sequence INTEGER PRIMARY KEY AUTOINCREMENT,timestamp REAL,event TEXT,request_id TEXT,actor TEXT,digest TEXT)')
            db.execute('INSERT INTO requests VALUES(?,?,?,?,?,?,?)', ('legacy', json.dumps(self.action.as_dict()),
                self.action.digest, 'old-policy-digest', 2000, 'approved', 'human'))
            db.execute('PRAGMA user_version=1')
        migrated = Engine(path, self.policy, reviewers={'human'}, clock=lambda: self.now)
        self.assertFalse(migrated.inspect('legacy')['policy_current'])
        with self.assertRaises(ApprovalError):
            migrated.execute(self.action, lambda _: self.fail('called'), request_id='legacy')
        with contextlib.closing(sqlite3.connect(path)) as db:
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 2)
        self.assertEqual(migrated.audit()[0]['event'], 'schema_migrated')

    def test_failed_revocation_rolls_back(self):
        request = self.approved()
        with contextlib.closing(sqlite3.connect(self.engine.database)) as db, db:
            db.execute("CREATE TRIGGER fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'unavailable'); END")
        with self.assertRaises(sqlite3.Error):
            self.engine.revoke(request, reviewer='human')
        self.assertEqual(self.engine.inspect(request)['status'], 'approved')

    def test_backup_restore_integrity_and_invalidation(self):
        request = self.approved()
        backup = self.root / 'backup.sqlite3'
        self.assertEqual(len(backup_database(self.engine.database, backup)['sha256']), 64)
        restored = self.root / 'restored.sqlite3'
        restore_database(backup, restored, self.policy, actor='admin')
        engine = Engine(restored, self.policy, reviewers={'human'}, clock=lambda: self.now)
        with self.assertRaises(ApprovalError):
            engine.execute(self.action, lambda _: self.fail('called'), request_id=request)
        with self.assertRaises(FileExistsError):
            backup_database(self.engine.database, backup)
        with self.assertRaises(ValueError):
            backup_database(self.root / 'missing', self.root / 'unused')
        self.assertFalse((self.root / 'unused').exists())

    def test_metadata_export_and_retention_preview(self):
        request = self.approved()
        output = self.root / 'audit.jsonl'
        self.assertEqual(export_audit(self.engine.database, output)['events'], 2)
        self.assertNotIn('payload-not-exported', output.read_text())
        self.assertEqual(json.loads(output.read_text().splitlines()[-1])['event'], 'approved')
        self.now = 5000
        self.assertEqual(self.engine.prune(before=4000, actor='admin')['requests'], 1)
        self.assertEqual(self.engine.inspect(request)['status'], 'approved')
        self.assertEqual(self.engine.prune(before=4000, audit_before=4000, actor='admin', apply=True),
                         {'requests': 1, 'audit': 2})
        self.assertEqual(self.engine.audit()[0]['event'], 'retention_applied')
        with self.assertRaises(ApprovalError):
            self.engine.inspect(request)
        with self.assertRaises(ValueError):
            self.engine.prune(before=6000, actor='admin')

    def test_maintenance_cli_and_revocation(self):
        import io
        from agentguard.cli import main
        config = self.root / 'policy.json'
        config.write_text(json.dumps({'rules': [{'tool': 't', 'resource': 'r', 'principal': 'p', 'decision': 'approval'}]}))
        args = ['--db', str(self.engine.database), '--policy', str(config), '--reviewer', 'human']
        def run(tail):
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                return main(args + tail)
        request = self.approved()
        self.assertEqual(run(['revoke', request, '--as', 'human']), 0)
        self.assertEqual(self.engine.inspect(request)['status'], 'revoked')
        backup = str(self.root / 'backup.sqlite3')
        self.assertEqual(run(['backup', backup]), 0)
        self.assertEqual(run(['backup', backup]), 1)
        self.assertEqual(run(['export-audit', str(self.root / 'audit.jsonl')]), 0)
        self.assertEqual(run(['activate-policy', '--as', 'admin']), 0)
        self.assertEqual(run(['restore', backup, str(self.root / 'restored.sqlite3'), '--as', 'admin']), 0)
        self.assertEqual(run(['prune', '--before', '0', '--as', 'admin']), 0)

    def test_migration_failure_rolls_back_schema(self):
        path = self.root / 'legacy-failure.sqlite3'
        with contextlib.closing(sqlite3.connect(path)) as db, db:
            db.execute('CREATE TABLE requests(id TEXT PRIMARY KEY,action TEXT,digest TEXT,policy TEXT,expires REAL,status TEXT,reviewer TEXT)')
            db.execute('CREATE TABLE audit(sequence INTEGER PRIMARY KEY AUTOINCREMENT,timestamp REAL,event TEXT,request_id TEXT,actor TEXT,digest TEXT)')
            db.execute("CREATE TRIGGER fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'unavailable'); END")
            db.execute('PRAGMA user_version=1')
        with self.assertRaises(sqlite3.Error):
            Engine(path, self.policy, reviewers={'human'})
        with contextlib.closing(sqlite3.connect(path)) as db:
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 1)
            columns = {r[1] for r in db.execute('PRAGMA table_info(requests)')}
            self.assertNotIn('generation', columns)
        # Backup must remain usable before a v1 engine migration is possible.
        import io
        from agentguard.cli import main
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(['--db', str(path), 'backup', str(self.root / 'legacy-backup.sqlite3')]), 0)
        with contextlib.closing(sqlite3.connect(path)) as db:
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 1)


class NoteTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'notes'
        self.writer = NoteWriter(self.root)

    def action(self, filename='approved-note.txt', text='A real note'):
        return Action('notes.create', 'local-notes', 'demo-agent', {'filename': filename, 'text': text})

    def test_real_write_only_after_approval_and_no_overwrite(self):
        policy_file = Path(__file__).resolve().parents[1] / 'examples/notes-policy.json'
        policy = Policy.from_dict(json.loads(policy_file.read_text()))
        engine = Engine(self.root.parent / 'state.sqlite3', policy, reviewers={'operator'})
        action = self.action()
        with self.assertRaises(ApprovalError):
            engine.execute(action, self.writer)
        self.assertFalse((self.root / 'approved-note.txt').exists())
        request = engine.request(action)
        engine.review(request, reviewer='operator', approve=True)
        engine.execute(action, self.writer, request_id=request)
        self.assertEqual((self.root / 'approved-note.txt').read_text(), 'A real note')
        with self.assertRaises(FileExistsError):
            self.writer(action)

    def test_path_traversal_device_names_types_and_limits(self):
        for filename in ('../escape.txt', '/absolute.txt', 'C:\\escape.txt', '.hidden.txt', 'CON.txt',
                         'NUL.txt', 'com1.txt', 'sub/name.txt', 'name.txt:stream', 'name.txt.', 'a' * 65 + '.txt'):
            with self.subTest(filename=filename), self.assertRaises(ValueError):
                self.writer(self.action(filename))
        for text in ('', '\x00', 'a' * 2049):
            with self.assertRaises(ValueError):
                self.writer(self.action(text=text))
        self.assertEqual(list(self.root.iterdir()), [])

    @unittest.skipUnless(os.name == 'posix', 'POSIX symlink security test')
    def test_symlink_target_and_symlink_root(self):
        outside = self.root.parent / 'outside.txt'
        outside.write_text('unchanged')
        (self.root / 'approved-note.txt').symlink_to(outside)
        with self.assertRaises(FileExistsError):
            self.writer(self.action())
        self.assertEqual(outside.read_text(), 'unchanged')
        link = self.root.parent / 'link'
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            NoteWriter(link)
