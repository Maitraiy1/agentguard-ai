"""Trusted local backup, restore and metadata-only audit export helpers."""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from contextlib import closing
from pathlib import Path

from .core import Policy
from .engine import Engine


def private_create(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb')


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(65536), b''):
            digest.update(block)
    return digest.hexdigest()


def backup_database(source: str | Path, destination: str | Path) -> dict:
    source, destination = Path(source), Path(destination)
    # mode=ro refuses missing sources. Exclusive creation refuses existing targets/symlinks.
    if not source.is_file():
        raise ValueError('Source database does not exist')
    with private_create(destination):
        pass
    try:
        deadline = time.monotonic() + 30
        def progress(status, remaining, total):
            if time.monotonic() > deadline:
                raise TimeoutError('Backup exceeded 30 seconds; stop writers and retry')
        with closing(sqlite3.connect(source.resolve().as_uri() + '?mode=ro', uri=True)) as src:
            with closing(sqlite3.connect(destination)) as dst:
                src.backup(dst, pages=256, progress=progress, sleep=0.1)
                if dst.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
                    raise ValueError('Backup integrity check failed')
        return {'path': str(destination), 'sha256': file_digest(destination)}
    except BaseException:
        destination.unlink(missing_ok=True)
        raise


def restore_database(source: str | Path, destination: str | Path, policy: Policy, *, actor: str) -> dict:
    """Restore to a NEW path and invalidate historical approvals before use."""
    with closing(sqlite3.connect(Path(source).resolve().as_uri() + '?mode=ro', uri=True)) as db:
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        version = db.execute('PRAGMA user_version').fetchone()[0]
        if not {'requests', 'audit'} <= tables or version not in (1, 2):
            raise ValueError('Restore requires a supported AgentGuard backup')
    backup_database(source, destination)
    try:
        engine = Engine(destination, policy, reviewers=set())
        generation = engine.activate_policy(actor=actor)
        return {'path': str(destination), 'generation': generation,
                'sha256': file_digest(Path(destination))}
    except BaseException:
        Path(destination).unlink(missing_ok=True)
        raise


def export_audit(database: str | Path, destination: str | Path) -> dict:
    destination = Path(destination)
    output = private_create(destination)
    try:
        with output, closing(sqlite3.connect(Path(database).resolve().as_uri() + '?mode=ro', uri=True)) as db:
            db.row_factory = sqlite3.Row
            db.execute('BEGIN')
            cursor = db.execute('SELECT sequence,timestamp,event,request_id,actor,digest FROM audit ORDER BY sequence')
            count = 0
            for row in cursor:
                output.write((json.dumps(dict(row), sort_keys=True, ensure_ascii=True) + '\n').encode())
                count += 1
            output.flush()
            os.fsync(output.fileno())
        return {'path': str(destination), 'events': count, 'sha256': file_digest(destination)}
    except BaseException:
        output.close()
        destination.unlink(missing_ok=True)
        raise
