"""Purpose-built create-only text note adapter for a trusted private directory."""
from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import stat
import sys
from pathlib import Path

from .core import Action
from .demo_runner import load_policy, wait_and_execute
from .engine import Engine

RESERVED = {'CON', 'PRN', 'AUX', 'NUL'} | {f'{prefix}{i}' for prefix in ('COM', 'LPT') for i in range(1, 10)}


class NoteWriter:
    """Trusted host adapter; approval is enforced by calling through Engine.execute."""
    def __init__(self, root: str | Path):
        self.root = Path(root).absolute()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Reject visible symlinks and Windows junction/reparse components. The host must
        # keep this path and its parents outside the agent's write permissions.
        for component in (self.root, *self.root.parents):
            info = component.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
                raise ValueError('Notes directory must not contain symlinks or reparse points')
        if not self.root.is_dir():
            raise ValueError('Notes root must be a directory')

    def __call__(self, action: Action) -> str:
        if (action.tool, action.resource, action.principal) != ('notes.create', 'local-notes', 'demo-agent'):
            raise ValueError('Unsupported note action identity')
        values = action.parameters
        if set(values) != {'filename', 'text'}:
            raise ValueError('Note requires exactly filename and text')
        filename, text = values['filename'], values['text']
        if type(filename) is not str or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}\.txt', filename) is None:
            raise ValueError('Use a flat ASCII .txt filename, without paths or traversal')
        if filename[:-4].upper() in RESERVED:
            raise ValueError('Reserved Windows filename')
        if type(text) is not str or not text or '\x00' in text or len(text) > 2048:
            raise ValueError('Text must contain 1–2048 characters without NUL')
        encoded = text.encode('utf-8')
        if len(encoded) > 8192:
            raise ValueError('Text exceeds 8192 UTF-8 bytes')
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
        if os.name == 'posix':
            directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                descriptor = os.open(filename, flags, 0o600, dir_fd=directory)
            finally:
                os.close(directory)
        else:
            descriptor = os.open(self.root / filename, flags, 0o600)
        # O_EXCL means even existing symlinks/hard links cannot be overwritten.
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        return str(self.root / filename)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Create a real local text note after dashboard approval')
    parser.add_argument('--db', default='.agentguard/notes.sqlite3')
    parser.add_argument('--policy', default='examples/notes-policy.json')
    parser.add_argument('--root', default='.agentguard/notes')
    parser.add_argument('--reviewer', default='operator')
    parser.add_argument('--filename', default='approved-note.txt')
    parser.add_argument('--text', default='This note was created only after my approval.')
    parser.add_argument('--ttl', type=int, default=300)
    args = parser.parse_args(argv)
    try:
        # Keep this integration's policy/database separate from the original console demo.
        writer = NoteWriter(args.root)
        policy_path = Path(args.policy)
        engine = Engine(args.db, load_policy(policy_path), reviewers={args.reviewer})
        action = Action('notes.create', 'local-notes', 'demo-agent',
                        {'filename': args.filename, 'text': args.text})
        request_id = engine.request(action, ttl=args.ttl)
        print('Request ID:', request_id, flush=True)
        print(json.dumps(action.as_dict(), indent=2), flush=True)
        print('Refresh the dashboard using the notes policy/database and inspect this ID.', flush=True)
        outcome = wait_and_execute(engine, action, request_id, timeout=args.ttl, handler=writer,
                                   current_policy=lambda: load_policy(policy_path))
        print('Result:', outcome, flush=True)
        if outcome == 'executed':
            print('Created:', writer.root / args.filename, flush=True)
            return 0
        return 2
    except KeyboardInterrupt:
        print('Stopped; inspect audit before retrying.', file=sys.stderr)
        return 130
    except (OSError, ValueError, TypeError, RecursionError, sqlite3.Error) as error:
        print(f'Notes error: {error}. Inspect audit before retrying.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
