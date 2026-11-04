"""Password-authenticated, loopback-only reviewer dashboard. No execution endpoint."""
from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import html
import json
import os
import secrets
import sqlite3
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlsplit

from .core import Action, Policy, label, strict_json
from .engine import ApprovalError, Engine

COOKIE = "agentguard_session"
MAX_BODY = 8192


def password_hash(password: str, salt: bytes) -> str:
    return hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32).hex()


@dataclass(frozen=True)
class Credentials:
    reviewer: str
    salt: bytes
    digest: str

    @classmethod
    def create(cls, reviewer: str, password: str) -> Credentials:
        label(reviewer, "reviewer")
        if not 12 <= len(password) <= 256:
            raise ValueError("Use a password of 12–256 characters")
        salt = secrets.token_bytes(16)
        return cls(reviewer, salt, password_hash(password, salt))

    def verify(self, password: str) -> bool:
        return len(password) <= 256 and hmac.compare_digest(
            self.digest, password_hash(password, self.salt))

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Exclusive create prevents accidental overwrite of existing credentials.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump({"version": 1, "reviewer": self.reviewer,
                       "salt": self.salt.hex(), "digest": self.digest}, stream)

    @classmethod
    def load(cls, path: Path) -> Credentials:
        with path.open(encoding="utf-8") as stream:
            data = strict_json(stream.read(65537))
        if type(data) is not dict or set(data) != {"version", "reviewer", "salt", "digest"}:
            raise ValueError("Invalid credential file")
        if type(data["version"]) is not int or data["version"] != 1:
            raise ValueError("Unsupported credential version")
        label(data["reviewer"], "reviewer")
        salt = bytes.fromhex(data["salt"])
        digest = bytes.fromhex(data["digest"])
        if len(salt) != 16 or len(digest) != 32:
            raise ValueError("Invalid credential hash")
        return cls(data["reviewer"], salt, digest.hex())


@dataclass
class Session:
    csrf: str
    created: float
    used: float


class Dashboard(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, engine: Engine, credentials: Credentials, *, port: int = 8765,
                 clock=time.monotonic):
        if type(port) is not int or not 0 <= port <= 65535:
            raise ValueError("Invalid port")
        if credentials.reviewer not in engine.reviewers:
            raise ValueError("Dashboard reviewer must be in the engine allowlist")
        self.engine = engine
        self.credentials = credentials
        self.clock = clock
        self.sessions: dict[str, Session] = {}
        self.failures: list[float] = []
        self.auth_lock = threading.Lock()
        super().__init__(("127.0.0.1", port), Handler)
        self.origin = f"http://127.0.0.1:{self.server_port}"
        self.host = f"127.0.0.1:{self.server_port}"

    def _prune(self) -> None:
        now = self.clock()
        self.sessions = {key: value for key, value in self.sessions.items()
                         if now - value.created < 1800 and now - value.used < 900}
        self.failures = [stamp for stamp in self.failures if now - stamp < 60]

    def login(self, password: str) -> tuple[str | None, bool]:
        with self.auth_lock:
            self._prune()
            if len(self.failures) >= 5:
                return None, True
            if not self.credentials.verify(password):
                self.failures.append(self.clock())
                return None, False
            if len(self.sessions) >= 64:
                self.sessions.pop(next(iter(self.sessions)))
            token = secrets.token_urlsafe(32)
            self.sessions[token] = Session(secrets.token_urlsafe(32), self.clock(), self.clock())
            return token, False

    def session(self, token: str) -> Session | None:
        with self.auth_lock:
            self._prune()
            session = self.sessions.get(token)
            if session is not None:
                session.used = self.clock()
            return session

    def logout(self, token: str) -> None:
        with self.auth_lock:
            self.sessions.pop(token, None)


STYLE = """
:root{color-scheme:light;font:16px system-ui;background:#f1f5f9;color:#162135}
body{margin:0}header{background:#11243b;color:white;padding:22px 6vw;display:flex;
justify-content:space-between;align-items:center}header a{color:white}main{max-width:1100px;
margin:32px auto;padding:0 24px}h1{font-size:27px;margin:0}h2{font-size:21px}
a{color:#175c96}nav{display:flex;gap:18px;margin:20px 0}.card{background:white;padding:24px;
border:1px solid #dbe3ec;border-radius:12px;margin:18px 0}table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:12px;border-bottom:1px solid #e2e8f0;overflow-wrap:anywhere}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f1f5f9;padding:16px;border-radius:8px}
button{background:#145e93;color:white;border:0;border-radius:6px;padding:11px 18px;cursor:pointer}
button.deny{background:#a13439}input{display:block;box-sizing:border-box;width:100%;padding:12px;
margin:12px 0;border:1px solid #8796a8;border-radius:6px}form.inline{display:inline-block;
margin-right:12px}.muted{color:#56677c}.badge{padding:4px 9px;background:#e6eef7;
border-radius:20px;font-size:13px}.login{max-width:420px;margin:70px auto}
.wrap{overflow-x:auto}.fine{font-size:13px}code{overflow-wrap:anywhere}
"""


def escape(value) -> str:
    return html.escape(str(value), quote=True)


def timestamp(value: float) -> str:
    return datetime.fromtimestamp(value, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


class Handler(BaseHTTPRequestHandler):
    server: Dashboard
    server_version = "AgentGuard"
    sys_version = ""

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, format, *args):
        # Avoid logging request bodies, passwords, session IDs or payloads.
        pass

    def _send(self, status: int, body: str = "", *, location: str | None = None,
              cookie: str | None = None) -> None:
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        # no-referrer makes browser form POSTs send Origin: null. Preserve the
        # same-origin form origin without sending referrers to other sites.
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; "
                         "form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
        self.send_header("Connection", "close")
        if location:
            self.send_header("Location", location)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(raw)
        self.close_connection = True

    def _valid_host(self) -> bool:
        if self.headers.get_all("Host", []) != [self.server.host]:
            self._send(403, "Host rejected. Use the exact printed 127.0.0.1 URL.")
            return False
        return True

    def _token(self) -> str:
        try:
            cookies = SimpleCookie()
            cookies.load(self.headers.get("Cookie", ""))
            return cookies[COOKIE].value if COOKIE in cookies else ""
        except Exception:
            return ""

    def _page(self, title: str, content: str, session: Session | None = None) -> str:
        logout = ""
        nav = ""
        if session:
            logout = (f'<form method="post" action="/logout"><input type="hidden" name="csrf" '
                      f'value="{escape(session.csrf)}"><button>Sign out</button></form>')
            nav = '<nav><a href="/">Requests</a><a href="/audit">Audit history</a></nav>'
        return (f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
                f'<meta name="viewport" content="width=device-width, initial-scale=1">'
                f'<title>{escape(title)} · AgentGuard AI</title><style>{STYLE}</style></head>'
                f'<body><header><div><h1>AgentGuard AI</h1><small>Local approval dashboard</small>'
                f'</div>{logout}</header><main>{nav}{content}'
                '<p class="muted fine">Local evaluation dashboard · No tools execute from this page.'
                '</p></main></body></html>')

    def do_GET(self):
        if not self._valid_host():
            return
        path = urlsplit(self.path).path
        session = self.server.session(self._token())
        if path == "/login":
            content = ('<section class="card login"><h2>Reviewer sign in</h2>'
                       f'<p>Reviewer: <strong>{escape(self.server.credentials.reviewer)}</strong></p>'
                       '<form method="post" action="/login"><label for="password">Password</label>'
                       '<input id="password" name="password" type="password" required '
                       'maxlength="256" autocomplete="current-password">'
                       '<button type="submit">Sign in</button></form></section>')
            self._send(200, self._page("Sign in", content))
            return
        if not session:
            self._send(303, location="/login")
            return
        try:
            if path == "/":
                rows = self.server.engine.list_requests(limit=100)
                content = ('<h2>Approval requests</h2><p class="muted">Latest 100 requests. '
                           'Open a request to inspect its full payload. Refresh to see updates.</p>'
                           '<section class="card wrap"><table><tr><th>Action / resource</th>'
                           '<th>Requester</th><th>Status</th><th>Expires</th><th></th></tr>')
                for row in rows:
                    action = row["action"]
                    content += (f'<tr><td>{escape(action["tool"])}<br>'
                                f'<small>{escape(action["resource"])}</small></td>'
                                f'<td>{escape(action["principal"])}</td>'
                                f'<td><span class="badge">{escape(self._status(row))}</span></td>'
                                f'<td>{escape(timestamp(row["expires"]))}</td>'
                                f'<td><a href="/request/{quote(row["id"], safe="")}">Inspect</a></td></tr>')
                content += '</table>'
                if not rows:
                    content += '<p>No requests yet. Create one with the AgentGuard CLI.</p>'
                content += '</section>'
            elif path.startswith("/request/"):
                row = self.server.engine.inspect(path.removeprefix("/request/"))
                content = (f'<h2>Inspect request</h2><section class="card"><p>Status: '
                           f'<strong>{escape(self._status(row))}</strong></p>'
                           f'<p>Expires: {escape(timestamp(row["expires"]))}</p>'
                           '<h3>Exact action payload</h3>'
                           f'<pre>{escape(json.dumps(row["action"], indent=2, ensure_ascii=True))}</pre>'
                           f'<p class="fine">Action hash: <code>{escape(row["digest"])}</code></p>'
                           f'<p class="fine">Request: <code>{escape(row["id"])}</code></p>')
                if self._status(row) == "pending":
                    content += '<p>Review every parameter before deciding. Approval does not execute the tool.</p>'
                    for decision, text in (("approve", "Approve action"), ("deny", "Deny action")):
                        content += (f'<form class="inline" method="post" action="/review">'
                                    f'<input type="hidden" name="csrf" value="{escape(session.csrf)}">'
                                    f'<input type="hidden" name="request_id" value="{escape(row["id"])}">'
                                    f'<input type="hidden" name="decision" value="{decision}">'
                                    f'<button class="{decision}" type="submit">{text}</button></form>')
                content += '</section>'
            elif path == "/audit":
                content = ('<h2>Audit history</h2><p class="muted">Latest 100 events, newest first. '
                           'Parameters and exception messages are not included.</p>'
                           '<section class="card wrap"><table><tr><th>Time</th><th>Event</th>'
                           '<th>Actor</th><th>Action hash</th></tr>')
                for row in self.server.engine.audit():
                    content += (f'<tr><td>{escape(timestamp(row["timestamp"]))}</td>'
                                f'<td>{escape(row["event"])}</td><td>{escape(row["actor"])}</td>'
                                f'<td class="fine"><code>{escape(row["digest"])}</code></td></tr>')
                content += '</table></section>'
            else:
                self._send(404, self._page("Not found", '<h2>Page not found</h2>', session))
                return
            self._send(200, self._page("Review", content, session))
        except ApprovalError:
            self._send(404, "Request not found")
        except (sqlite3.Error, ValueError, TypeError, KeyError):
            self._send(503, "Unable to load dashboard data. Check the trusted server configuration.")

    def _status(self, row: dict) -> str:
        if row["status"] in ("pending", "approved"):
            if row["policy"] != self.server.engine.policy.digest:
                return "policy changed"
            if self.server.engine.clock() >= row["expires"]:
                return "expired"
        return row["status"]

    def do_POST(self):
        if not self._valid_host():
            return
        if self.headers.get_all("Origin", []) != [self.server.origin]:
            self._send(403, "Origin rejected")
            return
        if self.headers.get("Transfer-Encoding") or len(self.headers.get_all("Content-Length", [])) != 1:
            self._send(400, "Invalid body framing")
            return
        if self.headers.get_content_type() != "application/x-www-form-urlencoded":
            self._send(415, "Form encoding required")
            return
        try:
            length = int(self.headers["Content-Length"])
            if not 0 < length <= MAX_BODY:
                self._send(413, "Form too large")
                return
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError("Incomplete body")
            parsed = parse_qs(raw.decode("utf-8"), strict_parsing=True, max_num_fields=8)
            if any(len(values) != 1 for values in parsed.values()):
                raise ValueError("Duplicate form fields")
            form = {key: values[0] for key, values in parsed.items()}
        except (ValueError, UnicodeError, TimeoutError):
            self._send(400, "Invalid form")
            return
        if self.path == "/login":
            if set(form) != {"password"}:
                self._send(400, "Invalid login form")
                return
            token, throttled = self.server.login(form["password"])
            if not token:
                self._send(429 if throttled else 401,
                           "Too many attempts. Wait 60 seconds." if throttled else "Invalid password. Return to /login.")
                return
            self._send(303, location="/", cookie=f"{COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=1800")
            return
        token = self._token()
        session = self.server.session(token)
        if not session:
            self._send(401, "Sign in required")
            return
        if not hmac.compare_digest(form.get("csrf", "").encode(), session.csrf.encode()):
            self._send(403, "CSRF token rejected")
            return
        if self.path == "/logout" and set(form) == {"csrf"}:
            self.server.logout(token)
            self._send(303, location="/login", cookie=f"{COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
        elif self.path == "/review" and set(form) == {"csrf", "request_id", "decision"}:
            if form["decision"] not in ("approve", "deny"):
                self._send(400, "Unknown decision")
                return
            try:
                self.server.engine.review(form["request_id"], reviewer=self.server.credentials.reviewer,
                                          approve=form["decision"] == "approve")
            except ApprovalError as error:
                self._send(409, self._page("Review blocked", f'<h2>Review blocked</h2><p>{escape(error)}</p>', session))
                return
            except sqlite3.Error:
                self._send(503, "Storage unavailable; decision not confirmed. Refresh the request.")
                return
            self._send(303, location="/request/" + quote(form["request_id"], safe=""))
        else:
            self._send(400, "Unknown route or form fields")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Loopback-only AgentGuard reviewer dashboard")
    parser.add_argument("--credentials", default=".agentguard/dashboard.json")
    parser.add_argument("--db", default=".agentguard/state.sqlite3")
    parser.add_argument("--policy", default="examples/policy.json")
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init")
    init.add_argument("--reviewer", default="operator")
    serve = commands.add_parser("serve")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--demo", action="store_true", help="Create one sample request; executes nothing")
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            password = getpass.getpass("Create dashboard password (12+ characters): ")
            if password != getpass.getpass("Confirm password: "):
                raise ValueError("Passwords do not match")
            Credentials.create(args.reviewer, password).save(Path(args.credentials))
            print("Reviewer configured. Start with: python -m agentguard.dashboard serve --demo")
            return 0
        credentials = Credentials.load(Path(args.credentials))
        with Path(args.policy).open(encoding="utf-8") as stream:
            policy = Policy.from_dict(strict_json(stream.read(65537)))
        engine = Engine(args.db, policy, reviewers={credentials.reviewer})
        with Dashboard(engine, credentials, port=args.port) as server:
            if args.demo:
                engine.request(Action("notes.publish", "notes/demo", "demo-agent",
                                      {"text": "Hello from the dashboard demo"}), ttl=3600)
            print(f"Open {server.origin} in your browser. Reviewer: {credentials.reviewer}", flush=True)
            print("Local evaluation only. Press Ctrl+C to stop.", flush=True)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
        return 0
    except (OSError, ValueError, TypeError, sqlite3.Error, EOFError) as error:
        print(f"Dashboard error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
