"""Console security: user accounts, roles, API tokens and an audit trail.

Stored in ``data/console.db`` (separate from every workspace's analysis database).

* Passwords: PBKDF2-HMAC-SHA256, 310,000 iterations, 16-byte random salt per user;
  only the hash is stored. Compared in constant time.
* Brute-force protection: 5 failed logins lock the account for 15 minutes.
* Roles:
    - ``viewer``  - read-only
    - ``analyst`` - + triage alerts (benign / threat verdicts)
    - ``admin``   - + data sources, analysis, workspace settings, users, API tokens
* API tokens (for agents / log shippers pushing to the ingest API): random 32-byte
  tokens, shown once at creation, stored as SHA-256; each is scoped to one workspace
  (or ``*``) and can be revoked.
* Audit log: logins (and failures), verdicts, uploads, analyses, settings, users, tokens.
"""
from __future__ import annotations

import contextlib
import hashlib
import hmac
import secrets
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd

from .config import DATA_DIR

CONSOLE_DB = DATA_DIR / "console.db"
ROLES = ("viewer", "analyst", "admin")
PBKDF2_ITER = 310_000
MAX_FAILS, LOCK_MINUTES = 5, 15
MIN_PASSWORD = 8


@contextlib.contextmanager
def _con(db: Path | None = None):
    """One short transaction: commit on success, roll back on error, always close."""
    db = Path(db or CONSOLE_DB)
    db.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(db, timeout=10)
    try:
        _schema(con)
        yield con
        con.commit()
    except BaseException:
        con.rollback()
        raise
    finally:
        con.close()


def _schema(con: sqlite3.Connection):
    con.execute("""CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY, pw_hash TEXT, salt TEXT, role TEXT, created TEXT,
        last_login TEXT, failed INTEGER DEFAULT 0, locked_until TEXT)""")
    con.execute("""CREATE TABLE IF NOT EXISTS tokens (
        token_id TEXT PRIMARY KEY, name TEXT, token_hash TEXT, workspace TEXT,
        created_by TEXT, created TEXT, last_used TEXT, revoked INTEGER DEFAULT 0)""")
    con.execute("""CREATE TABLE IF NOT EXISTS audit (
        ts TEXT, username TEXT, action TEXT, workspace TEXT, detail TEXT)""")


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _hash(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITER).hex()


# ------------------------------------------------------------------ users
def has_users(db: Path | None = None) -> bool:
    with _con(db) as con:
        return con.execute("SELECT COUNT(*) FROM users").fetchone()[0] > 0


def create_user(username: str, password: str, role: str = "analyst", by: str = "setup",
                db: Path | None = None) -> None:
    username = username.strip().lower()
    if not username or not username.replace(".", "").replace("_", "").replace("-", "").isalnum():
        raise ValueError("Username: letters, digits, '.', '_' or '-'")
    if role not in ROLES:
        raise ValueError(f"Role must be one of {ROLES}")
    if len(password) < MIN_PASSWORD:
        raise ValueError(f"Password must be at least {MIN_PASSWORD} characters")
    salt = secrets.token_bytes(16)
    with _con(db) as con:
        if con.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
            raise ValueError(f"User '{username}' already exists")
        con.execute("INSERT INTO users (username, pw_hash, salt, role, created) VALUES (?,?,?,?,?)",
                    (username, _hash(password, salt), salt.hex(), role, _now()))
    audit(by, "user.create", detail=f"{username} ({role})", db=db)


def authenticate(username: str, password: str, db: Path | None = None) -> dict:
    """Return the user record, or raise ValueError with a message safe to show."""
    username = username.strip().lower()
    generic = "Wrong username or password"
    outcome, detail, role = "login", "", None
    with _con(db) as con:
        row = con.execute("SELECT pw_hash, salt, role, failed, locked_until FROM users WHERE username=?",
                          (username,)).fetchone()
        if row is None:
            _hash(password, b"timing-equaliser")      # same cost as a real check
            outcome, detail = "login.failed", "unknown user"
        else:
            pw_hash, salt, role, failed, locked = row
            if locked and datetime.fromisoformat(locked) > datetime.now():
                outcome, detail = "login.blocked", f"locked until {locked}"
            elif not hmac.compare_digest(_hash(password, bytes.fromhex(salt)), pw_hash):
                failed = (failed or 0) + 1
                until = (datetime.now() + timedelta(minutes=LOCK_MINUTES)).isoformat(timespec="seconds") \
                    if failed >= MAX_FAILS else None
                con.execute("UPDATE users SET failed=?, locked_until=? WHERE username=?",
                            (0 if until else failed, until, username))
                outcome, detail = "login.failed", "account locked" if until else f"attempt {failed}"
            else:
                con.execute("UPDATE users SET failed=0, locked_until=NULL, last_login=? WHERE username=?",
                            (_now(), username))
    audit(username, outcome, detail=detail, db=db)      # after the transaction above has committed
    if outcome == "login.blocked":
        raise ValueError(f"Account locked after {MAX_FAILS} failed attempts - try again after {locked[11:16]}")
    if outcome != "login":
        raise ValueError(generic)
    return dict(username=username, role=role)


def list_users(db: Path | None = None) -> pd.DataFrame:
    with _con(db) as con:
        return pd.read_sql("SELECT username, role, created, last_login, locked_until FROM users ORDER BY username", con)


def set_role(username: str, role: str, by: str, db: Path | None = None):
    if role not in ROLES:
        raise ValueError(f"Role must be one of {ROLES}")
    with _con(db) as con:
        admins = con.execute("SELECT username FROM users WHERE role='admin'").fetchall()
        if role != "admin" and [(username,)] == admins:
            raise ValueError("Can't demote the last admin")
        con.execute("UPDATE users SET role=? WHERE username=?", (role, username))
    audit(by, "user.role", detail=f"{username} -> {role}", db=db)


def set_password(username: str, password: str, by: str, db: Path | None = None):
    if len(password) < MIN_PASSWORD:
        raise ValueError(f"Password must be at least {MIN_PASSWORD} characters")
    salt = secrets.token_bytes(16)
    with _con(db) as con:
        con.execute("UPDATE users SET pw_hash=?, salt=?, failed=0, locked_until=NULL WHERE username=?",
                    (_hash(password, salt), salt.hex(), username))
    audit(by, "user.password", detail=username, db=db)


def change_password(username: str, old: str, new: str, db: Path | None = None):
    """A user changing their own password: the current one must be right."""
    authenticate(username, old, db=db)          # raises (and audits) on a wrong password
    if old == new:
        raise ValueError("The new password must differ from the current one")
    set_password(username, new, by=username, db=db)


def delete_user(username: str, by: str, db: Path | None = None):
    with _con(db) as con:
        admins = [r[0] for r in con.execute("SELECT username FROM users WHERE role='admin'")]
        if admins == [username]:
            raise ValueError("Can't delete the last admin")
        con.execute("DELETE FROM users WHERE username=?", (username,))
    audit(by, "user.delete", detail=username, db=db)


def can(user: dict | None, action: str) -> bool:
    """Permission check. Actions: view, triage, manage."""
    need = {"view": "viewer", "triage": "analyst", "manage": "admin"}[action]
    return bool(user) and ROLES.index(user["role"]) >= ROLES.index(need)


# ------------------------------------------------------------------ API tokens
def create_token(name: str, workspace: str, by: str, db: Path | None = None) -> str:
    """Create an ingest token. Returns the secret - it is never shown again."""
    secret = "ueba_" + secrets.token_urlsafe(32)
    token_id = secrets.token_hex(4)
    with _con(db) as con:
        con.execute("INSERT INTO tokens (token_id, name, token_hash, workspace, created_by, created) "
                    "VALUES (?,?,?,?,?,?)",
                    (token_id, name.strip() or "token", hashlib.sha256(secret.encode()).hexdigest(),
                     workspace, by, _now()))
    audit(by, "token.create", workspace=workspace, detail=f"{token_id} {name}", db=db)
    return secret


def verify_token(secret: str, workspace: str, db: Path | None = None) -> dict | None:
    """Token record if valid for ``workspace`` (or scoped to '*'), else None."""
    if not secret:
        return None
    h = hashlib.sha256(secret.encode()).hexdigest()
    with _con(db) as con:
        rows = con.execute("SELECT token_id, name, token_hash, workspace FROM tokens WHERE revoked=0").fetchall()
        for token_id, name, th, scope in rows:
            if hmac.compare_digest(th, h):
                if scope not in ("*", workspace):
                    return None
                con.execute("UPDATE tokens SET last_used=? WHERE token_id=?", (_now(), token_id))
                return dict(token_id=token_id, name=name, workspace=scope)
    return None


def list_tokens(db: Path | None = None) -> pd.DataFrame:
    with _con(db) as con:
        return pd.read_sql("SELECT token_id, name, workspace, created_by, created, last_used, revoked "
                           "FROM tokens ORDER BY created DESC", con)


def revoke_token(token_id: str, by: str, db: Path | None = None):
    with _con(db) as con:
        con.execute("UPDATE tokens SET revoked=1 WHERE token_id=?", (token_id,))
    audit(by, "token.revoke", detail=token_id, db=db)


# ------------------------------------------------------------------ audit
def audit(username: str, action: str, workspace: str = "", detail: str = "", db: Path | None = None):
    with _con(db) as con:
        con.execute("INSERT INTO audit VALUES (?,?,?,?,?)", (_now(), username, action, workspace, detail[:500]))


def audit_log(limit: int = 500, db: Path | None = None) -> pd.DataFrame:
    with _con(db) as con:
        return pd.read_sql("SELECT * FROM audit ORDER BY ts DESC, rowid DESC LIMIT ?", con, params=(limit,))
