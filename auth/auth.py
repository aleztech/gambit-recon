# auth/auth.py
import os
import json
import time
from pathlib import Path
from typing import Optional, Dict, Any

try:
    import bcrypt  # type: ignore
except Exception:
    bcrypt = None  # type: ignore

# Product defaults (outside repo)
DEFAULT_USERS_FILE = Path.home() / ".config" / "gambit-recon" / "users.json"
DEFAULT_AUDIT_FILE = Path.home() / ".local" / "state" / "gambit-recon" / "audit.log"

# TTL seconds for session validity. 0 disables TTL.
DEFAULT_SESSION_TTL = int((os.environ.get("GAMBIT_SESSION_TTL") or "0").strip() or "0")


def _users_file() -> Path:
    p = (os.environ.get("GAMBIT_USERS_FILE") or "").strip()
    return Path(p) if p else DEFAULT_USERS_FILE


def _audit_file() -> Path:
    p = (os.environ.get("GAMBIT_AUDIT_FILE") or "").strip()
    return Path(p) if p else DEFAULT_AUDIT_FILE


def _load_users() -> Dict[str, Any]:
    """
    Loads users map: { "username": { "password_hash": "...", "role": "...", "enabled": true } }
    Accepts either {"users": {...}} or direct dict {...}.
    """
    p = _users_file()
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("users"), dict):
            return data["users"]
        if isinstance(data, dict):
            return data
        return {}
    except Exception:
        return {}


def _ensure_secure_paths():
    """
    Ensures parent dirs exist. Does NOT create users file.
    """
    uf = _users_file()
    af = _audit_file()
    uf.parent.mkdir(parents=True, exist_ok=True)
    af.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(uf.parent, 0o700)
    except Exception:
        pass


def audit(event: str, username: str = "", meta: Optional[Dict[str, Any]] = None):
    """
    Append-only JSONL audit. Keep it simple and reliable.
    """
    _ensure_secure_paths()
    p = _audit_file()
    rec = {
        "ts": int(time.time()),
        "event": event,
        "user": username or "",
        "meta": meta or {},
    }
    line = json.dumps(rec, ensure_ascii=False)
    with p.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def session_is_valid(auth_obj: Dict[str, Any]) -> bool:
    """
    Validates session shape and TTL (if enabled).
    """
    if not auth_obj or not isinstance(auth_obj, dict):
        return False
    if not auth_obj.get("username") or not auth_obj.get("role"):
        return False

    ttl = DEFAULT_SESSION_TTL
    if ttl and ttl > 0:
        login_ts = int(auth_obj.get("login_ts") or 0)
        if not login_ts:
            return False
        if int(time.time()) - login_ts > ttl:
            return False

    return True


def authenticate(username: str, password: str) -> Optional[Dict[str, str]]:
    """
    Authenticates against local users file (outside repo).
    Returns {"username": <u>, "role": <role>} if ok, else None.
    """
    if not username or not password:
        return None
    if bcrypt is None:
        # Fail closed if bcrypt not installed
        return None

    _ensure_secure_paths()
    users = _load_users()
    u = users.get(username)

    if not u or not isinstance(u, dict):
        return None
    if u.get("enabled") is False:
        return None

    stored = (u.get("password_hash") or "").strip()
    if not stored:
        return None

    try:
        ok = bcrypt.checkpw(password.encode("utf-8"), stored.encode("utf-8"))
    except Exception:
        ok = False
    if not ok:
        return None

    role = (u.get("role") or "viewer").strip().lower()
    if role not in ("admin", "ciso", "analyst", "viewer"):
        role = "viewer"

    return {"username": username, "role": role}
