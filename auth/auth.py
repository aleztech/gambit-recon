# auth/auth.py
import os
import json
import time
import secrets
from pathlib import Path
from typing import Optional, Dict, Any, Tuple

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


def _ensure_secure_paths():
    uf = _users_file()
    af = _audit_file()
    uf.parent.mkdir(parents=True, exist_ok=True)
    af.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(uf.parent, 0o700)
    except Exception:
        pass
    try:
        os.chmod(af.parent, 0o700)
    except Exception:
        pass


def audit(event: str, username: str = "", meta: Optional[Dict[str, Any]] = None):
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


def _load_users_raw() -> Dict[str, Any]:
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


def load_users() -> Dict[str, Dict[str, Any]]:
    _ensure_secure_paths()
    users = _load_users_raw()
    return users if isinstance(users, dict) else {}


def save_users(users: Dict[str, Dict[str, Any]]):
    _ensure_secure_paths()
    p = _users_file()
    payload = {"users": users}
    p.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    try:
        os.chmod(p, 0o600)
    except Exception:
        pass


def get_user(username: str) -> Optional[Dict[str, Any]]:
    users = load_users()
    u = users.get(username)
    return u if isinstance(u, dict) else None


def _hash_password(password: str) -> str:
    if bcrypt is None:
        raise RuntimeError("bcrypt not installed")
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(username: str, password: str) -> bool:
    u = get_user(username)
    if not u or u.get("enabled") is False:
        return False
    stored = (u.get("password_hash") or "").strip()
    if not stored or bcrypt is None:
        return False
    try:
        return bool(bcrypt.checkpw(password.encode("utf-8"), stored.encode("utf-8")))
    except Exception:
        return False


def set_password(username: str, new_password: str, must_change: bool = False):
    users = load_users()
    if username not in users:
        raise KeyError("user not found")
    users[username]["password_hash"] = _hash_password(new_password)
    users[username]["must_change"] = bool(must_change)
    save_users(users)


def set_enabled(username: str, enabled: bool):
    users = load_users()
    if username not in users:
        raise KeyError("user not found")
    users[username]["enabled"] = bool(enabled)
    save_users(users)


def set_role(username: str, role: str):
    role = (role or "viewer").strip().lower()
    if role not in ("admin", "ciso", "analyst", "viewer"):
        role = "viewer"
    users = load_users()
    if username not in users:
        raise KeyError("user not found")
    users[username]["role"] = role
    save_users(users)


def create_user(username: str, role: str, enabled: bool = True, temp_password: Optional[str] = None) -> Tuple[str, Dict[str, Any]]:
    username = (username or "").strip()
    if not username:
        raise ValueError("username required")
    if not username.replace("_", "").replace("-", "").isalnum():
        raise ValueError("username must be alnum/_/-")

    users = load_users()
    if username in users:
        raise ValueError("user already exists")

    role = (role or "viewer").strip().lower()
    if role not in ("admin", "ciso", "analyst", "viewer"):
        role = "viewer"

    pwd = temp_password or secrets.token_urlsafe(14)
    users[username] = {
        "password_hash": _hash_password(pwd),
        "role": role,
        "enabled": bool(enabled),
        "must_change": True,
        "created_ts": int(time.time()),
    }
    save_users(users)
    return pwd, users[username]


def session_is_valid(auth_obj: Dict[str, Any]) -> bool:
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
    if not username or not password:
        return None
    if bcrypt is None:
        return None

    _ensure_secure_paths()
    u = get_user(username)
    if not u or u.get("enabled") is False:
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
