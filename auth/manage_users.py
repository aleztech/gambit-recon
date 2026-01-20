#!/usr/bin/env python3
import os, json, argparse, getpass
from pathlib import Path

import bcrypt

DEFAULT_USERS_FILE = Path.home() / ".config" / "gambit-recon" / "users.json"

def users_file() -> Path:
    p = (os.environ.get("GAMBIT_USERS_FILE") or "").strip()
    return Path(p) if p else DEFAULT_USERS_FILE

def load_users(p: Path) -> dict:
    if not p.exists():
        return {}
    data = json.loads(p.read_text(encoding="utf-8"))
    if isinstance(data, dict) and isinstance(data.get("users"), dict):
        return data["users"]
    if isinstance(data, dict):
        return data
    return {}

def save_users(p: Path, users: dict):
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(p.parent, 0o700)
    except Exception:
        pass
    p.write_text(json.dumps({"users": users}, indent=2), encoding="utf-8")
    try:
        os.chmod(p, 0o600)
    except Exception:
        pass

def cmd_add(args):
    p = users_file()
    users = load_users(p)
    pw = getpass.getpass("Password: ").encode("utf-8")
    h = bcrypt.hashpw(pw, bcrypt.gensalt()).decode("utf-8")
    users[args.username] = {"password_hash": h, "role": args.role, "enabled": True}
    save_users(p, users)
    print("OK added:", args.username, "role=", args.role, "->", p)

def cmd_disable(args):
    p = users_file()
    users = load_users(p)
    if args.username not in users:
        raise SystemExit("User not found")
    users[args.username]["enabled"] = False
    save_users(p, users)
    print("OK disabled:", args.username)

def cmd_enable(args):
    p = users_file()
    users = load_users(p)
    if args.username not in users:
        raise SystemExit("User not found")
    users[args.username]["enabled"] = True
    save_users(p, users)
    print("OK enabled:", args.username)

def cmd_passwd(args):
    p = users_file()
    users = load_users(p)
    if args.username not in users:
        raise SystemExit("User not found")
    pw = getpass.getpass("New password: ").encode("utf-8")
    h = bcrypt.hashpw(pw, bcrypt.gensalt()).decode("utf-8")
    users[args.username]["password_hash"] = h
    save_users(p, users)
    print("OK updated password:", args.username)

def cmd_list(args):
    p = users_file()
    users = load_users(p)
    for u, v in sorted(users.items()):
        print(u, "role="+str(v.get("role","viewer")), "enabled="+str(v.get("enabled", True)))

def main():
    ap = argparse.ArgumentParser(prog="manage_users.py")
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("add")
    a.add_argument("username")
    a.add_argument("--role", default="admin", choices=["admin","ciso","analyst","viewer"])
    a.set_defaults(fn=cmd_add)

    d = sub.add_parser("disable")
    d.add_argument("username")
    d.set_defaults(fn=cmd_disable)

    e = sub.add_parser("enable")
    e.add_argument("username")
    e.set_defaults(fn=cmd_enable)

    p = sub.add_parser("passwd")
    p.add_argument("username")
    p.set_defaults(fn=cmd_passwd)

    l = sub.add_parser("list")
    l.set_defaults(fn=cmd_list)

    args = ap.parse_args()
    args.fn(args)

if __name__ == "__main__":
    main()
