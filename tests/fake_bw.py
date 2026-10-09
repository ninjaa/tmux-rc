#!/usr/bin/env python3
"""A stand-in for the Bitwarden CLI, enough of it for openbus/vault.py: status, config
server, login/unlock with --passwordfile, sync, list items, get password, logout. State
lives in $BITWARDEN_APPDATADIR/fake.json; every call appends its argv, BW_SESSION and pid
to calls.jsonl there, so a test can check what reached argv and what reached the
environment. A test sets "sync" in the state to "fail" or "hang" to break the server."""

import json
import os
import sys
import time
from pathlib import Path

ITEMS = [
    {"id": "11111111-1111-4111-8111-111111111111", "type": 1, "name": "sudo on build-box",
     "login": {"username": "deploy", "password": "s3cret-from-vault"}},
    {"id": "22222222-2222-4222-8222-222222222222", "type": 1, "name": "No password",
     "login": {"username": "nobody", "password": None}},
    {"id": "33333333-3333-4333-8333-333333333333", "type": 2, "name": "A secure note",
     "notes": "note-body-never-listed"},
    {"id": "44444444-4444-4444-8444-444444444444", "type": 1, "name": "Ansible vault",
     "login": {"username": None, "password": "ansible-pass"}},
    {"id": "55555555-5555-4555-8555-555555555555", "type": 1, "name": "Old\x1b[2Jbox",
     "deletedDate": "2026-10-01T00:00:00Z", "login": {"username": "x", "password": "trashed"}},
    {"id": "66666666-6666-4666-8666-666666666666", "type": 1, "name": "CI\x1b[31m\nbot",
     "login": {"username": "ci", "password": "ci-pass"}},
]
MASTER = "correct horse battery staple"

home = Path(os.environ["BITWARDEN_APPDATADIR"])
home.mkdir(parents=True, exist_ok=True)
state_file = home / "fake.json"
state = json.loads(state_file.read_text()) if state_file.exists() else {
    "server": None, "email": None, "session": None, "n": 0}
args = sys.argv[1:]
session = os.environ.get("BW_SESSION")
with (home / "calls.jsonl").open("a") as log:
    log.write(json.dumps({"argv": args, "session": session, "pid": os.getpid()}) + "\n")


def done(out="", code=0, err=""):
    state_file.write_text(json.dumps(state))
    sys.stdout.write(out)
    sys.stderr.write(err)
    sys.exit(code)


def unlocked():
    if not state["email"]:
        done(code=1, err="You are not logged in.\n")
    if not session or session != state["session"]:
        done(code=1, err="Vault is locked.\n")


def new_session():
    with Path(args[args.index("--passwordfile") + 1]).open() as fh:
        if fh.read().strip() != MASTER:
            done(code=1, err="Invalid master password.\n")
    state["n"] += 1
    state["session"] = f"SESSIONKEY-{state['n']}"
    done(state["session"])


match args:
    case ["status"]:
        status = ("unauthenticated" if not state["email"] else
                  "unlocked" if session and session == state["session"] else "locked")
        done(json.dumps({"serverUrl": state["server"], "userEmail": state["email"],
                         "status": status}))
    case ["config", "server", url]:
        if state["email"]:
            done(code=1, err="Logout required before server config update.\n")
        state["server"] = url
        done("Saved setting `config`.\n")
    case ["login", email, *_]:
        state["email"] = email
        new_session()
    case ["unlock", *_]:
        new_session()
    case ["logout"]:
        state.update(email=None, session=None)
        done("You have logged out.\n")
    case ["sync"]:
        unlocked()
        if state.get("sync") == "hang":
            time.sleep(60)
        if state.get("sync") == "fail":
            done(code=1, err="fetch failed: connect ECONNREFUSED\n")
        done("Syncing complete.\n")
    case ["list", "items"]:
        unlocked()
        done(json.dumps(ITEMS))
    case ["get", "password", item_id]:
        unlocked()
        found = [i["login"]["password"] for i in ITEMS if i["id"] == item_id and "login" in i]
        done((found[0] or "") if found else "", 0 if found else 1, "" if found else "Not found.\n")
    case _:
        done(code=1, err=f"unknown command {args}\n")
