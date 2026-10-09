"""Vault fill against tests/fake_bw.py: login/unlock with the session key only ever in the
child's environment, entries listed without their passwords, and a vault_item compose
routed into tmux.send_secret with an audit line that names the entry, not the value.
The prompt guards themselves are exercised end to end in test_secret_input.py."""

import asyncio
import json
import logging
import os
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from openbus import server, tmux, vault

SUDO = "11111111-1111-4111-8111-111111111111"
CI = "66666666-6666-4666-8666-666666666666"
VALUES = ("s3cret-from-vault", "ansible-pass", "note-body-never-listed", "correct horse",
          "trashed", "ci-pass")


def _calls(appdata):
    return [json.loads(line) for line in (appdata / "calls.jsonl").read_text().splitlines()]


@pytest.fixture
def pane(monkeypatch):
    pane = SimpleNamespace(id="%7", pid="1234")
    sent = []
    monkeypatch.setattr(tmux, "find_pane", lambda pane_id: pane)
    monkeypatch.setattr(tmux, "send_secret",
                        lambda p, secret, strict=False: sent.append((p, secret, strict)))
    monkeypatch.setattr(server.app.state, "watcher",
                        SimpleNamespace(request_reparse=lambda p: None), raising=False)
    return sent


def test_off_unless_configured(monkeypatch, pane):
    for var in ("TMUXRC_VAULT_SERVER", "TMUXRC_VAULT_EMAIL", "TMUXRC_VAULT_PASSWORD_FILE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("TMUXRC_VAULT_SERVER", "https://vault.example.org")  # one alone: still off
    client = TestClient(server.app)
    assert client.get("/api/version").json()["vault"] is False
    assert client.get("/api/vault/items").status_code == 404
    assert client.post("/api/panes/%7/compose",
                       files=[("vault_item", (None, SUDO))]).status_code == 404
    assert not pane


def test_lists_names_only_and_keeps_the_session_out_of_argv(fake_bw):
    client = TestClient(server.app)
    assert client.get("/api/version").json()["vault"] is True
    response = client.get("/api/vault/items")
    assert response.status_code == 200
    assert response.json() == {"enabled": True, "items": [
        {"id": "44444444-4444-4444-8444-444444444444", "name": "Ansible vault", "username": ""},
        {"id": CI, "name": "CI[31mbot", "username": "ci"},  # no control bytes; not the trash
        {"id": SUDO, "name": "sudo on build-box", "username": "deploy"},
    ]}
    assert not any(value in response.text for value in VALUES)
    calls = _calls(fake_bw)
    assert [c["argv"][0] for c in calls] == ["status", "config", "login", "sync", "list"]
    assert calls[1]["argv"] == ["config", "server", "https://vault.example.org"]
    assert calls[2]["argv"][:2] == ["login", "tmux-rc@example.org"]
    assert [c["session"] for c in calls[3:]] == ["SESSIONKEY-1"] * 2

    # A restarted daemon finds bw logged in but locked: unlock, don't log in again.
    vault._client = None
    assert client.get("/api/vault/items").status_code == 200
    later = _calls(fake_bw)[len(calls):]
    assert [c["argv"][0] for c in later] == ["status", "unlock", "sync", "list"]
    assert later[-1]["session"] == "SESSIONKEY-2"
    every = _calls(fake_bw)
    assert not any("SESSIONKEY" in arg or "correct horse" in arg
                   for c in every for arg in c["argv"])
    assert all(c["session"] is None for c in every if c["argv"][0] in ("status", "login", "unlock"))


def test_a_stale_session_unlocks_once(fake_bw):
    client = vault.client()
    assert asyncio.run(client.get_password(SUDO)) == ("sudo on build-box", "s3cret-from-vault")
    state = json.loads((fake_bw / "fake.json").read_text())
    (fake_bw / "fake.json").write_text(json.dumps({**state, "session": "revoked"}))
    before = len(_calls(fake_bw))
    assert asyncio.run(client.get_password(SUDO))[1] == "s3cret-from-vault"
    assert [c["argv"][0] for c in _calls(fake_bw)[before:]] == ["get", "status", "unlock", "get"]
    assert _calls(fake_bw)[-1]["argv"] == ["get", "password", SUDO]  # never the whole item


def test_get_refuses_bad_ids_and_entries_without_a_password(fake_bw):
    client = vault.client()
    for item_id in ("--raw", "../x", "", "22222222-2222-4222-8222-22222222222Z"):
        with pytest.raises(vault.NotFoundError):
            asyncio.run(client.get_password(item_id))
    assert not (fake_bw / "calls.jsonl").exists()  # none of those reached bw
    # No password, in the trash, or not there at all: only listed entries are fetched.
    for item_id in ("22222222-2222-4222-8222-222222222222",
                    "55555555-5555-4555-8555-555555555555",
                    "99999999-9999-4999-8999-999999999999"):
        with pytest.raises(vault.NotFoundError, match="not found"):
            asyncio.run(client.get_password(item_id))
    assert not any(c["argv"][:2] == ["get", "password"] for c in _calls(fake_bw))


def test_compose_vault_item_takes_the_secret_path(fake_bw, pane, caplog):
    caplog.set_level(logging.INFO)
    client = TestClient(server.app)
    response = client.post("/api/panes/%7/compose", files=[("vault_item", (None, SUDO))])
    assert response.status_code == 200
    assert [(secret, strict) for _, secret, strict in pane] == [("s3cret-from-vault", True)]
    assert "AUDIT compose" in caplog.text and "secret (vault: sudo on build-box)" in caplog.text

    # Alone, like a typed password; a wrong id is refused before anything is sent.
    assert client.post("/api/panes/%7/compose", files=[
        ("vault_item", (None, SUDO)), ("secret", (None, "x"))]).status_code == 400
    assert client.post("/api/panes/%7/compose", files=[
        ("vault_item", (None, SUDO)), ("text", (None, "x"))]).status_code == 400
    missing = client.post("/api/panes/%7/compose",
                          files=[("vault_item", (None, "99999999-9999-4999-8999-999999999999"))])
    assert missing.status_code == 404 and missing.json()["detail"] == "vault item not found"
    assert len(pane) == 1
    assert not any(value in caplog.text for value in VALUES)


def test_a_loose_password_file_is_refused(fake_bw, tmp_path, pane):
    (tmp_path / "master").chmod(0o644)
    response = TestClient(server.app).get("/api/vault/items")
    assert response.status_code == 502
    assert "owner only" in response.json()["detail"]


def test_compose_audits_a_printable_entry_name(fake_bw, pane, caplog):
    caplog.set_level(logging.INFO)
    client = TestClient(server.app)
    response = client.post("/api/panes/%7/compose", files=[("vault_item", (None, CI))])
    assert response.status_code == 200
    assert "secret (vault: CI[31mbot)" in caplog.text and "\x1b" not in caplog.text


def _state(appdata, **changes):
    state = json.loads((appdata / "fake.json").read_text())
    (appdata / "fake.json").write_text(json.dumps({**state, **changes}))


def _alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def test_a_failed_or_hung_sync_still_lists(fake_bw, monkeypatch, caplog):
    client = vault.client()
    assert len(asyncio.run(client.list_items())) == 3
    _state(fake_bw, sync="fail")
    client._synced = 0.0  # due again
    assert len(asyncio.run(client.list_items())) == 3
    assert "vault sync failed" in caplog.text
    before = len(_calls(fake_bw))
    asyncio.run(client.list_items())  # backing off: straight to the local copy
    assert [c["argv"][0] for c in _calls(fake_bw)[before:]] == ["list"]

    _state(fake_bw, sync="hang")
    monkeypatch.setattr(vault, "SYNC_TIMEOUT_S", 0.5)
    client._synced = 0.0
    assert len(asyncio.run(client.list_items())) == 3
    hung = [c for c in _calls(fake_bw) if c["argv"] == ["sync"]][-1]
    assert not _alive(hung["pid"])  # killed and reaped, not left holding data.json


def test_a_cancelled_call_kills_bw(fake_bw):
    client = vault.client()
    asyncio.run(client.list_items())
    _state(fake_bw, sync="hang")
    client._synced = 0.0

    async def cancel_mid_sync():
        task = asyncio.create_task(client.list_items())
        for _ in range(100):
            await asyncio.sleep(0.05)
            if [c for c in _calls(fake_bw) if c["argv"] == ["sync"]][1:]:
                break
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(cancel_mid_sync())
    hung = [c for c in _calls(fake_bw) if c["argv"] == ["sync"]][-1]
    assert not _alive(hung["pid"])


def test_a_refused_unlock_is_not_retried_on_every_tap(fake_bw, tmp_path):
    (tmp_path / "master").write_text("wrong\n")
    client = vault.client()
    for _ in range(3):
        with pytest.raises(vault.VaultError, match="Invalid master password"):
            asyncio.run(client.list_items())
    assert [c["argv"][0] for c in _calls(fake_bw)].count("login") == 1


@pytest.mark.parametrize("problem", ["garbage", "no password file"])
def test_unreadable_answers_are_vault_errors(fake_bw, tmp_path, monkeypatch, problem):
    if problem == "garbage":
        bw = tmp_path / "garbage-bw"
        bw.write_text("#!/bin/sh\necho not json\n")
        bw.chmod(0o700)
        monkeypatch.setenv("TMUXRC_VAULT_BW", str(bw))
    else:
        (tmp_path / "master").unlink()
    response = TestClient(server.app).get("/api/vault/items")
    assert response.status_code == 502
    assert response.json()["detail"] in (
        "bw status returned unreadable output",
        "cannot read the vault password file: No such file or directory")
