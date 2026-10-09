"""Vault fill against tests/fake_bw.py: login/unlock with the session key only ever in the
child's environment, entries listed without their passwords, and a vault_item compose
routed into tmux.send_secret with an audit line that names the entry, not the value.
The prompt guards themselves are exercised end to end in test_secret_input.py."""

import asyncio
import json
import logging
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from openbus import server, tmux, vault

SUDO = "11111111-1111-4111-8111-111111111111"
VALUES = ("s3cret-from-vault", "ansible-pass", "note-body-never-listed", "correct horse")


def _calls(appdata):
    return [json.loads(line) for line in (appdata / "calls.jsonl").read_text().splitlines()]


@pytest.fixture
def pane(monkeypatch):
    pane = SimpleNamespace(id="%7", pid="1234")
    sent = []
    monkeypatch.setattr(tmux, "find_pane", lambda pane_id: pane)
    monkeypatch.setattr(tmux, "send_secret", lambda p, secret: sent.append((p, secret)))
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


def test_get_refuses_bad_ids_and_entries_without_a_password(fake_bw):
    client = vault.client()
    for item_id in ("--raw", "../x", "", "22222222-2222-4222-8222-22222222222Z"):
        with pytest.raises(vault.NotFoundError):
            asyncio.run(client.get_password(item_id))
    assert not (fake_bw / "calls.jsonl").exists()  # none of those reached bw
    with pytest.raises(vault.NotFoundError, match="no password"):
        asyncio.run(client.get_password("22222222-2222-4222-8222-222222222222"))
    with pytest.raises(vault.NotFoundError, match="not found"):
        asyncio.run(client.get_password("99999999-9999-4999-8999-999999999999"))


def test_compose_vault_item_takes_the_secret_path(fake_bw, pane, caplog):
    caplog.set_level(logging.INFO)
    client = TestClient(server.app)
    response = client.post("/api/panes/%7/compose", files=[("vault_item", (None, SUDO))])
    assert response.status_code == 200
    assert [secret for _, secret in pane] == ["s3cret-from-vault"]
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
