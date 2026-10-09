from pathlib import Path

import pytest

from openbus import tmux, vault


@pytest.fixture(autouse=True)
def _vertex_project(monkeypatch):
    """Vertex entries are offered only when a project is set. Supply one so the suite does
    not depend on the checkout's .env (a worktree has none) for what it offers."""
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "test-project")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)  # likewise: never the dev's key


@pytest.fixture(autouse=True)
def _no_enter_settle(monkeypatch):
    """send_keys waits before the Return so a TUI doesn't read it as a newline
    (tmux._ENTER_SETTLE_S). Real time in every send would tax the whole suite for a
    delay that is about a terminal's paste heuristic, not about our logic — so it is
    zero by default here. test_send_enter_settle.py opts back in."""
    monkeypatch.setattr(tmux, "_ENTER_SETTLE_S", 0)
    # Unit tests never address a real pane. Identity-specific tests override this.
    monkeypatch.setattr(tmux, "pane_pid", lambda pane_id: "1234")
    monkeypatch.setattr(tmux, "at_password_prompt", lambda pane_id: False)
    monkeypatch.setattr(tmux, "_last_paste", {})


@pytest.fixture
def fake_bw(tmp_path, monkeypatch):
    """The vault feature, configured against tests/fake_bw.py. Yields its data dir, where
    calls.jsonl records each call's argv and BW_SESSION."""
    password_file = tmp_path / "master"
    password_file.write_text("correct horse battery staple\n")
    password_file.chmod(0o600)
    appdata = tmp_path / "bw"
    monkeypatch.setenv("TMUXRC_VAULT_SERVER", "https://vault.example.org")
    monkeypatch.setenv("TMUXRC_VAULT_EMAIL", "tmux-rc@example.org")
    monkeypatch.setenv("TMUXRC_VAULT_PASSWORD_FILE", str(password_file))
    monkeypatch.setenv("TMUXRC_VAULT_BW", str(Path(__file__).with_name("fake_bw.py")))
    monkeypatch.setenv("TMUXRC_VAULT_APPDATA", str(appdata))
    monkeypatch.setattr(vault, "_client", None)
    return appdata
