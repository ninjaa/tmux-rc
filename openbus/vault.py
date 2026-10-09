"""Fill a password prompt from a Vaultwarden (Bitwarden-compatible) vault, through the
official `bw` CLI. The browser only ever sees entry names and usernames; a password is
fetched by id inside the daemon and handed to tmux.send_secret, the one secret path.

Off unless TMUXRC_VAULT_SERVER, TMUXRC_VAULT_EMAIL and TMUXRC_VAULT_PASSWORD_FILE are all
set. The master password stays in its file (`--passwordfile`); the session key `bw`
returns lives in this process only and reaches later calls through BW_SESSION in the
child's environment, never argv, where any local `ps` could read it."""

from __future__ import annotations

import asyncio
import json
import os
import re
import time
from pathlib import Path

# Login + unlock run the vault's KDF and sync talks to the server; nothing else is slow.
TIMEOUT_S = 60
SYNC_EVERY_S = 60
LOGIN = 1  # Bitwarden item type for a login (username + password)
_ITEM_ID = re.compile(r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}", re.IGNORECASE)
# What `bw` says when the session key is missing, stale or revoked: unlock once, retry.
_RELOCK = re.compile(r"not logged in|vault is locked|not unlocked|session", re.IGNORECASE)


class VaultError(Exception):
    """A failure safe to show and audit: built from `bw`'s stderr or our own words, never
    its stdout, which is where a password comes back."""


class NotFoundError(VaultError):
    pass


class Vault:
    def __init__(self, server: str, email: str, password_file: str, bw: str, appdata: str):
        self.config = (server, email, password_file, bw, appdata)
        self.server, self.email, self.password_file = server.rstrip("/"), email, password_file
        self.bw, self.appdata = bw, appdata
        self._session: str | None = None
        self._synced = 0.0
        self._lock = asyncio.Lock()  # bw keeps one data.json: concurrent calls corrupt it

    async def _run(self, *args: str, session: bool = True) -> str:
        Path(self.appdata).mkdir(parents=True, exist_ok=True, mode=0o700)
        env = {**os.environ, "BITWARDEN_APPDATADIR": self.appdata, "BW_NOINTERACTION": "true"}
        env.pop("BW_SESSION", None)
        if session and self._session:
            env["BW_SESSION"] = self._session
        try:
            proc = await asyncio.create_subprocess_exec(
                self.bw, *args, env=env, stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        except OSError as error:
            raise VaultError(f"cannot run {self.bw}: {error.strerror}") from None
        try:
            out, err = await asyncio.wait_for(proc.communicate(), TIMEOUT_S)
        except TimeoutError:
            proc.kill()
            await proc.wait()
            raise VaultError(f"bw {args[0]} timed out") from None
        if proc.returncode:
            reason = err.decode(errors="replace").strip().splitlines()
            raise VaultError(f"bw {args[0]}: {reason[-1] if reason else 'failed'}"[:160])
        return out.decode()

    async def _unlock(self) -> None:
        """Bring `bw` to unlocked against our server, logging in only if it must."""
        self._session = None
        status = json.loads(await self._run("status", session=False))
        if (status.get("serverUrl") or "").rstrip("/") != self.server:
            if status.get("status") != "unauthenticated":  # bw only re-points when logged out
                await self._run("logout", session=False)
            await self._run("config", "server", self.server, session=False)
            status["status"] = "unauthenticated"
        if (status.get("userEmail") or self.email).lower() != self.email.lower():
            await self._run("logout", session=False)
            status["status"] = "unauthenticated"
        mode = os.stat(self.password_file).st_mode
        if mode & 0o077:
            raise VaultError("the vault password file must be readable by its owner only")
        verb = ["login", self.email] if status.get("status") == "unauthenticated" else ["unlock"]
        key = (await self._run(*verb, "--passwordfile", self.password_file, "--raw",
                               session=False)).strip()
        if not key:
            raise VaultError(f"bw {verb[0]} returned no session")
        self._session, self._synced = key, 0.0

    async def _call(self, *args: str) -> str:
        """Run with a live session: unlock first if there is none, and once more if `bw`
        says the one we hold has gone stale."""
        if not self._session:
            await self._unlock()
        try:
            return await self._run(*args)
        except VaultError as error:
            if not _RELOCK.search(str(error)):
                raise
        await self._unlock()
        return await self._run(*args)

    async def list_items(self) -> list[dict]:
        """Login entries that have a password, as id/name/username — never the password."""
        async with self._lock:
            if time.monotonic() - self._synced > SYNC_EVERY_S:
                await self._call("sync")
                self._synced = time.monotonic()
            items = json.loads(await self._call("list", "items"))
        fillable = [i for i in items
                    if i.get("type") == LOGIN and (i.get("login") or {}).get("password")]
        return sorted(({"id": i["id"], "name": i.get("name") or "", "username":
                        i["login"].get("username") or ""} for i in fillable),
                      key=lambda i: (i["name"].casefold(), i["username"].casefold()))

    async def get_password(self, item_id: str) -> tuple[str, str]:
        """(name, password) of one fillable entry. The id is checked before it reaches
        argv, so a crafted one can't become a `bw` flag."""
        if not _ITEM_ID.fullmatch(item_id):
            raise NotFoundError("not a vault item id")
        async with self._lock:
            try:
                item = json.loads(await self._call("get", "item", item_id))
            except VaultError as error:
                if "not found" in str(error).lower():
                    raise NotFoundError("vault item not found") from None
                raise
        password = (item.get("login") or {}).get("password") if item.get("type") == LOGIN else None
        if not password:
            raise NotFoundError("that vault item has no password")
        return item.get("name") or "", password


_client: Vault | None = None


def client() -> Vault | None:
    """The configured vault, or None when the feature is off. Read per call, like the
    other TMUXRC_* settings; one client (one session, one lock) per configuration."""
    global _client  # noqa: PLW0603 - the session key must outlive a request
    server = os.environ.get("TMUXRC_VAULT_SERVER", "").strip()
    email = os.environ.get("TMUXRC_VAULT_EMAIL", "").strip()
    password_file = os.environ.get("TMUXRC_VAULT_PASSWORD_FILE", "").strip()
    if not (server and email and password_file):
        return None
    bw = os.environ.get("TMUXRC_VAULT_BW", "").strip() or "bw"
    appdata = os.environ.get("TMUXRC_VAULT_APPDATA", "").strip() or str(
        Path.home() / ".local" / "state" / "tmux-rc" / "bw")
    config = (server, email, password_file, bw, appdata)
    if _client is None or _client.config != config:
        _client = Vault(*config)
    return _client
