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
import logging
import os
import re
import time
from contextlib import suppress
from pathlib import Path

logger = logging.getLogger(__name__)

# Login + unlock run the vault's KDF; nothing else should take long. A sync that hangs is
# skipped rather than waited on: listing falls back to bw's local copy (see list_items).
TIMEOUT_S = 60
SYNC_TIMEOUT_S = 15
SYNC_EVERY_S = 60
SYNC_RETRY_S = 15  # after a failed sync, before trying the server again
AUTH_RETRY_S = 60  # a refused login/unlock is not retried on every tap
LOGIN = 1  # Bitwarden item type for a login (username + password)
_ITEM_ID = re.compile(r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}", re.IGNORECASE)
# What `bw` says when the session key is missing, stale or revoked: unlock once, retry.
_RELOCK = re.compile(r"not logged in|vault is locked|not unlocked|session", re.IGNORECASE)
# bw keeps one data.json per data dir: concurrent calls corrupt it. One lock for the
# module, not per Vault, so a reconfigured client can't race the one it replaced.
_LOCK = asyncio.Lock()


class VaultError(Exception):
    """A failure safe to show and audit: built from `bw`'s stderr or our own words, never
    its stdout, which is where a password comes back."""


class NotFoundError(VaultError):
    pass


def _json(out: str, verb: str):
    try:
        return json.loads(out)
    except ValueError:
        raise VaultError(f"bw {verb} returned unreadable output") from None


def _printable(text: str) -> str:
    """An entry name is vault data headed for the audit line and OTel: no control bytes."""
    return "".join(c for c in text if c.isprintable())


class Vault:
    def __init__(self, server: str, email: str, password_file: str, bw: str, appdata: str):
        self.config = (server, email, password_file, bw, appdata)
        self.server, self.email, self.password_file = server.rstrip("/"), email, password_file
        self.bw, self.appdata = bw, appdata
        self._session: str | None = None
        self._synced = 0.0
        self._refused: tuple[float, VaultError] | None = None  # last failed login/unlock
        self._names: dict[str, str] = {}  # fillable entries from the last list: id -> name

    async def _run(self, *args: str, session: bool = True, wait_s: float = TIMEOUT_S) -> str:
        env = {**os.environ, "BITWARDEN_APPDATADIR": self.appdata, "BW_NOINTERACTION": "true"}
        env.pop("BW_SESSION", None)
        if session and self._session:
            env["BW_SESSION"] = self._session
        try:
            Path(self.appdata).mkdir(parents=True, exist_ok=True, mode=0o700)
            proc = await asyncio.create_subprocess_exec(
                self.bw, *args, env=env, stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        except OSError as error:
            raise VaultError(f"cannot run {self.bw}: {error.strerror}") from None
        try:
            out, err = await asyncio.wait_for(proc.communicate(), wait_s)
        except BaseException as error:  # a timeout, or the request cancelled under us
            with suppress(ProcessLookupError):
                proc.kill()
            await asyncio.shield(proc.wait())  # never leave a bw holding data.json
            if isinstance(error, TimeoutError):
                raise VaultError(f"bw {args[0]} timed out") from None
            raise
        if proc.returncode:
            reason = err.decode(errors="replace").strip().splitlines()
            raise VaultError(f"bw {args[0]}: {reason[-1] if reason else 'failed'}"[:160])
        return out.decode()

    async def _unlock(self) -> None:
        """Bring `bw` to unlocked against our server, logging in only if it must."""
        self._session = None
        if self._refused and time.monotonic() - self._refused[0] < AUTH_RETRY_S:
            raise self._refused[1]
        status = _json(await self._run("status", session=False), "status")
        if (status.get("serverUrl") or "").rstrip("/") != self.server:
            if status.get("status") != "unauthenticated":  # bw only re-points when logged out
                await self._run("logout", session=False)
            await self._run("config", "server", self.server, session=False)
            status["status"] = "unauthenticated"
        if (status.get("userEmail") or self.email).lower() != self.email.lower():
            await self._run("logout", session=False)
            status["status"] = "unauthenticated"
        try:
            mode = os.stat(self.password_file).st_mode
        except OSError as error:
            raise VaultError(f"cannot read the vault password file: {error.strerror}") from None
        if mode & 0o077:
            raise VaultError("the vault password file must be readable by its owner only")
        verb = ["login", self.email] if status.get("status") == "unauthenticated" else ["unlock"]
        try:
            key = (await self._run(*verb, "--passwordfile", self.password_file, "--raw",
                                   session=False)).strip()
            error = None if key else VaultError(f"bw {verb[0]} returned no session")
        except VaultError as refused:
            error = refused
        if error:
            self._refused = (time.monotonic(), error)
            raise error
        self._session, self._synced, self._refused = key, 0.0, None

    async def _call(self, *args: str, wait_s: float = TIMEOUT_S) -> str:
        """Run with a live session: unlock first if there is none, and once more if `bw`
        says the one we hold has gone stale."""
        if not self._session:
            await self._unlock()
        try:
            return await self._run(*args, wait_s=wait_s)
        except VaultError as error:
            if not _RELOCK.search(str(error)):
                raise
        await self._unlock()
        return await self._run(*args, wait_s=wait_s)

    async def _list(self) -> list[dict]:
        """Under _LOCK. A failed sync still lists: bw answers from its local copy, which
        is at worst a minute or a server outage behind."""
        if time.monotonic() - self._synced > SYNC_EVERY_S:
            try:
                await self._call("sync", wait_s=SYNC_TIMEOUT_S)
                self._synced = time.monotonic()
            except VaultError as error:
                logger.warning("vault sync failed, listing the local copy: %s", error)
                self._synced = time.monotonic() - SYNC_EVERY_S + SYNC_RETRY_S
        items = _json(await self._call("list", "items"), "list")
        fillable = sorted(({"id": i["id"], "name": _printable(i.get("name") or ""),
                            "username": i["login"].get("username") or ""}
                           for i in items if i.get("type") == LOGIN and not i.get("deletedDate")
                           and (i.get("login") or {}).get("password")),
                          key=lambda i: (i["name"].casefold(), i["username"].casefold()))
        self._names = {i["id"]: i["name"] for i in fillable}
        return fillable

    async def list_items(self) -> list[dict]:
        """Login entries that have a password, as id/name/username — never the password."""
        async with _LOCK:
            return await self._list()

    async def get_password(self, item_id: str) -> tuple[str, str]:
        """(name, password) of one fillable entry: one the last list offered (listing again
        if it is not there), fetched alone with `bw get password`. The id is checked
        before it reaches argv, so a crafted one can't become a `bw` flag."""
        if not _ITEM_ID.fullmatch(item_id):
            raise NotFoundError("not a vault item id")
        async with _LOCK:
            if item_id not in self._names:
                await self._list()
            if item_id not in self._names:
                raise NotFoundError("vault item not found")
            try:
                password = (await self._call("get", "password", item_id)).removesuffix("\n")
            except VaultError as error:
                if "not found" in str(error).lower():
                    raise NotFoundError("vault item not found") from None
                raise
            if not password:
                raise NotFoundError("that vault item has no password")
            return self._names[item_id], password


_client: Vault | None = None


def client() -> Vault | None:
    """The configured vault, or None when the feature is off. Read per call, like the
    other TMUXRC_* settings; one client (one session) per configuration."""
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
