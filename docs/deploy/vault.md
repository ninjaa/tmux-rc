---
weight: 3
title: "Vault fill"
---

# Filling password prompts from a vault

When a pane is at a password prompt (`sudo`, `ssh`, `read -s`), the composer turns into a
password field. With a vault configured, a key button next to it opens **From vault**: a
searchable list of entries, and tapping one makes the daemon type that entry's password into
the pane. The vault is a Vaultwarden (or any Bitwarden-compatible) server, read through the
official [`bw` CLI](https://bitwarden.com/help/cli/).

## Setup

1. Create a **dedicated account** on the server for tmux-rc, and put in its vault only the
   entries the phone should be able to fill. Don't point it at your personal vault: every
   login entry with a password in this vault is offered.
2. Install `bw` on the daemon's host, and write the account's master password to a file only
   you can read:

   ```bash
   install -m 600 /dev/null ~/.config/tmux-rc/vault-master
   $EDITOR ~/.config/tmux-rc/vault-master
   ```

3. Set these in the daemon's environment (`.env`, or the unit's `Environment=`), then restart
   it:

| var | default | meaning |
| --- | --- | --- |
| `TMUXRC_VAULT_SERVER` | — | the server URL, e.g. `https://vault.example.org` |
| `TMUXRC_VAULT_EMAIL` | — | the dedicated account's email |
| `TMUXRC_VAULT_PASSWORD_FILE` | — | the master password file; refused unless only its owner can read it |
| `TMUXRC_VAULT_BW` | `bw` | path to the `bw` binary. Usually absolute: an npm install (e.g. `/opt/node-…/bin/bw`) is not on the systemd unit's `PATH`, and its `#!/usr/bin/env node` needs `node` on that `PATH` |
| `TMUXRC_VAULT_APPDATA` | `~/.local/state/tmux-rc/bw` | `bw`'s own data dir, kept apart from any `bw` you use by hand |

The feature is off, and its button hidden, unless the first three are all set. The first
use logs in (or unlocks) and syncs, so it takes a few seconds; later lists sync at most once
a minute, and list `bw`'s local copy when the server can't be reached.

## Security model

- **Passwords stay out of the page, as hygiene.** `GET /api/vault/items` returns ids, names
  and usernames, and a fill sends only the entry's id (`vault_item` on `/compose`), so a
  password never sits in the browser's memory, history or caches. This is not a boundary
  against a hostile client of the daemon: anyone who can reach it can fill any entry into
  a prompt they control and read what arrives, just as they can already type into any
  pane. That is why the account is dedicated and holds only what the phone should fill,
  and why the [deploy pages](../) put a real login in front of the daemon.
- **A fill goes to a local password prompt only.** The daemon sends it down the same path
  as a typed password, with the same guards (the pane must still be at the prompt when it
  arrives, the value must be one printable line, it reaches tmux on stdin, never argv),
  plus one more: the pane's tty must be a local line reader, echo off with line editing
  on, as `sudo`, `ssh`'s own prompt, `git` and `read -s` are. A raw tty is refused, so a
  vault fill cannot answer `sudo` on the far side of an `ssh` session, or anything a
  full-screen app draws; type that password instead.
- **The audit line names the entry, never the value:** `secret (vault: <entry name>)`, with
  control characters dropped from the name.
- **The master password stays in its file** (`bw --passwordfile`). The session key `bw`
  hands back is held in the daemon's memory only and passed to later `bw` calls in their
  environment (`BW_SESSION`), never on a command line where `ps` would show it. A refused
  login or unlock is not retried for a minute.
