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
| `TMUXRC_VAULT_BW` | `bw` | path to the `bw` binary, when it isn't on the daemon's `PATH` |
| `TMUXRC_VAULT_APPDATA` | `~/.local/state/tmux-rc/bw` | `bw`'s own data dir, kept apart from any `bw` you use by hand |

The feature is off, and its button hidden, unless the first three are all set. The first
use logs in (or unlocks) and syncs, so it takes a few seconds; later lists sync at most once
a minute.

## Security model

- **The browser sees names and usernames only.** `GET /api/vault/items` returns ids, names
  and usernames. A fill sends only the entry's id (`vault_item` on `/compose`); the daemon
  looks the password up and sends it down the same path as a typed one, with the same
  guards: the pane must be at a password prompt when it arrives, the value must be one
  printable line, and it reaches tmux on stdin, never argv.
- **The audit line names the entry, never the value:** `secret (vault: <entry name>)`.
- **The master password stays in its file** (`bw --passwordfile`). The session key `bw`
  hands back is held in the daemon's memory only and passed to later `bw` calls in their
  environment (`BW_SESSION`), never on a command line where `ps` would show it.
- Anyone who can reach the daemon can fill any entry in that vault into a password prompt,
  as they can already type into any pane. That is why the account is dedicated, and why
  the [deploy pages](../) put a real login in front of the daemon.
