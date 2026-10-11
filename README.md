# ement-e2ee

A transparent end-to-end-encryption proxy that gives the Emacs Matrix client
[ement.el](https://github.com/alphapapa/ement.el) full E2EE support — without
modifying ement at all. It is a Rust reimplementation of the role
[pantalaimon](https://github.com/matrix-org/pantalaimon) plays in ement's
README, built on
[matrix-sdk-crypto](https://github.com/matrix-org/matrix-rust-sdk)
(vodozemac; the same crypto core Element uses) instead of the deprecated
libolm.

```
Emacs / ement.el  ──plain HTTP──▶  ement-e2ee (localhost)  ──HTTPS──▶  homeserver
                                   · decrypts m.room.encrypted in sync/history
                                   · encrypts your sends (megolm)
                                   · device keys, to-device, key requests
                                   · SSSS recovery, cross-signing, key backup
                                   · encrypted attachments
```
    
## Features

- **Receive**: decrypts `m.room.encrypted` events in `/sync`, `/messages`,
  `/context`, `/event`, and `/notifications` responses; undecryptable events
  render as a readable placeholder and trigger an automatic room-key request.
  When the key arrives later, the placeholder is replaced in place.
- **Send**: transparently encrypts everything sent into encrypted rooms
  (messages, edits, reactions), including establishing olm sessions and
  sharing megolm keys with full (not lazy-loaded) room membership.
- **Join your existing identity**: `ctl bootstrap` takes your recovery key or
  passphrase, imports your cross-signing keys from SSSS, signs this device
  (green shield in Element), and restores your history keys from server-side
  key backup. New room keys are backed up automatically afterwards.
- **Verification**: emoji (SAS) verification against your other devices via
  `ctl verify`, which asks one question: do the emoji match?
- **Diagnostics**: `ctl debug check` tests the whole chain and names the
  remedy for each problem; further subcommands look into a room, an event,
  the device lists or the logs.
- **Media**: uploads are encrypted (spec `EncryptedFile`/AES-CTR), downloads
  decrypted on the fly — including ement's tokenless avatar fetches. Media
  sent to unencrypted rooms is re-uploaded as plaintext automatically.
- **Multi-account**: sessions are keyed by access token; each gets its own
  sqlite crypto store under `~/.local/share/ement-e2ee/`.

## Build

Requires Rust ≥ 1.96 (`rustup` recommended). All dependencies, including the
[matrix-rust-sdk](https://github.com/matrix-org/matrix-rust-sdk) crates, are
released versions from crates.io, locked by `Cargo.lock`.

```sh
cargo build --release
cargo install --path .   # puts ement-e2ee on ~/.cargo/bin
```

## Setup

```sh
ement-e2ee setup --user-id @you:example.org
```

finds your homeserver (via `.well-known`), writes
`~/.config/ement-e2ee/config.toml`, installs and starts a systemd user
service (after asking), and prints the `ement-connect` form to evaluate in
Emacs. `--homeserver URL` skips discovery, `--no-service` leaves the service
alone, and an existing config is kept unless `--force` is given. Then, with
ement connected:

```sh
ement-e2ee ctl bootstrap     # join your encrypted identity (asks for the recovery key)
ement-e2ee ctl verify        # optional: emoji-verify against another device
ement-e2ee ctl debug check   # is everything in order?
```

`ctl bootstrap` imports your cross-signing keys from secret storage, signs
this device and restores your key backup; the recovery key is prompted for
(or read from `--recovery-key-file`), never passed via argv.

`ctl verify` waits for a verification started on your other device (in
Element: Settings → Sessions → the ement session → Verify), or starts one
itself with `--device DEVICEID`. It shows the emoji, asks whether the other
device shows the same, and reports the result. Keep ement connected while it
runs.

### By hand

1. Configure:

   ```sh
   mkdir -p ~/.config/ement-e2ee
   cp config.example.toml ~/.config/ement-e2ee/config.toml
   $EDITOR ~/.config/ement-e2ee/config.toml   # set homeserver
   ```

2. Run the proxy — either directly:

   ```sh
   ement-e2ee serve
   ```

   or as a systemd user service:

   ```sh
   install -Dm644 contrib/ement-e2ee.service ~/.config/systemd/user/ement-e2ee.service
   systemctl --user daemon-reload
   systemctl --user enable --now ement-e2ee
   journalctl --user -u ement-e2ee -f    # follow the logs
   ```

   The unit expects the binary at `~/.cargo/bin/ement-e2ee` (where
   `cargo install` puts it) and starts on login. On WSL2, enable systemd
   first: add `[boot] systemd=true` to `/etc/wsl.conf`, then restart the
   distro (`wsl.exe --shutdown`). To keep the proxy alive without an open
   session, `loginctl enable-linger $USER`.

3. Connect ement through it:

   ```elisp
   (ement-connect :user-id "@you:example.org"
                  :password "yourpass"
                  :uri-prefix "http://localhost:8009")
   ```

   On first sync the proxy registers device keys for ement's device; it shows
   up in Element → Settings → Sessions.

## Configuration

`config.example.toml` lists every setting. Beyond `listen` and `homeserver`:

- `store_passphrase_command` — a shell command that prints the passphrase
  encrypting the crypto store (`pass show …`, `secret-tool lookup …`), so it
  need not sit in the file. `store_passphrase` holds it directly instead.
- `admin_token` — required on the `/_ement` admin API when set. `ctl` reads
  it, and the listen address, from the same config file (`ctl --config FILE`
  for a non-default one).
- `store_dir` — a leading `~` is expanded.

The proxy shuts down cleanly on SIGINT and SIGTERM (`systemctl stop`),
giving requests in flight three seconds to finish.

## Admin CLI

```
ement-e2ee ctl status
ement-e2ee ctl bootstrap [--recovery-key-file FILE]
ement-e2ee ctl verify [--device DEVICEID] [--timeout SECS]
ement-e2ee ctl verify list|start|show|accept|start-sas|sas-accept|confirm|mismatch|cancel
ement-e2ee ctl keys export FILE   # passphrase-protected, Element-compatible
ement-e2ee ctl keys import FILE
ement-e2ee ctl debug check|session|devices|room|event|logs|log-level|report
```

The CLI talks to `/_ement/*` on the proxy's listen address, which it takes
from the config file (`--proxy URL` overrides it). The `verify` subcommands
perform single steps of a flow, for scripting.

## Debugging

Start with `ement-e2ee ctl debug check`. It tests the homeserver connection,
the clock, the access token, the published device keys and one-time keys,
cross-signing, the key backup, whether ement is syncing and the messages
still waiting for keys, and prints what to do about each problem; it exits non-zero
if a check fails. Then, as needed:

```
ement-e2ee ctl debug event ROOM_ID EVENT_ID   # why this message does (not) decrypt, and the fix
ement-e2ee ctl debug room ROOM_ID             # encryption settings, recipients' devices, placeholders
ement-e2ee ctl debug devices [USER_ID]        # devices and how far each is trusted
ement-e2ee ctl debug session                  # sync activity, counters, pending work
ement-e2ee ctl debug logs [--level warn]      # recent log lines, kept in memory
ement-e2ee ctl debug log-level ement_e2ee=debug   # change the log filter without a restart
ement-e2ee ctl debug report --output FILE     # all of it as JSON, for a bug report
```

Every subcommand takes `--json` for the proxy's raw answer and `--user-id`
to pick a session when several accounts are connected. The report contains
Matrix IDs and public keys, but no tokens, passphrases or private keys.

## Caveats

- **Late keys repair placeholders in place, as edits.** When the key for an
  "undecryptable" placeholder arrives (from the sender, another device, a key
  import or `ctl bootstrap`), the proxy hands ement an edit that replaces the
  placeholder, so the message carries ement's `[edited]` marker. Reactions
  and other non-message events become a one-line note instead; reopening the
  room renders them properly. Placeholders in the notifications buffer are
  not repaired, and the proxy forgets which placeholders it has handed out
  when it restarts.
- **The proxy only pumps crypto while ement is syncing** (its long-poll is the
  heartbeat): room keys and verification messages reach the proxy inside
  ement's `/sync` responses. Keep ement connected during `ctl verify`;
  `ctl debug check` warns when it has not synced for two minutes.
- **Session restore**: if you use `ement-save-sessions`, the proxy re-learns
  the session from the token via `/account/whoami` — nothing to do. If you
  log out (token invalidated), the session is evicted; log in through the
  proxy again.
- **Tokenless media** (room avatars): ement fetches these without auth; the
  proxy borrows an active session's token upstream. With zero sessions they
  pass through untouched.
- **Trust model**: the proxy decrypts regardless of sender-device trust
  (ement has no UI to distinguish) and shares room keys with all devices in
  the room, like other clients' defaults.
- **WSL2**: keep the clock NTP-synced (crypto is timestamp-sensitive), bind
  only on 127.0.0.1 (default), and note that localhost is shared with Windows
  processes.

## Storage

`~/.local/share/ement-e2ee/{user}/{device}/`:

- `matrix-sdk-crypto.sqlite3` — olm account, sessions, room keys, trust state
    (optionally encrypted with `store_passphrase`).
- `media.sqlite` — mxc → attachment encryption keys (needed to decrypt media
  you've received/sent; deleting it makes old encrypted media undownloadable
  until re-fetched keys arrive by other means).

Deleting the whole store directory makes the proxy create a fresh olm account
for the same device ID on next connect — other clients will then warn about a
changed device. Prefer keeping it; back it up if you care.

## Development

```sh
cargo test          # unit tests plus end-to-end tests (see below)
cargo run -- serve --homeserver https://matrix.org --log-level debug
curl http://127.0.0.1:8009/_matrix/client/versions   # smoke test
```

The end-to-end tests (`src/e2e_tests.rs`) run real matrix-sdk-crypto machines
through the proxy against an in-process fake homeserver (`src/testutil.rs`),
over loopback HTTP: message round trips, `/notifications` and history
decryption, media, key export/import, placeholder repair, `ctl bootstrap`
(SSSS, cross-signing, backup restore), `ctl verify` (SAS, interactive and
step by step) and `ctl debug`. `tests/process.rs` runs the built binary:
signals, exit codes, `ctl` against a live proxy, `setup`. None of it needs a
network or an account.
