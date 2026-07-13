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
  `/context`, and `/event` responses; undecryptable events render as a
  readable placeholder and trigger an automatic room-key request.
- **Send**: transparently encrypts everything sent into encrypted rooms
  (messages, edits, reactions), including establishing olm sessions and
  sharing megolm keys with full (not lazy-loaded) room membership.
- **Join your existing identity**: `ctl bootstrap` takes your recovery key or
  passphrase, imports your cross-signing keys from SSSS, signs this device
  (green shield in Element), and restores your history keys from server-side
  key backup. New room keys are backed up automatically afterwards.
- **Verification**: emoji (SAS) verification against your other devices via
  `ctl verify`.
- **Media**: uploads are encrypted (spec `EncryptedFile`/AES-CTR), downloads
  decrypted on the fly — including ement's tokenless avatar fetches. Media
  sent to unencrypted rooms is re-uploaded as plaintext automatically.
- **Multi-account**: sessions are keyed by access token; each gets its own
  sqlite crypto store under `~/.local/share/ement-e2ee/`.

## Build

Requires Rust ≥ 1.93 (`rustup` recommended) and a checkout of
[matrix-rust-sdk](https://github.com/matrix-org/matrix-rust-sdk) at
`../matrix-rust-sdk` (path dependencies).

```sh
cargo build --release
cargo install --path .   # puts ement-e2ee on ~/.cargo/bin
```

## Setup

1. Configure:

   ```sh
   mkdir -p ~/.config/ement-e2ee
   cp config.example.toml ~/.config/ement-e2ee/config.toml
   $EDITOR ~/.config/ement-e2ee/config.toml   # set homeserver
   ```

2. Run the proxy (`contrib/ement-e2ee.service` for systemd):

   ```sh
   ement-e2ee serve
   ```

3. Connect ement through it:

   ```elisp
   (ement-connect :user-id "@you:example.org"
                  :uri-prefix "http://localhost:8009")
   ```

   On first sync the proxy registers device keys for ement's device; it shows
   up in Element → Settings → Sessions.

4. Join your encrypted identity (prompts for your recovery key; never passes
   it via argv):

   ```sh
   ement-e2ee ctl status      # sanity check: session listed?
   ement-e2ee ctl bootstrap   # SSSS import + self-sign + backup restore
   ```

5. Optionally, emoji-verify against another device (e.g. Element):

   ```sh
   ement-e2ee ctl verify start ELEMENTDEVICEID   # or start it from Element and `verify list`
   ement-e2ee ctl verify show <flow>             # compare the emoji
   ement-e2ee ctl verify confirm <flow>
   ```

## Admin CLI

```
ement-e2ee ctl status
ement-e2ee ctl bootstrap [--recovery-key-file FILE]
ement-e2ee ctl verify list|start|show|accept|start-sas|sas-accept|confirm|cancel
ement-e2ee ctl keys export FILE   # passphrase-protected, Element-compatible
ement-e2ee ctl keys import FILE
```

The CLI talks to `/_ement/*` on the proxy's listen address; set `admin_token`
in the config if localhost isn't trustworthy enough for you.

## Caveats

- **Late-arriving keys don't retro-fix delivered events.** The proxy is a
  pass-through: once ement has rendered a "unable to decrypt" placeholder,
  arriving keys can't rewrite it. Close and reopen the room buffer — history
  refetches through `/messages` and decrypts fine. Run `ctl bootstrap` before
  serious use to make this rare.
- **The proxy only pumps crypto while ement is syncing** (its long-poll is the
  heartbeat). Keep ement connected during `ctl verify`.
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
cargo test          # unit tests (route classifier, rewrites, media crypto)
cargo run -- serve --homeserver https://matrix.org --log-level debug
curl http://127.0.0.1:8009/_matrix/client/versions   # smoke test
```
