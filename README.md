# Paragon Chat

A serverless, peer-to-peer encrypted messenger written in Python.

Two peers connect **directly** (optionally through Tor), authenticate each
other with a SPAKE2 password-authenticated key exchange, and exchange
messages and files over an authenticated ChaCha20-Poly1305 channel.
There is no relay, no account server, and no metadata collector: the entire
state (identity, contacts, history, queued messages, settings) lives in a
single password-encrypted `.paragon` file.

This is a foundation project, not a hardened product. Read
[Security notes](#security-notes) before using it for anything sensitive.

---

## Table of contents

1. [Features](#features)
2. [Requirements](#requirements)
3. [Install](#install)
4. [Quick start](#quick-start)
5. [Identity model](#identity-model)
6. [Tor setup (onion v3)](#tor-setup-onion-v3)
7. [Using the GUI](#using-the-gui)
8. [Using the CLI](#using-the-cli)
9. [Files and transfers](#files-and-transfers)
10. [Environment variables](#environment-variables)
11. [Account file format](#account-file-format)
12. [Security notes](#security-notes)
13. [Troubleshooting](#troubleshooting)
14. [Project layout](#project-layout)

---

## Features

- **Serverless P2P** over plain TCP or Tor v3 `.onion`.
- **SPAKE2-Symmetric** PAKE handshake keyed by a shared token: knowing the
  peer's ID is required to connect, no keys are ever sent in cleartext.
- **ChaCha20-Poly1305** AEAD on every frame, per-direction session keys
  derived with HKDF from the handshake transcript.
- **Encrypted account file** with Argon2id (100 MB, time=2, par=8) + AES-GCM
  + gzip, written atomically.
- **Tor v3 onion identity generator**: Ed25519 keypair, correct onion
  checksum, and a ready-to-use HiddenService directory.
- **Onion-only mode**: refuses plain IP/host peers, no direct-IP dials.
- **Messaging** with delivery ACKs, retry on missing ACK, and optional
  random send delay (timing-correlation resistance).
- **File transfers** with SHA-256 integrity check, offer/accept/decline
  flow, and a strict size cap.
- **Ping/pong latency** indicator.
- **Tkinter GUI** and a minimal **CLI**.

---

## Requirements

- **Python 3.8+** (3.10+ recommended).
- **tkinter** (bundled with CPython on Windows and most Linux distros;
  on Debian/Ubuntu: `sudo apt install python3-tk`).
- **Tor** (only for `.onion` mode; not needed for plain LAN/IP usage).
- Python packages: see [requirements.txt](requirements.txt).

---

## Install

```bash
pip install -r requirements.txt
```

Or manually:

```bash
pip install pynacl argon2-cffi cryptography spake2
```

No system service, daemon, or database is required.

---

## Quick start

### Two peers on the same machine (smoke test, no Tor)

Peer A:

```bash
python chat.py
# Account path: a.paragon   (new file)
# Password: ****
# Click: Generate plain (IP/host), Host=127.0.0.1, Port=9001
# Click: Create account
# Click: Copy my ID  -> share this base64 string with peer B
```

Peer B:

```bash
python chat.py
# Account path: b.paragon   (new file)
# Password: ****
# Click: Generate plain (IP/host), Host=127.0.0.1, Port=9002
# Click: Create account
# Click: Copy my ID  -> share with peer A
```

In both windows:

1. Click `+ Add`, paste the other peer's ID, click `ADD`.
2. Select the contact on the left.
3. Type a message, press Enter.

The status dot `*` appears when the session comes up; `v` marks a
delivered message.

### Real deployment

For real use, generate an onion identity on both sides and route through
Tor. See [Tor setup](#tor-setup-onion-v3).

---

## Identity model

An **ID** is the whole address, base64url-encoded, in the form:

```
host:port|token        (then base64url, padding stripped)
```

where:

- `host` is either a plain hostname/IP, or a **Tor v3 `.onion` address**
  (56 base32 chars + `.onion`).
- `port` is the port the peer expects to reach you on. For onion mode this
  is the **virtual** HiddenService port, not your local bind port.
- `token` is a 32-byte random secret, base64url-encoded. The PAKE
  handshake uses `sha256(token)` as the shared password.

**The ID is a secret.** Anyone who has your ID has your token and can
attempt a handshake. Treat it like a password: share only over a channel
you already trust (Signal, in person, PGP, etc.).

### Onion v3 identity

When you click `Generate onion identity (v3)`:

1. A 32-byte Ed25519 seed is generated with `os.urandom`.
2. `(pubkey, secret_key)` is derived via libsodium
   (`crypto_sign_seed_keypair`).
3. The onion address is computed correctly:
   `base32(pubkey || SHA3-256(".onion checksum" || pubkey || 0x03)[:2] || 0x03)`.
4. A HiddenService directory is written with:
   - `hostname`
   - `hs_ed25519_public_key` (`== ed25519v1-public: type0 ==\x00\x00\x00` + pubkey)
   - `hs_ed25519_secret_key` (`== ed25519v1-secret: type0 ==\x00\x00\x00` + secret)
   with mode 0600 on the secret key.

The seed is stored **inside** the encrypted `.paragon` file, never in
plaintext. The HS directory is the one secret you must protect on disk.

---

## Tor setup (onion v3)

### 1. Install and run Tor

- **Tor Browser** (easiest): just launch it. SOCKS listens on `127.0.0.1:9150`.
- **Standalone Tor**: install `tor`, run it as a service / in the foreground.
  SOCKS listens on `127.0.0.1:9050`.

### 2. Generate your identity in Paragon

1. Launch `python chat.py`.
2. On the identity screen, leave `Port` at `9001` (or any port you like).
3. Set `Tor HS dir` to a private folder, e.g. `C:\Paragon\hs_9001`.
4. Click `Generate onion identity (v3)`.
   Paragon writes the HS files right away.
5. Click `Copy my ID` and share it.

### 3. Wire Tor to that HiddenService directory

Copy [torrc.example](torrc.example) and merge into your real `torrc`:

```
HiddenServiceDir C:\Paragon\hs_9001
HiddenServicePort 9001 127.0.0.1:9001
```

- `HiddenServiceDir` must match the folder you chose in step 2.
- `HiddenServicePort <virtual> <target>`:
  - `<virtual>` = the `Port` in your Paragon ID (e.g. 9001).
  - `<target>`  = where Paragon actually listens locally.
    By default this is `127.0.0.1:<listen_port>` where `listen_port`
    equals your `Port` unless you override `PARAGON_LISTEN_PORT`.

### 4. Restart Tor

On Windows with Tor Browser, use the Tor Browser's Tor process. With a
standalone Tor, restart the service. Publishing the descriptor usually
takes **30-60 seconds** after restart.

### 5. Point Paragon's SOCKS client at Tor

Paragon uses `127.0.0.1:9050` by default. For Tor Browser:

```bat
set PARAGON_SOCKS_PORT=9150
python chat.py
```

### 6. Verify

- Open your onion address in a Tor Browser tab. It should fail to load
  (Paragon is not HTTP), but the descriptor resolves once Tor has published
  it. If the page says the onion is unreachable for several minutes after
  restart, check `HiddenServiceDir` / permissions.

### Multiple identities on one machine

Add one block per identity in `torrc`:

```
HiddenServiceDir C:\Paragon\hs_9001
HiddenServicePort 9001 127.0.0.1:9001

HiddenServiceDir C:\Paragon\hs_9002
HiddenServicePort 9002 127.0.0.1:9002
```

Each Paragon process needs its own `.paragon` file and its own listen port
(`PARAGON_LISTEN_PORT`).

---

## Using the GUI

Launch with no arguments:

```bash
python chat.py
```

### Account screen

- **Path**: `.paragon` file. If it does not exist, it is created
  (password twice). If it exists, it is opened (password once).
- **Password**: never stored. Forgot it -> file is unrecoverable.

### Identity screen

- **Generate onion identity (v3)** — recommended. Produces a `.onion`
  address and the matching HiddenService directory. Onion-only mode is
  enabled for the resulting account: plain IP peers cannot be added and
  no direct-IP dials are attempted.
- **Generate plain (IP/host)** — LAN/IP mode. Your real IP and port will
  be visible to any peer you connect to.
- **Port** — the advertised port (for onion: the virtual HS port).
- **Tor HS dir** — where the HiddenService key files are written.
- **Copy my ID** — copies the base64 ID to the clipboard.

### Chat window

- **Left sidebar**: peer list. Filled dot = session up, empty dot = no session.
- **+ Add**: paste peer's ID + optional display name.
- **Right-click** on a peer: `Rename`, `Remove`.
- **Status bar**: online/offline + last measured ping RTT.
- **Bottom**: text input (Enter to send) + paperclip button for files.
- **Hourglass** = in flight, **check** = delivered (ACK received).
  Messages that don't get an ACK within 30 s are re-queued automatically.

### Settings (gear icon)

- **Delay min/max** (seconds): random delay before each send.
  Set `0/0` to disable. Useful against timing correlation.
- **Ping interval** (seconds, min 5): keepalive / latency probe.
- **Current ID**: your identity; `Copy ID`.
- **Regenerate token**: new identity. All current contacts will see you
  as a new peer. Use deliberately.

---

## Using the CLI

The CLI is minimal and intended for scripting and smoke tests.

```bash
# Generate a plain identity without creating an account file
python chat.py --gen 127.0.0.1 9001
# prints: ID: <base64>   TOKEN: <base64>

# Open or create an account interactively
python chat.py account.paragon                 # open, prompts for password
python chat.py new.paragon <base64_id>         # create with a given ID
```

Interactive commands in the CLI session:

```
to <peer_key> <text>      send a message
exit                      quit
```

`peer_key` is the first 16 hex chars of `sha256(id_str)` — printed in
`list(core.peers)`.

---

## Files and transfers

- Click the paperclip, choose a file. The receiver gets an
  **Accept / Decline** dialog (60 s timeout).
- Received files land in `./downloads/` (created next to the running
  script), with collision-safe renaming (`name.1.ext`, `name.2.ext`, ...).
- Each transfer is chunked at 64 KB, hashed with SHA-256 on the fly, and
  the receiver rejects the file if the digest does not match.
- Hard cap per file: **100 MB**.
- Filenames are sanitized: `/`, `\`, and NUL are replaced; leading dots
  are prefixed; length is capped to 200 chars.
- Received chunks larger than the declared size abort the transfer
  (disk-exhaustion guard).

---

## Environment variables

All are optional; defaults shown in parentheses.

| Variable | Meaning |
|---|---|
| `PARAGON_DELAY_MIN` (`0`) | Minimum random send delay, seconds. |
| `PARAGON_DELAY_MAX` (`0`) | Maximum random send delay, seconds. |
| `PARAGON_PING_INTERVAL` (`30`) | Keepalive interval, seconds (min 5). |
| `PARAGON_SOCKS_HOST` (`127.0.0.1`) | SOCKS5 proxy host for `.onion` dials. |
| `PARAGON_SOCKS_PORT` (`9050`) | SOCKS5 proxy port (`9150` for Tor Browser). |
| `PARAGON_LISTEN_HOST` (auto) | Local bind host. Only used in onion mode; defaults to `127.0.0.1`. |
| `PARAGON_LISTEN_PORT` (auto) | Local bind port. Only used in onion mode; defaults to the ID's `port`. |

Windows example:

```bat
set PARAGON_SOCKS_PORT=9150
set PARAGON_LISTEN_PORT=9010
python chat.py
```

---

## Account file format

`.paragon` files are:

```
"PARAGON\x00"   (8 bytes magic)
version         (1 byte, currently 0x01)
salt            (16 bytes)
nonce           (12 bytes)
AES-GCM ciphertext of gzip(JSON(state))
```

- Key = Argon2id(password, salt, time=2, memory=102400 KiB, par=8, len=32).
- The plaintext JSON contains: identity (host, port, token, token_hash,
  id_str, **onion_seed**), peers, settings (delays, ping interval, SOCKS,
  listen, hs_dir, onion_only), the outbound message queue, the outbound
  file queue, history, and seen message IDs.
- Writes are atomic: `path.tmp` is written then `os.replace`d over the
  original.

**Back this file up.** It is the only copy of your contacts and history.

---

## Security notes

Paragon is a working foundation, not a finished secure messenger. Before
relying on it, be aware:

### What it does well

- PAKE (SPAKE2-Symmetric) means passive eavesdroppers cannot derive the
  session key and active MITM fails without the token.
- All application frames are AEAD-sealed with per-direction keys bound to
  the handshake transcript.
- Account state is encrypted at rest with a memory-hard KDF.
- Onion mode prevents direct IP connections and rejects plain peers.

### Known limitations

- **No forward secrecy across sessions.** Session keys are fresh per
  connection, but the long-term token is static. Compromise of the token
  compromises future sessions, not past history.
- **No replay cache persistence across long gaps.** Dedup uses a bounded
  `seen_ids` list (10k entries). Very old re-sends could be re-accepted.
- **No metadata protection beyond Tor.** Over plain TCP, peer IPs and
  ports are visible to the network.
- **Threading:** the GUI calls public `Core` methods from the Tk thread
  while the asyncio loop runs in a background thread. Simple operations
  are fine in practice, but this is not a rigorously synchronized API.
- **Regenerating the token** invalidates all current contacts. It does
  not rotate the onion address; the onion keypair is separate.
- **Secret key on disk:** `hs_ed25519_secret_key` is the private key of
  your onion address. Leaking it lets an attacker impersonate your onion
  endpoint. Keep it off cloud sync and out of git.
- **No audit, no fuzzing, no test suite.** Review `core.py` before use.

### Recommendations

- Run Paragon **only behind Tor** (`onion_only=True`) for real privacy.
- Share your base64 ID only over a channel you already trust.
- Back up `.paragon`; never back it up without the password to a
  network-attached drive.
- Do not run two instances on the same `.paragon` file at the same time.

---

## Troubleshooting

### `not a .paragon file (bad magic)`

You pointed at a non-Paragon file, or the file was corrupted. Restore from
backup.

### `wrong password or corrupted file`

Wrong password, or the file was truncated. There is no recovery.

### Connection to a peer never comes up

- **Plain mode**: check firewall and that the peer's `host:port` is
  reachable (`telnet host port`).
- **Onion mode**: verify Tor is running and SOCKS is reachable at
  `PARAGON_SOCKS_HOST:PARAGON_SOCKS_PORT`. Wait 30-60 s after restarting
  Tor. Check `torrc` points at the correct `HiddenServiceDir`.
- **Onion-only refusal**: if you created the account with onion identity,
  you cannot add plain peers by design. Regenerate a plain identity if
  you need LAN mode.

### HiddenService not publishing

- `tor` log will say `[warn] Directory ... does not exist` or similar if
  the HS dir is wrong.
- On Linux/macOS, `hs_ed25519_secret_key` must be readable only by the
  Tor user. On Windows, permissions are laxer but the folder should not
  be world-readable.

### Files fail with `integrity check failed`

A chunk was corrupted or a malicious sender altered the stream. The file
is deleted and the sender is sent a NACK. Retry.

### `ModuleNotFoundError: No module named 'spake2'`

`pip install -r requirements.txt`. If pip picks a too-old `spake2`, try
`pip install spake2==0.9`.

### GUI fails to start: `No module named 'tkinter'`

On Debian/Ubuntu: `sudo apt install python3-tk`. On macOS with Homebrew
Python: `brew install python-tk`.

---

## Project layout

```
chat.py           Tkinter GUI + CLI entry point
core.py           Networking, crypto, account file, file transfer
default.paragon   Example account file (do not commit real ones)
torrc.example     Example Tor HiddenService configuration
requirements.txt  Python dependencies
README.md         This file
downloads/        Created at runtime; received files land here
hs_<port>/        Created at runtime; HiddenService keys for your onion
```

---

## License

No license is declared in this repository. Treat it as all-rights-reserved
until the author adds one.
