# ASKI CHAT

```
     _    ____  _  _____   ____ _   _    _  _____
    / \  / ___|| |/ /_ _| / ___| | | |  / \|_   _|
   / _ \ \___ \| ' / | | | |   | |_| | / _ \ | |
  / ___ \ ___) | . \ | | | |___|  _  |/ ___ \| |
 /_/   \_\____/|_|\_\___| \____|_| |_/_/   \_\_|
```

> **Decentralised P2P messenger with Signal-grade cryptography**
> Double Ratchet • XChaCha20-Poly1305 • Post-Compromise Security
> Voice & ASCII-video calls • File transfer • DHT discovery

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8.svg)](https://golang.org)
[![Version](https://img.shields.io/badge/Version-main%201.0-orange.svg)]()

ASKI CHAT — fully decentralised messenger with Signal Protocol-level cryptography. No servers, no databases, no accounts. Just you, your contact, and math.

---

## Highlights

| Feature | Description |
|---------|-------------|
| **Double Ratchet** | Signal-style ratchet with per-message key rotation |
| **Post-Compromise Security** | Automatic recovery after key compromise |
| **Forward Secrecy** | Compromise of current keys doesn't reveal past messages |
| **XChaCha20-Poly1305** | Authenticated encryption with 192-bit nonce per message |
| **X25519 DH Ratchet** | Curve25519 with automatic ephemeral key rotation |
| **Out-of-order delivery** | Up to 500 skipped messages with auto-recovery |
| **Master password** | Identity + contacts encrypted with AES-256-GCM over Argon2id |
| **Files** | Chunked transfer with SHA-256 verification and progress |
| **Voice calls** | Opus-encoded 48 kHz direct P2P audio (direct-only, no relay) |
| **Video calls** | ASCII-rendered webcam or built-in avatar over P2P |
| **Global-only P2P** | LAN/loopback never advertised — traffic goes via public internet only |
| **DHT discovery** | Find contacts through the global IPFS/Kad-DHT |
| **Mutual trust** | Both sides must `.addfriend` — prevents spam and random dials |
| **TUI** | Terminal UI built on [Bubble Tea](https://github.com/charmbracelet/bubbletea) with IDE-style autocomplete |
| **i18n** | English / Русский / Deutsch / Français / 中文 / 日本語 |

---

## Install

### Build from source

```bash
git clone https://github.com/TheSiriuss/F2F-chat.git
cd F2F-chat
./build.sh               # standard build → f2f-cli.exe (~32 MB)
./build.sh --upx         # UPX-compressed → f2f-cli-upx.exe (~8 MB)
```

Requires Go 1.21+ and a CGO-capable GCC (MinGW on Windows) because we statically link libopus for voice calls.

### Run

```bash
./f2f-cli
```

On first start you'll be asked for a master password. The password encrypts your identity key and contacts on disk via Argon2id (256 MB / t=4) — the app is **useless to anyone without it**. Pick a strong one.

---

## Quickstart

Open the TUI, press `.` in the input field — a dropdown with every command appears.

```
.bootstrap                 connect to the DHT
.login nikita              create or load the "nikita" profile
.info                      show your PeerID + fingerprint
.copy                      copy the .addfriend line into clipboard
```

Send the output of `.copy` to your friend (via Signal, email, carrier pigeon — any out-of-band channel). They run it verbatim on their side:

```
.addfriend nikita 12D3KooW...abc base64pub==
```

Then both of you:

```
.connect nikita            open an encrypted chat
type a message             just hit Enter to send
.call nikita               voice call (Opus, direct P2P)
.vidcall nikita            video call (ASCII webcam or built-in avatar)
.file /path/to/file        send a file
.hangup                    end the call
.leave                     leave the chat
```

Full command list: `?` in the input, or browse the autocomplete dropdown.

---

## Call protocol — why you might see "relay refused"

ASKI CHAT is a true P2P app. Audio/video calls go through a **direct** libp2p connection — never through a public relay — for two reasons:

1. **Bandwidth**: circuit-v2 relays have a 128 KiB per-direction data cap. That's ~14 seconds of voice at 48 kbit/s or ~6 seconds of video before the relay resets you.
2. **Privacy**: relay operators see traffic volume and timing. Direct connections don't.

If your NAT is symmetric (common on mobile carriers and some corporate networks) and hole-punching fails, `.call` will **refuse to start** instead of dropping the call mid-sentence. You'll see a clear message pointing at workarounds (VPN, IPv6, running your own relay).

Text chat + files still work over relay as a fallback — they fit within the bandwidth budget.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                         USER (TUI)                           │
│  • dot-command palette with contact-aware autocomplete       │
│  • dedicated call view with ASCII video viewport             │
│  • i18n — 6 languages, switchable at runtime (.language)     │
└─────────────────────────────┬────────────────────────────────┘
                              │
┌─────────────────────────────┴────────────────────────────────┐
│                        f2f.Node                              │
│                                                              │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────┐  │
│  │ Chat stream  │   │ Call stream  │   │  Video stream    │  │
│  │              │   │              │   │                  │  │
│  │ Double       │   │ Per-frame    │   │ Per-frame        │  │
│  │ Ratchet      │   │ XChaCha20    │   │ XChaCha20        │  │
│  │ (msgs/files) │   │ (Opus audio) │   │ (ASCII video)    │  │
│  └──────────────┘   └──────────────┘   └──────────────────┘  │
│                                                              │
│  Per-protocol HKDF key derivation from shared secret so      │
│  chat/call/video keys can never accidentally overlap.        │
└─────────────────────────────┬────────────────────────────────┘
                              │
┌─────────────────────────────┴────────────────────────────────┐
│                       libp2p / Kad-DHT                       │
│  • QUIC + TCP transports, holepunch (DCUtR), relay fallback  │
│  • Connection manager with protected contacts                │
│  • 20-second libp2p ping keepalive to preserve NAT mapping   │
│  • Global-only address advertisement (LAN/loopback filtered) │
└──────────────────────────────────────────────────────────────┘
```

### Crypto
- **Chat messages**: Double Ratchet (HKDF-SHA256 + X25519 DH ratchet + symmetric ratchet). Per-message `MsgKey` never repeats. PCS after 30 sec of activity.
- **Voice frames**: XChaCha20-Poly1305 with monotonic counter nonce; per-frame HKDF rotation every 250 frames.
- **Video frames**: Same scheme, independent HKDF info string.
- **Stored files** (`identity.dat`, `contacts.dat`): AES-256-GCM with key derived via Argon2id from the master password (256 MB / t=4 / 32-byte salt).

### Networking
- **Discovery**: Kad-DHT via `libp2p.EnableRelay()` + bootstrap peers.
- **Dial**: DHT `FindPeer` → direct dial all addresses → hole-punch via DCUtR.
- **Relay**: circuit-v2 stays around for chat/files if direct fails, but voice/video refuse it explicitly.
- **Keep-alive**: periodic libp2p Ping every 20 s to each contact to keep UDP NAT mappings warm.

---

## Configuration

Stored in `settings.json` alongside the binary:

| Field | Description |
|-------|-------------|
| `audio_input_device_id` / `_name` | Microphone (set via `.settings input <N>`) |
| `audio_output_device_id` / `_name` | Speakers (`.settings output <N>`) |
| `voice_auto_play` | Auto-play incoming `.wav` voicemails |
| `video_source_type` | `"ascii"` (default, no camera), `"camera"`, `"file"` |
| `video_camera_id` | DirectShow / V4L2 / AVFoundation device name |
| `video_source_path` | Image/GIF used when type == `"file"` |
| `language` | UI language: `en` / `ru` / `de` / `fr` / `zh` / `ja` |

Change anything at runtime through `.settings` — the TUI persists changes automatically.

---

## Security model

### Threats we defend against
- **Passive eavesdropping**: everything end-to-end encrypted, no plaintext on the wire.
- **Relay-operator snooping**: direct connections for calls; chat ratcheted.
- **Local device compromise (post-factum)**: forward secrecy means past messages stay encrypted.
- **Disk seizure**: identity + contacts encrypted with Argon2id-derived key; attacker needs your password.
- **Message forgery**: Poly1305 AEAD tag on every frame; counter nonces prevent replays.
- **Man-in-the-middle**: 160-bit fingerprint for out-of-band verification.
- **Spam / random dials**: mutual `.addfriend` required — you literally can't receive anything from unverified peers.

### Threats we *don't* claim to defend against
- **Keylogger on your machine**: we can't encrypt what you type before you type it.
- **Coercion to reveal password**: the password is your responsibility.
- **Global adversary doing traffic analysis**: this is P2P, not Tor. Your IP is visible to your contact (and to DHT peers until hole-punch completes).
- **Compromise of libp2p identity at runtime**: memory dump = active ratchet keys exposed. PCS limits the blast radius but not a point-in-time snapshot.

### Cryptographic choices
| What | Why |
|------|-----|
| XChaCha20-Poly1305 | 192-bit nonce eliminates any possibility of nonce reuse |
| X25519 | Fastest audited curve; constant-time impl in Go stdlib |
| HKDF-SHA256 | Standard, no rust/CGO dependency |
| Argon2id (256 MB / t=4) | Memory-hard — even GPUs slow down dramatically |
| Ed25519 signatures | On the handshake envelope; binds ephemeral DH to long-term identity |

---

## Testing

```bash
go test ./pkg/f2f/...                     # full suite
go test -run TestReal_Direct ./pkg/f2f/   # real-libp2p + 70-second voice call
go test -run TestReal_Relay ./pkg/f2f/    # relay refusal policy verified
```

25+ real-libp2p tests cover:
- Connect handshake, reconnect, race-both-sides-dial, stale addr survival
- Stream-level message/file delivery
- Voice-call offer / accept / decline / hangup / double-offer rejection
- Relay bandwidth cap reproduced + call refused when relay-only
- 70-second direct voice call staying in `CallActive`

---

## Project layout

```
cmd/
  cli/                    main entry point + TUI
    tui/                  Bubble Tea model, views, i18n, banner
    audio.go              legacy CLI audio handlers
    ...
  asciigen/               one-shot: PNG → embedded ASCII frame
pkg/
  f2f/                    core library
    call.go               voice-call protocol (own libp2p stream)
    video.go              ASCII-video capture + transmission
    camera.go             ffmpeg subprocess for webcam
    ascii.go              image → ASCII rendering
    ascii_logo.go         embedded ASKI avatar
    network.go            chat stream (.connect) flow
    crypto.go             HKDF / Argon2id / fingerprint
    call.go               in-band call signaling + DCUtR upgrade
    ...
aski.png / aski2.png / aski3.png
build.sh
README.md                 (this file)
```

---

## Roadmap

- **Own relay server** mode (`f2f-cli --relay --listen ...`) with `WithInfiniteLimits()` so users with symmetric NAT can run their own relay without the 128 KiB cap
- **Encrypted group chats** (MLS-style)
- **Offline queue** — retry send when peer comes online (already partially supported via contacts.dat)
- **Call-screen video source switch** without restarting the call
- **Tor transport** as an optional privacy layer

---

## Status

**Main branch 1.0** — early, works. Use at your own risk.
Not audited. Don't use for anything where life / liberty / livelihood depend on it.

Bug reports welcome via GitHub issues.

---

## License

GNU Affero General Public License v3.0 — see [LICENSE](LICENSE).

TL;DR: you can use, modify, and distribute this, but any public service built on it must also be open-source under AGPL.
