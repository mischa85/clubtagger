# Clubtagger Development Notes

## Overview

Clubtagger is a DJ track identification system that combines:
- **Shazam audio fingerprinting** — identifies tracks from audio input
- **Pioneer Pro DJ Link protocol** — reads track metadata directly from CDJs
- **Confidence accumulation model** — unified scoring of multiple signals

## Hardware Setup

- **4x CDJ-3000X** — Professional DJ players on Pro DJ Link network (link-local)
- **DJM-V10** — Mixer at device 33, sends on_air signals to CDJs
- **NXS-GW** — Gateway device (device 25) broadcast by CDJ-3000X, shares IP with real CDJ

## Architecture

### Key Components

| File | Purpose |
|------|---------|
| `confidence.c` | Unified confidence accumulation model |
| `prolink/prolink.c` | CDJ device discovery and status packet processing |
| `prolink/prolink_thread.c` | Pro DJ Link thread, track selection logic |
| `prolink/registration.c` | Device registration on the network |
| `prolink/dbserver.c` | DBServer connection for track metadata |
| `prolink/nfs_client.c` | NFS client for artwork/waveforms |
| `prolink/pdb_parser.c` | Rekordbox PDB database parser |
| `prolink/onelibrary.c` | OneLibrary (exportLibrary.db) decryption + SQLite |
| `shazam/id_thread.c` | Audio fingerprint ID and signal emission |
| `www/app.js` | Web UI JavaScript |
| `www/index.html` | Web UI HTML |

### Confidence Model

The confidence model (`confidence.c`) replaces the old hardcoded decision rules.
Each deck accumulates a score (0-1000) from weighted signals:

| Signal | Weight | When |
|--------|--------|------|
| CDJ_LOADED | +200 | Track metadata resolved from database |
| CDJ_PLAYING | +50 | Deck started playing |
| CDJ_DURATION | +15/10s | Continuous playback (cap +150) |
| CDJ_ON_AIR | +100 | DJM reports deck on-air |
| CDJ_ON_AIR_EDGE | +200 | Moment fader goes up |
| SHAZAM_MATCH | +250 | Shazam returned a result |
| SHAZAM_CONFIRM | +150 | Consecutive Shazam match |
| ISRC_MATCH | +400 | ISRC match CDJ+Shazam |
| FUZZY_MATCH | +200 | Title+artist match CDJ+Shazam |
| SHAZAM_DISAGREE | -100 | Different track returned |

Track accepted at 600 (60%). Decay: 3 units/second with no signals.

### Track Source Types

| Source | Meaning |
|--------|---------|
| `both` | CDJ + Shazam cross-correlation |
| `audio` | Shazam fingerprint only (vinyl/analog) |
| `cdj/on-air` | CDJ with on-air signal from DJM |
| `cdj/duration` | CDJ with continuous playback |
| `cdj` | CDJ metadata only |

## Issues Fixed

### 1. NXS-GW Device Appearing as Extra Device
**Problem:** CDJ-3000X broadcasts a gateway device (NXS-GW, device 25) that shares IP with real CDJ.
**Solution:** Filter devices with "-GW" in name as `DEVICE_TYPE_UNKNOWN`.

### 2. Shazam Overriding Correct CDJ Tracks
**Problem:** Shazam would return wrong matches and override CDJ.
**Solution:** Confidence model — CDJ signals accumulate independently, Shazam disagreement penalizes.

### 3. CDJ-3000X Extended Status Packets
**Problem:** CDJ-3000X sends 1152-byte status packets with alternating subtypes. Every other packet has rekordbox_id=0/slot=0 causing track flipping.
**Solution:** Skip track fields when rekordbox_id=0 AND slot=0 AND device already has valid track data.

### 4. Auto-Passive Mode
**Problem:** Need to avoid consuming a player slot when traffic is already flowing (SPAN port, multi-CDJ).
**Solution:** 10-second observation phase. If status packets received without registering → stay passive. Otherwise register.

### 5. OneLibrary Support
**Problem:** CDJ-3000X uses encrypted SQLite database (SQLCipher 4) instead of PDB.
**Solution:** Decrypt with PBKDF2-HMAC-SHA512 + AES-256-CBC, open in-memory with sqlite3_deserialize().

### 6. Shazam Rate Limiting
**Problem:** Shazam API returns error 6 when called too frequently.
**Solution:** Exponential backoff (30/60/120/300s) on API errors. Default gap increased to 20s.

## Protocol Corrections (from alphatheta-connect)

- Port names: 50001=beat, 50002=status (were swapped)
- Added play states: CUING(0x07), PLATTER_HELD(0x08), SEARCHING(0x09), SPUN_DOWN(0x0e), ENDED(0x11)
- Added streaming slots: SLOT_STREAMING(0x06), SLOT_BEATPORT(0x09)
- Added CDJ-3000 position packets (subtype2=0x00 on port 50001, ~30ms)
- NFS read chunk increased from 1280 to 8192 bytes

## Configuration Constants

| Constant | Value | Location |
|----------|-------|----------|
| Accept threshold | 600 (60%) | confidence.h |
| Decay rate | 3/second | confidence.h |
| Duration tick | 15 per 10s | confidence.h |
| Shazam gap | 20s default | main.c |
| Same-track hold | 120s default | main.c |
| Shazam backoff | 30-300s on error | id_thread.c |
| NFS read chunk | 8192 bytes | nfs_client.c |
| Observation period | 10s | registration.c |
| Min keepalives for NFS | 5 | registration.h |

## Building

```bash
cd clubtagger
make clean && make
```

Requires: libcurl, libsqlite3, libpcap, OpenSSL (libcrypto), optionally libvibra (Shazam), libFLAC.
