# clubtagger

**clubtagger** is a low-latency recorder and song tagger for clubs and venues.  
It captures live audio from ALSA or SLink (Allen & Heath SQ network audio), generates acoustic fingerprints locally using [vibra],  
identifies songs via Shazam-compatible lookup, and integrates with Pioneer CDJ/XDJ equipment via Pro DJ Link.

---

## Features
- 🎧 **Live audio capture** — ALSA (Linux) or SLink (Allen & Heath SQ, 24-bit)
- 🔎 **Local fingerprinting** via `libvibra` (no audio leaves the system)
- 🎛️ **Pro DJ Link integration** — reads track metadata directly from Pioneer CDJs/XDJs
- 📚 **OneLibrary support** — decrypts and queries Rekordbox 6+ exportLibrary.db (CDJ-3000X)
- 🧠 **Smart matching** — requires 3 consecutive confirmations to reduce false positives
- 🔤 **Fuzzy matching** — Levenshtein distance handles typos and encoding differences
- 🎵 **Vinyl-friendly** — tolerates pitch variations from turntables
- 💾 **WAV/FLAC recording** with seamless file splitting
- 🗄️ **SQLite logging** — track plays with timestamps, ISRC codes
- 🌐 **Web UI** — real-time VU meters and CDJ deck status via SSE
- ⚙️ Lightweight C implementation with modular architecture

---

## Build

### Linux (full features)
```bash
sudo apt-get install libasound2-dev libcurl4-openssl-dev libsqlite3-dev libpcap-dev libflac-dev
make
```

### macOS (SLink + CDJ)
```bash
brew install curl sqlite libpcap flac openssl
make            # builds without ALSA support
```

### Dependencies
- `libcurl` — HTTP communication
- `libvibra` — local acoustic fingerprinting (optional, enables `--audio-tag`)
- `libsqlite3` — track database
- `libpcap` — network packet capture (SLink, Pro DJ Link)
- `libcrypto` (OpenSSL) — OneLibrary decryption (SQLCipher 4)
- `libFLAC` — FLAC encoding (optional)
- `libasound2` — ALSA audio capture (Linux only)

The build auto-detects available libraries. Without libvibra, only `--record` and `--cdj-tag` modes are available.

---

## Usage

clubtagger has three main modes that can be combined:

| Mode | Flag | Description |
|------|------|-------------|
| Recording | `--record` | Capture audio to WAV/FLAC files |
| Audio tagging | `--audio-tag` | Identify songs via Shazam fingerprinting |
| CDJ tagging | `--cdj-tag` | Read track metadata from Pioneer CDJs |

### Audio fingerprinting + recording (ALSA)
```bash
./clubtagger --record --audio-tag \
  --source alsa --device hw:2,0 \
  --db tracks.db --verbose
```

### Audio fingerprinting + recording (SLink)
```bash
./clubtagger --record --audio-tag \
  --source slink --device en0 --rate 96000 \
  --format flac --db tracks.db
```

### CDJ-only tagging (no audio)
```bash
./clubtagger --cdj-tag \
  --prolink-interface en7 \
  --db tracks.db --verbose
```

### Combined: Audio + CDJ (best accuracy)
```bash
./clubtagger --record --audio-tag --cdj-tag \
  --source slink --device en7 \
  --prolink-interface en7 \
  --db tracks.db --sse-socket /tmp/clubtagger.sock
```

### Passive CDJ tagging (SPAN port, no slot consumed)
```bash
./clubtagger --cdj-tag \
  --prolink-interface eth1 --prolink-passive \
  --db tracks.db
```

---

## Options

### Mode flags
| Option | Description |
|--------|-------------|
| `--record` | Enable audio recording to WAV/FLAC |
| `--audio-tag` | Enable Shazam fingerprint identification (requires libvibra) |
| `--cdj-tag` | Enable CDJ/Pro DJ Link track reading |

### Audio source
| Option | Description | Default |
|--------|-------------|---------|
| `--source` | Audio source: `alsa` or `slink` | (required for audio) |
| `--device` | ALSA device or network interface | `default` |
| `--rate` | Sample rate (Hz) | `48000` |
| `--channels` | Audio channels | `2` |
| `--bits` | Bit depth (16 or 24) | `16` |

### Recording & detection
| Option | Description | Default |
|--------|-------------|---------|
| `--format` | Output format: `wav` or `flac` | `wav` |
| `--prefix` | Filename prefix | `capture` |
| `--outdir` | Output directory | `.` |
| `--max-file-sec` | Max seconds per file | `600` |
| `--ring-sec` | Ring buffer size | `max-file-sec + 60` |
| `--threshold` | RMS threshold for music detection | `50` |
| `--sustain-sec` | Seconds above threshold to start | `1.0` |
| `--silence-sec` | Silence duration to stop | `15` |

The `--threshold` value is used for both recording triggers and Shazam fingerprinting.

### Audio tagging (requires libvibra)
| Option | Description | Default |
|--------|-------------|---------|
| `--fingerprint-sec` | Fingerprint length | `12` |
| `--interval` | Seconds between checks | `2` |
| `--shazam-gap-sec` | Min seconds between lookups | `10` |
| `--same-track-hold-sec` | Skip lookups for same track | `90` |

### CDJ tagging
| Option | Description | Default |
|--------|-------------|---------|
| `--prolink-interface` | Network interface for CDJ traffic | (required) |
| `--prolink-passive` | SPAN/mirror port mode (eavesdrop only, no registration) | Off |
| `--olib-key KEY` | OneLibrary (exportLibrary.db) decryption passphrase | (none) |

### Matching (combined --audio-tag + --cdj-tag)
| Option | Description | Default |
|--------|-------------|---------|
| `--match-threshold` | Fuzzy match similarity % (0-100) | `60` |

### Output
| Option | Description | Default |
|--------|-------------|---------|
| `--db` | SQLite database path | (none) |
| `--sse-socket` | Unix socket for web UI SSE | (none) |
| `--verbose` | Enable detailed logging | Off |

---

## Pro DJ Link Integration

clubtagger supports two modes for Pro DJ Link integration:

### Auto-detection (default)

On startup, clubtagger observes the network for 10 seconds without sending anything. If status/beat packets are already flowing (because 2+ CDJs or a CDJ + DJM are already communicating), it stays **passive** — no player slot consumed, completely invisible to the DJ network.

If no status packets are seen during observation (single CDJ with no peers, or CDJs waiting for a peer before broadcasting), clubtagger registers as a virtual CDJ (**active mode**), occupying one player slot.

| Situation | Auto-detected mode | Slot used? |
|-----------|-------------------|------------|
| SPAN/mirror port | Passive | No |
| 2+ CDJs on switch | Passive | No |
| CDJ + DJM on switch | Passive | No |
| Single CDJ, no other peers | Active | Yes (1 slot) |

In both modes, clubtagger can:
1. **Receive status packets** from CDJs (rekordbox ID, BPM, play state, on-air)
2. **Receive beat/position packets** with real-time playback position (CDJ-3000: ~30ms)
3. **Passively capture databases** (PDB and OneLibrary) from NFS traffic between CDJs
4. **Correlate with fingerprints** for higher confidence matches

Active mode additionally enables:
5. **Fetch databases** (OneLibrary + PDB) directly from CDJs via NFS
6. **Query DBServer** (port 1051) for track title/artist as a fallback

If a track can't be resolved passively, clubtagger can temporarily re-activate to query DBServer, then return to passive.

### Forced passive mode — `--prolink-passive`

Forces passive mode regardless of auto-detection. Use this when you know you're on a SPAN port and want to guarantee zero network footprint.

```bash
./clubtagger --cdj-tag --prolink-interface eth1 --prolink-passive --db tracks.db
```

**Limitation:** Passive mode (both auto and forced) requires at least two devices on the DJ network. A single CDJ with no peers won't broadcast status or beat packets. Use active mode (omit `--prolink-passive`) for single-CDJ setups — auto-detection handles this automatically.

### How it works

```
CDJ Status Packet → rekordbox_id → OneLibrary lookup (SQLite)
                                 ↘ PDB lookup (fallback)
                                 ↘ DBServer query (last resort)
                                               ↘ Fuzzy match with Shazam result
```

### OneLibrary (CDJ-3000X)

CDJ-3000X and newer hardware export databases in the OneLibrary format — a SQLCipher 4 encrypted SQLite database (`PIONEER/rekordbox/exportLibrary.db`). clubtagger:

1. Fetches the encrypted database via NFSv2
2. Derives the decryption key using PBKDF2-HMAC-SHA512 (256,000 iterations)
3. Decrypts all pages with AES-256-CBC
4. Loads the result as an in-memory SQLite database
5. Queries tracks by content_id with artist JOINs

OneLibrary provides richer metadata than the legacy PDB format (26 tables including playlists, cue points, history, and more). If OneLibrary is not available (older USB sticks without Rekordbox 6+ export), clubtagger falls back to the PDB parser.

### Supported hardware

| Device | Database | Position Packets | Max Players |
|--------|----------|-----------------|-------------|
| CDJ-2000NXS2 | PDB only | No | 4 |
| CDJ-3000 | PDB + OneLibrary | Yes (~30ms) | 6 |
| CDJ-3000X | PDB + OneLibrary | Yes (~30ms) | 6 |
| DJM-900NXS2 | — | — | (mixer) |
| DJM-V10 | — | — | (6ch mixer) |

### Fuzzy matching

When comparing CDJ metadata with Shazam results, clubtagger uses:
1. **Substring containment** — "One More Time" matches "One More Time (Original Mix)"
2. **Levenshtein similarity** — "Tiësto" matches "Tiesto" (86% similarity)

Configure with `--match-threshold` (default 60%).

---

## Web UI

Enable the SSE server to get a real-time web interface:

```bash
./clubtagger --cdj-tag --prolink-interface en7 \
  --sse-socket /tmp/clubtagger.sock
```

### nginx proxy (recommended)
```nginx
location /sse {
    proxy_pass http://unix:/tmp/clubtagger.sock;
    proxy_http_version 1.1;
    proxy_set_header Connection '';
    proxy_buffering off;
    proxy_cache off;
}

location / {
    root /path/to/clubtagger/www;
}
```

### Features
- **VU meters** — real-time audio levels with peak hold
- **CDJ deck status** — playing/paused, ON AIR, BPM, slot (USB/SD/CD)
- **Now playing** — current identified track
- **Track history** — recent plays with timestamps

---

## Output example

```
[cap] started: rate=96000 ch=2 (SLink source, 24-bit)
[cdj] CDJ-2000NXS2 #1 online @ 192.168.1.101
[cdj] 📥 Fetching database from 192.168.1.101 (USB)...
[cdj] ✅ Loaded 847 tracks from database
[wrt] TRIGGER avg=142 (prebuffer 480000 frames)
[id] 2026-02-08 00:15:23 MATCH: Daft Punk — One More Time [ISRC GBDUW0000059] (85%, both)
[cdj] Fuzzy title match: 92% ("One More Time" vs "One More Time (Radio Edit)")
[wrt] SPLIT at 57600000 frames (10.0 min)
```

### SQLite database

```sql
SELECT timestamp, artist, title, confidence, source FROM plays ORDER BY timestamp DESC LIMIT 5;
```

| timestamp | artist | title | confidence | source |
|-----------|--------|-------|------------|--------|
| 2026-02-08 00:15:23 | Daft Punk | One More Time | 85 | both |
| 2026-02-08 00:11:45 | Kraftwerk | The Model | 75 | audio |
| 2026-02-08 00:08:12 | Aphex Twin | Windowlicker | 70 | cdj/on-air |

---

## Architecture

```
clubtagger/
├── audio/            # Audio capture (ALSA, SLink, AF_XDP)
├── prolink/          # Pro DJ Link protocol implementation
│   ├── prolink.c     # Packet parsing (keepalive, status, beat, position)
│   ├── registration.c # Virtual CDJ registration and slot management
│   ├── dbserver.c    # DBServer queries (port 1051)
│   ├── nfs_client.c  # NFS v2 client for database fetching
│   ├── pdb_parser.c  # Rekordbox export.pdb parser (legacy)
│   ├── onelibrary.c  # OneLibrary exportLibrary.db decrypt + SQLite query
│   └── track_cache.c # In-memory metadata cache
├── shazam/           # Audio fingerprinting
├── writer/           # Async WAV/FLAC writing
├── server/           # SSE server for web UI
├── db/               # SQLite integration
└── www/              # Web UI (HTML/JS)
```

### Ring Buffer

Audio is captured into a fixed-size ring buffer. Oldest samples are automatically overwritten. When recording triggers, all buffered audio becomes the "prebuffer". This provides:
- **Constant memory usage** regardless of silence duration
- **Gapless recording** when music briefly dips below threshold
- **No lost samples** as long as gaps are shorter than the buffer

---

## Notes
- clubtagger never sends raw audio — only fingerprint hashes
- CDJ integration auto-detects whether to register or stay passive; SPAN ports and multi-CDJ setups consume zero player slots
- UTF-8 safe throughout: handles accented characters, emoji, CJK
- Supports streaming tracks (Beatport LINK, etc.) via status packet detection
- Intended for licensed environments to log playback for rights reporting
- Respect third-party service terms and copyright laws

---

## License
MIT — see [`LICENSE`](LICENSE)

---

## Credits
- [BayernMuller/vibra](https://github.com/BayernMuller/vibra)
- [Deep Symmetry](https://djl-analysis.deepsymmetry.org/) — Pro DJ Link protocol documentation
- [alphatheta-connect](https://github.com/erikrichardlarson/alphatheta-connect) — CDJ-3000 protocol details
- [pyrekordbox](https://github.com/dylanljones/pyrekordbox) — OneLibrary format research
- [ALSA Project](https://www.alsa-project.org/)
- [libcurl](https://curl.se/libcurl/)
- [SQLite](https://sqlite.org/)
- [OpenSSL](https://www.openssl.org/) — SQLCipher 4 decryption
