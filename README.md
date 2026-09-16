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
- 🧠 **Confidence model** — weighted signal accumulation from CDJ + Shazam + on-air status
- 🔤 **Fuzzy matching** — Levenshtein distance handles typos and encoding differences
- 🎵 **Vinyl-friendly** — tolerates pitch variations from turntables
- 💾 **WAV/FLAC recording** with seamless file splitting
- 🗄️ **SQLite logging** — track plays with timestamps, ISRC codes
- 🌐 **Web UI** — real-time VU meters, deck status, beat/BPM/key via WebSocket
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
  --db tracks.db --ws-socket /run/clubtagger.sock
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
| `--max-file-sec` | Max seconds per file | `120` |
| `--ring-sec` | Ring buffer size | `max-file-sec + 60` |
| `--threshold` | RMS threshold for music detection | `50` |
| `--sustain-sec` | Seconds above threshold to start | `3.0` |
| `--silence-sec` | Silence duration to stop | `40` |
| `--prebuffer-sec` | Max pre-roll kept in front of a trigger | `10` |

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
| `--ws-socket` | WebSocket server: Unix socket path or TCP port number | (none) |
| `--timezone` | Override timezone | Europe/Amsterdam |
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

Enable the WebSocket server for a real-time web interface:

```bash
./clubtagger --cdj-tag --prolink-interface en7 \
  --ws-socket /run/clubtagger.sock
```

For development/testing, use a TCP port instead of a Unix socket:

```bash
./clubtagger --cdj-tag --prolink-interface en7 \
  --ws-socket 9090
```

### nginx proxy (recommended for production)

See `nginx.conf.example` for a full configuration with HTTPS and basic auth.

```nginx
upstream clubtagger {
    server unix:/run/clubtagger.sock;
}

location = /ws {
    auth_basic off;
    proxy_pass http://clubtagger;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_buffering off;
    proxy_read_timeout 24h;
}

location / {
    root /var/www/clubtagger;
}
```

### Recordings browser and set export

`recordings.html` (linked from the main page) shows the recordings of a date as
waveform timelines per channel and exports any range as one lossless FLAC.
Everything runs in the browser; the recorder only serves static files.

- **Date window**: picking a date shows 00:00 of that date until 12:00 the next
  day, so an evening that runs past midnight stays together and day events show
  up too. Contiguous recordings form a *session*; gaps between sessions are
  drawn empty.
- **Waveforms** come from the `.peaks` sidecar the recorder writes next to every
  FLAC segment (10 min/max points per second, 16-bit, ~10 kB per 2-minute
  segment). Recordings made before sidecars existed can be backfilled once:
  `nice -n 19 peaksgen /data/recordings` (about 1 s per segment; skips files
  that already have a sidecar).
- **Selection**: drag on a waveform; the edges snap to segment boundaries and can be dragged individually afterwards.
  Scroll to zoom, shift-scroll or drag the ruler to pan, double-click a session
  to fit it, click a segment to listen to it.
- **Export** splices the selected segments without decoding: frame headers are
  renumbered and their CRCs recomputed, the audio payload is copied byte for
  byte, and a new STREAMINFO, SEEKTABLE and tags are written in front. Segments
  recorded with a blocksize that divides the segment length (the default since
  the blocksize change) give an ordinary fixed-blocksize FLAC; older 4096-block
  recordings give a spec-legal variable-blocksize FLAC. Because the file is
  streamed to disk while it is built (a 2-hour set is ~2 GB), the export needs
  Chrome or Edge (File System Access API) on a secure context; see the NAS
  section for the plain-HTTP case. Any CRC failure aborts the export;
  no partial file is left behind.
- **Where it runs**: on the backup NAS the recorder pushes to (below), not on
  the recorder. `recordings.html` reads the directory through a JSON autoindex
  at `/recordings-json/` and fetches files from `/recordings/`; the nginx
  locations are in `nginx.conf.example` (commented out for the recorder).

**Where the recordings live and where the browser runs.** Not on the
recorder. The recorder pushes `/data/recordings` (FLAC + `.peaks`, minus the
staging directory) every five minutes with rsync to a router (OpenWrt on a
MediaTek MT7986A) that has the recordings disk attached over USB 3
(`clubtagger-sync.timer`; plain rsync protocol on port 873, so neither box
spends CPU on ssh or TLS for gigabytes of audio; the login is
challenge-response, the password is never sent in clear). That router also
terminates HTTPS with hardware AES at line rate and serves `www/` plus the
disk: `tools/router-rsyncd.conf.example` and `tools/router-nginx.conf.example`.
One URL inside and outside the LAN, ordinary basic auth, the export streams in
any Chrome/Edge without flags. On the recorder set `REMOTE` in
`/etc/systemd/system/clubtagger-sync.service`, the password in
`/etc/rsync.pass`, and enable the timer. Nothing is deleted on the recorder
yet; when that comes, delete a FLAC and its `.peaks` together.

The page also supports a server that checks nginx `secure_link` signed URLs
instead of a password (key button in the header; the key stays in the
browser's localStorage and signs every request). That was designed for a
server too weak for TLS and is not needed in the router layout. For a
PC-class box, `tools/recordings-proxy.mjs` serves the page on localhost and
proxies every request to a recorder or router over HTTPS.

Development without the recorder: `node tests/dev-server.mjs <dir-with-flac-and-peaks>`
serves `www/` with the same two locations. `npm test` runs the splicer unit
tests, `node tests/splice-cli.mjs out.flac seg1.flac seg2.flac ...` splices
from the command line and `tests/verify-splice.sh` checks a result against its
sources with `flac`, `metaflac` and `ffmpeg` (byte-identical PCM, seeking).

### Features
- **VU meters** — 60 Hz audio levels with peak hold and decay
- **CDJ deck status** — real-time from raw Pro DJ Link packets:
  - Playing/paused, ON AIR, BPM with pitch offset
  - Musical key (A-based mapping from CDJ-3000)
  - Beat position (4-dot indicator updated per-beat)
  - Loop state and beat count
  - Master, Sync, Master Tempo badges
  - Track position / duration (CDJ-3000: 30ms updates)
  - Media source (USB/SD/Link) and database source (OneLibrary/PDB/DBServer)
- **Track identification** — confidence bars with CDJ + Shazam signals
- **Track history** — recent plays from database
- **Activity log** — live system messages
- **System stats** — CPU load, memory, disk space

### Architecture

Raw Pro DJ Link packets are forwarded as **binary WebSocket frames** directly to the browser. JavaScript parses packet bytes using known offsets (BPM, pitch, beat, key, loop, position). This provides sub-millisecond UI updates without C-side JSON serialization overhead.

Metadata that requires C-side logic (track title, artist, confidence, ISRC, database source) is sent as **JSON text frames** at 1 Hz.

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
│   ├── pdb.c         # Rekordbox export.pdb fetch + parser
│   ├── onelibrary.c  # OneLibrary exportLibrary.db decrypt + SQLite query
│   └── track_cache.c # In-memory metadata cache
├── shazam/           # Audio fingerprinting
├── writer/           # Async WAV/FLAC writing
├── server/           # WebSocket server (binary packet relay + JSON events)
├── db/               # SQLite integration
└── www/              # Web UI (HTML/JS)
```

### Segment files

Each channel is written as consecutive FLAC segments of `--max-file-sec`
(default 120 s), named `YYYYMMDD_HHMMSS_<prefix>_<channel>.flac` in local time.
Consecutive segments of one recording are sample-continuous. A segment is
encoded in memory, written to `<outdir>/.incoming/`, fsync'd and renamed into
place, then its `.peaks` sidecar is written; a sidecar therefore always belongs
to a complete FLAC. The encoder blocksize is chosen to divide the segment
length (4608 at 48 and 96 kHz) so full segments have no short tail frame. Each
file carries `CLUBTAGGER_CHANNEL`, `CLUBTAGGER_START_MS`, `CLUBTAGGER_CURSOR`
and `CLUBTAGGER_RUN_ID` Vorbis comments; cursor + run id let readers prove that
two segments are contiguous.

### Real-time behaviour

The capture thread runs `SCHED_FIFO` at priority 80 and pins itself to CPU 1;
`main()` pins every other thread (FLAC encoding, Shazam, WebSocket, writer) to
CPU 0 and locks all memory with `mlockall`. On the device, `rt-tuning.sh`
steers the SLink NIC interrupts to CPU 1 and nginx runs as a single worker on
CPU 0 with a per-download rate cap, so serving an export never competes with
capture. Lost packets show up as `sequence discontinuity` log lines and in the
"Lost" counter of the web UI; that number should stay at 0.

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
