# clubtagger

**clubtagger** is a low-latency recorder and song tagger for clubs and venues.  
It captures live audio from ALSA or SLink (Allen & Heath SQ network audio), generates acoustic fingerprints locally using [vibra],  
identifies songs via Shazam-compatible lookup, and integrates with Pioneer CDJ/XDJ equipment via Pro DJ Link.

---

## Features
- 🎧 **Live audio capture** — ALSA (Linux) or SLink (Allen & Heath SQ, 24-bit)
- 🔎 **Local fingerprinting** via `libvibra` (no audio leaves the system)
- 🎛️ **Pro DJ Link integration** — reads track metadata directly from Pioneer CDJs
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
brew install curl sqlite libpcap flac
make            # builds without ALSA support
```

### Dependencies
- `libcurl` — HTTP communication
- `libvibra` — local acoustic fingerprinting (optional, enables `--audio-tag`)
- `libsqlite3` — track database
- `libpcap` — network packet capture (SLink, Pro DJ Link)
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

### Recording
| Option | Description | Default |
|--------|-------------|---------|
| `--format` | Output format: `wav` or `flac` | `wav` |
| `--prefix` | Filename prefix | `capture` |
| `--outdir` | Output directory | `.` |
| `--max-file-sec` | Max seconds per file | `600` |
| `--ring-sec` | Ring buffer size | `max-file-sec + 60` |
| `--threshold` | Amplitude threshold for recording | `50` |
| `--sustain-sec` | Seconds above threshold to start | `1.0` |
| `--silence-sec` | Silence duration to stop | `15` |

### Audio tagging (requires libvibra)
| Option | Description | Default |
|--------|-------------|---------|
| `--fingerprint-sec` | Fingerprint length | `12` |
| `--interval` | Seconds between checks | `2` |
| `--min-rms` | Minimum RMS to trigger | `300` |
| `--shazam-gap-sec` | Min seconds between lookups | `10` |
| `--same-track-hold-sec` | Skip lookups for same track | `90` |

### CDJ tagging
| Option | Description | Default |
|--------|-------------|---------|
| `--prolink-interface` | Network interface for CDJ traffic | (required) |

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

clubtagger passively monitors Pro DJ Link network traffic to:

1. **Read track metadata** from CDJ status packets (rekordbox ID, BPM, position)
2. **Query DBServer** (port 1051) for track title/artist
3. **Fetch PDB databases** via NFS to cache all tracks on USB/SD
4. **Correlate with fingerprints** for higher confidence matches

### How it works

```
CDJ Status Packet → rekordbox_id → PDB lookup → track_cache
                                 ↘ DBServer query (fallback)
                                               ↘ Fuzzy match with Shazam result
```

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
├── audio/           # Audio capture (ALSA, SLink, AF_XDP)
├── prolink/         # Pro DJ Link protocol implementation
│   ├── prolink.c    # Packet parsing (keepalive, status, beat)
│   ├── dbserver.c   # DBServer queries (port 1051)
│   ├── nfs_client.c # NFS v2 client for PDB files
│   ├── pdb_parser.c # Rekordbox export.pdb parser
│   └── track_cache.c # In-memory metadata cache
├── shazam/          # Audio fingerprinting
├── writer/          # Async WAV/FLAC writing
├── server/          # SSE server for web UI
├── db/              # SQLite integration
└── www/             # Web UI (HTML/JS)
```

### Ring Buffer

Audio is captured into a fixed-size ring buffer. Oldest samples are automatically overwritten. When recording triggers, all buffered audio becomes the "prebuffer". This provides:
- **Constant memory usage** regardless of silence duration
- **Gapless recording** when music briefly dips below threshold
- **No lost samples** as long as gaps are shorter than the buffer

---

## Notes
- clubtagger never sends raw audio — only fingerprint hashes
- CDJ integration is completely passive (no packets sent to players)
- UTF-8 safe throughout: handles accented characters, emoji, CJK
- Intended for licensed environments to log playback for rights reporting
- Respect third-party service terms and copyright laws

---

## License
MIT — see [`LICENSE`](LICENSE)

---

## Credits
- [BayernMuller/vibra](https://github.com/BayernMuller/vibra)
- [Deep Symmetry](https://djl-analysis.deepsymmetry.org/) — Pro DJ Link protocol documentation
- [ALSA Project](https://www.alsa-project.org/)
- [libcurl](https://curl.se/libcurl/)
- [SQLite](https://sqlite.org/)
