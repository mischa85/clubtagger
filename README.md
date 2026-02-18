# clubtagger

**clubtagger** is a low-latency recorder and song tagger for clubs and venues.  
It captures live audio from ALSA or SLink (Allen & Heath SQ network audio), generates acoustic fingerprints locally using [vibra],  
and identifies songs via Shazam-compatible lookup — without uploading raw audio.

---

## Features
- 🎧 **Live audio capture** — ALSA (Linux) or SLink (Allen & Heath SQ, 24-bit)
- 🔎 **Local fingerprinting** via `libvibra` (no audio leaves the system)
- 🧠 **Smart matching** — requires 3 consecutive confirmations to reduce false positives
- 🎵 **Vinyl-friendly** — tolerates pitch variations from turntables, different pressings
- 🕒 **Accurate timestamps** with configurable thresholds
- 💾 **WAV/FLAC recording** with seamless file splitting (10-minute segments by default)
- 🔄 **Fixed-size ring buffer** — constant memory usage, gapless recording
- 🗄️ **SQLite logging** — track plays with timestamps, ISRC codes, and WAV file references
- 🔇 **Noise-resistant**: only queries when RMS exceeds `--min-rms`
- ⚙️ Lightweight C implementation

---

## Build

### Linux (ALSA)
```bash
sudo apt-get install libasound2-dev libcurl4-openssl-dev libsqlite3-dev libpcap-dev
make
```

### macOS (SLink only)
```bash
brew install curl sqlite libpcap
make            # builds without ALSA support
```

### Dependencies
- `libcurl` — HTTP communication
- `libvibra` — local acoustic fingerprinting (included or linked)
- `libsqlite3` — track database (optional)
- `libpcap` — SLink packet capture
- `libasound2` — ALSA audio capture (Linux only)

---

## Usage

### ALSA capture (Linux)
```bash
./clubtagger --source alsa --device hw:2,0 --rate 48000 --channels 2 \
  --threshold 50 --silence-sec 15 \
  --db tracks.db --verbose
```

### SLink capture (Allen & Heath SQ)
```bash
./clubtagger --source slink --device en0 --rate 96000 --channels 2 \
  --threshold 50 --silence-sec 15 --format flac \
  --db tracks.db --verbose
```

### Key options

| Option | Description | Default |
|--------|-------------|---------|
| `--source` | Audio source: `alsa` or `slink` | (required) |
| `--device` | ALSA device or network interface | `default` |
| `--rate` | Sample rate (Hz) | `48000` |
| `--channels` | Audio channels | `2` |
| `--bits` | Bit depth (16 or 24) | `16` (auto 24 for SLink) |
| `--frames` | Frames per read | `1024` |
| `--ring-sec` | Ring buffer size (must be > max-file-sec) | `max-file-sec + 60` |
| `--fingerprint-sec` | Fingerprint length | `12` |
| `--interval` | Seconds between recognition checks | `2` |
| `--min-rms` | Minimum RMS to trigger recognition | `300` |
| `--threshold` | Amplitude threshold for recording | `50` |
| `--sustain-sec` | Seconds above threshold to start recording | `1.0` |
| `--silence-sec` | Silence duration to stop recording | `15` |
| `--max-file-sec` | Max seconds per WAV/FLAC file (0 = no limit) | `600` |
| `--format` | Output format: `wav` or `flac` | `wav` |
| `--shazam-gap-sec` | Minimum seconds between lookups | `10` |
| `--same-track-hold-sec` | Skip new lookups for same track | `90` |
| `--prefix` | Filename prefix for WAV files | `capture` |
| `--db` | SQLite database for track logging | (none) |
| `--verbose` | Enable detailed logging | Off |

---

## Output example

```
[cap] started: rate=96000 ch=2 (SLink source, 24-bit)
[wrt] TRIGGER avg=142 (prebuffer 480000 frames)
[id] 2026-02-08 00:15:23 MATCH: Daft Punk — One More Time [ISRC GBDUW0000059] (confirmed)
[wrt] SPLIT at 57600000 frames (10.0 min)
[wrt] STOP (silence)
```

### SQLite database

When using `--db`, tracks are logged to a SQLite database:

```sql
SELECT timestamp, artist, title, quality FROM plays ORDER BY timestamp DESC LIMIT 5;
```

| timestamp | artist | title | quality |
|-----------|--------|-------|---------|
| 2026-02-08 00:15:23 | Daft Punk | One More Time | confirmed |
| 2026-02-08 00:11:45 | Kraftwerk | The Model | excellent |

---

## Architecture

### Ring Buffer

Audio is captured into a fixed-size ring buffer (`--ring-sec`, defaults to `--max-file-sec` + 60s). The buffer must be larger than `--max-file-sec` to allow headroom for async writes. Oldest samples are automatically overwritten. When recording triggers, all buffered audio becomes the "prebuffer". This provides:
- **Constant memory usage** regardless of how long silence lasts
- **Gapless recording** when music briefly dips below threshold
- **No lost samples** as long as silence gaps are shorter than the ring buffer

### SLink Protocol

SLink is Allen & Heath's network audio protocol used by SQ-series mixers. clubtagger captures packets with EtherType `0x04ee` containing 24-bit stereo samples at positions 24-29 (big-endian). The audio is converted to little-endian for WAV/FLAC output.

To capture SLink traffic, run clubtagger with root privileges or configure libpcap permissions.

---

## Notes
- clubtagger never sends audio — only vibra fingerprints.
- Match quality is determined by timeskew/frequencyskew values from Shazam.
- Ambiguous fingerprints (multiple matches with high skew) are rejected.
- Intended for licensed environments to log playback for rights reporting.
- Respect third-party service terms and copyright laws.

---

## License
MIT — see [`LICENSE`](LICENSE)

---

## Credits
- [BayernMuller/vibra](https://github.com/BayernMuller/vibra)
- [ALSA Project](https://www.alsa-project.org/)
- [libcurl](https://curl.se/libcurl/)
- [SQLite](https://sqlite.org/)
