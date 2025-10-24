# clubtagger

**clubtagger** is a low-latency recorder and song tagger for clubs and venues.  
It captures live audio from ALSA, generates acoustic fingerprints locally using [vibra],  
and identifies songs via Shazam-compatible lookup — without uploading raw audio.

---

## Features
- 🎧 **Live ALSA capture** (stereo, configurable)
- 🔎 **Local fingerprinting** via `libvibra` (no audio leaves the system)
- 🧠 **Smart voting** — 2-of-3 consensus with confirmation before changing tracks
- 🕒 **Accurate timestamps** and configurable prebuffer/thresholds
- 💾 **Optional WAV recording** (pre-trigger + silence-stop)
- 🔇 **Noise-resistant**: only queries when RMS exceeds `--min-rms`
- ⚙️ Lightweight C implementation with no dependencies beyond ALSA, cURL, and vibra

---

## Build

```bash
sudo apt-get install libasound2-dev libcurl4-openssl-dev
make
# or debug build:
make debug
```

### Dependencies
- `libasound2-dev` — ALSA audio capture
- `libcurl4-openssl-dev` — HTTP communication
- `libvibra` — local acoustic fingerprinting
- `libstdc++`, `libm`

---

## Usage

```bash
./clubtagger   --device default   --rate 48000 --channels 2 --frames 1024 --ring-sec 20   --fingerprint-sec 12 --min-rms 300 --interval 2   --shazam-gap-sec 10 --same-track-hold-sec 90   --threshold 200 --sustain-sec 2.0 --prebuffer-sec 5 --silence-sec 3.0   --prefix capture --verbose
```

### Key options

| Option | Description | Default |
|--------|--------------|----------|
| `--device` | ALSA device name | `default` |
| `--rate` | Sample rate (Hz) | `48000` |
| `--channels` | Audio channels | `2` |
| `--frames` | ALSA frames per read | `1024` |
| `--ring-sec` | Ring buffer duration | `20` |
| `--fingerprint-sec` | Fingerprint length | `12` |
| `--interval` | Seconds between recognition checks | `2` |
| `--min-rms` | Minimum RMS to trigger recognition | `300` |
| `--threshold` | Amplitude threshold for recording | `200` |
| `--sustain-sec` | Seconds above threshold to start writing WAV | `2.0` |
| `--prebuffer-sec` | Audio included before trigger | `5.0` |
| `--silence-sec` | Silence duration to stop recording | `3.0` |
| `--shazam-gap-sec` | Minimum seconds between lookups | `10` |
| `--same-track-hold-sec` | Skip new lookups for same track | `90` |
| `--prefix` | Filename prefix for WAV files | `capture` |
| `--verbose` | Enable detailed logging | Off |

---

## Output example

```
[id] 2025-10-23 22:07:11 MATCH: Daft Punk — One More Time [ISRC GBDUW0000059]
[wrt] writing capture_20251023-220711.wav
[wrt] stopped after silence (duration 45.2 s)
```

---

## Notes
- clubtagger never sends audio — only vibra fingerprints.
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
