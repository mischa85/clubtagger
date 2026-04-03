# Live Show Issues — 2026-03-28

Analysis of the live show log. No code changes until after the show.

## Setup

- Device 1: CDJ-3000X @ 169.254.10.144 — DJ's USB (1188 tracks, OneLibrary works)
- Device 5: CDJ-3000X @ 169.254.10.154 — Marcel's USB (1859 tracks, OneLibrary works)
- Device 6: CDJ-3000X @ 169.254.6.240 — DJ's USB (2165 tracks, PDB only, OneLibrary NFS always fails)
- Device 33: DJM-V10
- Device 2: CDJ-3000X (no media, was used earlier for Link browsing)

## Issue 1: OneLibrary ID collision across databases

**Symptom:** Track names on CDJ might be wrong — showing tracks from a different USB.

**Root cause:** `onelibrary_lookup(content_id)` searches ALL loaded OneLibrary databases
globally. It does not filter by device IP or slot. When multiple USBs are on the network
with overlapping `content_id` values (very likely — rekordbox assigns sequential IDs),
a lookup for Device 6's track might match a completely different track in Device 1's
or Device 5's OneLibrary.

**Example scenario:**
- Device 6 loads track with `rekordbox_id=150`
- Device 5's OneLibrary also has a `content_id=150` (different track)
- `onelibrary_lookup(150)` returns Device 5's track → wrong name displayed

**Fix:** Scope OneLibrary lookups to the source device. The lookup should accept
`(content_id, device_ip, slot)` and only search the matching database. When the
track is via Link (`source_player != self`), use the source device's database.

## Issue 2: Device 6 OneLibrary NFS always fails

**Symptom:** Every track change on Device 6 triggers "USB removed → USB inserted →
Fetching USB OneLibrary → fails 3x → no physical media?" But PDB loads fine (2165 tracks).

**Observations:**
- PDB fetch succeeds every time for Device 6 — NFS works for PDB files
- OneLibrary NFS specifically fails — maybe the encrypted OneLibrary file doesn't
  exist on this USB (older rekordbox export? no OneLibrary key match?)
- The DJ's USB might use an older export format that has PDB but not OneLibrary
- The `0x3a` check passes (allows fetch), so it's not the Link detection blocking it
- The PDB fallback works correctly and resolves tracks

**Fix:** When OneLibrary NFS fails but PDB succeeds, mark `usb_olib_fetched = 1` to
prevent further OneLibrary attempts. Currently both are tracked independently, so
OneLibrary keeps retrying even after PDB loaded.

## Issue 3: Constant database re-fetching on track change

**Symptom:** Every time Device 6 loads a new track, we see:
```
💾 Device 6: USB removed
💾 Device 6: USB inserted
📥 Device 6: Fetching USB OneLibrary...
📥 Device 6: Fetching USB PDB...
✅ Device 6: USB PDB loaded (2165 tracks)
```
The PDB is re-downloaded every single time. 2165 tracks, every track change.

**Root cause:** The CDJ-3000X toggles `usb_local` (byte 0x37) from `0x02` to `0x00`
and back during track changes. Our edge detection sees this as USB removed→inserted,
which resets `usb_olib_fetched` and `usb_db_fetched`, triggering full re-fetch.

This is NOT a real USB swap — the DJ is not physically removing the USB. The CDJ
briefly reports `usb_local=0x00` during internal state transitions.

**Fix options:**
1. **Debounce** — Don't trigger USB removed if USB inserted follows within <2 seconds.
   The CDJ toggle happens within the same second.
2. **Don't re-fetch if same IP** — If the "new" USB is on the same device IP as the
   old one, and the database was already loaded, skip the re-fetch. Only re-fetch if
   the track count changes or the database is actually different.
3. **Check if database already loaded** — Before fetching, check if we already have
   a database for this device+slot. If the existing one is recent (loaded < 60s ago),
   skip the fetch.

## Issue 4: PDB vs OneLibrary data inconsistency

**Observation:** Device 6 tracks are resolved via PDB. Device 1 tracks via OneLibrary.
Device 5 tracks via OneLibrary. If the PDB and OneLibrary databases have different
`content_id` → track mappings (due to different export versions, or PDB using a
different ID scheme), the ID collision in Issue 1 becomes worse.

**Investigation needed:** Verify whether PDB `rekordbox_id` maps 1:1 with OneLibrary
`content_id`. If they differ, the cross-database lookup is fundamentally broken for
mixed PDB/OneLibrary setups.

## Issue 5: Shazam permanently stops when only unnamed tracks are playing

**Symptom:** After 00:10:17, Shazam never queries again. CDJs continue running
(Deck 6 playing "(unknown)"), but the id_thread is in permanent hold.

**Root cause:** `id_thread.c:105` — `if (dd->track_title[0] == '\0') continue`
skips unnamed decks when checking for unaccepted tracks. If the only playing
deck has no title (database not loaded), it's invisible to the check. All
*named* decks are already accepted → `any_unaccepted = 0` → Shazam holds forever.

**Fix:** Unnamed playing decks should count as needing Shazam (they're the ones
that need it most — CDJ can't identify them, so audio fingerprint is the only path).

## Issue 5b: Shazam keeps querying long after acceptance

**Symptom:** After a track is accepted on Deck 0 (audio-only), Shazam continues
querying every 20 seconds. For hours. Even when no CDJ tracks are changing.

**Impact:** Wastes Shazam API calls, fills the log, and the "Deck 0: Shazam confirm"
messages keep adding to an already-accepted track's confidence (100% capped, harmless
but noisy).

**Fix:** Once a track is accepted and no CDJ deck is actively playing a different
unresolved track, reduce Shazam query frequency significantly or stop until the next
track transition.

## Issue 6: Audio-only (Deck 0) effectively dead for fast-mixing DJs

**Example:** "Franck Roger — The Feeling" returned by Shazam 7+ times at 50%
confidence. Each confirm adds only +100 to deck 0 (audio-only). Needs 6
uninterrupted confirms to reach 55%. But a single different Shazam result
(e.g., Rihanna at 47%) resets the audio-only slot via `is_different_track`,
and The Feeling has to rebuild from zero.

**Full picture from live log:** From 22:58 to 00:10 (~70 minutes), Deck 0
accepted exactly ONE track. Shazam queried every 20 seconds the whole time
and got results, but every result was a different track. The DJ's mixing
style (fast techno transitions) means Shazam rarely returns the same track
twice in a row. The audio-only slot resets on every different result, so
confidence never accumulates.

**Root cause:** The audio-only slot treats any different track as a complete
reset. For fast-mixing DJs, Shazam returns different tracks every query.
Even when the same track appears 5-6 times within 3 minutes, a single
different result in between resets everything.

**Fix options:**
1. Don't fully reset the audio-only slot on a single different result — use
   SHAZAM_DISAGREE instead (penalize, don't destroy).
2. Lower the acceptance threshold for audio-only when Shazam is consistent
   over a longer time window (e.g., 5+ matches of the same track within 3 min).
3. Track "persistence" — if the same track keeps coming back after interruptions,
   carry over partial confidence instead of starting from zero.

## Issue 7: Silent loss of CDJ contact

**Symptom:** After 21:57, no more CDJ packets received. No crash, no error logged.
Shazam continues querying (audio still flowing), but no DECK/Device messages.
Last CDJ activity: 21:57:37 (Deck 1 off air). Log continues for 20 more minutes
with only Shazam queries.

**Possible causes:**
1. Keepalive thread stalled (blocked by NFS fetch?) — CDJs drop peers after ~5-10s
   of no keepalives, stop sending status packets.
2. AF_XDP socket issue — packet ring buffer full or socket error.
3. Network interface issue — link down on enp3s0.

**Fix:** Add a watchdog that monitors time since last CDJ packet. If >30 seconds,
log a warning. If >60 seconds, attempt re-registration or restart the AF_XDP socket.
Also: NFS fetches should have a hard timeout to prevent blocking the prolink thread
indefinitely.

## Issue 8: CDJ confidence accumulates while track is "(unknown)", instant accept on name resolve

**Example:** Deck 2 "Subclass 801" — track loaded at 22:36:04 as "(unknown)" (no database).
Playing from 22:36:33, ON AIR from 22:39:39. CDJ signals (ON_AIR_EDGE, ON_AIR, PLAYING,
duration ticks) accumulate silently because there's no title to attach them to.
At 22:42:24, OneLibrary loads and resolves the name. CDJ_LOADED fires → instant accept
at 98%. Shazam confirms 80 seconds later (too late to matter).

**Root cause:** CDJ confidence signals (ON_AIR, duration) are applied to the deck even
when the track is unnamed. The moment the name resolves, all that accumulated confidence
plus CDJ_LOADED exceeds threshold immediately.

**Fix options:**
1. Don't accumulate CDJ confidence on unnamed tracks — only start the clock once we
   have a title. This would delay acceptance but ensure Shazam has time.
2. Don't accept on CDJ_LOADED alone — require a minimum time since first identification
   (e.g., 30 seconds) so Shazam can weigh in.
3. When CDJ_LOADED fires on a previously-unknown track, cap the initial confidence
   to avoid instant acceptance. Let it tick up naturally from there.

## Priority order

1. **Issue 5** (Shazam stops permanently) — Total system blindness. Hours of
   untagged music. Fix: unnamed playing decks must count as needing Shazam.
2. **Issue 3** (constant re-fetch) — Blocks prolink thread, likely caused Issue 7
   (CDJ contact loss). Fix: debounce or cache check.
3. **Issue 7** (silent CDJ contact loss) — Probably caused by NFS blocking the
   keepalive thread. Fix: watchdog + NFS timeout.
4. **Issue 1** (ID collision) — Wrong track names. Fix: scope lookups to device.
5. **Issue 8** (premature CDJ acceptance) — Tracks accepted before mix-in.
   Fix: don't accumulate confidence on unnamed tracks (signal gating).
6. **Issue 6** (audio-only too fragile) — Shazam useless for fast DJs.
   Fix: persistence across interruptions (weight-based).
7. **Issue 2** (OneLibrary retry after PDB success) — Easy fix, reduces noise.
8. **Issue 4** (PDB/OneLibrary ID mismatch) — Needs investigation.

## Future: Raw packet forwarding to Web UI

Consider adding a WebSocket alongside SSE that forwards raw Pro DJ Link
packets (binary) to the browser. JS parses with DataView using known offsets.

Benefits: real-time beat animation (per-beat, not 500ms poll), 30ms position
updates (CDJ-3000), protocol changes only need JS updates. SSE remains for
curated track/confidence data. ~10KB/s bandwidth on LAN is fine.

Requires SSE→WebSocket migration for the real-time channel. Keep SSE for
track events/history/log.

## Additional observations from full log analysis

- **2-hour total blackout** (00:10–02:05): zero tracks tagged. Issue 5 + Issue 3 cascade.
- **Duplicate audio-only acceptances**: same track accepted multiple times on Deck 0
  (Altitude — Falling 2x, Frankman — Underarms 2x, Process — Sense 2x). Audio-only
  slot resets and re-accepts when the track keep playing.
- **Same track accepted on multiple decks**: "Jandy Rainbow — The Pulse of Music"
  accepted on Deck 1, Deck 0, and Deck 6 within 10 minutes.
- **Device 6 OneLibrary always fails**: DJ's USB doesn't have OneLibrary format
  (older rekordbox export). PDB works every time. Should mark `usb_olib_fetched=1`
  after PDB success to avoid 3x NFS attempts per track change.
- **63 total acceptances in 8 hours** with a 2-hour gap = ~10/hour effective rate.
  Many tracks during the fast-mixing period (20:00–22:00) missed by Shazam entirely.
