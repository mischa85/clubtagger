# Pro DJ Link Protocol Reference

Consolidated protocol documentation from alphatheta-connect analysis and packet capture research.

## Network Ports

| Port | Protocol | Direction | Purpose |
|------|----------|-----------|---------|
| 50000 | UDP | Broadcast | Device announcements and keepalives |
| 50001 | UDP | Broadcast | Beat sync + CDJ-3000 position packets |
| 50002 | UDP | Broadcast | CDJ status updates (track, play state, on-air) |
| 50006 | TCP | Peer-to-peer | TLS key exchange for encrypted NFS (CDJ-3000X) |
| 111 | UDP | Unicast | RPC portmapper (plain or encrypted) |
| 545/635 | UDP | Unicast | NFS mount (Pioneer non-standard port) |
| 2049 | UDP | Unicast | NFS file access (plain or encrypted) |
| 1051 | TCP | Unicast | DBServer metadata queries (legacy) |
| 12523 | TCP | Unicast | RemoteDB port discovery (CDJ-3000X) |

## Packet Signature

All Pro DJ Link UDP packets start with 10-byte magic: `"Qspt1WmJOL"` (hex: `51 73 70 74 31 57 6d 4a 4f 4c`).

## Device Announcement (Port 50000, subtype 0x06, 54 bytes)

```
Offset  Size  Field
0x00    10    Magic "Qspt1WmJOL"
0x0a    1     Packet type (0x06)
0x0b    1     Subtype
0x0c    20    Device name (null-padded, e.g. "CDJ-3000X")
0x20    1     Struct version (0x01)
0x21    1     Protocol version (0x02=standard, 0x03=CDJ-3000, 0x04=CDJ-3000 keepalive)
0x22    1     Unknown (0x00 in CDJ-3000X)
0x23    1     Packet length (0x36 = 54)
0x24    1     Device number (1-6)
0x25    1     Device type (0x01=CDJ, 0x02=DJM, 0x03=rekordbox)
0x26    6     MAC address
0x2c    4     IP address (big-endian)
0x30    1     Presence flag (0x01)
0x31    4     Reserved
0x35    1     Capability flag (0x00=standard, 0x64=CDJ-3000, 0xe4=CDJ-3000X TLS-capable)
```

## CDJ Status Packet (Port 50002, subtype 0x0a, 212-1152 bytes)

```
Offset  Size  Field
0x0a    1     Subtype (0x0a)
0x0b    20    Device name (space-padded)
0x20    1     Subtype2 (0x03=CDJ status with track data)
0x21    1     D - Device number (1-6)
0x27    1     A - Activity (0x00=idle, 0x01=active)
0x28    1     Dr - Source player for track (0=none, else device#)
0x29    1     Sr - Slot (0x00=none, 0x01=CD, 0x02=SD, 0x03=USB, 0x04=Link, 0x06=Streaming, 0x09=Beatport)
0x2a    1     Tr - Track type (0x00=none, 0x01=rekordbox, 0x02=unanalyzed, 0x05=CD, 0x06=streaming)
0x2c    4     Rekordbox ID (big-endian uint32)
0x32    2     Track number in list (big-endian uint16)
0x35    1     tsrt - Track sort mode when loaded
0x37    1     tsrc - Menu track was loaded from (0x02=artist, 0x04=track, 0x05=playlist, etc.)
0x38    3     tcat1 - Menu category 1
0x3b    5     tcat2 - Menu category 2
0x46    2     dn - Track count on disc/playlist
0x58    1     ld1 - Load indicator (0x80 on new song, nxs2/XDJ-1000)
0x5a    2     uc1 - Cue update (0xffff on cue add/delete)
0x5e    2     ut - Tag update
0x66    2     ld2 - Load finished indicator (0xffff, nxs2/XDJ-1000)
0x6a    1     Ua - USB activity (alternates 0x04/0x06)
0x6b    1     Sa - SD activity
0x6f    1     Ul - USB local: 0x04=no media, 0x00=loaded, 0x02-03=ejecting
0x73    1     Sl - SD local: same as Ul
0x75    1     L - Link available: 0x01 if any USB/SD/CD on network
0x7b    1     P1 - Play state (0x00=empty, 0x02=loading, 0x03=playing, 0x04=looping,
               0x05=paused, 0x06=cued, 0x07=cuing, 0x08=platter held, 0x09=searching,
               0x0e=spun down, 0x11=ended, 0x12=emergency loop)
0x7c    4     Firmware version ASCII
0x84    4     Syncn - Increments on master handoff
0x89    1     F - Status flags (bit6=play, bit5=master, bit4=sync, bit3=on-air, bit0=BPM sync)
0x8b    1     P2 - Secondary play state (0x7a=playing, 0x7e=stopped, 0x6e=jog)
0x8c    4     Pitch1 - Current effective pitch (0x100000=0%, 0x000000=−100%, 0x200000=+100%)
0x90    2     Mv - Master validity (0x7fff=no track, 0x8000=rekordbox, 0x0000=non-rb)
0x92    2     BPM × 100 (big-endian uint16)
0x94    2     Mslip - Master slip (0x7fff when not slipping)
0x96    2     BPMslip - Slip mode BPM
0x98    4     Pitch2 - Fader position with brake/release speed
0x9d    1     P3 - Mode (0x09=vinyl fwd, 0x0d=CDJ fwd, 0x0b=slip)
0x9e    1     Mm - Master meaningful (0x00=not, 0x01=rb master, 0x02=non-rb master)
0x9f    1     Mh - Master handoff (0xff=normal, else device# taking over)
0xa0    4     Beat counter (big-endian uint32, 0xffffffff if no rb track)
0xa4    2     Cue countdown in bars (0x01ff=none/64+ bars)
0xa6    1     Bb - Beat in measure (1-4, 0x00 if no rb track)
0xb3    1     ug - Grid update (0xff when beat grid modified)
0xb7    1     Mp - CDJ-3000 media presence bitmask (bits for USB/SD)
0xb8    1     Ue - USB unsafe eject (0x01)
0xb9    1     Se - SD unsafe eject (0x01)
0xba    1     el - Emergency loop active (0x01)
0xc0    4     Pitch3 - Effective pitch (duplicate of Pitch1)
0xc4    4     Pitch4 - Fader position (instant response)
0xc8    4     Packet counter (not all players increment)
0xcc    1     nx - Hardware type (0x05=older, 0x0f=nexus, 0x1f=CDJ-3000/XDJ-XZ)
0xcd    1     t - Touch Audio support (bit 5)
```

### FLAGS byte (0x89) bit definitions
| Bit | Mask | Field |
|-----|------|-------|
| 6 | 0x40 | Playing |
| 5 | 0x20 | Master |
| 4 | 0x10 | Sync |
| 3 | 0x08 | On-air |

### CDJ-3000 Extended Fields (requires len ≥ 0x15f)
```
0x158   1     Mt - Master Tempo: 0x00=off, 0x01=on
0x15c   1     Key note (0x00=A, 0x01=Bb, ... 0x0b=G#) — NOTE: A-based, not C-based
0x15d   1     Key scale: 0x00=minor, 0x01=major
0x15e   1     Key accidental: 0x00=natural, 0x01=sharp, 0xff=flat
```

### CDJ-3000 Loop Fields (requires len ≥ 0x1ca)
```
0x1b6   4     Loop start position (big-endian, 0=no loop)
0x1be   4     Loop end position (big-endian)
0x1c8   2     Loop length in beats (big-endian)
```

**CDJ-3000X note:** Sends 1152-byte status packets with alternating subtype2 values. Only subtype2=0x03 has track data at standard offsets. Other variants (0x05, 0x06) have different layouts — skip track fields if rekordbox_id=0 and slot=0 to avoid flipping.

## CDJ-3000 Position Packet (Port 50001, subtype2 0x00, ~52 bytes)

Sent every ~30ms by CDJ-3000 and newer. Provides absolute position.

```
Offset  Size  Field
0x21    1     Device number
0x24    4     Track length in seconds (big-endian uint32)
0x28    4     Playhead in milliseconds (big-endian uint32)
0x2c    4     Pitch × 6400 (big-endian int32)
0x30    4     BPM × 10 (big-endian uint32, 0xFFFFFFFF = unknown)
```

## Beat Packet (Port 50001, subtype 0x28, 96 bytes)

```
Offset  Size  Field
0x21    1     Device number
0x24    4     Next beat in ms (big-endian)
0x54    4     Pitch adjustment (big-endian)
0x5a    2     BPM × 100 (big-endian)
0x5c    1     Beat in measure (1-4)
```

## On-Air Status (from DJM mixer)

### 4-Channel (DJM-900/1000, subtype2 0x00)
Channels 1-4 at offsets 0x24-0x27 (1 byte each, 0x01=on-air)

### 6-Channel (DJM-V10 + CDJ-3000, subtype2 0x03)
Channels 1-4 at 0x24-0x27, channels 5-6 at 0x2e-0x2f

## DBServer Protocol (TCP port 1051 or dynamic via port 12523)

### RemoteDB Port Discovery (CDJ-3000X, TCP 12523)
```
Client sends: [4B length=0x0F] "RemoteDBServer\0"
Server responds: [2B port number big-endian]
Server closes connection
```

### Message Format
```
Offset  Size  Field
0x00    4     Magic (0x872349ae)
0x04    4     Transaction ID
0x08    2     Message type
0x0a    1     Number of arguments
0x0b    12    Argument tags
0x17+   var   Arguments
```

### Key Message Types
| Request | Response | Purpose |
|---------|----------|---------|
| 0x0000 | — | Setup/introduce |
| 0x0100 | — | Disconnect |
| 0x2002 | 0x4000 | Rekordbox track metadata |
| 0x2003 | 0x4002 | Artwork |
| 0x2202 | 0x4000 | Unanalyzed track metadata |
| 0x3000 | 0x4101 | Render menu (fetch items) |

### DMST Value (32-bit composite)
```
Bits 31-24: Device number
Bits 23-16: Menu location (0x01=data, 0x07=folder)
Bits 15-8:  Slot (1=CD, 2=SD, 3=USB)
Bits 7-0:   Track type (1=rekordbox, 2=unanalyzed)
```

## OneLibrary Database (exportLibrary.db)

SQLCipher 4 encrypted SQLite database. Used by Rekordbox 6+ and CDJ-3000X.

### Encryption Parameters
| Parameter | Value |
|-----------|-------|
| Cipher | AES-256-CBC (no padding) |
| KDF | PBKDF2-HMAC-SHA512, 256,000 iterations |
| Page size | 4096 bytes |
| Reserve per page | 80 bytes (16 IV + 64 HMAC) |
| Salt | First 16 bytes of page 1 |

### Key Tables
| Table | Purpose |
|-------|---------|
| content | Tracks (title, BPM×100, length, foreign keys) |
| artist | Artist names (artist_id, name) |
| album | Album names |
| genre | Genres |
| key | Musical keys |
| cue | Cue points and loops |
| playlist / playlist_content | Playlists |
| history / history_content | Play history |

### Metadata Query
```sql
SELECT c.title, a.name FROM content c
LEFT JOIN artist a ON c.artist_id_artist = a.artist_id
WHERE c.content_id = ?
```

## NFS File Access

### Protocol Stack
1. Portmapper (UDP 111) → discover mount and NFS ports
2. Mount (UDP 545) → mount `/B/` (SD) or `/C/` (USB) export
3. NFS LOOKUP → `PIONEER/rekordbox/export.pdb` or `exportLibrary.db`
4. NFS READ → download file in chunks

### CDJ-3000X uses UTF-16LE filenames in NFS LOOKUP/MOUNT calls.

## Registration

### Virtual CDJ Registration
1. Observe network for 10 seconds (listen for existing peers)
2. If status packets seen during observation → stay passive (SPAN/multi-CDJ)
3. If no status → claim a slot (1-6), send keepalives every ~1.5s
4. CDJs require 5+ keepalives before accepting NFS requests

### Announce Packet Fields for CDJ-3000X Compatibility
- Protocol version byte (0x21) = 0x03
- Capability flag byte (0x35) = 0xe4 (enables TLS peer connections)
- Real MAC address required (zero MAC works for plain NFS but not TLS peer discovery)
