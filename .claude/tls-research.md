# CDJ-3000X TLS NFS Protocol — Research Notes

Status: **Partially reverse-engineered.** TLS handshake works, but the post-handshake
session setup message and UDP key derivation are not yet understood.

## Overview

CDJ-3000X devices encrypt all inter-CDJ NFS traffic using a TLS-derived key.
The CDJ is bilingual: it accepts both plain NFSv2 (from registered virtual CDJs)
and the encrypted protocol (from other CDJ-3000X peers).

## Protocol Flow (CDJ-to-CDJ)

```
1. CDJ-A announces on port 50000 with capability flag 0xe4 at byte 0x35
2. CDJ-A connects to CDJ-B on TCP port 50006
3. Preamble exchange: each side sends 1 byte = last octet of own IP address
4. TLS 1.3 handshake (X25519 + CHACHA20_POLY1305_SHA256 between CDJs)
5. Client sends 47-byte application data message (purpose unknown)
6. TCP connection closes
7. Steps 2-6 repeat in reverse direction (CDJ-B → CDJ-A)
8. Encrypted UDP RPC begins (portmapper:111, mount:545, NFS:2049)
```

## What We Know

### Preamble Byte
- Each CDJ sends the **last octet of its own IP address** as the preamble
- Confirmed across 4 CDJs with different IPs — byte always matches IP[3]
- Server responds with its own IP last octet

### TLS Parameters
- Between CDJs: TLS_CHACHA20_POLY1305_SHA256 (0x1303)
- When we connect as client: CDJ adapts, offers TLS_AES_256_GCM_SHA384 (0x1302)
- No client certificate required (CDJ accepts unauthenticated clients)
- CDJ **does** verify server certificates against a built-in CA

### Encrypted UDP Format
```
[4 bytes] XID           - standard RPC XID, matches request/response
[4 bytes] Session ID    - unique per CDJ pair, client/server differ by 1
[N bytes] Ciphertext    - AEAD-encrypted RPC payload
```

### Session IDs
- Unique per CDJ pair (different for each A↔B combination)
- Client and server values always differ by exactly 1
- NOT directly derivable from TLS session ID, random, key shares, or simple hashes
- Likely contained in or derived from the 47-byte post-handshake message

### 47-Byte Post-Handshake Message
- Sent by client after TLS handshake completes, inside the TLS tunnel
- 47 bytes of application data (64 bytes on wire: 47 plaintext + 16 AEAD tag + 1 content type)
- Purpose unknown — likely contains session parameters for UDP encryption
- Sending 47 zero bytes: CDJ accepts the write but closes without responding
- Not sending anything: CDJ waits ~2s then sends TLS alert (close_notify)

### Certificate Verification
- CDJ-to-CDJ: mutual TLS with proprietary CA certificates baked into firmware
- CDJ as server (us as client): accepts connection, no client cert required
- CDJ as client (us as server): rejects with "unknown CA" (alert 48)
- This means: **we can connect TO CDJs but CDJs can't complete TLS TO us**

### Capability Discovery
- CDJs only initiate TLS connections to peers with capability flag 0xe4 at announce byte 0x35
- Also requires protocol version 0x03 at byte 0x21 and device type at byte 0x25
- CDJs must see real MAC address (zero MAC prevents TLS peer discovery)
- TLS connections established between ALL CDJ pairs: N×(N-1) sessions for N CDJs

### Plaintext Services (CDJ-3000X)
- RemoteDB port discovery (TCP 12523): sends "RemoteDBServer\0", gets 2-byte port
- DBServer on dynamic port: standard 0x872349ae protocol, plaintext
- Keepalive/announce packets (UDP 50000): always plaintext broadcast
- Status packets (UDP 50002): always plaintext broadcast
- Beat packets (UDP 50001): always plaintext broadcast

## What Still Needs Work

### To decrypt CDJ-to-CDJ NFS traffic
1. Need to understand the 47-byte post-handshake message format
2. Need to derive UDP session ID from TLS session parameters
3. Need to determine AEAD nonce construction for UDP packets

### Possible approaches
- **Firmware extraction**: Extract the CA certificate and the post-handshake message format from CDJ firmware
- **Active probing**: Try different 47-byte message patterns and observe CDJ behavior
- **Key material export**: Use TLS 1.3 EKM (Exported Keying Material) with various labels — tested "cdj-nfs", "EXPORTER-Pioneer-NFS", "EXPORTER" — none matched observed session IDs

### Practical workaround
Plain NFSv2 still works when registered as a virtual CDJ. The TLS path is only needed
if AlphaTheta drops plain NFS support in future firmware.

## Test Tools

Two standalone test tools were built during research:

### tls-probe.c
Connects as TLS client to a CDJ on port 50006. Does preamble exchange, TLS 1.3
handshake, and dumps session parameters + KEYLOG secrets. Can send test payloads.

### tls-server.c
Listens on port 50006 and accepts incoming CDJ TLS connections. Generates a
self-signed certificate (rejected by CDJs — "unknown CA"). Useful for capturing
the CDJ's ClientHello and observing connection patterns.

Both require OpenSSL 3.x and link with `-lssl -lcrypto`.
