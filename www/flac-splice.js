/*
 * flac-splice.js - lossless concatenation of FLAC segments without decoding
 *
 * Every clubtagger segment is an independent FLAC stream whose audio is
 * sample-continuous with the next one. Joining them only needs the frame
 * headers rewritten: the frame/sample number continues across files, the
 * subframe payload is copied byte for byte, and both CRCs are recomputed.
 * One STREAMINFO, a SEEKTABLE built from the frames we pass, VORBIS_COMMENT
 * tags and a PADDING block go in front.
 *
 * Two output modes:
 *   fixed    - every segment but the last is a whole number of blocks: the
 *              output is an ordinary fixed-blocksize stream with renumbered
 *              frame numbers (what a normal encoder would have produced).
 *   variable - some segment ends with a short frame in the middle of the
 *              output (legacy 4096-block recordings, or joining across gaps):
 *              headers switch to the variable-blocksize strategy and carry
 *              absolute sample numbers instead. Spec-legal, decoders accept it.
 *
 * Pure module: no DOM, no fetch. Runs in a Worker and in Node (tests, CLI).
 * Sources and sinks are tiny interfaces:
 *   Source: { async read() -> Uint8Array | null }          (null = EOF)
 *   Sink:   { async write(u8), async writeAt(pos, u8), async close(), async abort() }
 */

/* ───────────────────────────── CRCs ───────────────────────────── */

const CRC8_TABLE = new Uint8Array(256);
const CRC16_TABLE = new Uint16Array(256);
for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) c = (c & 0x80) ? ((c << 1) ^ 0x07) & 0xff : (c << 1) & 0xff;
    CRC8_TABLE[i] = c;
    c = i << 8;
    for (let k = 0; k < 8; k++) c = (c & 0x8000) ? ((c << 1) ^ 0x8005) & 0xffff : (c << 1) & 0xffff;
    CRC16_TABLE[i] = c;
}

export function crc8(bytes, start = 0, end = bytes.length) {
    let c = 0;
    for (let i = start; i < end; i++) c = CRC8_TABLE[c ^ bytes[i]];
    return c;
}

export function crc16Update(crc, bytes, start = 0, end = bytes.length) {
    for (let i = start; i < end; i++) crc = ((crc << 8) & 0xffff) ^ CRC16_TABLE[(crc >> 8) ^ bytes[i]];
    return crc;
}

export function crc16(bytes, start = 0, end = bytes.length) {
    return crc16Update(0, bytes, start, end);
}

/* ─────────────────── FLAC "UTF-8 style" numbers ─────────────────── */

/* Number of bytes needed for v (v < 2^36). */
export function utf8Len(v) {
    if (v < 0x80) return 1;
    if (v < 0x800) return 2;
    if (v < 0x10000) return 3;
    if (v < 0x200000) return 4;
    if (v < 0x4000000) return 5;
    if (v < 0x80000000) return 6;
    if (v < 0x1000000000) return 7;
    throw new RangeError('number too large for FLAC header: ' + v);
}

/* Encode v at out[off]; returns bytes written. Arithmetic, not shifts: v may exceed 2^31. */
export function utf8Encode(v, out, off) {
    const n = utf8Len(v);
    if (n === 1) { out[off] = v; return 1; }
    const cont = n - 1;
    // lead byte: n ones, a zero, then the top bits of v
    const leadBits = 8 - n - 1;                    // payload bits in lead byte (0 for n=7)
    let rest = v;
    for (let k = cont; k >= 1; k--) {
        out[off + k] = 0x80 | (rest % 64);
        rest = Math.floor(rest / 64);
    }
    const leadPrefix = (0xff00 >> n) & 0xff;       // e.g. n=2 -> 0xC0, n=3 -> 0xE0
    out[off] = leadPrefix | (leadBits > 0 ? (rest & ((1 << leadBits) - 1)) : 0);
    return n;
}

/* Decode at bytes[off]; returns { value, len } or null if malformed. */
export function utf8Decode(bytes, off, avail) {
    const b0 = bytes[off];
    if (b0 < 0x80) return { value: b0, len: 1 };
    let n = 0;
    while (n < 8 && (b0 & (0x80 >> n))) n++;
    if (n < 2 || n > 7) return null;                // 10xxxxxx and 0xFF are invalid leads
    if (off + n > avail) return null;
    const leadBits = 8 - n - 1;
    let v = leadBits > 0 ? (b0 & ((1 << leadBits) - 1)) : 0;
    for (let k = 1; k < n; k++) {
        const b = bytes[off + k];
        if ((b & 0xc0) !== 0x80) return null;
        v = v * 64 + (b & 0x3f);
    }
    return { value: v, len: n };
}

/* ───────────────────────── metadata parsing ───────────────────────── */

const SAMPLE_RATE_CODES = [0, 88200, 176400, 192000, 8000, 16000, 22050, 24000, 32000, 44100, 48000, 96000];
const BPS_CODES = { 1: 8, 2: 12, 4: 16, 5: 20, 6: 24, 7: 32 };

export function parseStreamInfo(d, off) {
    const u16 = (o) => (d[o] << 8) | d[o + 1];
    const u24 = (o) => (d[o] << 16) | (d[o + 1] << 8) | d[o + 2];
    const minBlock = u16(off), maxBlock = u16(off + 2);
    const minFrame = u24(off + 4), maxFrame = u24(off + 7);
    const b = off + 10;
    const rate = (d[b] << 12) | (d[b + 1] << 4) | (d[b + 2] >> 4);
    const channels = ((d[b + 2] >> 1) & 7) + 1;
    const bps = (((d[b + 2] & 1) << 4) | (d[b + 3] >> 4)) + 1;
    // total_samples: 36 bits = low 4 bits of d[b+3] then 4 bytes
    const totalSamples = ((d[b + 3] & 0x0f) * 4294967296) +
        (((d[b + 4] << 24) >>> 0) + (d[b + 5] << 16) + (d[b + 6] << 8) + d[b + 7]);
    const md5 = d.slice(off + 18, off + 34);
    return { minBlock, maxBlock, minFrame, maxFrame, rate, channels, bps, totalSamples, md5 };
}

/*
 * Parse "fLaC" + metadata blocks from the start of `d` (avail bytes valid).
 * Returns { streamInfo, tags, vendor, firstFrameOffset }, or null when more
 * bytes are needed. Throws on a malformed stream.
 */
export function parseMetadata(d, avail) {
    if (avail < 4) return null;
    if (d[0] !== 0x66 || d[1] !== 0x4c || d[2] !== 0x61 || d[3] !== 0x43) throw new Error('not a FLAC stream (no fLaC marker)');
    let p = 4;
    let streamInfo = null, tags = [], vendor = '';
    for (;;) {
        if (p + 4 > avail) return null;
        const last = !!(d[p] & 0x80), type = d[p] & 0x7f;
        const len = (d[p + 1] << 16) | (d[p + 2] << 8) | d[p + 3];
        if (p + 4 + len > avail) return null;
        const body = p + 4;
        if (type === 0) {
            if (len < 34) throw new Error('short STREAMINFO');
            streamInfo = parseStreamInfo(d, body);
        } else if (type === 4) {
            const td = new TextDecoder();
            const u32le = (o) => (d[o] | (d[o + 1] << 8) | (d[o + 2] << 16) | (d[o + 3] << 24)) >>> 0;
            let q = body;
            const vl = u32le(q); q += 4;
            vendor = td.decode(d.subarray(q, q + vl)); q += vl;
            const n = u32le(q); q += 4;
            for (let i = 0; i < n && q + 4 <= body + len; i++) {
                const l = u32le(q); q += 4;
                const s = td.decode(d.subarray(q, q + l)); q += l;
                const eq = s.indexOf('=');
                if (eq > 0) tags.push([s.slice(0, eq).toUpperCase(), s.slice(eq + 1)]);
            }
        } else if (type === 127) {
            throw new Error('invalid metadata block type 127');
        }
        p = body + len;
        if (last) break;
    }
    if (!streamInfo) throw new Error('no STREAMINFO block');
    return { streamInfo, tags, vendor, firstFrameOffset: p };
}

/* ───────────────────────── frame header parsing ───────────────────────── */

export const FRAME_HEADER_MAX = 16;   // 4 + 7 (number) + 2 (blocksize) + 2 (rate) + 1 (crc8)

/*
 * Parse a frame header at d[off] (avail bytes valid in d). Returns null if
 * the bytes are not a valid header, undefined if more bytes are needed.
 * `si` (STREAMINFO) is used to reject headers whose rate/channels/bps do not
 * match the stream.
 */
export function parseFrameHeader(d, off, avail, si) {
    if (off + 4 > avail) return undefined;
    if (d[off] !== 0xff || (d[off + 1] & 0xfe) !== 0xf8) return null;
    const variable = d[off + 1] & 1;
    const bsCode = d[off + 2] >> 4, srCode = d[off + 2] & 0x0f;
    const chCode = d[off + 3] >> 4, bpsCode = (d[off + 3] >> 1) & 7;
    if (d[off + 3] & 1) return null;               // reserved bit
    if (bsCode === 0 || srCode === 15) return null;
    if (!(bpsCode in BPS_CODES)) return null;
    if (chCode > 10) return null;
    let p = off + 4;
    if (p >= avail) return undefined;
    const num = utf8Decode(d, p, avail);
    if (!num) {
        // could be truncated rather than invalid
        if (avail - p < 7) return undefined;
        return null;
    }
    p += num.len;
    let blocksize;
    if (bsCode === 1) blocksize = 192;
    else if (bsCode <= 5) blocksize = 576 << (bsCode - 2);
    else if (bsCode === 6) { if (p + 1 > avail) return undefined; blocksize = d[p] + 1; p += 1; }
    else if (bsCode === 7) { if (p + 2 > avail) return undefined; blocksize = ((d[p] << 8) | d[p + 1]) + 1; p += 2; }
    else blocksize = 256 << (bsCode - 8);
    let rate;
    if (srCode === 0) rate = si ? si.rate : 0;
    else if (srCode <= 11) rate = SAMPLE_RATE_CODES[srCode];
    else if (srCode === 12) { if (p + 1 > avail) return undefined; rate = d[p] * 1000; p += 1; }
    else if (srCode === 13) { if (p + 2 > avail) return undefined; rate = (d[p] << 8) | d[p + 1]; p += 2; }
    else { if (p + 2 > avail) return undefined; rate = ((d[p] << 8) | d[p + 1]) * 10; p += 2; }
    if (p + 1 > avail) return undefined;
    if (crc8(d, off, p) !== d[p]) return null;
    const channels = chCode < 8 ? chCode + 1 : 2;
    const bps = BPS_CODES[bpsCode];
    if (si) {
        if (rate !== si.rate || channels !== si.channels || bps !== si.bps) return null;
    }
    return {
        len: p + 1 - off,          // header length incl. CRC-8
        variable, blocksize, number: num.value, numLen: num.len,
        bsCode, srCode, rate, channels, bps,
        extraStart: off + 4 + num.len, extraEnd: p,   // explicit blocksize/rate bytes
    };
}

/* ─────────────────────────── byte queue ─────────────────────────── */

export class ByteQueue {
    constructor(initial = 1 << 20) {
        this.buf = new Uint8Array(initial);
        this.start = 0;
        this.end = 0;
        this.base = 0;      // absolute offset of buf[0]
        this.eof = false;
    }
    get available() { return this.end - this.start; }
    abs(i) { return this.base + this.start + i; }
    push(chunk) {
        if (this.end + chunk.length > this.buf.length) {
            if (this.start > 0) {
                this.buf.copyWithin(0, this.start, this.end);
                this.base += this.start;
                this.end -= this.start;
                this.start = 0;
            }
            if (this.end + chunk.length > this.buf.length) {
                let ncap = this.buf.length * 2;
                while (ncap < this.end + chunk.length) ncap *= 2;
                const nb = new Uint8Array(ncap);
                nb.set(this.buf.subarray(0, this.end));
                this.buf = nb;
            }
        }
        this.buf.set(chunk, this.end);
        this.end += chunk.length;
    }
    consume(n) { this.start += n; }
    /* Pull from source until at least n bytes are available or EOF. */
    async ensure(n, source) {
        while (this.available < n && !this.eof) {
            const chunk = await source.read();
            if (chunk === null || chunk === undefined) { this.eof = true; break; }
            if (chunk.length) this.push(chunk);
        }
        return this.available >= n;
    }
}

/* ─────────────────────────── errors ─────────────────────────── */

export class SpliceError extends Error {
    constructor(message, info = {}) {
        super(message);
        this.name = 'SpliceError';
        Object.assign(this, info);
    }
}

export class SpliceCancelled extends Error {
    constructor() { super('cancelled'); this.name = 'SpliceCancelled'; }
}

/* ───────────────────────── frame scanner ───────────────────────── */

/*
 * Iterates over the frames of one FLAC segment read from `source`.
 * Yields { hdr, bytes, start, end } where bytes.subarray(start, end) is the
 * whole frame (header .. CRC-16 inclusive) and hdr is the parsed header.
 * Every frame boundary is proven by the CRC-16 of the frame (FLAC's CRC-16
 * has zero residue: running it over a frame including its CRC yields 0) and
 * by the next header parsing with the expected number.
 */
export async function* readFrames(source, meta, segName) {
    const q = new ByteQueue();
    const si = meta.streamInfo;
    // The caller already consumed the metadata bytes from `source`'s stream
    // through `meta.leftover`; start the queue with them.
    if (meta.leftover && meta.leftover.length) q.push(meta.leftover);

    const maxFrame = si.maxFrame ? si.maxFrame + 64 : (1 << 20);
    const minFrame = si.minFrame || 0;
    let expected = null;      // next frame number (fixed) / sample number (variable)
    let frameIdx = 0;

    for (;;) {
        await q.ensure(maxFrame + FRAME_HEADER_MAX, source);
        const avail = q.available;
        if (avail === 0) {
            if (frameIdx === 0) throw new SpliceError('no audio frames', { segment: segName });
            return;
        }
        const d = q.buf, s = q.start;
        const hdr = parseFrameHeader(d, s, q.end, si);
        if (!hdr) {
            throw new SpliceError('lost sync: no valid frame header', { segment: segName, offset: q.abs(0), frame: frameIdx });
        }
        if (expected !== null && hdr.number !== expected) {
            throw new SpliceError(`unexpected frame number ${hdr.number}, expected ${expected}`,
                                  { segment: segName, offset: q.abs(0), frame: frameIdx });
        }
        const nextExpected = hdr.variable ? hdr.number + hdr.blocksize : hdr.number + 1;

        // Scan forward with a running CRC-16 for the end of this frame.
        const lo = Math.max(minFrame, hdr.len + 2);
        const hi = Math.min(avail, maxFrame);
        let crc = 0;
        let i = 0;
        let end = -1;
        const T = CRC16_TABLE;
        while (i < hi) {
            crc = ((crc << 8) & 0xffff) ^ T[(crc >> 8) ^ d[s + i]];
            i++;
            if (i < lo || crc !== 0) continue;
            if (i === avail) {
                if (q.eof) { end = i; break; }       // last frame of the file
                continue;                             // need more bytes to decide
            }
            if (d[s + i] === 0xff && (d[s + i + 1] & 0xfe) === 0xf8) {
                const nh = parseFrameHeader(d, s + i, q.end, si);
                if (nh && nh.number === nextExpected && nh.variable === hdr.variable) { end = i; break; }
                if (nh === undefined) break;          // header truncated: refill and retry
            }
        }
        if (end < 0) {
            if (!q.eof && i >= avail - FRAME_HEADER_MAX) {
                // ran out of buffered bytes; fetch more and rescan this frame
                const got = await q.ensure(avail + maxFrame, source);
                if (got || q.available > avail) continue;
            }
            throw new SpliceError(q.eof && i >= avail ? 'CRC mismatch or truncated final frame' : 'frame exceeds maximum size or CRC mismatch',
                                  { segment: segName, offset: q.abs(0), frame: frameIdx });
        }
        yield { hdr, bytes: d, start: s, end: s + end, frame: frameIdx };
        q.consume(end);
        expected = nextExpected;
        frameIdx++;
    }
}

/* Read and parse the metadata of a segment; returns meta with `leftover` bytes for readFrames. */
export async function readMetadata(source, segName) {
    const q = new ByteQueue(64 * 1024);
    let meta = null;
    for (;;) {
        meta = parseMetadata(q.buf.subarray(q.start, q.end), q.available);
        if (meta) break;
        const before = q.available;
        await q.ensure(before + 1, source);
        if (q.available === before) throw new SpliceError('truncated metadata', { segment: segName });
    }
    meta.leftover = q.buf.slice(q.start + meta.firstFrameOffset, q.end);
    return meta;
}

/* ───────────────────────── metadata builders ───────────────────────── */

function putU16(d, o, v) { d[o] = (v >> 8) & 0xff; d[o + 1] = v & 0xff; }
function putU24(d, o, v) { d[o] = (v >> 16) & 0xff; d[o + 1] = (v >> 8) & 0xff; d[o + 2] = v & 0xff; }
function putU64(d, o, v) {
    // v is a Number < 2^53 (or the 0xFFFF... placeholder passed as -1)
    if (v < 0) { for (let i = 0; i < 8; i++) d[o + i] = 0xff; return; }
    const hi = Math.floor(v / 4294967296), lo = v % 4294967296;
    d[o] = (hi >>> 24) & 0xff; d[o + 1] = (hi >>> 16) & 0xff; d[o + 2] = (hi >>> 8) & 0xff; d[o + 3] = hi & 0xff;
    d[o + 4] = (lo >>> 24) & 0xff; d[o + 5] = (lo >>> 16) & 0xff; d[o + 6] = (lo >>> 8) & 0xff; d[o + 7] = lo & 0xff;
}

export function buildStreamInfo(si) {
    const d = new Uint8Array(34);
    putU16(d, 0, si.minBlock);
    putU16(d, 2, si.maxBlock);
    putU24(d, 4, si.minFrame);
    putU24(d, 7, si.maxFrame);
    // 20 bits rate | 3 bits channels-1 | 5 bits bps-1 | 36 bits total
    const total = si.totalSamples;
    const tHi = Math.floor(total / 4294967296) & 0x0f, tLo = total % 4294967296;
    d[10] = (si.rate >> 12) & 0xff;
    d[11] = (si.rate >> 4) & 0xff;
    d[12] = ((si.rate & 0x0f) << 4) | (((si.channels - 1) & 7) << 1) | (((si.bps - 1) >> 4) & 1);
    d[13] = (((si.bps - 1) & 0x0f) << 4) | tHi;
    d[14] = (tLo >>> 24) & 0xff; d[15] = (tLo >>> 16) & 0xff; d[16] = (tLo >>> 8) & 0xff; d[17] = tLo & 0xff;
    if (si.md5) d.set(si.md5, 18);   // else zeros = unknown
    return d;
}

export function buildSeekTable(points, capacity) {
    const d = new Uint8Array(18 * capacity);
    for (let i = 0; i < capacity; i++) {
        const o = i * 18;
        if (i < points.length) {
            putU64(d, o, points[i].sample);
            putU64(d, o + 8, points[i].offset);
            putU16(d, o + 16, points[i].blocksize);
        } else {
            putU64(d, o, -1);            // placeholder point
            putU64(d, o + 8, 0);
            putU16(d, o + 16, 0);
        }
    }
    return d;
}

export function buildVorbisComment(vendor, tags) {
    const te = new TextEncoder();
    const v = te.encode(vendor);
    const entries = tags.map(([k, val]) => te.encode(`${k}=${val}`));
    let len = 4 + v.length + 4;
    for (const e of entries) len += 4 + e.length;
    const d = new Uint8Array(len);
    const putU32le = (o, x) => { d[o] = x & 0xff; d[o + 1] = (x >> 8) & 0xff; d[o + 2] = (x >> 16) & 0xff; d[o + 3] = (x >>> 24) & 0xff; };
    let o = 0;
    putU32le(o, v.length); o += 4; d.set(v, o); o += v.length;
    putU32le(o, entries.length); o += 4;
    for (const e of entries) { putU32le(o, e.length); o += 4; d.set(e, o); o += e.length; }
    return d;
}

function blockHeader(type, len, last) {
    const d = new Uint8Array(4);
    d[0] = (last ? 0x80 : 0) | type;
    putU24(d, 1, len);
    return d;
}

/* ───────────────────────── output buffer ───────────────────────── */

class OutBuf {
    constructor(sink, size = 8 << 20) {
        this.sink = sink;
        this.buf = new Uint8Array(size);
        this.len = 0;
        this.pos = 0;         // absolute bytes emitted (incl. buffered)
    }
    async append(bytes, start = 0, end = bytes.length) {
        const n = end - start;
        if (this.len + n > this.buf.length) await this.flush();
        if (n > this.buf.length) {
            await this.sink.write(bytes.slice(start, end));
        } else {
            this.buf.set(bytes.subarray(start, end), this.len);
            this.len += n;
        }
        this.pos += n;
    }
    async appendByte2(v) {
        if (this.len + 2 > this.buf.length) await this.flush();
        this.buf[this.len++] = (v >> 8) & 0xff;
        this.buf[this.len++] = v & 0xff;
        this.pos += 2;
    }
    async flush() {
        if (this.len) {
            await this.sink.write(this.buf.slice(0, this.len));
            this.len = 0;
        }
    }
}

/* ───────────────────────── the splice ───────────────────────── */

export const VENDOR = 'clubtagger-splice 1';

/*
 * segments: [{ name, open() -> Source, totalSamples? }]
 * sink:     Sink
 * opts:     { mode: 'auto'|'fixed'|'variable', seekIntervalSec = 10, tags = [[k,v]],
 *             paddingBytes = 4096, totalSamplesHint? }
 * hooks:    { onProgress(p), isCancelled() }
 * Resolves to a summary { mode, totalSamples, frames, bytesOut, segments, blocksize, minBlock, maxBlock }.
 */
export async function spliceSegments(segments, sink, opts = {}, hooks = {}) {
    const seekIntervalSec = opts.seekIntervalSec ?? 10;
    const paddingBytes = opts.paddingBytes ?? 4096;
    const tags = opts.tags ?? [];
    const onProgress = hooks.onProgress ?? (() => {});
    const isCancelled = hooks.isCancelled ?? (() => false);
    if (!segments.length) throw new SpliceError('nothing to splice');

    const out = new OutBuf(sink);
    let si0 = null;               // STREAMINFO of the first segment
    let mode = opts.mode ?? 'auto';
    let variable = false;
    let headerLen = 0, seekCap = 0, seekTableOff = 0;
    const seekPoints = [];
    let nextSeekSample = 0;

    // Running stream statistics
    let sampleNumber = 0;         // absolute sample position of the next frame
    let frameNumber = 0;          // output frame index
    let minBlockNonLast = Infinity, maxBlock = 0, lastBlock = 0;
    let minFrame = Infinity, maxFrame = 0;
    let bytesIn = 0;
    const hdrBuf = new Uint8Array(FRAME_HEADER_MAX);
    const firstTags = [], lastTags = [];
    let lastShortSeen = false;    // previous output frame was shorter than the blocksize

    for (let s = 0; s < segments.length; s++) {
        if (isCancelled()) throw new SpliceCancelled();
        const seg = segments[s];
        const source = await seg.open();
        const meta = await readMetadata(source, seg.name);
        const si = meta.streamInfo;
        if (s === 0) firstTags.push(...meta.tags);
        if (s === segments.length - 1) lastTags.push(...meta.tags);

        if (!si0) {
            si0 = si;
            // Decide the output mode: fixed only when every non-last segment is a
            // whole number of blocks (needs totalSamples known for each of them).
            if (mode === 'auto') {
                const B = si.maxBlock;
                let ok = si.minBlock === si.maxBlock && B > 0;
                for (let k = 0; ok && k < segments.length - 1; k++) {
                    const t = segments[k].totalSamples;
                    if (!t || t % B !== 0) ok = false;
                }
                mode = ok ? 'fixed' : 'variable';
            }
            variable = mode === 'variable';

            // Fixed-size header so the first frame offset is known now.
            const hinted = opts.totalSamplesHint ??
                segments.reduce((a, g) => a + (g.totalSamples || si.totalSamples || 0), 0);
            seekCap = Math.ceil(hinted / (seekIntervalSec * si.rate)) + 1;
            const vc = buildVorbisComment(VENDOR, tags);
            await out.append(new Uint8Array([0x66, 0x4c, 0x61, 0x43]));               // fLaC
            await out.append(blockHeader(0, 34, false));
            await out.append(buildStreamInfo({ ...si, totalSamples: 0, md5: null, minFrame: 0, maxFrame: 0 }));
            seekTableOff = out.pos;
            await out.append(blockHeader(3, 18 * seekCap, false));
            await out.append(buildSeekTable([], seekCap));
            await out.append(blockHeader(4, vc.length, false));
            await out.append(vc);
            await out.append(blockHeader(1, paddingBytes, true));
            await out.append(new Uint8Array(paddingBytes));
            headerLen = out.pos;
        } else if (si.rate !== si0.rate || si.channels !== si0.channels || si.bps !== si0.bps) {
            throw new SpliceError(`format differs: ${si.rate} Hz/${si.channels} ch/${si.bps} bit vs ${si0.rate} Hz/${si0.channels} ch/${si0.bps} bit`,
                                  { segment: seg.name });
        }

        let segFrames = 0;
        for await (const f of readFrames(source, meta, seg.name)) {
            if (isCancelled()) throw new SpliceCancelled();
            const h = f.hdr;

            // In a fixed-blocksize stream only the very last frame may be short.
            // A short frame followed by any other frame means the preflight was
            // wrong about this segment set; refuse rather than emit a broken file.
            if (lastShortSeen && !variable) {
                throw new SpliceError('short frame followed by more audio; segments need variable-blocksize output',
                                      { segment: seg.name, frame: f.frame });
            }
            lastShortSeen = h.blocksize !== si0.maxBlock;

            // Seek point at the first frame at/after each interval
            if (sampleNumber >= nextSeekSample) {
                seekPoints.push({ sample: sampleNumber, offset: out.pos - headerLen, blocksize: h.blocksize });
                nextSeekSample += seekIntervalSec * si0.rate;
                while (nextSeekSample <= sampleNumber) nextSeekSample += seekIntervalSec * si0.rate;
            }

            // New header: sync + strategy, bytes 2-3 verbatim, number, extras, CRC-8
            hdrBuf[0] = 0xff;
            hdrBuf[1] = variable ? 0xf9 : 0xf8;
            hdrBuf[2] = f.bytes[f.start + 2];
            hdrBuf[3] = f.bytes[f.start + 3];
            let n = 4 + utf8Encode(variable ? sampleNumber : frameNumber, hdrBuf, 4);
            for (let k = h.extraStart; k < h.extraEnd; k++) hdrBuf[n++] = f.bytes[k];
            hdrBuf[n] = crc8(hdrBuf, 0, n);
            n++;

            const payloadStart = f.start + h.len, payloadEnd = f.end - 2;
            let c = crc16Update(0, hdrBuf, 0, n);
            c = crc16Update(c, f.bytes, payloadStart, payloadEnd);

            const frameLen = n + (payloadEnd - payloadStart) + 2;
            await out.append(hdrBuf, 0, n);
            await out.append(f.bytes, payloadStart, payloadEnd);
            await out.appendByte2(c);

            if (frameLen < minFrame) minFrame = frameLen;
            if (frameLen > maxFrame) maxFrame = frameLen;
            if (h.blocksize > maxBlock) maxBlock = h.blocksize;
            if (lastBlock && lastBlock < minBlockNonLast) minBlockNonLast = lastBlock;  // previous frame is now known not to be last
            lastBlock = h.blocksize;
            sampleNumber += h.blocksize;
            frameNumber++;
            segFrames++;
            bytesIn += f.end - f.start;
            if ((frameNumber & 63) === 0) {
                onProgress({ segment: s, segments: segments.length, frames: frameNumber, samples: sampleNumber, bytesIn, bytesOut: out.pos });
            }
        }
        if (seg.totalSamples && segFrames === 0) throw new SpliceError('segment produced no frames', { segment: seg.name });
        if (source.close) await source.close();
        onProgress({ segment: s + 1, segments: segments.length, frames: frameNumber, samples: sampleNumber, bytesIn, bytesOut: out.pos, segmentDone: true });
    }

    await out.flush();

    // Patch STREAMINFO and SEEKTABLE
    let minBlock = Math.min(minBlockNonLast === Infinity ? lastBlock : minBlockNonLast, maxBlock);
    if (minBlock < 16) minBlock = 16;
    if (!variable) minBlock = maxBlock = si0.maxBlock;
    const finalSi = { ...si0, minBlock, maxBlock, minFrame: minFrame === Infinity ? 0 : minFrame, maxFrame, totalSamples: sampleNumber, md5: null };
    await sink.writeAt(8, buildStreamInfo(finalSi));
    await sink.writeAt(seekTableOff + 4, buildSeekTable(seekPoints, seekCap));
    await sink.close();

    return { mode, totalSamples: sampleNumber, frames: frameNumber, bytesOut: out.pos, bytesIn,
             segments: segments.length, blocksize: si0.maxBlock, minBlock, maxBlock, rate: si0.rate,
             channels: si0.channels, bps: si0.bps, firstTags, lastTags, seekPoints: seekPoints.length };
}
