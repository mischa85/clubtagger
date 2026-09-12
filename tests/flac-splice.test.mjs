import { test } from 'node:test';
import assert from 'node:assert/strict';
import { crc8, crc16, utf8Encode, utf8Decode, utf8Len, parseFrameHeader, parseStreamInfo, buildStreamInfo,
         buildVorbisComment, buildSeekTable } from '../www/flac-splice.js';

const ascii = (s) => new TextEncoder().encode(s);

test('CRC-8 and CRC-16 check vectors', () => {
    assert.equal(crc8(ascii('123456789')), 0xF4);
    assert.equal(crc16(ascii('123456789')), 0xFEE8);
    // zero residue: CRC over data + its CRC is 0
    const d = ascii('clubtagger');
    const c = crc16(d);
    const withCrc = new Uint8Array([...d, c >> 8, c & 0xff]);
    assert.equal(crc16(withCrc), 0);
});

test('UTF-8 style numbers round-trip at every width boundary', () => {
    const cases = [0, 1, 127, 128, 2047, 2048, 65535, 65536, 2097151, 2097152, 67108863, 67108864,
                   2147483647, 2147483648, 11520000 * 60, 2 ** 36 - 1];
    const expectLen = [1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 6, 7];
    const buf = new Uint8Array(16);
    cases.forEach((v, i) => {
        const n = utf8Encode(v, buf, 0);
        assert.equal(n, expectLen[i], `len of ${v}`);
        assert.equal(utf8Len(v), n);
        const back = utf8Decode(buf, 0, n);
        assert.ok(back, `decode ${v}`);
        assert.equal(back.value, v, `value ${v}`);
        assert.equal(back.len, n);
    });
    assert.throws(() => utf8Len(2 ** 36));
    assert.equal(utf8Decode(new Uint8Array([0x80]), 0, 1), null);   // continuation byte as lead
    assert.equal(utf8Decode(new Uint8Array([0xff]), 0, 1), null);
});

test('frame header of the real 96 kHz / 24-bit recording parses', () => {
    // First header bytes of capture_20260322_025340.flac: ff f8 cb 1c 00 40 | 4e 06 ce ...
    // sync, fixed strategy, blocksize code 0xC (4096), rate code 0xB (96 kHz), channels 0x1 (2ch), bps 0xC>>1 = 6 (24 bit), frame 0, crc8 0x40
    const h = new Uint8Array([0xff, 0xf8, 0xcb, 0x1c, 0x00, 0x40, 0x4e, 0x06, 0xce]);
    const si = { rate: 96000, channels: 2, bps: 24 };
    const p = parseFrameHeader(h, 0, h.length, si);
    assert.ok(p, 'header should parse');
    assert.equal(p.variable, 0);
    assert.equal(p.blocksize, 4096);
    assert.equal(p.rate, 96000);
    assert.equal(p.channels, 2);
    assert.equal(p.bps, 24);
    assert.equal(p.number, 0);
    assert.equal(p.len, 6);
    // wrong stream format is rejected
    assert.equal(parseFrameHeader(h, 0, h.length, { rate: 48000, channels: 2, bps: 24 }), null);
    // corrupted crc8 is rejected
    const bad = h.slice(); bad[5] ^= 1;
    assert.equal(parseFrameHeader(bad, 0, bad.length, si), null);
    // truncated -> undefined (need more)
    assert.equal(parseFrameHeader(h, 0, 5, si), undefined);
});

test('explicit blocksize codes 6 and 7 and rate code 12', () => {
    // Build a header: fixed, bsCode 7 (16-bit blocksize-1), srCode 12 (8-bit kHz), 2ch, 24 bit, frame 5, blocksize 2500, 96 kHz
    const b = [0xff, 0xf8, (7 << 4) | 12, (1 << 4) | (6 << 1), 5, (2499 >> 8) & 0xff, 2499 & 0xff, 96];
    const arr = new Uint8Array([...b, 0]);
    arr[arr.length - 1] = crc8(arr, 0, arr.length - 1);
    const p = parseFrameHeader(arr, 0, arr.length, { rate: 96000, channels: 2, bps: 24 });
    assert.ok(p);
    assert.equal(p.blocksize, 2500);
    assert.equal(p.rate, 96000);
    assert.equal(p.extraEnd - p.extraStart, 3);
    const b6 = [0xff, 0xf8, (6 << 4) | 0xb, (1 << 4) | (6 << 1), 0, 15, 0];
    const a6 = new Uint8Array(b6); a6[6] = crc8(a6, 0, 6);
    assert.equal(parseFrameHeader(a6, 0, a6.length, { rate: 96000, channels: 2, bps: 24 }).blocksize, 16);
});

test('STREAMINFO builder round-trips through the parser', () => {
    const si = { minBlock: 4608, maxBlock: 4608, minFrame: 17, maxFrame: 27000, rate: 96000, channels: 2, bps: 24,
                 totalSamples: 11520000 * 66 + 12345, md5: null };
    const d = buildStreamInfo(si);
    const back = parseStreamInfo(d, 0);
    for (const k of ['minBlock', 'maxBlock', 'minFrame', 'maxFrame', 'rate', 'channels', 'bps', 'totalSamples']) {
        assert.equal(back[k], si[k], k);
    }
    assert.deepEqual([...back.md5], new Array(16).fill(0));
});

test('SEEKTABLE and VORBIS_COMMENT builders', () => {
    const st = buildSeekTable([{ sample: 0, offset: 0, blocksize: 4608 }, { sample: 2 ** 33, offset: 5, blocksize: 4608 }], 3);
    assert.equal(st.length, 54);
    assert.equal(st[18 + 3], 2);              // 2^33 = 0x0000000200000000 -> byte 3 of the u64 is 2
    assert.deepEqual([...st.subarray(36, 44)], new Array(8).fill(0xff));   // placeholder
    const vc = buildVorbisComment('vendor', [['TITLE', 'x'], ['DATE', '2026-09-10']]);
    const td = new TextDecoder();
    assert.equal(vc[0], 6);                    // vendor length LE
    assert.equal(td.decode(vc.subarray(4, 10)), 'vendor');
    assert.equal(vc[10], 2);                   // two comments
});
