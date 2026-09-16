import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { md5hex, md5, base64url, signUrl } from '../www/md5.js';

const enc = (s) => new TextEncoder().encode(s);

test('MD5 matches RFC 1321 vectors and node:crypto on varied lengths', () => {
    assert.equal(md5hex(enc('')), 'd41d8cd98f00b204e9800998ecf8427e');
    assert.equal(md5hex(enc('abc')), '900150983cd24fb0d6963f7d28e17f72');
    assert.equal(md5hex(enc('The quick brown fox jumps over the lazy dog')), '9e107d9d372bb6826bd81d3542a419d6');
    for (const n of [55, 56, 63, 64, 65, 119, 120, 128, 1000, 100000]) {
        const bytes = new Uint8Array(n).map((_, i) => (i * 131 + 7) & 0xff);
        assert.equal(md5hex(bytes), createHash('md5').update(bytes).digest('hex'), `length ${n}`);
    }
});

test('signUrl produces what nginx secure_link_md5 computes', () => {
    // Reference: echo -n "1757534205/recordings/x.flac secret" | openssl md5 -binary | openssl base64 | tr +/ -_ | tr -d =
    const now = 1757530605000;                     // expires = now/1000 + 3600 = 1757534205
    const url = signUrl('/recordings/x.flac', 'secret', 3600, now);
    const ref = createHash('md5').update('1757534205/recordings/x.flac secret').digest('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    assert.equal(url, `/recordings/x.flac?md5=${ref}&expires=1757534205`);
    assert.equal(base64url(md5(enc('abc'))), 'kAFQmDzST7DWlj99KOF_cg');
});
