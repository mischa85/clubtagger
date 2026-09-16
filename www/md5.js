/*
 * md5.js - MD5 for nginx secure_link signatures (RFC 1321)
 *
 * Only used to sign request URLs: nginx's secure_link_md5 compares the
 * base64url(md5(expires + uri + " " + secret)) we send against its own. MD5
 * is fine for that purpose: the secret never leaves the browser and the
 * signature only has to match; collision resistance is not what protects it.
 */

const K = new Int32Array(64);
const S = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
           5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
           4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
           6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296) | 0;

/* MD5 digest of a Uint8Array; returns a 16-byte Uint8Array. */
export function md5(bytes) {
    const len = bytes.length;
    const padded = new Uint8Array(((len + 8) >> 6 << 6) + 64);
    padded.set(bytes);
    padded[len] = 0x80;
    const bits = len * 8;
    const dv = new DataView(padded.buffer);
    dv.setUint32(padded.length - 8, bits >>> 0, true);
    dv.setUint32(padded.length - 4, Math.floor(bits / 4294967296), true);

    let a0 = 0x67452301, b0 = 0xefcdab89 | 0, c0 = 0x98badcfe | 0, d0 = 0x10325476;
    const M = new Int32Array(16);
    for (let off = 0; off < padded.length; off += 64) {
        for (let i = 0; i < 16; i++) M[i] = dv.getInt32(off + i * 4, true);
        let A = a0, B = b0, C = c0, D = d0;
        for (let i = 0; i < 64; i++) {
            let F, g;
            if (i < 16) { F = (B & C) | (~B & D); g = i; }
            else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) & 15; }
            else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) & 15; }
            else { F = C ^ (B | ~D); g = (7 * i) & 15; }
            F = (F + A + K[i] + M[g]) | 0;
            A = D; D = C; C = B;
            B = (B + ((F << S[i]) | (F >>> (32 - S[i])))) | 0;
        }
        a0 = (a0 + A) | 0; b0 = (b0 + B) | 0; c0 = (c0 + C) | 0; d0 = (d0 + D) | 0;
    }
    const out = new Uint8Array(16);
    const odv = new DataView(out.buffer);
    odv.setInt32(0, a0, true); odv.setInt32(4, b0, true); odv.setInt32(8, c0, true); odv.setInt32(12, d0, true);
    return out;
}

export function md5hex(bytes) {
    return [...md5(bytes)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/* base64url without padding, as nginx's secure_link expects. */
export function base64url(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i += 3) {
        const n = (bytes[i] << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
        s += chars[(n >> 18) & 63] + chars[(n >> 12) & 63];
        if (i + 1 < bytes.length) s += chars[(n >> 6) & 63];
        if (i + 2 < bytes.length) s += chars[n & 63];
    }
    return s;
}

/*
 * Sign a request path for an nginx location configured as
 *   secure_link $arg_md5,$arg_expires;
 *   secure_link_md5 "$secure_link_expires$uri $secret";
 * Returns path + "?md5=…&expires=…". `uri` must be the decoded path exactly as
 * nginx sees $uri (no query string).
 */
export function signUrl(uri, secret, ttlSec = 3600, now = Date.now()) {
    const expires = Math.floor(now / 1000) + ttlSec;
    const digest = md5(new TextEncoder().encode(`${expires}${uri} ${secret}`));
    return `${uri}?md5=${base64url(digest)}&expires=${expires}`;
}
