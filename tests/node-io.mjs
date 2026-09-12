// Node Source/Sink adapters for www/flac-splice.js
import { open, unlink } from 'node:fs/promises';

export async function fileSource(path, chunkSize = 256 * 1024) {
    const fh = await open(path, 'r');
    let pos = 0, done = false;
    return {
        async read() {
            if (done) return null;
            const buf = new Uint8Array(chunkSize);
            const { bytesRead } = await fh.read(buf, 0, chunkSize, pos);
            if (bytesRead === 0) { done = true; await fh.close(); return null; }
            pos += bytesRead;
            return buf.subarray(0, bytesRead);
        },
        async close() { if (!done) { done = true; await fh.close(); } },
    };
}

export async function fileSink(path) {
    const fh = await open(path, 'w');
    let pos = 0;
    return {
        async write(u8) { await fh.write(u8, 0, u8.length, pos); pos += u8.length; },
        async writeAt(p, u8) { await fh.write(u8, 0, u8.length, p); },
        async close() { await fh.close(); },
        async abort() { await fh.close(); await unlink(path).catch(() => {}); },
    };
}
