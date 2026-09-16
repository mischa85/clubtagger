/*
 * flac-splice.worker.js - runs spliceSegments() off the main thread
 *
 * main -> worker: { type: 'start', handle: FileSystemFileHandle | null, segments: [{ name, url, totalSamples, size }],
 *                   mode: 'auto'|'fixed'|'variable', tags: [[k, v]] }
 *                 handle null = no File System Access API (plain-HTTP page or another
 *                 browser): the file is assembled as a Blob and returned in 'done'.
 *                 { type: 'cancel' }
 * worker -> main: { type: 'progress', ... }   { type: 'done', summary }
 *                 { type: 'error', message, segment, frame, offset }   { type: 'cancelled' }
 */
import { spliceSegments, SpliceCancelled } from './flac-splice.js';

let cancelled = false;
let controller = null;

function fetchSource(url, name) {
    // One fetch per segment; the body is consumed as a stream. The next
    // segment's request is started while the current one is still being
    // processed (see prefetch below) to keep the connection warm.
    let reader = null, response = null, pending = null;
    return {
        prefetch() {
            if (!pending) pending = fetch(url, { signal: controller.signal, cache: 'no-store' });
            return pending;
        },
        async read() {
            if (!reader) {
                response = await this.prefetch();
                if (!response.ok) throw new Error(`HTTP ${response.status} for ${name}`);
                reader = response.body.getReader();
            }
            const { value, done } = await reader.read();
            return done ? null : value;
        },
        async close() { try { if (reader) await reader.cancel(); } catch (e) { /* ignore */ } },
    };
}

/*
 * Sink that accumulates the output as a Blob. Concatenating Blobs does not
 * copy: the browser keeps references to the parts (and pages large Blobs to
 * disk), so a 2 GB export stays feasible. Header patches (STREAMINFO,
 * SEEKTABLE) are applied at close() by slicing around them.
 */
class BlobSink {
    constructor() { this.blob = new Blob([]); this.patches = []; this.result = null; }
    async write(u8) { this.blob = new Blob([this.blob, u8]); }
    async writeAt(position, data) { this.patches.push({ position, data: data.slice() }); }
    async close() {
        this.patches.sort((a, b) => a.position - b.position);
        const parts = [];
        let pos = 0;
        for (const p of this.patches) {
            if (p.position > pos) parts.push(this.blob.slice(pos, p.position));
            parts.push(p.data);
            pos = p.position + p.data.length;
        }
        if (pos < this.blob.size) parts.push(this.blob.slice(pos));
        this.result = new Blob(parts, { type: 'audio/flac' });
        this.blob = null;
    }
    async abort() { this.blob = null; this.result = null; }
}

self.onmessage = async (ev) => {
    const msg = ev.data;
    if (msg.type === 'cancel') {
        cancelled = true;
        if (controller) controller.abort();
        return;
    }
    if (msg.type !== 'start') return;

    cancelled = false;
    controller = new AbortController();

    let sink, blobSink = null;
    if (msg.handle) {
        let writable = null;
        try {
            writable = await msg.handle.createWritable();
        } catch (e) {
            self.postMessage({ type: 'error', message: 'cannot open output file: ' + e.message });
            return;
        }
        sink = {
            write: (u8) => writable.write(u8),
            writeAt: (position, data) => writable.write({ type: 'write', position, data }),
            close: () => writable.close(),
            abort: () => writable.abort(),
        };
    } else {
        blobSink = new BlobSink();
        sink = blobSink;
    }

    const sources = msg.segments.map((s) => fetchSource(s.url, s.name));
    const segments = msg.segments.map((s, i) => ({
        name: s.name,
        totalSamples: s.totalSamples,
        open: async () => {
            if (i + 1 < sources.length) sources[i + 1].prefetch().catch(() => {});
            return sources[i];
        },
    }));

    let lastProgress = 0;
    try {
        const summary = await spliceSegments(segments, sink, { mode: msg.mode || 'auto', tags: msg.tags || [] }, {
            onProgress(p) {
                const now = Date.now();
                if (p.segmentDone || now - lastProgress > 250) {
                    lastProgress = now;
                    self.postMessage({ type: 'progress', ...p });
                }
            },
            isCancelled: () => cancelled,
        });
        self.postMessage({ type: 'done', summary, blob: blobSink ? blobSink.result : null });
    } catch (e) {
        try { await sink.abort(); } catch (e2) { /* nothing left to discard */ }
        if (e instanceof SpliceCancelled || cancelled) {
            self.postMessage({ type: 'cancelled' });
        } else {
            self.postMessage({ type: 'error', message: e.message, segment: e.segment, frame: e.frame, offset: e.offset });
        }
    } finally {
        for (const s of sources) s.close().catch(() => {});
    }
};
