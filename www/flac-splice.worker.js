/*
 * flac-splice.worker.js - runs spliceSegments() off the main thread
 *
 * main -> worker: { type: 'start', handle: FileSystemFileHandle, segments: [{ name, url, totalSamples, size }],
 *                   mode: 'auto'|'fixed'|'variable', tags: [[k, v]] }
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

    let writable = null;
    try {
        writable = await msg.handle.createWritable();
    } catch (e) {
        self.postMessage({ type: 'error', message: 'cannot open output file: ' + e.message });
        return;
    }
    const sink = {
        write: (u8) => writable.write(u8),
        writeAt: (position, data) => writable.write({ type: 'write', position, data }),
        close: () => writable.close(),
        abort: () => writable.abort(),
    };

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
        self.postMessage({ type: 'done', summary });
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
