#!/usr/bin/env node
// Splice FLAC segments from the command line, using the same module the
// browser Worker uses:  node tests/splice-cli.mjs [--mode fixed|variable] out.flac seg1.flac seg2.flac ...
import { spliceSegments, readMetadata } from '../www/flac-splice.js';
import { fileSource, fileSink } from './node-io.mjs';
import { basename } from 'node:path';

const args = process.argv.slice(2);
let mode = 'auto';
if (args[0] === '--mode') { mode = args[1]; args.splice(0, 2); }
if (args.length < 2) {
    console.error('usage: splice-cli.mjs [--mode fixed|variable] out.flac seg1.flac [seg2.flac ...]');
    process.exit(2);
}
const [outPath, ...inputs] = args;

// Preflight: total_samples per segment from STREAMINFO (the browser gets this from the sidecars)
const segments = [];
for (const path of inputs) {
    const src = await fileSource(path, 64 * 1024);
    const meta = await readMetadata(src, basename(path));
    await src.close();
    segments.push({ name: basename(path), totalSamples: meta.streamInfo.totalSamples, open: () => fileSource(path) });
}

const sink = await fileSink(outPath);
const t0 = Date.now();
let lastLog = 0;
try {
    const summary = await spliceSegments(segments, sink, {
        mode,
        tags: [['TITLE', 'splice-cli test'], ['ENCODER', 'clubtagger-splice 1'],
               ['SEGMENTS', String(inputs.length)], ['SOURCE_FIRST', basename(inputs[0])],
               ['SOURCE_LAST', basename(inputs[inputs.length - 1])]],
    }, {
        onProgress(p) {
            const now = Date.now();
            if (now - lastLog > 500 || p.segmentDone) {
                lastLog = now;
                process.stderr.write(`\r  seg ${p.segment}/${p.segments}  ${(p.bytesOut / 1048576).toFixed(1)} MB  ${p.frames} frames   `);
            }
        },
    });
    const dt = (Date.now() - t0) / 1000;
    process.stderr.write('\n');
    console.log(JSON.stringify({ ...summary, seconds: dt, mbPerSec: +(summary.bytesOut / 1048576 / dt).toFixed(1) }, null, 1));
} catch (e) {
    process.stderr.write('\n');
    await sink.abort().catch(() => {});
    console.error(`${e.name}: ${e.message}`, e.segment ? `segment=${e.segment}` : '', e.frame !== undefined ? `frame=${e.frame}` : '', e.offset !== undefined ? `offset=${e.offset}` : '');
    process.exit(1);
}
