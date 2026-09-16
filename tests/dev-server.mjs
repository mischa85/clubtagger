#!/usr/bin/env node
// Development server that mimics the nginx layout used on the recorder:
//   /                  -> www/ static files
//   /recordings/<f>    -> files from a recordings directory (Range supported)
//   /recordings-json/  -> nginx-style JSON autoindex of that directory
// Usage: node tests/dev-server.mjs <recordings-dir> [port]
// Set SECURE_LINK_SECRET=... to require nginx-style signed URLs (?md5=&expires=)
// on /recordings/ and /recordings-json/, exactly like tools/nas-nginx.conf.example.
import { createServer } from 'node:http';
import { stat, readdir } from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import { join, extname, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

const SECRET = process.env.SECURE_LINK_SECRET || '';
/* nginx secure_link check: md5 = base64url(md5(expires + uri + " " + secret)); returns 200/403/410 */
function secureLinkStatus(url) {
    if (!SECRET) return 200;
    const md5 = url.searchParams.get('md5'), expires = url.searchParams.get('expires');
    if (!md5 || !expires) return 403;
    const ref = createHash('md5').update(`${expires}${decodeURIComponent(url.pathname)} ${SECRET}`).digest('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    if (ref !== md5) return 403;
    if (+expires < Date.now() / 1000) return 410;
    return 200;
}

const recDir = resolve(process.argv[2] || '.');
const port = +(process.argv[3] || 8080);
const wwwDir = resolve(dirname(fileURLToPath(import.meta.url)), '../www');
const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json',
                '.flac': 'audio/flac', '.peaks': 'application/octet-stream', '.woff2': 'font/woff2' };

async function serveFile(req, res, path) {
    let st;
    try { st = await stat(path); } catch { res.writeHead(404); res.end('not found'); return; }
    if (!st.isFile()) { res.writeHead(404); res.end('not found'); return; }
    const type = types[extname(path)] || 'application/octet-stream';
    let start = 0, end = st.size - 1, status = 200;
    const range = req.headers.range;
    if (range) {
        const m = /^bytes=(\d*)-(\d*)$/.exec(range);
        if (m) {
            if (m[1]) start = +m[1];
            if (m[2]) end = +m[2];
            if (!m[1] && m[2]) { start = st.size - +m[2]; end = st.size - 1; }
            status = 206;
        }
    }
    res.writeHead(status, {
        'Content-Type': type, 'Content-Length': end - start + 1, 'Accept-Ranges': 'bytes',
        'Last-Modified': st.mtime.toUTCString(),
        ...(status === 206 ? { 'Content-Range': `bytes ${start}-${end}/${st.size}` } : {}),
    });
    if (req.method === 'HEAD') { res.end(); return; }
    // path-based stream: owns and closes its descriptor, also when the client aborts
    const stream = createReadStream(path, { start, end });
    stream.on('error', () => res.destroy());
    res.on('close', () => stream.destroy());
    stream.pipe(res);
}

createServer(async (req, res) => {
    const url = new URL(req.url, 'http://x');
    const p = decodeURIComponent(url.pathname);
    if (p.startsWith('/recordings/') || p.startsWith('/recordings-json')) {
        const st = secureLinkStatus(url);
        if (st !== 200) { res.writeHead(st); res.end(st === 410 ? 'expired' : 'forbidden'); return; }
    }
    if (p === '/recordings-json/' || p === '/recordings-json') {
        const names = await readdir(recDir);
        const out = [];
        for (const n of names) {
            if (n.startsWith('.')) continue;
            const st = await stat(join(recDir, n));
            out.push({ name: n, type: st.isDirectory() ? 'directory' : 'file', mtime: st.mtime.toUTCString(), size: st.size });
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(out));
        return;
    }
    if (p.startsWith('/recordings/')) {
        const name = p.slice('/recordings/'.length);
        if (name.includes('/') || name.startsWith('.')) { res.writeHead(404); res.end(); return; }
        return serveFile(req, res, join(recDir, name));
    }
    const rel = p === '/' ? '/index.html' : p;
    if (rel.includes('..')) { res.writeHead(400); res.end(); return; }
    return serveFile(req, res, join(wwwDir, rel));
}).listen(port, () => console.log(`dev server: http://localhost:${port}/recordings.html  (recordings from ${recDir})`));
