#!/usr/bin/env node
/*
 * recordings-proxy.mjs - run the recordings browser on another machine
 *
 * Serves www/ on http://localhost and forwards the data requests to the
 * clubtagger device: FLAC files over plain HTTP (no TLS work for the Atom or
 * for this machine), the directory listing and the .peaks sidecars over HTTPS.
 * The browser sees a single localhost origin, which is a secure context, so
 * the File System Access API used by the export works and nothing is
 * cross-origin or mixed content.
 *
 *   CLUBTAGGER_HTTPS=https://antia.duckdns.org:20124 \
 *   CLUBTAGGER_HTTP=http://antia.duckdns.org:20180 \
 *   CLUBTAGGER_AUTH=robbie:secret \
 *   node tools/recordings-proxy.mjs [port]            # default 8080, binds 127.0.0.1
 *
 * Then open http://localhost:8080/recordings.html. Set CLUBTAGGER_BIND=0.0.0.0
 * to serve other machines too (they lose the export: not a secure context).
 * The device's certificate is self-signed; it is accepted without verification.
 */
import { createServer, request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { stat } from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import { join, extname, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HTTPS = (process.env.CLUBTAGGER_HTTPS || '').replace(/\/$/, '');
const HTTP = (process.env.CLUBTAGGER_HTTP || '').replace(/\/$/, '');
const AUTH = process.env.CLUBTAGGER_AUTH || '';
const BIND = process.env.CLUBTAGGER_BIND || '127.0.0.1';
const PORT = +(process.argv[2] || process.env.PORT || 8080);
if (!HTTPS) { console.error('CLUBTAGGER_HTTPS is required (e.g. https://antia.duckdns.org:20124)'); process.exit(2); }
const wwwDir = resolve(dirname(fileURLToPath(import.meta.url)), '../www');
const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.woff2': 'font/woff2' };
const authHeader = AUTH ? 'Basic ' + Buffer.from(AUTH).toString('base64') : null;
const PASS_REQ = ['range', 'if-none-match', 'if-modified-since', 'accept-encoding'];
const PASS_RES = ['content-type', 'content-length', 'content-range', 'accept-ranges', 'last-modified', 'etag',
                  'cache-control', 'content-encoding', 'vary'];

function proxy(req, res, base, path) {
    const url = new URL(base + path);
    const mod = url.protocol === 'https:' ? httpsRequest : httpRequest;
    const headers = {};
    for (const h of PASS_REQ) if (req.headers[h]) headers[h] = req.headers[h];
    if (authHeader) headers.authorization = authHeader;
    const up = mod(url, { method: req.method, headers, rejectUnauthorized: false }, (upRes) => {
        const out = {};
        for (const h of PASS_RES) if (upRes.headers[h]) out[h] = upRes.headers[h];
        res.writeHead(upRes.statusCode, out);
        upRes.pipe(res);
    });
    up.on('error', (e) => {
        if (!res.headersSent) { res.writeHead(502, { 'Content-Type': 'text/plain' }); res.end('upstream error: ' + e.message); }
        else res.destroy();
    });
    res.on('close', () => up.destroy());
    req.pipe(up);
}

async function serveStatic(req, res, path) {
    let st;
    try { st = await stat(path); } catch { res.writeHead(404); res.end('not found'); return; }
    if (!st.isFile()) { res.writeHead(404); res.end('not found'); return; }
    res.writeHead(200, { 'Content-Type': types[extname(path)] || 'application/octet-stream', 'Content-Length': st.size, 'Cache-Control': 'no-cache' });
    if (req.method === 'HEAD') { res.end(); return; }
    const s = createReadStream(path);
    s.on('error', () => res.destroy());
    res.on('close', () => s.destroy());
    s.pipe(res);
}

createServer((req, res) => {
    const p = decodeURIComponent(new URL(req.url, 'http://x').pathname);
    if (p === '/recordings-json/' || p === '/recordings-json') return proxy(req, res, HTTPS, '/recordings-json/');
    if (p.startsWith('/recordings/')) {
        const name = p.slice('/recordings/'.length);
        if (name.includes('/') || name.startsWith('.')) { res.writeHead(404); res.end(); return; }
        // audio over plain HTTP when configured, everything else over HTTPS
        const base = (name.endsWith('.flac') && HTTP) ? HTTP : HTTPS;
        return proxy(req, res, base, '/recordings/' + encodeURIComponent(name));
    }
    const rel = p === '/' ? '/recordings.html' : p;
    if (rel.includes('..')) { res.writeHead(400); res.end(); return; }
    return serveStatic(req, res, join(wwwDir, rel));
}).listen(PORT, BIND, () => {
    console.log(`recordings proxy on http://${BIND === '0.0.0.0' ? 'localhost' : BIND}:${PORT}/recordings.html`);
    console.log(`  listing + sidecars via ${HTTPS}`);
    console.log(`  FLAC audio via ${HTTP || HTTPS + ' (set CLUBTAGGER_HTTP for plain HTTP)'}`);
    console.log(`  auth: ${AUTH ? AUTH.split(':')[0] : 'none'}`);
});
