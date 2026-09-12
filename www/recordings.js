/*
 * recordings.js - browse recorded segments by date and export a set as one FLAC
 *
 * Everything runs in the browser: the directory listing comes from nginx's
 * JSON autoindex, the waveform from the ".peaks" sidecars the recorder writes,
 * and the export is a byte-level splice of the selected segments streamed to
 * a file the user picks (File System Access API, Chrome/Edge).
 */
import { Timeline, fmtDur } from './timeline.js';

const TZ = 'Europe/Amsterdam';           // the recorder's zone: filenames are local time there
const LISTING_URL = '/recordings-json/';
const FILE_BASE = '/recordings/';
const HIDDEN_BY_DEFAULT = new Set(['master']);
const SEGMENT_SEC = 120;                  // recorder default --max-file-sec, used when no sidecar
const MOCK = new URLSearchParams(location.search).has('mock');
const DEBUG = new URLSearchParams(location.search).has('debug');   // logs every chaining decision

/* ─────────────────── time zone helpers ─────────────────── */

const dtf = new Intl.DateTimeFormat('en-US', {
    timeZone: TZ, hourCycle: 'h23', year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
});
function tzParts(ms) {
    const p = {};
    for (const { type, value } of dtf.formatToParts(new Date(ms))) p[type] = value;
    return { y: +p.year, m: +p.month, d: +p.day, h: +p.hour, mi: +p.minute, s: +p.second };
}
function tzOffsetMs(ms) {
    const p = tzParts(ms);
    return Date.UTC(p.y, p.m - 1, p.d, p.h, p.mi, p.s) - Math.floor(ms / 1000) * 1000;
}
/* Wall clock in TZ -> unix ms (two-pass to survive DST transitions). */
function zonedToUtc(y, m, d, h = 0, mi = 0, s = 0) {
    const guess = Date.UTC(y, m - 1, d, h, mi, s);
    let off = tzOffsetMs(guess - tzOffsetMs(guess));
    return guess - off;
}
const pad2 = (n) => String(n).padStart(2, '0');
function fmtTime(ms, withSeconds = false) {
    const p = tzParts(ms);
    return `${pad2(p.h)}:${pad2(p.mi)}` + (withSeconds ? `:${pad2(p.s)}` : '');
}
function dateKey(ms) { const p = tzParts(ms); return `${p.y}-${pad2(p.m)}-${pad2(p.d)}`; }
function isoWithOffset(ms) {
    const p = tzParts(ms), off = tzOffsetMs(ms) / 60000, sign = off >= 0 ? '+' : '-';
    return `${p.y}-${pad2(p.m)}-${pad2(p.d)}T${pad2(p.h)}:${pad2(p.mi)}:${pad2(p.s)}${sign}${pad2(Math.floor(Math.abs(off) / 60))}:${pad2(Math.abs(off) % 60)}`;
}
function shiftDate(key, days) {
    const [y, m, d] = key.split('-').map(Number);
    const t = Date.UTC(y, m - 1, d + days);
    const x = new Date(t);
    return `${x.getUTCFullYear()}-${pad2(x.getUTCMonth() + 1)}-${pad2(x.getUTCDate())}`;
}
function fmtBytes(b) {
    if (b >= 1e9) return (b / 1e9).toFixed(2) + ' GB';
    if (b >= 1e6) return (b / 1e6).toFixed(0) + ' MB';
    return (b / 1e3).toFixed(0) + ' kB';
}

/* ─────────────────── listing ─────────────────── */

const NAME_RE = /^(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})_(.+)_([^_.]+)\.(flac|peaks)$/;
function parseName(name) {
    const m = NAME_RE.exec(name);
    if (!m) return null;
    const [, y, mo, d, h, mi, s, prefix, channel, ext] = m;
    return { y: +y, mo: +mo, d: +d, h: +h, mi: +mi, s: +s, prefix, channel, ext,
             base: name.slice(0, -(ext.length + 1)), nameMs: zonedToUtc(+y, +mo, +d, +h, +mi, +s) };
}

async function fetchListing() {
    if (MOCK) return mockListing();
    const r = await fetch(LISTING_URL, { cache: 'no-store' });
    if (!r.ok) throw new Error(`listing failed: HTTP ${r.status}`);
    return r.json();
}

/* ─────────────────── sidecars ─────────────────── */

function parsePeaks(buf) {
    const dv = new DataView(buf);
    if (buf.byteLength < 56 || String.fromCharCode(dv.getUint8(0), dv.getUint8(1), dv.getUint8(2), dv.getUint8(3)) !== 'CTPK') {
        throw new Error('not a peaks sidecar');
    }
    const headerSize = dv.getUint16(6, true);
    const p = {
        version: dv.getUint16(4, true),
        rate: dv.getUint32(8, true),
        channels: dv.getUint16(12, true),
        bps: dv.getUint16(14, true),
        total: Number(dv.getBigUint64(16, true)),
        cursor: Number(dv.getBigUint64(24, true)),
        startMs: Number(dv.getBigInt64(32, true)),
        runId: dv.getUint32(40, true),
        pps: dv.getUint32(44, true),
        count: dv.getUint32(48, true),
    };
    const vals = new Int16Array(buf, headerSize, p.count * p.channels * 2);
    const env = new Uint16Array(p.count);
    for (let k = 0; k < p.count; k++) {
        let m = 0;
        for (let c = 0; c < p.channels; c++) {
            const mn = -vals[(k * p.channels + c) * 2], mx = vals[(k * p.channels + c) * 2 + 1];
            if (mn > m) m = mn;
            if (mx > m) m = mx;
        }
        env[k] = Math.min(32767, m);
    }
    p.env = env;
    return p;
}

const peaksCache = new Map();
async function loadPeaks(seg) {
    if (peaksCache.has(seg.name)) return peaksCache.get(seg.name);
    let p;
    if (MOCK) p = mockPeaks(seg);
    else {
        const r = await fetch(FILE_BASE + seg.base + '.peaks');
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        p = parsePeaks(await r.arrayBuffer());
    }
    peaksCache.set(seg.name, p);
    return p;
}

async function pool(items, n, fn) {
    let i = 0;
    const workers = new Array(Math.min(n, items.length)).fill(0).map(async () => {
        while (i < items.length) { const it = items[i++]; await fn(it); }
    });
    await Promise.all(workers);
}

/* ─────────────────── model ─────────────────── */

const state = {
    date: null,                 // 'YYYY-MM-DD'
    windowStart: 0, windowEnd: 0,
    channels: new Map(),        // id -> { id, segments, sessions, visible }
    selection: null,
    exporting: null,
    listingEpoch: 0,
};

function buildModel(listing) {
    const D = state.date;
    const [y, m, d] = D.split('-').map(Number);
    state.windowStart = zonedToUtc(y, m, d, 0, 0, 0);
    const n = shiftDate(D, 1).split('-').map(Number);
    state.windowEnd = zonedToUtc(n[0], n[1], n[2], 12, 0, 0);

    const havePeaks = new Set();
    const flacs = [];
    for (const e of listing) {
        if (e.type && e.type !== 'file') continue;
        const pn = parseName(e.name);
        if (!pn) continue;
        if (pn.ext === 'peaks') { havePeaks.add(pn.base); continue; }
        if (pn.nameMs < state.windowStart || pn.nameMs >= state.windowEnd) continue;
        flacs.push({ name: e.name, base: pn.base, channel: pn.channel, nameMs: pn.nameMs, size: e.size || 0 });
    }
    const prev = state.channels;
    const channels = new Map();
    for (const f of flacs) {
        if (!channels.has(f.channel)) {
            channels.set(f.channel, { id: f.channel, segments: [], sessions: [],
                                      visible: prev.has(f.channel) ? prev.get(f.channel).visible : !HIDDEN_BY_DEFAULT.has(f.channel) });
        }
        const seg = { ...f, hasSidecar: havePeaks.has(f.base), peaks: peaksCache.get(f.name) || null,
                      startMs: f.nameMs, durMs: SEGMENT_SEC * 1000, estimated: true, session: 0 };
        channels.get(f.channel).segments.push(seg);
    }
    for (const ch of channels.values()) ch.segments.sort((a, b) => a.nameMs - b.nameMs);
    state.channels = channels;
}

/* Place segments in time and group them into sessions. */
function chain(ch) {
    const segs = ch.segments;
    // the full-segment length: mode of total_samples over segments with sidecars
    const counts = new Map();
    let rate = 0;
    for (const s of segs) if (s.peaks) { counts.set(s.peaks.total, (counts.get(s.peaks.total) || 0) + 1); rate = s.peaks.rate; }
    let fullSamples = 0, best = 0;
    for (const [t, c] of counts) if (c > best) { best = c; fullSamples = t; }
    const fullMs = rate && fullSamples ? fullSamples / rate * 1000 : SEGMENT_SEC * 1000;

    ch.sessions = [];
    let prev = null;
    segs.forEach((s, i) => {
        s.durMs = s.peaks ? s.peaks.total / s.peaks.rate * 1000 : fullMs;
        s.estimated = !s.peaks;
        let continuous = false, rule = 'new session';
        if (prev) {
            const expected = prev.startMs + prev.durMs;
            const drift = s.nameMs - expected;
            if (s.peaks && prev.peaks && s.peaks.runId && s.peaks.runId === prev.peaks.runId &&
                s.peaks.cursor === prev.peaks.cursor + prev.peaks.total) {
                continuous = true; rule = 'cursor';                  // proven by the recorder's cursor
            } else if (s.peaks && prev.peaks && s.peaks.runId && s.peaks.runId === prev.peaks.runId) {
                rule = 'cursor break';                               // same run, samples missing in between
            } else if (drift >= -5000 && drift <= 90000) {
                // No cursor data (recordings older than the sidecars, or a recorder restart):
                // the filename cadence decides. The window absorbs the old writer's 60 s late
                // name on the 2nd file of a recording and a first segment shortened by a few
                // thousand lost frames at the trigger. Old recordings resumed sample-continuous
                // after short silences, so a short name gap is a continuation, not a new session.
                continuous = true; rule = 'cadence';
            }
            if (continuous) s.startMs = expected;
            if (DEBUG) console.log(`[chain ${ch.id}] ${s.name} ${rule} drift=${(drift / 1000).toFixed(1)}s` +
                                   ` prev.total=${prev.peaks ? prev.peaks.total : '?'} total=${s.peaks ? s.peaks.total : '?'}` +
                                   ` run=${s.peaks ? s.peaks.runId : '?'} cursor=${s.peaks ? s.peaks.cursor : '?'}`);
        } else if (DEBUG) {
            console.log(`[chain ${ch.id}] ${s.name} first segment`);
        }
        if (!continuous) {
            // The sidecar's wall clock is exact; the filename is second-resolution.
            // They should agree to within a second — if they do not, the sidecar
            // is from a different clock (or a test file) and the name wins.
            const own = s.peaks && s.peaks.startMs && Math.abs(s.peaks.startMs - s.nameMs) < 3600e3 ? s.peaks.startMs : s.nameMs;
            s.startMs = own;
        }
        // an estimated duration must not overlap the next file
        if (s.estimated && i + 1 < segs.length) {
            const nextMs = segs[i + 1].peaks && segs[i + 1].peaks.startMs ? segs[i + 1].peaks.startMs : segs[i + 1].nameMs;
            if (nextMs > s.startMs && nextMs - s.startMs < s.durMs) s.durMs = nextMs - s.startMs;
        }
        if (!continuous || !ch.sessions.length) {
            ch.sessions.push({ i0: i, i1: i, startMs: s.startMs, endMs: s.startMs + s.durMs });
        } else {
            const sess = ch.sessions[ch.sessions.length - 1];
            sess.i1 = i;
            sess.endMs = s.startMs + s.durMs;
        }
        s.session = ch.sessions.length - 1;
        prev = s;
    });
}

/* ─────────────────── UI ─────────────────── */

const $ = (id) => document.getElementById(id);
const el = {
    date: $('date'), prev: $('prev'), next: $('next'), today: $('today'),
    channels: $('channels'), fit: $('fit'), whole: $('whole'),
    status: $('status'), summary: $('summary'), joingaps: $('joingaps'),
    exportBtn: $('export'), cancelBtn: $('cancel'), progress: $('progress'),
    progressFill: $('progress-fill'), progressText: $('progress-text'), result: $('result'),
    audio: $('audio'), auditionLabel: $('audition-label'), timeline: $('timeline'),
};

const timeline = new Timeline(el.timeline, {
    formatTime: fmtTime,
    tzOffsetMs,
    onSelect: (sel) => { state.selection = sel; renderSummary(); },
    onAudition: audition,
});

function setStatus(text, kind = '') {
    el.status.textContent = text || '';
    el.status.className = 'notice ' + kind;
    el.status.hidden = !text;
}

function visibleChannels() {
    return [...state.channels.values()].filter((c) => c.visible);
}

function renderChannelToggles() {
    el.channels.innerHTML = '';
    const ids = [...state.channels.keys()].sort();
    for (const id of ids) {
        const ch = state.channels.get(id);
        const lab = document.createElement('label');
        const cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.checked = ch.visible;
        cb.addEventListener('change', () => {
            ch.visible = cb.checked;
            if (state.selection && state.selection.channel === id && !ch.visible) { state.selection = null; timeline.setSelection(null); renderSummary(); }
            pushToTimeline();
            if (ch.visible) loadSidecars([ch]);
        });
        lab.appendChild(cb);
        lab.appendChild(document.createTextNode(` ${id} (${ch.segments.length})`));
        el.channels.appendChild(lab);
    }
}

function pushToTimeline() {
    for (const ch of state.channels.values()) chain(ch);
    timeline.setLimits(state.windowStart, state.windowEnd);
    timeline.setChannels(visibleChannels());
    timeline.setSelection(state.selection);
    const now = Date.now();
    timeline.setNow(now >= state.windowStart && now <= state.windowEnd ? now : null);
}

function extent() {
    let a = Infinity, b = -Infinity;
    for (const ch of visibleChannels()) for (const s of ch.sessions) { a = Math.min(a, s.startMs); b = Math.max(b, s.endMs); }
    if (a === Infinity) return null;
    return { startMs: a, endMs: b };
}

function fitAll() {
    const e = extent();
    if (e) timeline.fit(e.startMs, e.endMs);
    else timeline.setView(state.windowStart, state.windowEnd);
}

function renderSummary() {
    const sel = state.selection;
    const ch = sel && state.channels.get(sel.channel);
    if (!sel || !ch) {
        el.summary.textContent = 'Drag on a waveform to select the range to export. Click a segment to listen to it. Scroll to zoom, shift-scroll to pan.';
        el.exportBtn.disabled = true;
        return;
    }
    const segs = ch.segments.slice(sel.i0, sel.i1 + 1);
    const a = segs[0], b = segs[segs.length - 1];
    const startMs = a.startMs, endMs = b.startMs + b.durMs;
    const bytes = segs.reduce((x, s) => x + (s.size || 0), 0);
    const gaps = new Set(segs.map((s) => s.session)).size - 1;
    const noSidecar = segs.filter((s) => !s.peaks).length;
    el.summary.innerHTML =
        `<b>${ch.id}</b> · ${dateKey(startMs)} ${fmtTime(startMs, true)} → ${fmtTime(endMs, true)} · ${fmtDur(endMs - startMs)} · ` +
        `${segs.length} segment${segs.length === 1 ? '' : 's'} · ${fmtBytes(bytes)}` +
        (gaps > 0 ? ` · <span class="warn">${gaps} gap${gaps > 1 ? 's' : ''} removed</span>` : '') +
        (noSidecar ? ` · <span class="warn">${noSidecar} without waveform</span>` : '');
    el.exportBtn.disabled = !!state.exporting || MOCK;
}

/* ─────────────────── loading ─────────────────── */

async function loadSidecars(channels) {
    const todo = [];
    for (const ch of channels) for (const s of ch.segments) if (s.hasSidecar && !s.peaks) todo.push(s);
    if (!todo.length) return;
    const epoch = state.listingEpoch;
    let pending = 0, failed = 0;
    await pool(todo, 6, async (seg) => {
        try {
            const p = await loadPeaks(seg);
            if (epoch !== state.listingEpoch) return;
            seg.peaks = p;
        } catch (e) {
            failed++;
            console.warn('peaks', seg.name, e.message);
        }
        if (++pending % 12 === 0) pushToTimeline();
    });
    if (epoch !== state.listingEpoch) return;
    pushToTimeline();
    renderSummary();
    if (failed) setStatus(`${failed} waveform sidecar${failed > 1 ? 's' : ''} could not be loaded.`, 'warn');
}

let refreshTimer = 0;
async function loadDate(dateStr, { keepView = false } = {}) {
    state.date = dateStr;
    el.date.value = dateStr;
    const url = new URL(location.href);
    url.searchParams.set('date', dateStr);
    history.replaceState(null, '', url);
    state.listingEpoch++;
    if (!keepView) { state.selection = null; timeline.setSelection(null); }
    setStatus('Loading recordings…');
    let listing;
    try {
        listing = await fetchListing();
    } catch (e) {
        setStatus(`Could not load the recordings listing: ${e.message}`, 'error');
        return;
    }
    buildModel(listing);
    renderChannelToggles();
    pushToTimeline();
    if (!keepView) fitAll();
    renderSummary();
    const total = [...state.channels.values()].reduce((n, c) => n + c.segments.length, 0);
    if (!total) setStatus(`No recordings for ${dateStr} (window ${dateStr} 00:00 → ${shiftDate(dateStr, 1)} 12:00).`, 'warn');
    else setStatus('');
    await loadSidecars(visibleChannels());

    clearTimeout(refreshTimer);
    const now = Date.now();
    if (now >= state.windowStart && now <= state.windowEnd) {
        refreshTimer = setTimeout(() => loadDate(state.date, { keepView: true }), 30000);
    }
}

function defaultDate() {
    const p = tzParts(Date.now());
    const today = `${p.y}-${pad2(p.m)}-${pad2(p.d)}`;
    return p.h < 12 ? shiftDate(today, -1) : today;   // early morning still belongs to yesterday's date
}

/* ─────────────────── audition ─────────────────── */

let auditionSeg = null, auditionChannel = null;
function audition(channelId, seg, atMs) {
    auditionSeg = seg;
    auditionChannel = channelId;
    el.auditionLabel.textContent = `${channelId} · ${fmtTime(seg.startMs, true)} · ${seg.name}`;
    if (MOCK) { el.auditionLabel.textContent += ' (mock: no audio)'; return; }
    const offset = Math.max(0, (atMs - seg.startMs) / 1000);
    el.audio.src = FILE_BASE + seg.name;
    el.audio.currentTime = offset;
    el.audio.play().catch(() => {});
}
el.audio.addEventListener('timeupdate', () => {
    if (auditionSeg) timeline.setPlayhead({ channel: auditionChannel, ms: auditionSeg.startMs + el.audio.currentTime * 1000 });
});
el.audio.addEventListener('ended', () => {
    // continue into the next segment of the same session
    const ch = state.channels.get(auditionChannel);
    if (!ch) return;
    const i = ch.segments.indexOf(auditionSeg);
    const next = ch.segments[i + 1];
    if (next && next.session === auditionSeg.session) audition(auditionChannel, next, next.startMs);
    else timeline.setPlayhead(null);
});
el.audio.addEventListener('pause', () => { if (el.audio.ended) timeline.setPlayhead(null); });

/* ─────────────────── export ─────────────────── */

let worker = null;
function getWorker() {
    if (!worker) {
        worker = new Worker('flac-splice.worker.js', { type: 'module' });
        worker.onmessage = onWorkerMessage;
        worker.onerror = (e) => finishExport({ type: 'error', message: e.message || 'worker error' });
    }
    return worker;
}

async function startExport() {
    const sel = state.selection;
    const ch = sel && state.channels.get(sel.channel);
    if (!ch) return;
    if (!window.showSaveFilePicker) {
        showResult('This browser cannot stream a large file to disk. Use Chrome or Edge for the export.', 'error');
        return;
    }
    const segs = ch.segments.slice(sel.i0, sel.i1 + 1);
    const fmts = new Set(segs.filter((s) => s.peaks).map((s) => `${s.peaks.rate}/${s.peaks.channels}/${s.peaks.bps}`));
    if (fmts.size > 1) {
        showResult(`The selected segments have different formats (${[...fmts].join(', ')}); pick a range with one format.`, 'error');
        return;
    }
    const startMs = segs[0].startMs, endMs = segs[segs.length - 1].startMs + segs[segs.length - 1].durMs;
    const suggested = `clubtagger_${ch.id}_${dateKey(startMs)}_${fmtTime(startMs).replace(':', '')}-${fmtTime(endMs).replace(':', '')}.flac`;
    let handle;
    try {
        handle = await window.showSaveFilePicker({
            suggestedName: suggested, id: 'clubtagger-export',
            types: [{ description: 'FLAC audio', accept: { 'audio/flac': ['.flac'] } }],
        });
    } catch (e) {
        if (e.name === 'AbortError') return;     // user closed the dialog
        showResult('Could not open the save dialog: ' + e.message, 'error');
        return;
    }
    const totalBytes = segs.reduce((x, s) => x + (s.size || 0), 0);
    state.exporting = { startedAt: Date.now(), totalBytes, segs: segs.length, name: handle.name };
    el.exportBtn.disabled = true;
    el.cancelBtn.hidden = false;
    el.progress.hidden = false;
    el.result.hidden = true;
    el.progressFill.style.width = '0%';
    el.progressText.textContent = 'Starting…';
    getWorker().postMessage({
        type: 'start', handle, mode: 'auto',
        segments: segs.map((s) => ({ name: s.name, url: FILE_BASE + s.name, totalSamples: s.peaks ? s.peaks.total : undefined, size: s.size })),
        tags: [
            ['TITLE', `${ch.id} ${dateKey(startMs)} ${fmtTime(startMs)}-${fmtTime(endMs)}`],
            ['DATE', dateKey(startMs)],
            ['CLUBTAGGER_CHANNEL', ch.id],
            ['START_TIME', isoWithOffset(startMs)],
            ['END_TIME', isoWithOffset(endMs)],
            ['SEGMENTS', String(segs.length)],
            ['SOURCE_FIRST', segs[0].name],
            ['SOURCE_LAST', segs[segs.length - 1].name],
            ['ENCODER', 'clubtagger-splice 1'],
        ],
    });
}

function onWorkerMessage(ev) {
    const m = ev.data;
    const ex = state.exporting;
    if (!ex) return;
    if (m.type === 'progress') {
        const frac = ex.totalBytes ? Math.min(1, m.bytesIn / ex.totalBytes) : 0;
        const elapsed = (Date.now() - ex.startedAt) / 1000;
        const rate = elapsed > 0 ? m.bytesIn / elapsed : 0;
        const eta = rate > 0 ? (ex.totalBytes - m.bytesIn) / rate : 0;
        el.progressFill.style.width = (frac * 100).toFixed(1) + '%';
        el.progressText.textContent =
            `${(frac * 100).toFixed(0)}% · segment ${Math.min(m.segment + 1, ex.segs)}/${ex.segs} · ${fmtBytes(m.bytesOut)} written · ` +
            `${fmtBytes(rate)}/s` + (eta > 1 ? ` · ${fmtDur(eta * 1000)} left` : '') +
            (frac >= 0.999 ? ' · finalizing…' : '');
        return;
    }
    finishExport(m);
}

function finishExport(m) {
    const ex = state.exporting;
    state.exporting = null;
    el.cancelBtn.hidden = true;
    el.progress.hidden = true;
    renderSummary();
    if (m.type === 'done') {
        const s = m.summary;
        showResult(`Saved ${ex ? ex.name : 'file'}: ${fmtDur(s.totalSamples / s.rate * 1000)}, ${fmtBytes(s.bytesOut)}, ${s.frames} frames, ` +
                   `${s.mode === 'fixed' ? 'fixed' : 'variable'} blocksize (${s.minBlock}–${s.maxBlock}), ${s.seekPoints} seek points.`, 'ok');
    } else if (m.type === 'cancelled') {
        showResult('Export cancelled; nothing was written.', 'warn');
    } else {
        showResult(`Export failed: ${m.message}` + (m.segment ? ` (segment ${m.segment}` + (m.frame !== undefined ? `, frame ${m.frame}` : '') +
                   (m.offset !== undefined ? `, byte ${m.offset}` : '') + ')' : '') + '. No file was written.', 'error');
    }
}

function showResult(text, kind) {
    el.result.textContent = text;
    el.result.className = 'notice ' + kind;
    el.result.hidden = false;
}

window.addEventListener('beforeunload', (e) => {
    if (state.exporting) { e.preventDefault(); e.returnValue = ''; }
});

/* ─────────────────── wiring ─────────────────── */

el.date.addEventListener('change', () => { if (el.date.value) loadDate(el.date.value); });
el.prev.addEventListener('click', () => loadDate(shiftDate(state.date, -1)));
el.next.addEventListener('click', () => loadDate(shiftDate(state.date, 1)));
el.today.addEventListener('click', () => loadDate(defaultDate()));
el.fit.addEventListener('click', fitAll);
el.whole.addEventListener('click', () => timeline.setView(state.windowStart, state.windowEnd));
el.joingaps.addEventListener('change', () => { timeline.joinGaps = el.joingaps.checked; });
el.exportBtn.addEventListener('click', startExport);
el.cancelBtn.addEventListener('click', () => { if (worker) worker.postMessage({ type: 'cancel' }); });
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !state.exporting) { state.selection = null; timeline.setSelection(null); renderSummary(); }
});

/* Theme switcher, same as index.html */
const THEMES = ['default', 'mono', 'stage'];
function applyTheme(name) {
    if (!THEMES.includes(name)) name = 'default';
    document.body.setAttribute('data-theme', name);
    try { localStorage.setItem('theme', name); } catch (e) { /* private mode */ }
    document.querySelectorAll('#theme-switch button').forEach((b) => b.classList.toggle('active', b.dataset.theme === name));
    timeline.render();
}
let savedTheme = 'default';
try { savedTheme = localStorage.getItem('theme') || 'default'; } catch (e) { /* private mode */ }
applyTheme(savedTheme);
document.querySelectorAll('#theme-switch button').forEach((b) => b.addEventListener('click', () => applyTheme(b.dataset.theme)));

/* ─────────────────── mock data (?mock) ─────────────────── */

function mockListing() {
    const D = new URLSearchParams(location.search).get('date') || defaultDate();
    const [y, m, d] = D.split('-').map(Number);
    const out = [];
    const mk = (ms, ch, size) => {
        const p = tzParts(ms);
        const name = `${p.y}${pad2(p.m)}${pad2(p.d)}_${pad2(p.h)}${pad2(p.mi)}${pad2(p.s)}_capture_${ch}.flac`;
        out.push({ name, type: 'file', mtime: new Date(ms).toUTCString(), size });
        out.push({ name: name.replace(/\.flac$/, '.peaks'), type: 'file', mtime: new Date(ms).toUTCString(), size: 9656 });
    };
    // an afternoon session and an evening running past midnight, dj1 + master, dj2 only in the evening
    const sessions = [[15, 10, 0, 95], [20, 16, 45, 340]];
    for (const [h, mi, s, minutes] of sessions) {
        const start = zonedToUtc(y, m, d, h, mi, s);
        for (let k = 0; k < minutes / 2; k++) {
            const ms = start + k * 120000;
            mk(ms, 'dj1', 34e6 + Math.random() * 3e6);
            mk(ms + 13000, 'master', 30e6 + Math.random() * 3e6);
            if (h >= 20 && k > 20) mk(ms + 7000, 'dj2', 33e6 + Math.random() * 3e6);
        }
    }
    return out;
}
function mockPeaks(seg) {
    const rate = 96000, count = 1200;
    const env = new Uint16Array(count);
    let v = 0.4 + Math.random() * 0.3;
    for (let k = 0; k < count; k++) {
        v += (Math.random() - 0.5) * 0.15;
        v = Math.max(0.05, Math.min(0.95, v));
        env[k] = Math.round(v * 32767 * (0.7 + 0.3 * Math.abs(Math.sin(k / 9))));
    }
    return { rate, channels: 2, bps: 24, total: 11520000, cursor: 0, startMs: seg.nameMs, runId: 0, pps: 10, count, env };
}

/* ─────────────────── go ─────────────────── */

loadDate(new URLSearchParams(location.search).get('date') || defaultDate());
