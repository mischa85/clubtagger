/*
 * timeline.js - waveform timeline for recorded segments
 *
 * One canvas row per channel plus a shared time ruler. Draws the peaks from
 * the ".peaks" sidecars, session/gap structure, the selection, an audition
 * playhead and the "now" line. Handles zoom (wheel), pan (shift-wheel, middle
 * drag, ruler drag), drag-selection snapped to segment boundaries, click to
 * audition and double-click to fit a session.
 *
 * Data model (set with setChannels):
 *   channel: { id, segments: [seg], sessions: [{ i0, i1, startMs, endMs }] }
 *   seg:     { name, startMs, durMs, peaks: { pps, count, env: Uint16Array } | null,
 *              session: index, estimated: bool }
 */
export class Timeline {
    constructor(root, opts = {}) {
        this.root = root;
        this.opts = opts;                      // { formatTime(ms, withSeconds), onSelect(sel), onSelecting(sel), onAudition(channelId, seg), onViewChange(view) }
        this.channels = [];
        this.view = { startMs: 0, endMs: 1 };
        this.limits = { startMs: 0, endMs: 1 };
        this.selection = null;                 // { channel, i0, i1 }
        this.playhead = null;                  // { channel, ms }
        this.nowMs = null;
        this.joinGaps = false;
        this.rows = new Map();                 // channelId -> { wrap, canvas, ctx, label }
        this.drag = null;
        this.raf = 0;
        this.rowHeight = opts.rowHeight || 96;

        this.root.classList.add('tl');
        this.ruler = document.createElement('canvas');
        this.ruler.className = 'tl-ruler';
        this.root.appendChild(this.ruler);
        this.rowsEl = document.createElement('div');
        this.rowsEl.className = 'tl-rows';
        this.root.appendChild(this.rowsEl);

        this.ro = new ResizeObserver(() => this.render());
        this.ro.observe(this.root);
        this.bindRuler();
    }

    /* ─────────── data / view ─────────── */

    setChannels(channels) {
        this.channels = channels;
        const ids = new Set(channels.map((c) => c.id));
        for (const [id, row] of this.rows) if (!ids.has(id)) { row.wrap.remove(); this.rows.delete(id); }
        for (const c of channels) if (!this.rows.has(c.id)) this.addRow(c.id);
        // keep DOM order = channel order
        for (const c of channels) this.rowsEl.appendChild(this.rows.get(c.id).wrap);
        this.render();
    }

    setLimits(startMs, endMs) { this.limits = { startMs, endMs }; }

    setView(startMs, endMs, silent = false) {
        const minSpan = 30 * 1000, maxSpan = this.limits.endMs - this.limits.startMs;
        let span = Math.min(Math.max(endMs - startMs, minSpan), maxSpan);
        if (startMs < this.limits.startMs) startMs = this.limits.startMs;
        if (startMs + span > this.limits.endMs) startMs = this.limits.endMs - span;
        this.view = { startMs, endMs: startMs + span };
        if (!silent && this.opts.onViewChange) this.opts.onViewChange(this.view);
        this.render();
    }

    fit(startMs, endMs, padFrac = 0.03) {
        const pad = Math.max((endMs - startMs) * padFrac, 15000);
        this.setView(startMs - pad, endMs + pad);
    }

    setSelection(sel) { this.selection = sel; this.render(); }
    setPlayhead(ph) { this.playhead = ph; this.render(); }
    setNow(ms) { this.nowMs = ms; this.render(); }

    /* ─────────── geometry ─────────── */

    x(ms) { return (ms - this.view.startMs) / (this.view.endMs - this.view.startMs) * this.width; }
    t(x) { return this.view.startMs + x / this.width * (this.view.endMs - this.view.startMs); }
    get width() { return this.root.clientWidth || 800; }

    channel(id) { return this.channels.find((c) => c.id === id); }

    segmentAt(ch, ms) {
        return ch.segments.findIndex((s) => ms >= s.startMs && ms < s.startMs + s.durMs);
    }

    /* Nearest segment to a time (for snapping when the pointer is in a gap). */
    nearestSegment(ch, ms) {
        let best = -1, bestD = Infinity;
        ch.segments.forEach((s, i) => {
            const d = ms < s.startMs ? s.startMs - ms : ms >= s.startMs + s.durMs ? ms - (s.startMs + s.durMs) : 0;
            if (d < bestD) { bestD = d; best = i; }
        });
        return best;
    }

    /* Snap a dragged time range to segment indices, clamped to the anchor's session unless joinGaps. */
    snap(ch, anchorMs, otherMs) {
        const a = this.nearestSegment(ch, anchorMs);
        if (a < 0) return null;
        let b = this.nearestSegment(ch, otherMs);
        if (b < 0) b = a;
        let i0 = Math.min(a, b), i1 = Math.max(a, b);
        if (!this.joinGaps) {
            const sess = ch.sessions[ch.segments[a].session];
            i0 = Math.max(i0, sess.i0);
            i1 = Math.min(i1, sess.i1);
        }
        return { channel: ch.id, i0, i1 };
    }

    /* ─────────── DOM rows ─────────── */

    addRow(id) {
        const wrap = document.createElement('div');
        wrap.className = 'tl-row';
        const label = document.createElement('div');
        label.className = 'tl-label';
        label.textContent = id;
        const canvas = document.createElement('canvas');
        canvas.className = 'tl-canvas';
        canvas.style.height = this.rowHeight + 'px';
        wrap.appendChild(label);
        wrap.appendChild(canvas);
        this.rowsEl.appendChild(wrap);
        const row = { wrap, canvas, ctx: canvas.getContext('2d'), label, id };
        this.rows.set(id, row);
        this.bindRow(row);
    }

    /* Which selection edge (if any) is under x on this channel: 'start', 'end' or null. */
    edgeAt(channelId, x) {
        const sel = this.selection;
        if (!sel || sel.channel !== channelId) return null;
        const ch = this.channel(channelId);
        const a = ch && ch.segments[sel.i0], b = ch && ch.segments[sel.i1];
        if (!a || !b) return null;
        const x0 = this.x(a.startMs), x1 = this.x(b.startMs + b.durMs);
        const grab = 7;
        if (Math.abs(x - x1) <= grab) return 'end';
        if (Math.abs(x - x0) <= grab) return 'start';
        return null;
    }

    /* Move one edge of the selection to the segment nearest to `ms`. */
    moveEdge(ch, which, ms) {
        const sel = this.selection;
        let idx = this.nearestSegment(ch, ms);
        if (idx < 0) return;
        if (!this.joinGaps) {
            const fixed = ch.segments[which === 'start' ? sel.i1 : sel.i0];
            const sess = ch.sessions[fixed.session];
            idx = Math.min(Math.max(idx, sess.i0), sess.i1);
        }
        if (which === 'start') this.selection = { channel: ch.id, i0: Math.min(idx, sel.i1), i1: sel.i1 };
        else this.selection = { channel: ch.id, i0: sel.i0, i1: Math.max(idx, sel.i0) };
        this.render();
        if (this.opts.onSelecting) this.opts.onSelecting(this.selection);   // live summary while dragging
    }

    bindRow(row) {
        const c = row.canvas;
        c.addEventListener('pointerdown', (e) => {
            if (e.button === 1) { this.startPan(e, c); return; }
            if (e.button !== 0) return;
            const rect = c.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const edge = this.edgeAt(row.id, x);
            if (edge) {
                this.drag = { kind: 'edge', channel: row.id, which: edge, moved: false };
            } else {
                this.drag = { kind: 'select', channel: row.id, x0: x, t0: this.t(x), moved: false, shift: e.shiftKey };
            }
            c.setPointerCapture(e.pointerId);
        });
        c.addEventListener('pointermove', (e) => {
            const rect = c.getBoundingClientRect();
            const x = e.clientX - rect.left;
            if (!this.drag) {
                c.style.cursor = this.edgeAt(row.id, x) ? 'col-resize' : 'crosshair';
                return;
            }
            if (this.drag.channel !== row.id) return;
            const ch = this.channel(row.id);
            if (!ch) return;
            if (this.drag.kind === 'edge') {
                this.drag.moved = true;
                this.moveEdge(ch, this.drag.which, this.t(x));
                return;
            }
            if (this.drag.kind !== 'select') return;
            if (!this.drag.moved && Math.abs(x - this.drag.x0) < 4) return;
            this.drag.moved = true;
            const sel = this.snap(ch, this.drag.t0, this.t(x));
            if (sel) {
                this.selection = sel;
                this.render();
                if (this.opts.onSelecting) this.opts.onSelecting(sel);   // live summary while dragging
            }
        });
        const finish = (e) => {
            if (!this.drag || (this.drag.kind !== 'select' && this.drag.kind !== 'edge')) return;
            const d = this.drag;
            this.drag = null;
            const ch = this.channel(row.id);
            if (!ch) return;
            if (d.kind === 'edge') {
                if (this.opts.onSelect) this.opts.onSelect(this.selection);
            } else if (d.moved) {
                if (this.opts.onSelect) this.opts.onSelect(this.selection);
            } else {
                const i = this.segmentAt(ch, d.t0);
                if (i >= 0 && this.opts.onAudition) this.opts.onAudition(row.id, ch.segments[i], d.t0);
            }
        };
        c.addEventListener('pointerup', finish);
        c.addEventListener('pointercancel', () => { this.drag = null; });
        c.addEventListener('dblclick', (e) => {
            const rect = c.getBoundingClientRect();
            const ms = this.t(e.clientX - rect.left);
            const ch = this.channel(row.id);
            const i = ch ? this.nearestSegment(ch, ms) : -1;
            if (i >= 0) { const s = ch.sessions[ch.segments[i].session]; this.fit(s.startMs, s.endMs); }
        });
        c.addEventListener('wheel', (e) => this.onWheel(e, c), { passive: false });
        c.addEventListener('contextmenu', (e) => e.preventDefault());
    }

    bindRuler() {
        const r = this.ruler;
        r.addEventListener('pointerdown', (e) => this.startPan(e, r));
        r.addEventListener('wheel', (e) => this.onWheel(e, r), { passive: false });
    }

    startPan(e, el) {
        e.preventDefault();
        const start = { x: e.clientX, view: { ...this.view } };
        const span = this.view.endMs - this.view.startMs;
        const move = (ev) => {
            const dx = ev.clientX - start.x;
            const dt = -dx / this.width * span;
            this.setView(start.view.startMs + dt, start.view.endMs + dt);
        };
        const up = () => { el.removeEventListener('pointermove', move); el.removeEventListener('pointerup', up); el.removeEventListener('pointercancel', up); };
        el.setPointerCapture(e.pointerId);
        el.addEventListener('pointermove', move);
        el.addEventListener('pointerup', up);
        el.addEventListener('pointercancel', up);
    }

    onWheel(e, el) {
        e.preventDefault();
        const span = this.view.endMs - this.view.startMs;
        if (e.shiftKey || (Math.abs(e.deltaX) > Math.abs(e.deltaY))) {
            const d = (e.shiftKey ? e.deltaY : e.deltaX) / this.width * span;
            this.setView(this.view.startMs + d, this.view.endMs + d);
            return;
        }
        const rect = el.getBoundingClientRect();
        const x = e.clientX - rect.left;
        const t = this.t(x);
        const factor = Math.exp(e.deltaY * 0.0015);
        const newSpan = span * factor;
        const frac = x / this.width;
        this.setView(t - newSpan * frac, t + newSpan * (1 - frac));
    }

    /* ─────────── rendering ─────────── */

    render() {
        if (this.raf) return;
        this.raf = requestAnimationFrame(() => { this.raf = 0; this.draw(); });
    }

    sizeCanvas(canvas, h) {
        const dpr = window.devicePixelRatio || 1;
        const w = this.width;
        if (canvas.width !== Math.round(w * dpr) || canvas.height !== Math.round(h * dpr)) {
            canvas.width = Math.round(w * dpr);
            canvas.height = Math.round(h * dpr);
        }
        canvas.style.width = w + 'px';
        canvas.style.height = h + 'px';
        const ctx = canvas.getContext('2d');
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        return ctx;
    }

    css(name) { return getComputedStyle(this.root).getPropertyValue(name).trim() || undefined; }

    draw() {
        const W = this.width;
        const colors = {
            bg: this.css('--bg-card') || '#0f0f1a',
            session: this.css('--bg-inset') || '#1a1a2e',
            wave: this.css('--tl-wave') || '#00d4ff',
            waveDim: this.css('--tl-wave-dim') || '#0a7fa0',
            sel: this.css('--tl-sel') || 'rgba(0, 212, 255, 0.22)',
            selEdge: this.css('--tl-sel-edge') || '#00d4ff',
            text: this.css('--text-dim') || '#aaa',
            faint: this.css('--text-faint') || '#666',
            grid: this.css('--border-soft') || '#2a2a3e',
            play: this.css('--tl-play') || '#ffcc00',
            now: this.css('--tl-now') || '#f44336',
            hatch: this.css('--text-faintest') || '#445',
        };
        this.drawRuler(W, colors);
        for (const ch of this.channels) {
            const row = this.rows.get(ch.id);
            if (row) this.drawRow(row, ch, W, colors);
        }
    }

    tickStep() {
        const span = this.view.endMs - this.view.startMs;
        const steps = [10e3, 30e3, 60e3, 5 * 60e3, 10 * 60e3, 15 * 60e3, 30 * 60e3, 3600e3, 2 * 3600e3, 3 * 3600e3, 6 * 3600e3, 12 * 3600e3];
        for (const s of steps) if (s / span * this.width >= 80) return s;
        return steps[steps.length - 1];
    }

    drawRuler(W, colors) {
        const H = 22;
        const ctx = this.sizeCanvas(this.ruler, H);
        ctx.clearRect(0, 0, W, H);
        ctx.fillStyle = colors.bg;
        ctx.fillRect(0, 0, W, H);
        const step = this.tickStep();
        const fmt = this.opts.formatTime || ((ms) => new Date(ms).toISOString().slice(11, 16));
        const offset = this.opts.tzOffsetMs ? this.opts.tzOffsetMs(this.view.startMs) : 0;
        // ticks aligned to local wall-clock multiples of step
        let t = Math.floor((this.view.startMs + offset) / step) * step - offset;
        ctx.font = '11px -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';
        ctx.textBaseline = 'middle';
        ctx.fillStyle = colors.text;
        ctx.strokeStyle = colors.grid;
        for (; t <= this.view.endMs; t += step) {
            const x = Math.round(this.x(t)) + 0.5;
            ctx.beginPath(); ctx.moveTo(x, H - 6); ctx.lineTo(x, H); ctx.stroke();
            ctx.fillText(fmt(t, step < 60e3), x + 3, H / 2);
        }
    }

    drawRow(row, ch, W, colors) {
        const H = this.rowHeight;
        const ctx = this.sizeCanvas(row.canvas, H);
        ctx.clearRect(0, 0, W, H);
        ctx.fillStyle = colors.bg;
        ctx.fillRect(0, 0, W, H);
        const mid = H / 2;
        const vs = this.view.startMs, ve = this.view.endMs;
        const pxPerMs = W / (ve - vs);

        // sessions and gap labels
        ctx.fillStyle = colors.session;
        for (const s of ch.sessions) {
            const x0 = Math.max(0, this.x(s.startMs)), x1 = Math.min(W, this.x(s.endMs));
            if (x1 > x0) ctx.fillRect(x0, 0, x1 - x0, H);
        }
        ctx.fillStyle = colors.faint;
        ctx.font = '11px -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        for (let i = 1; i < ch.sessions.length; i++) {
            const gs = ch.sessions[i - 1].endMs, ge = ch.sessions[i].startMs;
            const x0 = this.x(gs), x1 = this.x(ge);
            const vx0 = Math.max(70, x0), vx1 = Math.min(W, x1);   // 70: leave room for the channel label
            if (vx1 - vx0 > 60) {
                ctx.fillText(fmtDur(ge - gs) + ' gap', (vx0 + vx1) / 2, mid);
            }
        }
        ctx.textAlign = 'left';

        // waveform: sweep points into per-pixel max columns
        const cols = new Float32Array(W);
        const hasPeaks = new Uint8Array(W);
        const segOfCol = new Int32Array(W).fill(-1);
        ch.segments.forEach((seg, si) => {
            const s0 = seg.startMs, s1 = seg.startMs + seg.durMs;
            if (s1 < vs || s0 > ve) return;
            const xa = Math.max(0, Math.floor(this.x(s0))), xb = Math.min(W - 1, Math.ceil(this.x(s1)));
            for (let x = xa; x <= xb; x++) segOfCol[x] = si;
            if (!seg.peaks) return;
            const p = seg.peaks;
            const msPerPoint = 1000 / p.pps;
            // visible point range
            let pa = Math.max(0, Math.floor((vs - s0) / msPerPoint)), pb = Math.min(p.count - 1, Math.ceil((ve - s0) / msPerPoint));
            for (let k = pa; k <= pb; k++) {
                const t0 = s0 + k * msPerPoint;
                let x0 = Math.floor((t0 - vs) * pxPerMs), x1 = Math.floor((t0 + msPerPoint - vs) * pxPerMs);
                if (x1 < 0 || x0 >= W) continue;
                if (x0 < 0) x0 = 0;
                if (x1 >= W) x1 = W - 1;
                const v = p.env[k] / 32768;
                for (let x = x0; x <= x1; x++) { if (v > cols[x]) cols[x] = v; hasPeaks[x] = 1; }
            }
        });
        // draw columns; alternate shade per segment for visible boundaries
        for (let x = 0; x < W; x++) {
            if (segOfCol[x] < 0) continue;
            if (!hasPeaks[x]) {
                // no sidecar: hatched placeholder
                if (((x >> 2) & 1) === 0) { ctx.fillStyle = colors.hatch; ctx.fillRect(x, mid - H * 0.2, 1, H * 0.4); }
                continue;
            }
            const h = Math.max(1, cols[x] * (H * 0.46));
            ctx.fillStyle = (segOfCol[x] & 1) ? colors.waveDim : colors.wave;
            ctx.fillRect(x, mid - h, 1, h * 2);
        }

        // selection
        if (this.selection && this.selection.channel === ch.id) {
            const a = ch.segments[this.selection.i0], b = ch.segments[this.selection.i1];
            if (a && b) {
                const x0 = this.x(a.startMs), x1 = this.x(b.startMs + b.durMs);
                ctx.fillStyle = colors.sel;
                ctx.fillRect(x0, 0, x1 - x0, H);
                ctx.fillStyle = colors.selEdge;
                ctx.fillRect(Math.round(x0), 0, 2, H);
                ctx.fillRect(Math.round(x1) - 2, 0, 2, H);
            }
        }
        // playhead
        if (this.playhead && this.playhead.channel === ch.id) {
            const x = Math.round(this.x(this.playhead.ms)) + 0.5;
            ctx.strokeStyle = colors.play; ctx.lineWidth = 1.5;
            ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, H); ctx.stroke();
        }
        // now
        if (this.nowMs && this.nowMs >= vs && this.nowMs <= ve) {
            const x = Math.round(this.x(this.nowMs)) + 0.5;
            ctx.strokeStyle = colors.now; ctx.lineWidth = 1;
            ctx.setLineDash([3, 3]);
            ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, H); ctx.stroke();
            ctx.setLineDash([]);
        }
    }
}

export function fmtDur(ms) {
    const s = Math.round(ms / 1000);
    const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
    if (h) return `${h}h${String(m).padStart(2, '0')}m`;
    if (m) return sec ? `${m}m${String(sec).padStart(2, '0')}s` : `${m}m`;
    return `${sec}s`;
}
