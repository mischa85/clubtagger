// Clubtagger Web UI
(function() {
    'use strict';
    
    // DOM elements
    const vuLeft = document.getElementById('vu-left');
    const vuRight = document.getElementById('vu-right');
    const peakLeft = document.getElementById('peak-left');
    const peakRight = document.getElementById('peak-right');
    const tracksEl = document.getElementById('tracks');
    const statusEl = document.getElementById('status');
    const decksEl = document.getElementById('decks');
    // Recording panel elements
    const statFormat = document.getElementById('stat-format');
    const statRuntime = document.getElementById('stat-runtime');
    const statLost = document.getElementById('stat-lost');
    const statWritten = document.getElementById('stat-written');
    const recStatus = document.getElementById('rec-status');
    // Nerd stats elements
    const statUptime = document.getElementById('stat-uptime');
    const statCdjs = document.getElementById('stat-cdjs');
    const statWs = document.getElementById('stat-ws');
    const statTagged = document.getElementById('stat-tagged');
    const statPkts = document.getElementById('stat-pkts');
    const statShazam = document.getElementById('stat-shazam');
    const statRing = document.getElementById('stat-ring');
    const statLoad = document.getElementById('stat-load');
    const statMem = document.getElementById('stat-mem');
    const statDisk = document.getElementById('stat-disk');
    
    // Slot names
    const SLOTS = { 0: '', 1: 'CD', 2: 'SD', 3: 'USB', 4: 'Link', 6: 'Stream', 9: 'Beatport' };
    
    // Peak hold state
    let peakLVal = 0, peakRVal = 0;
    let peakLDecay = 0, peakRDecay = 0;
    
    // Convert 16-bit value (0-32767) to percentage
    function toPercent(val) {
        // Use logarithmic scale for better visual representation
        if (val === 0) return 0;
        const db = 20 * Math.log10(val / 32767);
        // Map -60dB to 0dB -> 0% to 100%
        const pct = Math.max(0, Math.min(100, (db + 60) / 60 * 100));
        return pct;
    }
    
    // Update VU meters (using mask technique - set mask height to hide gradient)
    function updateVU(left, right) {
        const lPct = toPercent(left);
        const rPct = toPercent(right);
        
        // Mask height is inverse of level (100% mask = 0% visible)
        vuLeft.style.height = (100 - lPct) + '%';
        vuRight.style.height = (100 - rPct) + '%';
        
        // Peak hold with decay
        if (lPct > peakLVal) {
            peakLVal = lPct;
            peakLDecay = 30; // Hold for ~500ms at 60fps
        }
        if (rPct > peakRVal) {
            peakRVal = rPct;
            peakRDecay = 30;
        }
        
        peakLeft.style.bottom = peakLVal + '%';
        peakRight.style.bottom = peakRVal + '%';
    }
    
    // Decay peaks
    function decayPeaks() {
        if (peakLDecay > 0) {
            peakLDecay--;
        } else if (peakLVal > 0) {
            peakLVal = Math.max(0, peakLVal - 2);
            peakLeft.style.bottom = peakLVal + '%';
        }
        
        if (peakRDecay > 0) {
            peakRDecay--;
        } else if (peakRVal > 0) {
            peakRVal = Math.max(0, peakRVal - 2);
            peakRight.style.bottom = peakRVal + '%';
        }
    }
    setInterval(decayPeaks, 16);
    
    // Format runtime seconds
    function formatRuntime(secs) {
        if (secs < 60) return secs + 's';
        if (secs < 3600) return Math.floor(secs/60) + 'm ' + (secs%60) + 's';
        const h = Math.floor(secs/3600);
        const m = Math.floor((secs%3600)/60);
        return h + 'h ' + m + 'm';
    }
    
    // Format milliseconds as m:ss.t (tenths)
    function formatPosMs(ms) {
        const m = Math.floor(ms / 60000);
        const s = Math.floor((ms % 60000) / 1000);
        const t = Math.floor((ms % 1000) / 100);
        return m + ':' + (s < 10 ? '0' : '') + s + '.' + t;
    }
    // Format seconds as m:ss
    function formatPosSec(sec) {
        const m = Math.floor(sec / 60);
        const s = sec % 60;
        return m + ':' + (s < 10 ? '0' : '') + s;
    }

    // Format bytes to human readable
    function formatBytes(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
        if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + ' MB';
        return (bytes / 1073741824).toFixed(2) + ' GB';
    }
    
    // Update recording panel (from 'vu' event at 60Hz)
    function updateRecPanel(data) {
        if (statFormat && data.rate) {
            const fmt = data.fmt ? data.fmt.toUpperCase() : 'WAV';
            const src = data.src ? data.src.toUpperCase() : '';
            statFormat.textContent = (data.rate/1000) + 'kHz/' + data.ch + 'ch ' + fmt + (src ? ' (' + src + ')' : '');
        }
        if (statRuntime && data.rate) {
            const frames = data.frames || 0;
            statRuntime.textContent = formatRuntime(Math.floor(frames / data.rate));
        }
        if (recStatus) {
            if (data.rec) {
                recStatus.textContent = '● REC';
                recStatus.className = 'rec-indicator recording';
            } else {
                recStatus.textContent = 'Standby';
                recStatus.className = 'rec-indicator standby';
            }
        }
        if (statLost) {
            statLost.textContent = data.lost || 0;
        }
        if (statWritten && data.frames && data.rate) {
            const bytes = data.frames * data.ch * 3; /* 24-bit = 3 bytes/sample */
            statWritten.textContent = formatBytes(bytes);
        }
    }

    // Update nerd stats (from 'stats' event at 1Hz)
    function updateNerdStats(data) {
        if (statUptime && data.uptime !== undefined)
            statUptime.textContent = formatRuntime(data.uptime);
        if (statCdjs && data.cdjs !== undefined)
            statCdjs.textContent = data.cdjs;
        if (statWs && data.ws_clients !== undefined)
            statWs.textContent = data.ws_clients;
        if (statTagged && data.tracks_tagged !== undefined)
            statTagged.textContent = data.tracks_tagged;
        if (statPkts && data.pkt_sec !== undefined)
            statPkts.textContent = data.pkt_sec;
        if (statShazam && data.sz_queries !== undefined) {
            const rate = data.sz_queries > 0
                ? Math.round(data.sz_matches / data.sz_queries * 100) : 0;
            statShazam.textContent = data.sz_matches + '/' + data.sz_queries + ' (' + rate + '%)';
        }
        if (statRing && data.ring_sec !== undefined)
            statRing.textContent = data.ring_sec + 's (' + data.ring_pct + '%)';
        if (statLoad && data.load !== undefined)
            statLoad.textContent = data.load.toFixed(2);
        if (statMem && data.mem !== undefined && data.memtot !== undefined) {
            const pct = ((data.mem / data.memtot) * 100).toFixed(0);
            statMem.textContent = formatBytes(data.mem) + ' (' + pct + '%)';
        }
        if (statDisk && data.diskfree !== undefined && data.disktot !== undefined) {
            const pct = ((data.diskfree / data.disktot) * 100).toFixed(0);
            statDisk.textContent = formatBytes(data.diskfree) + ' free';
            statDisk.className = 'value' + (pct < 10 ? ' warn' : '');
        }
    }
    
    // Source badge HTML helper
    function sourceBadge(src, conf) {
        if (!src) return '';
        // Normalize source - handle variations like "cdj/stable"
        let badge = '';
        if (src === 'both') {
            badge = '<span class="source-badge both">✓ Matched</span>';
        } else if (src.startsWith('cdj')) {
            const label = src === 'cdj/stable' ? 'CDJ ⏱' : 'CDJ';
            badge = `<span class="source-badge cdj">💿 ${label}</span>`;
        } else if (src === 'audio') {
            badge = '<span class="source-badge audio">🎵 Audio</span>';
        }
        const confText = conf ? `<span class="confidence">${conf}%</span>` : '';
        return badge + confText;
    }
    
    // Update the track identification panel (all active candidates)
    function updateIdentification(decks) {
        const idEl = document.getElementById('identification');
        if (!idEl) return;

        // Collect all candidates with a title and any confidence
        let candidates = [];
        if (decks) {
            for (const d of decks) {
                if (!d.title) continue;
                if (!d.conf && !d.conf_ok) continue;
                candidates.push(d);
            }
        }

        if (candidates.length === 0) {
            idEl.innerHTML = '<div class="id-waiting">Waiting for track...</div>';
            return;
        }

        // Sort by confidence descending
        candidates.sort((a, b) => (b.conf || 0) - (a.conf || 0));

        idEl.innerHTML = candidates.map(c => {
            const pct = c.conf || 0;
            const color = c.conf_ok ? '#4caf50' : pct >= 30 ? '#ff9800' : '#666';
            const src = c.conf_src && c.conf_src !== 'unknown' ? c.conf_src : '';
            const deckLabel = c.n > 0 ? `Deck ${c.n}` : 'Audio';
            return `
                <div class="id-track${c.conf_ok ? ' accepted' : ''}">
                    <div class="id-artist">${escapeHtml(c.artist) || '—'}</div>
                    <div class="id-title">${escapeHtml(c.title)}</div>
                </div>
                <div class="conf-bar-container">
                    <div class="conf-bar" style="width:${pct}%;background:${color}"></div>
                    <div class="conf-threshold"></div>
                    <span class="conf-label">${pct}%${c.conf_ok ? ' ✓' : ''}${src ? ' · ' + src : ''} · ${deckLabel}</span>
                </div>`;
        }).join('');
    }

    // Update CDJ deck status
    /* CDJ-3000 key byte at 0x15c is A-based: 0=A, 1=Bb, 2=B, 3=C, ... 11=G# */
    function keyName(note, scale, acc) {
        if (note > 11) return '';
        const notes = ['A','A#','B','C','C#','D','D#','E','F','F#','G','G#'];
        const flats = ['A','Bb','B','C','Db','D','Eb','E','F','Gb','G','Ab'];
        let name = (acc === 255 || acc === 0xff) ? flats[note] : notes[note];
        return name + (scale === 0 ? 'm' : '');
    }

    // Merge metadata from 'decks' JSON into rawDecks (C-side data: title, artist, confidence)
    function mergeDecksMetadata(decks) {
        if (!decks) return;
        for (const d of decks) {
            if (d.audio_only) continue; // handled by updateIdentification
            const n = d.n;
            if (!rawDecks[n]) rawDecks[n] = {};
            rawDecks[n].title = d.title || '';
            rawDecks[n].artist = d.artist || '';
            rawDecks[n].isrc = d.isrc || '';
            if (d.name) rawDecks[n].name = d.name;
            rawDecks[n].conf = d.conf || 0;
            rawDecks[n].conf_ok = d.conf_ok || false;
            rawDecks[n].conf_src = d.conf_src || '';
            rawDecks[n].rekordbox_id = d.rekordbox_id || 0;
            rawDecks[n].db_src = d.db_src || '';
            rawDecks[n].format = d.format || '';
            rawDecks[n].bitrate = d.bitrate || 0;
            rawDecks[n].samplerate = d.samplerate || 0;
            rawDecks[n].depth = d.depth || 0;
            rawDecks[n].on_air_known = true; // C knows on-air state
        }
    }

    // Render all deck cards from rawDecks (single source of truth)
    function renderDecks() {
        // Collect active decks (seen within last 10s)
        const now = Date.now();
        const active = [];
        for (const n in rawDecks) {
            const d = rawDecks[n];
            if (!d.lastUpdate || now - d.lastUpdate > 10000) continue;
            active.push({n: parseInt(n), ...d});
        }

        if (active.length === 0) {
            decksEl.innerHTML = '<div class="no-decks">No CDJs detected</div>';
            return;
        }

        active.sort((a, b) => a.n - b.n);

        decksEl.innerHTML = active.map(d => {
            const classes = ['deck', 'cdj-style'];
            if (d.playing) classes.push('playing');
            if (d.on_air) classes.push('on-air');

            const beatDots = d.bpm > 0 ? '<span class="cdj-beats">' +
                [1,2,3,4].map(b => `<span class="beat-dot${d.beat_in_bar === b ? ' active' : ''}" id="beat-${d.n}-${b}"></span>`).join('') +
                '</div>' : '';

            /* Compute display values */
            const posMs = d.playhead_ms || 0;
            const trackLen = d.track_length || 0;
            const pct = (trackLen > 0 && posMs > 0) ? Math.min(100, posMs / (trackLen * 1000) * 100) : 0;
            const remainMs = (trackLen > 0 && posMs > 0) ? Math.max(0, trackLen * 1000 - posMs) : 0;

            const baseBpm = d.bpm > 0 ? (d.bpm / 100) : 0;
            const pitchPct = (d.pitch || 0) / 100;
            const effectiveBpm = baseBpm > 0 ? (baseBpm * (1 + pitchPct / 100)).toFixed(1) : '--.-';
            const pitchStr = baseBpm > 0 ? (pitchPct >= 0 ? '+' : '') + pitchPct.toFixed(2) + '%' : '';

            const slotName = SLOTS[d.track_slot] || '';
            const keyStr = d.key_note <= 11 ? keyName(d.key_note, d.key_scale, d.key_acc) : '';

            let fmtStr = '';
            if (d.format) {
                fmtStr = d.format;
                if (d.samplerate && d.depth) fmtStr += ' ' + Math.round(d.samplerate/1000) + '/' + d.depth;
                else if (d.bitrate) fmtStr += ' ' + d.bitrate + 'k';
            }

            const onairL = d.on_air ? '((' : '';
            const onairR = d.on_air ? '))' : '';
            const onairCls = d.on_air ? 'cdj-onair-active' : 'cdj-onair-dim';

            const timeMode = d.timeMode || 'remain';
            const timeLabel = timeMode === 'remain' ? 'REMAIN' : 'ELAPSED';
            const timeVal = (timeMode === 'remain' && trackLen > 0 && posMs > 0)
                ? '-' + formatPosMs(remainMs)
                : (posMs > 0 ? formatPosMs(posMs) : '--:--.--');

            /* Waveform or fallback */
            const hasWf = d.waveform && d.waveform.detail;
            const hasOverview = d.waveform && d.waveform.preview;

            let progressBar = '';
            if (!hasWf && posMs > 0) {
                progressBar = `<div class="deck-progress" id="progress-${d.n}">` +
                    `<div class="deck-progress-bar" style="width:${pct.toFixed(1)}%"></div>` +
                    `<span class="deck-progress-time deck-progress-elapsed">${formatPosMs(posMs)}</span>` +
                    (trackLen > 0 ? `<span class="deck-progress-time deck-progress-remain">-${formatPosMs(remainMs)}</span>` : '') +
                    `</div>`;
            }

            return `
                <div class="${classes.join(' ')}" id="deck-${d.n}">
                    <div class="cdj-title">
                        <span class="cdj-note">♪</span>
                        <span class="cdj-track-name">${escapeHtml(d.artist ? d.artist + ' - ' : '')}${escapeHtml(d.title) || 'No track loaded'}</span>
                        ${fmtStr ? '<span class="cdj-format">' + fmtStr + '</span>' : ''}
                    </div>
                    ${hasWf
                        ? `<div class="cdj-detail-wrap">
                             <canvas class="cdj-detail" id="detail-${d.n}"></canvas>
                             <div class="cdj-zoom">
                               <button onclick="cycleZoom(-1)">+</button>
                               <button onclick="cycleZoom(1)">&minus;</button>
                             </div>
                           </div>`
                        : `<div class="cdj-detail-fallback">${progressBar}</div>`
                    }
                    <div class="cdj-info">
                        <div class="cdj-col">
                            <div class="cdj-label">PLAYER</div>
                            <div class="cdj-player-box"><span class="${onairCls}">${onairL}</span>${d.n}<span class="${onairCls}">${onairR}</span></div>
                            ${d.master ? '<div class="cdj-sub cdj-badge-master">MASTER</div>' : ''}
                        </div>
                        <div class="cdj-col">
                            ${beatDots}
                        </div>
                        <div class="cdj-col cdj-grow">
                            <div class="cdj-label">${timeLabel}</div>
                            <div class="cdj-time" id="cdj-time-${d.n}" onclick="rawDecks[${d.n}].timeMode=rawDecks[${d.n}].timeMode==='elapsed'?'remain':'elapsed'">${timeVal}</div>
                            ${d.playing ? '<div class="cdj-sub cdj-play-state">▶' + (d.looping ? ' LOOP' + (d.loop_beats > 0 ? ' ' + d.loop_beats : '') : '') + '</div>' : '<div class="cdj-sub">❚❚</div>'}
                        </div>
                        <div class="cdj-col">
                            <div class="cdj-label">TEMPO${d.sync ? ' <span class="cdj-badge-sync">SYNC</span>' : ''}</div>
                            <div class="cdj-pitch">${pitchStr || '+0.00%'}</div>
                            ${d.master_tempo ? '<div class="cdj-sub cdj-badge-mt">MT</div>' : ''}
                        </div>
                        <div class="cdj-col">
                            <div class="cdj-label">BPM</div>
                            <div class="cdj-bpm">${effectiveBpm}</div>
                            ${keyStr ? '<div class="cdj-key">' + keyStr + '</div>' : ''}
                        </div>
                    </div>
                    <div class="cdj-bottom">
                        ${hasOverview ? '<canvas class="cdj-overview" id="overview-' + d.n + '"></canvas>' : '<div class="cdj-overview-placeholder"></div>'}
                        <span class="cdj-source">${slotName}${d.db_src ? ' · ' + d.db_src : ''}</span>
                    </div>
                </div>
            `;
        }).join('');

        /* Re-render waveforms after DOM rebuild */
        for (const d of active) {
            if (d.waveform) {
                const posMs = d.playhead_ms || 0;
                const trackLen = d.track_length || 0;
                const pct = (trackLen > 0 && posMs > 0) ? Math.min(100, posMs / (trackLen * 1000) * 100) : 0;
                if (d.waveform.detail) {
                    const dc = document.getElementById('detail-' + d.n);
                    if (dc) renderDetail(dc, d.waveform.detail, posMs, trackLen);
                }
                if (d.waveform.preview) {
                    const oc = document.getElementById('overview-' + d.n);
                    if (oc) renderOverview(oc, d.waveform.preview, pct);
                }
            }
        }
    }


    // Add track to list
    function addTrack(artist, title, timestamp, source, confidence, isrc) {
        let time;
        if (timestamp) {
            // Parse timestamp from database (format: "YYYY-MM-DD HH:MM:SS")
            const parts = timestamp.split(' ');
            if (parts.length === 2) {
                time = parts[1].substring(0, 5);  // "HH:MM"
            } else {
                time = timestamp;
            }
        } else {
            const now = new Date();
            time = now.toLocaleTimeString('nl-NL', { hour: '2-digit', minute: '2-digit' });
        }
        
        const isrcHtml = isrc ? `<div class="track-isrc">${escapeHtml(isrc)}</div>` : '';
        
        const div = document.createElement('div');
        div.className = 'track';
        div.innerHTML = `
            <div class="track-time">${escapeHtml(time)}</div>
            <div class="track-info">
                <span class="track-artist">${escapeHtml(artist)}</span>
                <span class="track-title"> — ${escapeHtml(title)}</span>
                ${isrcHtml}
            </div>
            <div class="track-meta">${sourceBadge(source, confidence)}</div>
        `;
        
        // Insert at top
        if (tracksEl.firstChild) {
            tracksEl.insertBefore(div, tracksEl.firstChild);
        } else {
            tracksEl.appendChild(div);
        }
        
        // Keep only last 20 tracks
        while (tracksEl.children.length > 20) {
            tracksEl.removeChild(tracksEl.lastChild);
        }
    }
    
    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }
    
    // =========================================================================
    // Raw CDJ packet parser (binary WebSocket frames)
    // =========================================================================

    /* Pro DJ Link packet offsets (from prolink_protocol.h) */
    const PKT = {
        DEVICE_NUM: 0x21, PLAY_STATE: 0x7b, FLAGS: 0x89, FLAGS2: 0x8b,
        BPM: 0x92, PITCH1: 0x8c, BEAT_IN_BAR: 0xa6,
        USB_STATE: 0x6f, SD_STATE: 0x73, LINK_AVAIL: 0x75,
        MEDIA_PRESENCE: 0xb7, EMERGENCY_LOOP: 0xba,
        SOURCE_PLAYER: 0x28, TRACK_SLOT: 0x29,
        REKORDBOX_ID: 0x2c, TRACK_MENU: 0x37,
        KEY_NOTE: 0x15c, KEY_SCALE: 0x15d, KEY_ACC: 0x15e,
        MASTER_TEMPO: 0x158, LOOP_START: 0x1b6, LOOP_END: 0x1be,
        LOOP_BEATS: 0x1c8
    };
    const BEAT_PKT = { DEVICE_NUM: 0x21, BEAT_IN_BAR: 0x5c, BPM: 0x5a };
    const POS_PKT = { DEVICE_NUM: 0x21, TRACK_LEN: 0x24, PLAYHEAD: 0x28 };

    /* Per-device state from raw packets */
    const rawDecks = {};

    function parseStatusPacket(dv, len) {
        const devNum = dv.getUint8(PKT.DEVICE_NUM);
        if (!rawDecks[devNum]) rawDecks[devNum] = {};
        const d = rawDecks[devNum];

        const flags = dv.getUint8(PKT.FLAGS);
        d.playing = (flags & 0x40) !== 0;
        d.master = (flags & 0x20) !== 0;
        d.sync = (flags & 0x10) !== 0;
        d.on_air = (flags & 0x08) !== 0;
        d.play_state = dv.getUint8(PKT.PLAY_STATE);
        d.bpm = dv.getUint16(PKT.BPM);
        d.beat_in_bar = dv.getUint8(PKT.BEAT_IN_BAR);
        d.source_player = dv.getUint8(PKT.SOURCE_PLAYER);
        d.track_slot = dv.getUint8(PKT.TRACK_SLOT);
        d.usb_state = dv.getUint8(PKT.USB_STATE);
        d.sd_state = dv.getUint8(PKT.SD_STATE);

        /* Pitch: 0x100000 = 0%, stored as pct*100 */
        const pitchRaw = dv.getUint32(PKT.PITCH1);
        d.pitch = Math.round((pitchRaw - 0x100000) * 10000 / 0x100000);

        d.looping = (d.play_state === 0x04) || (dv.getUint8(PKT.EMERGENCY_LOOP) !== 0);
        d.loop_beats = 0;

        /* CDJ-3000 extended fields */
        if (len >= 0x1ca) {
            const ls = dv.getUint32(PKT.LOOP_START);
            const le = dv.getUint32(PKT.LOOP_END);
            if (ls > 0 && le > ls) {
                d.looping = true;
                d.loop_beats = dv.getUint16(PKT.LOOP_BEATS);
            }
        }
        if (len >= 0x15f) {
            d.key_note = dv.getUint8(PKT.KEY_NOTE);
            d.key_scale = dv.getUint8(PKT.KEY_SCALE);
            d.key_acc = dv.getUint8(PKT.KEY_ACC);
            d.master_tempo = dv.getUint8(PKT.MASTER_TEMPO);
        }

        d.lastUpdate = Date.now();
        renderDecks();
        updateDeckFromRaw(devNum);
    }

    function parseBeatPacket(dv) {
        const devNum = dv.getUint8(BEAT_PKT.DEVICE_NUM);
        if (!rawDecks[devNum]) rawDecks[devNum] = {};
        rawDecks[devNum].beat_in_bar = dv.getUint8(BEAT_PKT.BEAT_IN_BAR);
        rawDecks[devNum].lastBeat = Date.now();
        updateDeckFromRaw(devNum);
    }

    function parsePositionPacket(dv) {
        const devNum = dv.getUint8(POS_PKT.DEVICE_NUM);
        if (!rawDecks[devNum]) rawDecks[devNum] = {};
        rawDecks[devNum].playhead_ms = dv.getUint32(POS_PKT.PLAYHEAD);
        rawDecks[devNum].track_length = dv.getUint32(POS_PKT.TRACK_LEN);
        /* Position updates are fast (30ms) — don't rebuild DOM every time,
         * just update the position display if it exists */
        const ms = rawDecks[devNum].playhead_ms;
        const tl = rawDecks[devNum].track_length || 0;
        if (ms > 0) {
            const pct = tl > 0 ? Math.min(100, ms / (tl * 1000) * 100) : 0;

            const wf = rawDecks[devNum].waveform;

            /* Scrolling detail waveform */
            const detailCanvas = document.getElementById('detail-' + devNum);
            if (detailCanvas && wf && wf.detail) {
                renderDetail(detailCanvas, wf.detail, ms, tl);
            }

            /* Overview strip */
            const overviewCanvas = document.getElementById('overview-' + devNum);
            if (overviewCanvas && wf && wf.preview) {
                renderOverview(overviewCanvas, wf.preview, pct);
            }

            /* Time display */
            const timeEl = document.getElementById('cdj-time-' + devNum);
            if (timeEl) {
                const mode = rawDecks[devNum].timeMode || 'remain';
                if (mode === 'remain' && tl > 0)
                    timeEl.textContent = '-' + formatPosMs(Math.max(0, tl * 1000 - ms));
                else
                    timeEl.textContent = formatPosMs(ms);
            }

            /* Fallback: plain progress bar */
            const progEl = document.getElementById('progress-' + devNum);
            if (progEl && (!wf || !wf.detail)) {
                const bar = progEl.firstElementChild;
                if (bar && tl > 0) bar.style.width = pct.toFixed(1) + '%';
                const elapsedEl = progEl.querySelector('.deck-progress-elapsed');
                if (elapsedEl) elapsedEl.textContent = formatPosMs(ms);
                const remainEl = progEl.querySelector('.deck-progress-remain');
                if (remainEl && tl > 0) remainEl.textContent = '-' + formatPosMs(Math.max(0, tl * 1000 - ms));
            }
        }
    }

    /* ── ANLZ waveform parser ──────────────────────────────────────────── */

    function parseANLZ(buffer) {
        const dv = new DataView(buffer);
        if (buffer.byteLength < 12) return null;

        const magic = String.fromCharCode(dv.getUint8(0), dv.getUint8(1), dv.getUint8(2), dv.getUint8(3));
        if (magic !== 'PMAI') return null;
        const headerLen = dv.getUint32(4);

        /* Collect both preview and detail waveforms */
        let preview = null, detail = null;
        let offset = headerLen;
        while (offset + 12 <= buffer.byteLength) {
            const fourcc = String.fromCharCode(
                dv.getUint8(offset), dv.getUint8(offset+1),
                dv.getUint8(offset+2), dv.getUint8(offset+3));
            const tagLen = dv.getUint32(offset + 8);
            if (tagLen < 12 || offset + tagLen > buffer.byteLength) break;

            const eb = (offset + 12 < buffer.byteLength) ? dv.getUint32(offset + 12) : 0;
            const ne = (offset + 16 < buffer.byteLength) ? dv.getUint32(offset + 16) : 0;

            if (fourcc === 'PWV6' && eb === 3 && ne > 0) {
                /* 3-band preview (1200 entries) */
                const ds = offset + 20;
                if (ds + ne * 3 <= offset + tagLen)
                    preview = { type: '3band', entries: ne, data: new Uint8Array(buffer, ds, ne * 3) };
            } else if (fourcc === 'PWV7' && eb === 3 && ne > 0) {
                /* 3-band detail (150/sec) */
                const ds = offset + 24;
                if (ds + ne * 3 <= offset + tagLen)
                    detail = { type: '3band', entries: ne, data: new Uint8Array(buffer, ds, ne * 3) };
            } else if (fourcc === 'PWV4' && eb === 6 && ne > 0) {
                /* Color preview */
                const ds = offset + 24;
                if (!preview && ds + ne * 6 <= offset + tagLen)
                    preview = { type: 'color6', entries: ne, data: new Uint8Array(buffer, ds, ne * 6) };
            } else if (fourcc === 'PWV5' && eb === 2 && ne > 0) {
                /* Color detail */
                const ds = offset + 24;
                if (!detail && ds + ne * 2 <= offset + tagLen)
                    detail = { type: 'color', entries: ne, data: new Uint8Array(buffer, ds, ne * 2) };
            } else if (fourcc === 'PWAV') {
                /* Mono preview */
                const pl = dv.getUint32(offset + 12);
                const ds = offset + 20;
                if (!preview && pl > 0 && ds + pl <= offset + tagLen)
                    preview = { type: 'mono', entries: pl, data: new Uint8Array(buffer, ds, pl) };
            } else if (fourcc === 'PWV3') {
                /* Mono detail */
                const ds = offset + 24;
                if (!detail && eb === 1 && ne > 0 && ds + ne <= offset + tagLen)
                    detail = { type: 'mono', entries: ne, data: new Uint8Array(buffer, ds, ne) };
            }

            offset += tagLen;
        }
        if (!preview && !detail) return null;
        /* If only one type found, use it for both */
        return { preview: preview || detail, detail: detail || preview };
    }

    /* ── Waveform rendering helpers ─────────────────────────────────── */

    /* Draw 3-band waveform entries into a canvas region */
    function draw3band(ctx, wf, startEntry, count, x0, w, h, peak) {
        if (!peak) {
            peak = 1;
            for (let i = 0; i < wf.entries * 3; i++)
                if (wf.data[i] > peak) peak = wf.data[i];
        }
        const colW = w / count;
        for (let i = 0; i < count; i++) {
            const idx = startEntry + i;
            if (idx < 0 || idx >= wf.entries) continue;
            const mid = wf.data[idx * 3];
            const high = wf.data[idx * 3 + 1];
            const low = wf.data[idx * 3 + 2];
            const x = x0 + (i / count) * w;
            const lowH = (low / peak) * h;
            const midH = (mid / peak) * h;
            const highH = (high / peak) * h;
            ctx.fillStyle = '#1a3a7a';
            ctx.fillRect(x, h - lowH, Math.max(colW, 1), lowH);
            ctx.fillStyle = '#c07018';
            ctx.fillRect(x, h - Math.max(lowH, midH), Math.max(colW, 1), midH);
            ctx.fillStyle = 'rgba(200, 235, 255, 0.85)';
            ctx.fillRect(x, h - Math.max(lowH, midH, highH), Math.max(colW, 1), highH);
        }
    }

    function drawMono(ctx, wf, startEntry, count, x0, w, h) {
        const colW = w / count;
        ctx.fillStyle = '#4488cc';
        for (let i = 0; i < count; i++) {
            const idx = startEntry + i;
            if (idx < 0 || idx >= wf.entries) continue;
            const height = wf.data[idx] & 0x1f;
            const x = x0 + (i / count) * w;
            const barH = (height / 31) * h;
            ctx.fillRect(x, h - barH, Math.max(colW, 1), barH);
        }
    }

    /* Render overview waveform (full track, thin strip) */
    function renderOverview(canvas, wf, pct) {
        if (!canvas || !wf) return;
        const ctx = canvas.getContext('2d');
        const dpr = window.devicePixelRatio || 1;
        const w = canvas.width = canvas.clientWidth * dpr;
        const h = canvas.height = canvas.clientHeight * dpr;
        ctx.clearRect(0, 0, w, h);

        if (wf.type === '3band') draw3band(ctx, wf, 0, wf.entries, 0, w, h);
        else drawMono(ctx, wf, 0, wf.entries, 0, w, h);

        /* Playhead line */
        if (pct > 0) {
            const x = Math.round(pct * w / 100);
            ctx.fillStyle = 'rgba(255, 255, 255, 0.9)';
            ctx.fillRect(x - 1, 0, 2, h);
        }
    }

    /* Render scrolling detail waveform (centered on playhead) */
    var zoomLevels = [5, 10, 20, 30]; /* seconds visible */
    var zoomIndex = 1; /* default 10 seconds */

    function renderDetail(canvas, wf, playheadMs, trackLenSec) {
        if (!canvas || !wf) return;
        const ctx = canvas.getContext('2d');
        const dpr = window.devicePixelRatio || 1;
        const w = canvas.width = canvas.clientWidth * dpr;
        const h = canvas.height = canvas.clientHeight * dpr;
        ctx.clearRect(0, 0, w, h);

        /* 150 entries per second for detail waveforms */
        const eps = (wf.entries > 0 && trackLenSec > 0) ? wf.entries / trackLenSec : 150;
        const visibleSec = zoomLevels[zoomIndex] || 10;
        const visibleEntries = Math.round(visibleSec * eps);
        const centerEntry = Math.floor((playheadMs / 1000) * eps);
        const startEntry = centerEntry - Math.floor(visibleEntries / 2);

        /* Find peak for normalization across visible window */
        let peak = 1;
        if (wf.type === '3band') {
            for (let i = Math.max(0, startEntry); i < Math.min(wf.entries, startEntry + visibleEntries); i++) {
                for (let b = 0; b < 3; b++)
                    if (wf.data[i * 3 + b] > peak) peak = wf.data[i * 3 + b];
            }
        }

        if (wf.type === '3band') draw3band(ctx, wf, startEntry, visibleEntries, 0, w, h, peak);
        else drawMono(ctx, wf, startEntry, visibleEntries, 0, w, h);

        /* Center playhead line */
        const cx = Math.round(w / 2);
        ctx.fillStyle = 'rgba(255, 60, 60, 0.9)';
        ctx.fillRect(cx - 1, 0, 2, h);
    }

    function cycleZoom(dir) {
        zoomIndex = Math.max(0, Math.min(zoomLevels.length - 1, zoomIndex + dir));
    }

    function handleBinaryFrame(data) {
        if (data.byteLength < 5) return;
        const header = new DataView(data, 0, 5);
        const portId = header.getUint8(0);

        /* Waveform frame: [0xFF][device_num][len2][len1][len0][ANLZ data...] */
        if (portId === 0xFF && data.byteLength >= 5) {
            const devNum = header.getUint8(1);
            const anlzLen = (header.getUint8(2) << 16) | (header.getUint8(3) << 8) | header.getUint8(4);
            if (5 + anlzLen <= data.byteLength) {
                const anlzBuf = data.slice(5, 5 + anlzLen);
                const wf = parseANLZ(anlzBuf);
                if (wf && !rawDecks[devNum]) rawDecks[devNum] = {};
                if (wf) {
                    rawDecks[devNum].waveform = wf; /* { preview, detail } */
                }
            }
            return;
        }

        /* CDJ packet frames need 7-byte header */
        if (data.byteLength < 8) return;
        const portId2 = new DataView(data, 0, 7).getUint8(0);
        const payloadLen = (new DataView(data, 0, 7).getUint8(5) << 8) | new DataView(data, 0, 7).getUint8(6);
        if (7 + payloadLen > data.byteLength) return;

        const payload = new DataView(data, 7, payloadLen);

        if (portId2 === 2 && payloadLen >= 0xa7) {
            parseStatusPacket(payload, payloadLen);
        } else if (portId2 === 1) {
            /* Beat port: could be beat packet or position packet */
            if (payloadLen >= 96 && payload.getUint8(0x0a) === 0x28) {
                parseBeatPacket(payload);
            } else if (payloadLen >= 52) {
                parsePositionPacket(payload);
            }
        }
    }

    /* Update deck card UI from raw packet data.
     * Called on every status/beat packet — updates in-place, no full rebuild. */
    function updateDeckFromRaw(devNum) {
        const d = rawDecks[devNum];
        if (!d) return;

        /* Update beat dots */
        for (let b = 1; b <= 4; b++) {
            const dot = document.getElementById('beat-' + devNum + '-' + b);
            if (dot) {
                if (d.beat_in_bar === b) dot.classList.add('active');
                else dot.classList.remove('active');
            }
        }

        /* Update play/on-air badges */
        const deckEl = document.getElementById('deck-' + devNum);
        if (deckEl) {
            deckEl.classList.toggle('playing', !!d.playing);
            deckEl.classList.toggle('on-air', !!d.on_air);
        }

        /* Update BPM/pitch display */
        const bpmEl = document.getElementById('bpm-' + devNum);
        if (bpmEl && d.bpm > 0) {
            const baseBpm = d.bpm / 100;
            const pitchPct = d.pitch / 100;
            const effectiveBpm = (baseBpm * (1 + pitchPct / 100)).toFixed(1);
            const pitchStr = Math.abs(pitchPct) > 0.05
                ? ` <span class="deck-pitch">(${pitchPct >= 0 ? '+' : ''}${pitchPct.toFixed(2)}%)</span>` : '';
            bpmEl.innerHTML = `${effectiveBpm} BPM${pitchStr}`;
        }
    }

    // =========================================================================
    // WebSocket connection
    // =========================================================================

    let ws = null;
    let reconnectTimeout = null;

    function connect() {
        if (ws) ws.close();

        const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
        ws = new WebSocket(proto + '//' + location.host + '/ws');
        ws.binaryType = 'arraybuffer';

        ws.onopen = function() {
            statusEl.textContent = 'Connected';
            statusEl.className = 'status connected';
            if (reconnectTimeout) {
                clearTimeout(reconnectTimeout);
                reconnectTimeout = null;
            }
        };

        ws.onmessage = function(e) {
            if (e.data instanceof ArrayBuffer) {
                handleBinaryFrame(e.data);
                return;
            }

            /* Text frame: JSON event */
            try {
                const msg = JSON.parse(e.data);
                switch (msg.event) {
                case 'vu':
                    updateVU(msg.l, msg.r);
                    updateRecPanel(msg);
                    break;
                case 'track':
                    if (msg.a || msg.t)
                        addTrack(msg.a, msg.t, null, msg.src, msg.conf, msg.isrc);
                    break;
                case 'decks':
                    mergeDecksMetadata(msg.data);
                    updateIdentification(msg.data);
                    break;
                case 'history':
                    if (msg.data) {
                        for (let i = msg.data.length - 1; i >= 0; i--) {
                            const t = msg.data[i];
                            addTrack(t.a, t.t, t.ts, t.src, t.conf, t.isrc);
                        }
                    }
                    break;
                case 'log':
                    if (msg.data) {
                        const logEl = document.getElementById('activity-log');
                        if (!logEl) break;
                        var now = new Date().toLocaleTimeString('nl-NL', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
                        msg.data.forEach(function(m) {
                            const div = document.createElement('div');
                            div.className = 'log-line';
                            div.textContent = now + ' ' + m;
                            logEl.appendChild(div);
                        });
                        while (logEl.children.length > 50)
                            logEl.removeChild(logEl.firstChild);
                        logEl.scrollTop = logEl.scrollHeight;
                    }
                    break;
                case 'stats':
                    updateNerdStats(msg);
                    break;
                case 'shazam':
                    /* Shazam state updates — could add UI for this */
                    break;
                }
            } catch (err) {
                console.error('WS parse error:', err);
            }
        };

        ws.onclose = function() {
            statusEl.textContent = 'Disconnected';
            statusEl.className = 'status disconnected';
            if (!reconnectTimeout) {
                reconnectTimeout = setTimeout(connect, 2000);
            }
        };

        ws.onerror = function() {
            ws.close();
        };
    }

    // Start
    if (new URLSearchParams(location.search).has('mock')) {
        statusEl.textContent = 'Mock Mode';
        statusEl.className = 'status connected';

        /* Generate fake waveform data */
        function fakeWaveform(entries) {
            const data = new Uint8Array(entries * 3);
            for (let i = 0; i < entries; i++) {
                const t = i / entries;
                const beat = Math.sin(t * Math.PI * 64) * 0.3 + 0.5;
                const drop = (t > 0.25 && t < 0.75) ? 1.2 : 0.6;
                data[i*3]   = Math.min(255, Math.floor((Math.random()*40+60) * beat * drop)); // mid
                data[i*3+1] = Math.min(255, Math.floor((Math.random()*30+20) * beat * drop)); // high
                data[i*3+2] = Math.min(255, Math.floor((Math.random()*50+80) * beat * drop)); // low
            }
            return { type: '3band', entries: entries, data: data };
        }

        /* Create 2 mock decks */
        rawDecks[2] = {
            playing: true, on_air: true, master: true, sync: false,
            bpm: 12840, pitch: 32, beat_in_bar: 1, play_state: 0x04,
            track_slot: 3, source_player: 2, looping: true, loop_beats: 4,
            master_tempo: true, key_note: 3, key_scale: 0, key_acc: 0,
            playhead_ms: 142000, track_length: 420, on_air_known: true,
            title: 'Holding On (Original Club Mix)', artist: 'Lika Morgan',
            name: 'CDJ-3000X', isrc: 'USRC11234567', db_src: 'OneLibrary',
            format: 'FLAC', samplerate: 44100, depth: 24, bitrate: 1411,
            conf: 72, conf_ok: true, conf_src: 'both',
            lastUpdate: Date.now(),
            waveform: { preview: fakeWaveform(1200), detail: fakeWaveform(63000) }
        };
        rawDecks[5] = {
            playing: true, on_air: false, master: false, sync: true,
            bpm: 12800, pitch: -45, beat_in_bar: 3, play_state: 0x69,
            track_slot: 3, source_player: 5, looping: false, loop_beats: 0,
            master_tempo: false, key_note: 10, key_scale: 1, key_acc: 0,
            playhead_ms: 67000, track_length: 355, on_air_known: true,
            title: 'Cascade (Original Mix)', artist: 'Psyk',
            name: 'CDJ-3000X', isrc: '', db_src: 'DBServer',
            format: 'MP3', samplerate: 44100, depth: 0, bitrate: 320,
            conf: 45, conf_ok: false, conf_src: 'cdj',
            lastUpdate: Date.now(),
            waveform: { preview: fakeWaveform(1200), detail: fakeWaveform(53250) }
        };

        renderDecks();

        /* Simulate playhead movement */
        setInterval(function() {
            for (var n in rawDecks) {
                var d = rawDecks[n];
                if (d.playing) {
                    d.playhead_ms += 30;
                    if (d.track_length && d.playhead_ms > d.track_length * 1000) d.playhead_ms = 0;
                    d.beat_in_bar = (Math.floor(d.playhead_ms / 500) % 4) + 1;

                    /* Update detail waveform */
                    var dc = document.getElementById('detail-' + n);
                    if (dc && d.waveform && d.waveform.detail)
                        renderDetail(dc, d.waveform.detail, d.playhead_ms, d.track_length);

                    /* Update overview */
                    var oc = document.getElementById('overview-' + n);
                    if (oc && d.waveform && d.waveform.preview) {
                        var pct = d.track_length > 0 ? Math.min(100, d.playhead_ms / (d.track_length * 1000) * 100) : 0;
                        renderOverview(oc, d.waveform.preview, pct);
                    }

                    /* Update time */
                    var te = document.getElementById('cdj-time-' + n);
                    if (te) {
                        var tl = d.track_length || 0;
                        var mode = d.timeMode || 'remain';
                        if (mode === 'remain' && tl > 0)
                            te.textContent = '-' + formatPosMs(Math.max(0, tl*1000 - d.playhead_ms));
                        else
                            te.textContent = formatPosMs(d.playhead_ms);
                    }

                    /* Update beat dots */
                    for (var b = 1; b <= 4; b++) {
                        var dot = document.getElementById('beat-' + n + '-' + b);
                        if (dot) {
                            if (d.beat_in_bar === b) dot.classList.add('active');
                            else dot.classList.remove('active');
                        }
                    }
                }
            }
        }, 30);
    } else {
        connect();
    }
})();
