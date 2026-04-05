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
            if (d.title) rawDecks[n].title = d.title;
            if (d.artist) rawDecks[n].artist = d.artist;
            if (d.isrc) rawDecks[n].isrc = d.isrc;
            if (d.name) rawDecks[n].name = d.name;
            if (d.conf !== undefined) rawDecks[n].conf = d.conf;
            if (d.conf_ok !== undefined) rawDecks[n].conf_ok = d.conf_ok;
            if (d.conf_src) rawDecks[n].conf_src = d.conf_src;
            if (d.rekordbox_id) rawDecks[n].rekordbox_id = d.rekordbox_id;
            if (d.db_src) rawDecks[n].db_src = d.db_src;
            if (d.format) rawDecks[n].format = d.format;
            if (d.bitrate) rawDecks[n].bitrate = d.bitrate;
            if (d.samplerate) rawDecks[n].samplerate = d.samplerate;
            if (d.depth) rawDecks[n].depth = d.depth;
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
            const classes = ['deck'];
            if (d.playing) classes.push('playing');
            if (d.on_air) classes.push('on-air');

            const deckLabel = (d.name || 'CDJ') + ' (' + d.n + ')';

            const beatDots = d.bpm > 0 ? '<div class="beat-indicator">' +
                [1,2,3,4].map(b => `<span class="beat-dot${d.beat_in_bar === b ? ' active' : ''}" id="beat-${d.n}-${b}"></span>`).join('') +
                '</div>' : '';

            let bpmText = '';
            if (d.bpm > 0) {
                const baseBpm = d.bpm / 100;
                const pitchPct = (d.pitch || 0) / 100;
                const effectiveBpm = (baseBpm * (1 + pitchPct / 100)).toFixed(1);
                const pitchStr = Math.abs(pitchPct) > 0.05
                    ? ` <span class="deck-pitch">(${pitchPct >= 0 ? '+' : ''}${pitchPct.toFixed(2)}%)</span>` : '';
                bpmText = `<span class="deck-bpm" id="bpm-${d.n}">${effectiveBpm} BPM${pitchStr}</span>`;
            }

            const slotName = SLOTS[d.track_slot] || '';
            let sourceText = '';
            if (slotName) {
                if (d.source_player > 0 && d.source_player !== d.n) {
                    sourceText = `<span class="deck-source">CDJ${d.source_player}/${slotName} (Link)</span>`;
                } else {
                    sourceText = `<span class="deck-source">${slotName}</span>`;
                }
            }

            const keyText = d.key_note <= 11 ? `<span class="deck-key">${keyName(d.key_note, d.key_scale, d.key_acc)}</span>` : '';

            const loopBadge = d.looping
                ? `<span class="deck-badge loop">LOOP${d.loop_beats > 0 ? ' ' + d.loop_beats : ''}</span>` : '';

            const mtBadge = d.master_tempo ? '<span class="deck-badge mt">MT</span>' : '';
            const masterBadge = d.master ? '<span class="deck-badge master">MASTER</span>' : '';
            const syncBadge = d.sync ? '<span class="deck-badge sync">SYNC</span>' : '';

            let playTimeText = '';
            const posMs = d.playhead_ms || 0;
            const trackLen = d.track_length || 0;
            if (posMs > 0) {
                const pm = Math.floor(posMs / 60000);
                const ps = Math.floor((posMs % 60000) / 1000);
                const posStr = `${pm}:${ps < 10 ? '0' : ''}${ps}`;
                if (trackLen > 0) {
                    const tm = Math.floor(trackLen / 60);
                    const ts = trackLen % 60;
                    playTimeText = `<span class="deck-playtime" id="pos-${d.n}">${posStr} / ${tm}:${ts < 10 ? '0' : ''}${ts}</span>`;
                } else {
                    playTimeText = `<span class="deck-playtime" id="pos-${d.n}">${posStr}</span>`;
                }
            }

            let fmtBadge = '';
            if (d.format) {
                let info = d.format;
                if (d.samplerate) info += ' ' + (d.samplerate/1000) + 'kHz';
                if (d.depth) info += '/' + d.depth + 'bit';
                else if (d.bitrate) info += ' ' + d.bitrate + 'k';
                fmtBadge = `<span class="deck-badge fmt">${info}</span>`;
            }
            const isrcText = d.isrc ? `<span class="deck-isrc">${escapeHtml(d.isrc)}</span>` : '';
            const dbText = d.db_src ? `<span class="deck-db">${d.db_src}</span>` : '';

            return `
                <div class="${classes.join(' ')}" id="deck-${d.n}">
                    <div class="deck-header">
                        <span class="deck-num">${deckLabel}</span>${beatDots}
                        <div class="deck-status">
                            ${d.playing ? (d.play_state === 0x05 ? '<span class="deck-badge cueing">▶ Cue</span>' : '<span class="deck-badge playing">▶ Playing</span>') : '<span class="deck-badge paused">❚❚ Paused</span>'}
                            ${d.on_air_known ? (d.on_air ? '<span class="deck-badge on-air">ON AIR</span>' : '<span class="deck-badge off-air">OFF AIR</span>') : ''}
                            ${masterBadge}${syncBadge}${loopBadge}${mtBadge}
                            ${playTimeText}
                        </div>
                    </div>
                    <div class="deck-track">
                        <div class="deck-artist">${escapeHtml(d.artist) || '—'}</div>
                        <div class="deck-title">${escapeHtml(d.title) || 'No track loaded'}</div>
                    </div>
                    <div class="deck-meta">
                        ${bpmText}${keyText ? ' · ' + keyText : ''}${sourceText ? ' · ' + sourceText : ''}
                        ${fmtBadge}
                        ${isrcText ? ' · ' + isrcText : ''}
                        ${dbText ? ' · ' + dbText : ''}
                    </div>
                </div>
            `;
        }).join('');
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
        const posEl = document.getElementById('pos-' + devNum);
        if (posEl && rawDecks[devNum].playhead_ms > 0) {
            const pm = Math.floor(rawDecks[devNum].playhead_ms / 60000);
            const ps = Math.floor((rawDecks[devNum].playhead_ms % 60000) / 1000);
            const tl = rawDecks[devNum].track_length || 0;
            const tm = Math.floor(tl / 60);
            const ts = tl % 60;
            posEl.textContent = `${pm}:${ps < 10 ? '0' : ''}${ps}` +
                (tl > 0 ? ` / ${tm}:${ts < 10 ? '0' : ''}${ts}` : '');
        }
    }

    function handleBinaryFrame(data) {
        if (data.byteLength < 8) return;  /* 7-byte header + at least 1 byte payload */
        const header = new DataView(data, 0, 7);
        const portId = header.getUint8(0);
        const payloadLen = (header.getUint8(5) << 8) | header.getUint8(6);
        if (7 + payloadLen > data.byteLength) return;

        const payload = new DataView(data, 7, payloadLen);

        if (portId === 2 && payloadLen >= 0xa7) {
            parseStatusPacket(payload, payloadLen);
        } else if (portId === 1) {
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
    connect();
})();
