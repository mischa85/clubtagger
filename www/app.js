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
    // Stats elements
    const statFormat = document.getElementById('stat-format');
    const statRuntime = document.getElementById('stat-runtime');
    const statLost = document.getElementById('stat-lost');
    const statLoad = document.getElementById('stat-load');
    const statMem = document.getElementById('stat-mem');
    const statDisk = document.getElementById('stat-disk');
    const statWritten = document.getElementById('stat-written');
    const recStatus = document.getElementById('rec-status');
    
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
    
    // Update audio stats display
    function updateAudioStats(data) {
        if (statFormat && data.rate) {
            const fmt = data.fmt ? data.fmt.toUpperCase() : 'WAV';
            statFormat.textContent = (data.rate/1000) + 'kHz/' + data.ch + 'ch ' + fmt;
        }
        if (statRuntime && data.frames && data.rate) {
            statRuntime.textContent = formatRuntime(Math.floor(data.frames/data.rate));
        }
        if (recStatus) {
            if (data.rec) {
                recStatus.textContent = '● REC';
                recStatus.className = 'rec-status recording';
            } else {
                recStatus.textContent = 'Standby';
                recStatus.className = 'rec-status standby';
            }
        }
        if (statLost) {
            statLost.textContent = data.lost || 0;
            statLost.className = 'value' + (data.lost > 0 ? ' warn' : ' ok');
        }
        if (statLoad && data.load !== undefined) {
            statLoad.textContent = data.load.toFixed(2);
        }
        if (statMem && data.mem !== undefined && data.memtot !== undefined) {
            const pct = ((data.mem / data.memtot) * 100).toFixed(0);
            statMem.textContent = formatBytes(data.mem) + ' (' + pct + '%)';
        }
        if (statDisk && data.diskfree !== undefined && data.disktot !== undefined) {
            const pct = ((data.diskfree / data.disktot) * 100).toFixed(0);
            statDisk.textContent = formatBytes(data.diskfree) + ' free';
            statDisk.className = 'value' + (pct < 10 ? ' warn' : '');
        }
        if (statWritten && data.written !== undefined) {
            statWritten.textContent = formatBytes(data.written);
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
    function keyName(note, scale, acc) {
        if (note > 11) return '';
        const notes = ['C','C#','D','D#','E','F','F#','G','G#','A','A#','B'];
        let name = notes[note];
        if (acc === 1) name = notes[note]; // sharp already in array
        else if (acc === 255 || acc === 0xff) {
            // flat: use flat notation
            const flats = ['C','Db','D','Eb','E','F','Gb','G','Ab','A','Bb','B'];
            name = flats[note];
        }
        return name + (scale === 0 ? 'm' : '');
    }

    function updateDecks(decks) {
        // Filter out audio-only entries (shown in identification panel instead)
        const cdjDecks = decks ? decks.filter(d => !d.audio_only) : [];

        if (cdjDecks.length === 0) {
            decksEl.innerHTML = '<div class="no-decks">No CDJs detected</div>';
            return;
        }

        // Sort by deck number
        cdjDecks.sort((a, b) => a.n - b.n);

        decksEl.innerHTML = cdjDecks.map(d => {
            const classes = ['deck'];
            if (d.playing) classes.push('playing');
            if (d.on_air) classes.push('on-air');

            const deckLabel = (d.name || 'CDJ') + ' (' + d.n + ')';

            // Beat indicator (4 dots, current beat highlighted)
            const beatDots = d.bpm > 0 ? '<div class="beat-indicator">' +
                [1,2,3,4].map(b => `<span class="beat-dot${d.beat === b ? ' active' : ''}"></span>`).join('') +
                '</div>' : '';

            // BPM with pitch (pitch is percentage * 100, e.g. 326 = +3.26%)
            let bpmText = '';
            if (d.bpm > 0) {
                const pitchPct = d.pitch / 100;
                const effectiveBpm = (d.bpm * (1 + pitchPct / 100)).toFixed(1);
                const pitchStr = Math.abs(pitchPct) > 0.05
                    ? ` <span class="deck-pitch">(${pitchPct >= 0 ? '+' : ''}${pitchPct.toFixed(2)}%)</span>` : '';
                bpmText = `<span class="deck-bpm">${effectiveBpm} BPM${pitchStr}</span>`;
            }

            // Track source
            const slotName = SLOTS[d.slot] || '';
            let sourceText = '';
            if (slotName) {
                if (d.src_player > 0 && d.src_player !== d.n) {
                    sourceText = `<span class="deck-source">CDJ${d.src_player}/${slotName} (Link)</span>`;
                } else {
                    sourceText = `<span class="deck-source">${slotName}</span>`;
                }
            }

            // Key display
            const keyText = d.key_note <= 11 ? `<span class="deck-key">${keyName(d.key_note, d.key_scale, d.key_acc)}</span>` : '';

            // Loop badge
            const loopBadge = d.looping
                ? `<span class="deck-badge loop">LOOP${d.loop_beats > 0 ? ' ' + d.loop_beats : ''}</span>` : '';

            // Master tempo badge
            const mtBadge = d.master_tempo ? '<span class="deck-badge mt">MT</span>' : '';

            // Track position or continuous play time
            let playTimeText = '';
            if (d.position_ms > 0) {
                const pm = Math.floor(d.position_ms / 60000);
                const ps = Math.floor((d.position_ms % 60000) / 1000);
                const posStr = `${pm}:${ps < 10 ? '0' : ''}${ps}`;
                if (d.track_length > 0) {
                    const tm = Math.floor(d.track_length / 60);
                    const ts = d.track_length % 60;
                    playTimeText = `<span class="deck-playtime">${posStr} / ${tm}:${ts < 10 ? '0' : ''}${ts}</span>`;
                } else {
                    playTimeText = `<span class="deck-playtime">${posStr}</span>`;
                }
            } else if (d.playing && d.play_time > 0) {
                const m = Math.floor(d.play_time / 60);
                const s = d.play_time % 60;
                playTimeText = `<span class="deck-playtime">${m}:${s < 10 ? '0' : ''}${s}</span>`;
            }

            const isrcText = d.isrc ? `<span class="deck-isrc">${escapeHtml(d.isrc)}</span>` : '';
            const dbText = d.db_src ? `<span class="deck-db">${d.db_src}</span>` : '';

            return `
                <div class="${classes.join(' ')}">
                    <div class="deck-header">
                        <span class="deck-num">${deckLabel}</span>${beatDots}
                        <div class="deck-status">
                            ${d.playing ? '<span class="deck-badge playing">▶ Playing</span>' : '<span class="deck-badge paused">❚❚ Paused</span>'}
                            ${d.on_air_known ? (d.on_air ? '<span class="deck-badge on-air">ON AIR</span>' : '<span class="deck-badge off-air">OFF AIR</span>') : ''}
                            ${loopBadge}${mtBadge}
                            ${playTimeText}
                        </div>
                    </div>
                    <div class="deck-track">
                        <div class="deck-artist">${escapeHtml(d.artist) || '—'}</div>
                        <div class="deck-title">${escapeHtml(d.title) || 'No track loaded'}</div>
                    </div>
                    <div class="deck-meta">
                        ${bpmText}${keyText ? ' · ' + keyText : ''}${sourceText ? ' · ' + sourceText : ''}
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
            time = now.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
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
    
    // SSE connection
    let evtSource = null;
    let reconnectTimeout = null;
    
    function connect() {
        if (evtSource) {
            evtSource.close();
        }
        
        evtSource = new EventSource('/sse');
        
        evtSource.onopen = function() {
            statusEl.textContent = 'Connected';
            statusEl.className = 'status connected';
            if (reconnectTimeout) {
                clearTimeout(reconnectTimeout);
                reconnectTimeout = null;
            }
        };
        
        evtSource.onmessage = function(e) {
            try {
                const data = JSON.parse(e.data);
                if (typeof data.l === 'number' && typeof data.r === 'number') {
                    updateVU(data.l, data.r);
                    updateAudioStats(data);
                }
            } catch (err) {
                console.error('Parse error:', err);
            }
        };
        
        evtSource.addEventListener('track', function(e) {
            try {
                const data = JSON.parse(e.data);
                if (data.a || data.t) {
                    addTrack(data.a, data.t, null, data.src, data.conf, data.isrc);
                }
            } catch (err) {
                console.error('Track parse error:', err);
            }
        });
        
        evtSource.addEventListener('decks', function(e) {
            try {
                const decks = JSON.parse(e.data);
                updateDecks(decks);
                updateIdentification(decks);
            } catch (err) {
                console.error('Decks parse error:', err);
            }
        });
        
        evtSource.addEventListener('history', function(e) {
            try {
                const tracks = JSON.parse(e.data);
                // Add tracks in reverse order (oldest first, so newest ends up at top)
                for (let i = tracks.length - 1; i >= 0; i--) {
                    const t = tracks[i];
                    addTrack(t.a, t.t, t.ts, t.src, t.conf, t.isrc);
                }
            } catch (err) {
                console.error('History parse error:', err);
            }
        });
        
        evtSource.addEventListener('log', function(e) {
            try {
                const messages = JSON.parse(e.data);
                const logEl = document.getElementById('activity-log');
                if (!logEl) return;
                messages.forEach(function(msg) {
                    const div = document.createElement('div');
                    div.className = 'log-line';
                    div.textContent = msg;
                    logEl.appendChild(div);
                });
                /* Keep only last 50 lines */
                while (logEl.children.length > 50) {
                    logEl.removeChild(logEl.firstChild);
                }
                /* Auto-scroll to bottom */
                logEl.scrollTop = logEl.scrollHeight;
            } catch (err) {
                console.error('Log parse error:', err);
            }
        });

        evtSource.onerror = function() {
            statusEl.textContent = 'Disconnected';
            statusEl.className = 'status disconnected';
            evtSource.close();
            
            // Reconnect after 2 seconds
            if (!reconnectTimeout) {
                reconnectTimeout = setTimeout(connect, 2000);
            }
        };
    }
    
    // Start
    connect();
})();
