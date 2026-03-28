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
    
    // Update the track identification panel (best candidate across all sources)
    function updateIdentification(decks) {
        const idEl = document.getElementById('identification');
        if (!idEl) return;

        // Find best candidate: highest confidence with a title
        let best = null;
        if (decks) {
            for (const d of decks) {
                if (!d.title) continue;
                if (!d.conf && !d.conf_ok) continue;
                if (!best || d.conf > best.conf) best = d;
            }
        }

        if (!best) {
            idEl.innerHTML = '<div class="id-waiting">Waiting for track...</div>';
            return;
        }

        const pct = best.conf || 0;
        const color = best.conf_ok ? '#4caf50' : pct >= 30 ? '#ff9800' : '#666';
        const src = best.conf_src && best.conf_src !== 'unknown' ? best.conf_src : '';
        const deckLabel = best.n > 0 ? `Deck ${best.n}` : 'Audio';

        idEl.innerHTML = `
            <div class="id-track${best.conf_ok ? ' accepted' : ''}">
                <div class="id-artist">${escapeHtml(best.artist) || '—'}</div>
                <div class="id-title">${escapeHtml(best.title)}</div>
            </div>
            <div class="conf-bar-container">
                <div class="conf-bar" style="width:${pct}%;background:${color}"></div>
                <div class="conf-threshold"></div>
                <span class="conf-label">${pct}%${best.conf_ok ? ' ✓' : ''}${src ? ' · ' + src : ''} · ${deckLabel}</span>
            </div>
        `;
    }

    // Update CDJ deck status
    function updateDecks(decks) {
        // Filter out audio-only entries (shown in identification panel instead)
        const cdjDecks = decks ? decks.filter(d => !d.audio_only) : [];

        if (cdjDecks.length === 0) {
            decksEl.innerHTML = '<div class="no-decks">No CDJs detected</div>';
            return;
        }

        // Sort by deck number
        cdjDecks.sort((a, b) => a.n - b.n);
        const decksToRender = cdjDecks;
        
        decksEl.innerHTML = decksToRender.map(d => {
            const classes = ['deck'];
            if (d.playing) classes.push('playing');
            if (d.on_air) classes.push('on-air');

            const slotName = SLOTS[d.slot] || '';
            const bpmText = d.bpm > 0 ? `<span class="deck-bpm">${d.bpm} BPM</span>` : '';
            const slotText = slotName ? ` · ${slotName}` : '';
            const deckLabel = (d.name || 'CDJ') + ' (' + d.n + ')';
            const isrcText = d.isrc ? `<span class="deck-isrc">${escapeHtml(d.isrc)}</span>` : '';

            // Play time with context
            let playTimeText = '';
            if (d.playing && d.play_time > 0) {
                const m = Math.floor(d.play_time / 60);
                const s = d.play_time % 60;
                const timeStr = `${m}:${s < 10 ? '0' : ''}${s}`;
                playTimeText = `<span class="deck-playtime" title="Continuous play time">${timeStr}</span>`;
            }

            // Position (from CDJ-3000 position packets)
            let posText = '';
            if (d.position_ms > 0) {
                const pm = Math.floor(d.position_ms / 60000);
                const ps = Math.floor((d.position_ms % 60000) / 1000);
                posText = `<span class="deck-position">${pm}:${ps < 10 ? '0' : ''}${ps}</span>`;
            }

            // Media indicators
            const mediaIcons = [];
            if (d.usb) mediaIcons.push('USB');
            if (d.sd) mediaIcons.push('SD');
            const mediaText = mediaIcons.length > 0 ? `<span class="deck-media">${mediaIcons.join('+')}</span>` : '';

            // Database source
            const dbText = d.db_src ? `<span class="deck-db">${d.db_src}</span>` : '';

            return `
                <div class="${classes.join(' ')}">
                    <div class="deck-header">
                        <span class="deck-num">${deckLabel}</span>
                        <div class="deck-status">
                            ${d.playing ? '<span class="deck-badge playing">▶ Playing</span>' : '<span class="deck-badge paused">❚❚ Paused</span>'}
                            ${d.on_air_known ? (d.on_air ? '<span class="deck-badge on-air">ON AIR</span>' : '<span class="deck-badge off-air">OFF AIR</span>') : ''}
                            ${playTimeText}
                        </div>
                    </div>
                    <div class="deck-track">
                        <div class="deck-artist">${escapeHtml(d.artist) || '—'}</div>
                        <div class="deck-title">${escapeHtml(d.title) || 'No track loaded'}</div>
                    </div>
                    <div class="deck-meta">
                        ${bpmText}${slotText}${posText ? ' · ' + posText : ''}
                        ${isrcText ? ' · ' + isrcText : ''}
                        ${mediaText ? ' · ' + mediaText : ''}${dbText ? ' · ' + dbText : ''}
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
