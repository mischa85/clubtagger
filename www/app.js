// Clubtagger Web UI
(function() {
    'use strict';
    
    // DOM elements
    const vuLeft = document.getElementById('vu-left');
    const vuRight = document.getElementById('vu-right');
    const peakLeft = document.getElementById('peak-left');
    const peakRight = document.getElementById('peak-right');
    const nowArtist = document.getElementById('now-artist');
    const nowTitle = document.getElementById('now-title');
    const nowIsrc = document.getElementById('now-isrc');
    const nowMeta = document.getElementById('now-meta');
    const tracksEl = document.getElementById('tracks');
    const statusEl = document.getElementById('status');
    const decksEl = document.getElementById('decks');
    const shazamEl = document.getElementById('shazam-status');
    
    // Stats elements
    const statFormat = document.getElementById('stat-format');
    const statRuntime = document.getElementById('stat-runtime');
    const statLost = document.getElementById('stat-lost');
    const statLoad = document.getElementById('stat-load');
    const statMem = document.getElementById('stat-mem');
    const statDisk = document.getElementById('stat-disk');
    const statWritten = document.getElementById('stat-written');
    const recStatus = document.getElementById('rec-status');
    
    // Shazam state names
    const SHAZAM_STATES = {
        0: { text: 'Idle', class: 'idle' },
        1: { text: 'Listening...', class: 'listening' },
        2: { text: 'Fingerprinting...', class: 'fingerprinting' },
        3: { text: 'Querying Shazam...', class: 'querying' },
        4: { text: 'Confirming...', class: 'confirming' },
        5: { text: 'Matched!', class: 'matched' },
        6: { text: 'Waiting...', class: 'throttled' },
        7: { text: 'Disabled', class: 'disabled' },
        8: { text: 'No Match', class: 'no-match' },
        9: { text: 'Error', class: 'error' }
    };
    
    // Slot names
    const SLOTS = { 0: '', 1: 'CD', 2: 'SD', 3: 'USB', 4: 'Link' };
    
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
    
    // Update now playing
    function updateNowPlaying(artist, title, source, confidence, isrc) {
        nowArtist.textContent = artist || '—';
        nowTitle.textContent = title || '';
        if (nowIsrc) {
            nowIsrc.textContent = isrc || '';
        }
        if (nowMeta) {
            nowMeta.innerHTML = sourceBadge(source, confidence);
        }
    }
    
    // Source badge HTML helper
    function sourceBadge(src, conf) {
        if (!src) return '';
        const badges = {
            'audio': '<span class="source-badge audio">🎵 Audio</span>',
            'cdj': '<span class="source-badge cdj">💿 CDJ</span>',
            'both': '<span class="source-badge both">✓ Matched</span>'
        };
        const confText = conf ? `<span class="confidence">${conf}%</span>` : '';
        return (badges[src] || '') + confText;
    }
    
    // Update Shazam status
    function updateShazam(data) {
        if (!shazamEl) return;
        const stateInfo = SHAZAM_STATES[data.state] || { text: 'Unknown', class: 'unknown' };
        shazamEl.className = 'shazam-status ' + stateInfo.class;
        
        if (data.state === 4 && data.candidate) {  // SHAZAM_CONFIRMING
            const needed = data.needed || 3;
            const confPct = data.conf ? ` (${data.conf}%)` : '';
            const cdjMatch = data.cdj ? ' 💿' : '';
            shazamEl.innerHTML = `<span class="shazam-text">${stateInfo.text}</span>` +
                `<span class="shazam-candidate">${escapeHtml(data.candidate)}${confPct}${cdjMatch}</span>` +
                `<span class="shazam-confirms">${data.confirms}/${needed}</span>`;
        } else if (data.attempts > 0 && (data.state === 1 || data.state === 2 || data.state === 3 || data.state === 8)) {
            // Show attempt count when listening/fingerprinting/querying/no-match
            shazamEl.innerHTML = `<span class="shazam-text">${stateInfo.text}</span>` +
                `<span class="shazam-attempts">${data.attempts}/5</span>`;
        } else {
            shazamEl.innerHTML = `<span class="shazam-text">${stateInfo.text}</span>`;
        }
    }
    
    // Update CDJ deck status
    function updateDecks(decks) {
        if (!decks || decks.length === 0) {
            decksEl.innerHTML = '<div class="no-decks">No CDJs detected</div>';
            return;
        }
        
        // Sort by deck number
        decks.sort((a, b) => a.n - b.n);
        
        decksEl.innerHTML = decks.map(d => {
            const classes = ['deck'];
            if (d.playing) classes.push('playing');
            if (d.on_air) classes.push('on-air');
            
            const slotName = SLOTS[d.slot] || '';
            const bpmText = d.bpm > 0 ? `<span class="deck-bpm">${d.bpm} BPM</span>` : '';
            const slotText = slotName ? ` · ${slotName}` : '';
            const deckLabel = (d.name || 'CDJ') + ' (' + d.n + ')';
            const isrcText = d.isrc ? `<span class="deck-isrc">${escapeHtml(d.isrc)}</span>` : '';
            
            return `
                <div class="${classes.join(' ')}">
                    <div class="deck-header">
                        <span class="deck-num">${deckLabel}</span>
                        <div class="deck-status">
                            ${d.playing ? '<span class="deck-badge playing">▶ Playing</span>' : '<span class="deck-badge paused">❚❚ Paused</span>'}
                            ${d.on_air ? '<span class="deck-badge on-air">ON AIR</span>' : ''}
                        </div>
                    </div>
                    <div class="deck-track">
                        <div class="deck-artist">${escapeHtml(d.artist) || '—'}</div>
                        <div class="deck-title">${escapeHtml(d.title) || 'No track loaded'}</div>
                    </div>
                    <div class="deck-meta">${bpmText}${slotText}${isrcText ? ' · ' + isrcText : ''}</div>
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
                    updateNowPlaying(data.a, data.t, data.src, data.conf, data.isrc);
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
                // Update now playing with most recent track
                if (tracks.length > 0) {
                    const latest = tracks[0];
                    updateNowPlaying(latest.a, latest.t, latest.src, latest.conf, latest.isrc);
                }
            } catch (err) {
                console.error('History parse error:', err);
            }
        });
        
        evtSource.addEventListener('shazam', function(e) {
            try {
                const data = JSON.parse(e.data);
                updateShazam(data);
            } catch (err) {
                console.error('Shazam parse error:', err);
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
