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
    const nowMeta = document.getElementById('now-meta');
    const tracksEl = document.getElementById('tracks');
    const statusEl = document.getElementById('status');
    const decksEl = document.getElementById('decks');
    const shazamEl = document.getElementById('shazam-status');
    const audioStatsEl = document.getElementById('audio-stats');
    
    // Shazam state names
    const SHAZAM_STATES = {
        0: { text: 'Idle', class: 'idle' },
        1: { text: 'Listening...', class: 'listening' },
        2: { text: 'Fingerprinting...', class: 'fingerprinting' },
        3: { text: 'Querying Shazam...', class: 'querying' },
        4: { text: 'Confirming...', class: 'confirming' },
        5: { text: 'Matched!', class: 'matched' },
        6: { text: 'Waiting...', class: 'throttled' },
        7: { text: 'Disabled', class: 'disabled' }
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
    
    // Get VU color based on level (green -> yellow -> red)
    function vuColor(pct) {
        if (pct < 70) {
            // Green to yellow (0-70%)
            const t = pct / 70;
            const r = Math.round(255 * t);
            return `rgb(${r}, 255, 0)`;
        } else if (pct < 90) {
            // Yellow to orange (70-90%)
            const t = (pct - 70) / 20;
            const g = Math.round(255 * (1 - t * 0.5));
            return `rgb(255, ${g}, 0)`;
        } else {
            // Orange to red (90-100%)
            const t = (pct - 90) / 10;
            const g = Math.round(128 * (1 - t));
            return `rgb(255, ${g}, 0)`;
        }
    }
    
    // Update VU meters
    function updateVU(left, right) {
        const lPct = toPercent(left);
        const rPct = toPercent(right);
        
        vuLeft.style.height = lPct + '%';
        vuRight.style.height = rPct + '%';
        vuLeft.style.backgroundColor = vuColor(lPct);
        vuRight.style.backgroundColor = vuColor(rPct);
        
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
    
    // Update audio stats display
    function updateAudioStats(data) {
        if (!audioStatsEl) return;
        const parts = [];
        if (data.rate) parts.push(`<span class="stat">${data.rate/1000}kHz ${data.ch}ch</span>`);
        if (data.rec) parts.push(`<span class="stat recording">● REC</span>`);
        if (data.rms !== undefined) parts.push(`<span class="stat">RMS ${data.rms}</span>`);
        if (data.lost > 0) parts.push(`<span class="stat lost">Lost ${data.lost}</span>`);
        if (data.frames) parts.push(`<span class="stat">${(data.frames/data.rate).toFixed(0)}s</span>`);
        audioStatsEl.innerHTML = parts.join('');
    }
    
    // Update now playing
    function updateNowPlaying(artist, title, source, confidence) {
        nowArtist.textContent = artist || '—';
        nowTitle.textContent = title || '';
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
            
            return `
                <div class="${classes.join(' ')}">
                    <div class="deck-header">
                        <span class="deck-num">${d.name || 'CDJ ' + d.n}</span>
                        <div class="deck-status">
                            ${d.playing ? '<span class="deck-badge playing">▶ Playing</span>' : '<span class="deck-badge paused">❚❚ Paused</span>'}
                            ${d.on_air ? '<span class="deck-badge on-air">ON AIR</span>' : ''}
                        </div>
                    </div>
                    <div class="deck-track">
                        <div class="deck-artist">${escapeHtml(d.artist) || '—'}</div>
                        <div class="deck-title">${escapeHtml(d.title) || 'No track loaded'}</div>
                    </div>
                    <div class="deck-meta">${bpmText}${slotText}</div>
                </div>
            `;
        }).join('');
    }
    
    // Add track to list
    function addTrack(artist, title, timestamp, source, confidence) {
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
            time = now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
        }
        
        const div = document.createElement('div');
        div.className = 'track';
        div.innerHTML = `
            <div class="track-time">${escapeHtml(time)}</div>
            <div class="track-info">
                <span class="track-artist">${escapeHtml(artist)}</span>
                <span class="track-title"> — ${escapeHtml(title)}</span>
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
                    updateNowPlaying(data.a, data.t, data.src, data.conf);
                    addTrack(data.a, data.t, null, data.src, data.conf);
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
                    addTrack(t.a, t.t, t.ts, t.src, t.conf);
                }
                // Update now playing with most recent track
                if (tracks.length > 0) {
                    const latest = tracks[0];
                    updateNowPlaying(latest.a, latest.t, latest.src, latest.conf);
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
