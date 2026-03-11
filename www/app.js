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
    const tracksEl = document.getElementById('tracks');
    const statusEl = document.getElementById('status');
    const decksEl = document.getElementById('decks');
    
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
    
    // Update VU meters
    function updateVU(left, right) {
        const lPct = toPercent(left);
        const rPct = toPercent(right);
        
        vuLeft.style.height = lPct + '%';
        vuRight.style.height = rPct + '%';
        
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
    
    // Update now playing
    function updateNowPlaying(artist, title) {
        nowArtist.textContent = artist || '—';
        nowTitle.textContent = title || '';
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
    function addTrack(artist, title) {
        const now = new Date();
        const time = now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
        
        const div = document.createElement('div');
        div.className = 'track';
        div.innerHTML = `
            <div class="track-time">${time}</div>
            <div class="track-info">
                <span class="track-artist">${escapeHtml(artist)}</span>
                <span class="track-title"> — ${escapeHtml(title)}</span>
            </div>
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
                }
            } catch (err) {
                console.error('Parse error:', err);
            }
        };
        
        evtSource.addEventListener('track', function(e) {
            try {
                const data = JSON.parse(e.data);
                if (data.a || data.t) {
                    updateNowPlaying(data.a, data.t);
                    addTrack(data.a, data.t);
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
    
    // Load recent tracks from database (optional REST endpoint)
    function loadTracks() {
        fetch('/tracks')
            .then(r => r.json())
            .then(tracks => {
                tracks.forEach(t => {
                    const div = document.createElement('div');
                    div.className = 'track';
                    const time = new Date(t.timestamp).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
                    div.innerHTML = `
                        <div class="track-time">${time}</div>
                        <div class="track-info">
                            <span class="track-artist">${escapeHtml(t.artist || '')}</span>
                            <span class="track-title"> — ${escapeHtml(t.title || '')}</span>
                        </div>
                    `;
                    tracksEl.appendChild(div);
                });
            })
            .catch(() => {
                // /tracks endpoint may not exist, that's ok
            });
    }
    
    // Start
    loadTracks();
    connect();
})();
