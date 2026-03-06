/**
 * app.js — Ghost Protocol Real-Time Dashboard
 *
 * Responsibilities:
 *   - WebSocket connection with exponential backoff reconnect
 *   - Initial REST session sync (GET /sessions) on page load
 *   - Route incoming events to 6 component handlers
 *   - Static MITRE 14-tactic grid with cumulative confidence heatmap
 *   - Threat escalation flash only when risk_score increases
 *   - Session selector filtering all panels
 */

'use strict';

/* ═══════════════════════════════════════════════
   CONSTANTS
═══════════════════════════════════════════════ */

const TACTICS = [
    'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
    'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
    'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
    'Exfiltration', 'Impact',
];

const TACTIC_SHORT = {
    'Reconnaissance': 'Recon',
    'Resource Development': 'Res Dev',
    'Initial Access': 'Init Access',
    'Execution': 'Execution',
    'Persistence': 'Persist',
    'Privilege Escalation': 'Priv Esc',
    'Defense Evasion': 'Def Evasion',
    'Credential Access': 'Cred Access',
    'Discovery': 'Discovery',
    'Lateral Movement': 'Lat Move',
    'Collection': 'Collection',
    'Command and Control': 'C&C',
    'Exfiltration': 'Exfil',
    'Impact': 'Impact',
};

const WS_PROTOCOL = location.protocol === 'https:' ? 'wss' : 'ws';
const WS_HOST = location.host || 'localhost:8000';
const WS_URL = `${WS_PROTOCOL}://${WS_HOST}/ws`;
const MAX_RECONNECT_DELAY_MS = 30_000;
const MAX_TERMINAL_ENTRIES = 200;
const MAX_TIMELINE_ENTRIES = 100;
const MAX_BEACON_ENTRIES = 50;

/* ═══════════════════════════════════════════════
   STATE
═══════════════════════════════════════════════ */

const state = {
    ws: null,
    reconnectTimer: null,
    reconnectCount: 0,
    selectedSession: null,          // session_id string | null
    sessions: {},            // session_id → { source_ip, username, status }
    sessionData: {},         // session_id → snapshot data
    logsCache: {},           // session_id → array of logs
    prevRiskScore: 0,
    cmdCount: 0,
    beaconCount: 0,
    mitreHits: {},            // technique_id → cumulative confidence
    tacticHits: {},            // tactic → cumulative confidence (for cell intensity)
    vpnFindings: [],
};

/* ═══════════════════════════════════════════════
   WEBSOCKET
═══════════════════════════════════════════════ */

function connect() {
    if (state.ws && state.ws.readyState === WebSocket.OPEN) return;

    state.ws = new WebSocket(WS_URL);

    state.ws.onopen = () => {
        state.reconnectCount = 0;
        setLive(true);
    };

    state.ws.onmessage = (e) => {
        try { routeEvent(JSON.parse(e.data)); }
        catch (err) { console.warn('[ghost] bad WS message', err); }
    };

    state.ws.onerror = () => { };   // onclose fires after onerror; handle there

    state.ws.onclose = () => {
        setLive(false);
        const delay = Math.min(500 * Math.pow(2, state.reconnectCount), MAX_RECONNECT_DELAY_MS);
        state.reconnectCount++;
        state.reconnectTimer = setTimeout(connect, delay);
    };
}

/* ═══════════════════════════════════════════════
   EVENT ROUTER
   Envelope: { type, session_id, timestamp, data }
═══════════════════════════════════════════════ */

function routeEvent(ev) {
    const { type, session_id, timestamp, data } = ev;

    // Session events always processed
    if (type === 'session') { handleSession(session_id, data); return; }

    // Most events are session-scoped; VPN security alerts are global.
    if (state.selectedSession && session_id !== state.selectedSession && type !== 'vpn_security_alert') return;

    switch (type) {
        case 'command': handleCommand(timestamp, data); break;
        case 'intent': handleIntent(data); break;
        case 'threat': handleThreat(data); break;
        case 'mitre': handleMitre(data); break;
        case 'vpn_security_alert': handleVPNSecurityAlert(data); break;
        case 'network_threat_alert': handleVPNSecurityAlert(data); break;
        case 'ai_summary': handleAiSummary(data); break;
        case 'attack_timeline': handleAttackTimeline(timestamp, data); break;
        case 'timeline': handleTimeline(timestamp, data); break;
        case 'beacon': handleBeacon(timestamp, data); break;
        case 'command_received': handleCommand(timestamp, data); break;
        case 'report_generated': handleReportGenerated(session_id, data); break;
        case 'session_closed': handleSessionClosed(session_id, data); break;
        default: console.warn('[ghost] unknown event type:', type);
    }
}

/* ═══════════════════════════════════════════════
   EVENT HANDLERS
═══════════════════════════════════════════════ */

/* session ─────────────────────────────────────── */
function handleSession(session_id, data) {
    const { action, source_ip, username } = data;

    if (action === 'started') {
        state.sessions[session_id] = { source_ip, username, status: 'active' };
        addSessionOption(session_id, source_ip, username);
        updateSessionPill();
        // Auto-select first session
        if (!state.selectedSession) selectSession(session_id);
    } else if (action === 'closed') {
        if (state.sessions[session_id]) state.sessions[session_id].status = 'closed';
        updateSessionPill();
    } else if (action === 'updated') {
        if (state.sessions[session_id])
            Object.assign(state.sessions[session_id], data);
    }
}

/* command ─────────────────────────────────────── */
function handleCommand(timestamp, data) {
    const { command, ai_response } = data;
    const out = document.getElementById('terminal-output');

    // Remove placeholder
    const ph = out.querySelector('.empty-state');
    if (ph) ph.remove();

    // Guard max entries
    while (out.children.length >= MAX_TERMINAL_ENTRIES) out.removeChild(out.firstChild);

    const ts = formatTime(timestamp);
    const div = document.createElement('div');
    div.className = 't-entry';
    div.innerHTML =
        `<div><span class="t-stamp">[${ts}]</span> ` +
        `<span class="t-prompt">$</span> ` +
        `<span class="t-cmd">${esc(command)}</span></div>` +
        (ai_response ? `<div class="t-resp">${esc(ai_response)}</div>` : '');
    out.appendChild(div);
    out.scrollTop = out.scrollHeight;

    state.cmdCount++;
    document.getElementById('cmd-count').textContent = `${state.cmdCount} cmds`;
}

/* intent ──────────────────────────────────────– */
function handleIntent(data) {
    const { 
        attacker_type, 
        primary_objective, 
        primary_intent, 
        sophistication_level, 
        sophistication, 
        confidence,
        reasoning 
    } = data;
    
    const objective = primary_objective || primary_intent || '—';
    const soph = sophistication_level || sophistication || '—';
    const conf = parseFloat(confidence) || 0;
    
    // Legacy Intelligence Card updates
    const objEl = document.getElementById('intel-objective');
    if (objEl) objEl.textContent = objective;
    
    const sophEl = document.getElementById('intel-soph');
    if (sophEl) sophEl.textContent = soph;
    
    const confPctEl = document.getElementById('intel-conf-pct');
    if (confPctEl) confPctEl.textContent = `${Math.round(conf * 100)}%`;
    
    const badge = document.getElementById('intel-conf');
    if (badge) badge.textContent = `${Math.round(conf * 100)}%`;
    
    // NEW: AI Intent Panel updates
    const aiTypeEl = document.getElementById('ai-attacker-type');
    if (aiTypeEl) {
        aiTypeEl.textContent = attacker_type || '—';
        aiTypeEl.parentElement?.classList.add('updated');
        setTimeout(() => aiTypeEl.parentElement?.classList.remove('updated'), 600);
    }
    
    const aiObjectiveEl = document.getElementById('ai-primary-objective');
    if (aiObjectiveEl) {
        aiObjectiveEl.textContent = objective;
        aiObjectiveEl.parentElement?.classList.add('updated');
        setTimeout(() => aiObjectiveEl.parentElement?.classList.remove('updated'), 600);
    }
    
    const aiSophEl = document.getElementById('ai-sophistication');
    if (aiSophEl) {
        aiSophEl.textContent = soph;
        aiSophEl.parentElement?.classList.add('updated');
        setTimeout(() => aiSophEl.parentElement?.classList.remove('updated'), 600);
    }
    
    const aiConfEl = document.getElementById('ai-intent-confidence');
    if (aiConfEl) {
        aiConfEl.textContent = `${Math.round(conf * 100)}%`;
        aiConfEl.parentElement?.classList.add('updated');
        setTimeout(() => aiConfEl.parentElement?.classList.remove('updated'), 600);
    }
    
    const aiReasonEl = document.getElementById('ai-intent-reasoning');
    if (aiReasonEl) {
        aiReasonEl.textContent = reasoning || '—';
        aiReasonEl.parentElement?.classList.add('updated');
        setTimeout(() => aiReasonEl.parentElement?.classList.remove('updated'), 600);
    }
}

/* threat ──────────────────────────────────────── */
function handleThreat(data) {
    const { 
        risk_score,
        score_change,
        threat_level, 
        apt_likelihood,
        reasoning 
    } = data;
    
    const score = parseFloat(risk_score) || 0;
    const level = (threat_level || 'LOW').toUpperCase();
    const change = parseFloat(score_change) || 0;

    // Legacy Risk Gauge updates
    const scoreEl = document.getElementById('risk-score');
    if (scoreEl) scoreEl.textContent = score.toFixed(0);
    
    const fillEl = document.getElementById('risk-fill');
    if (fillEl) fillEl.style.width = score + '%';
    
    const levelLabel = document.getElementById('risk-level-label');
    if (levelLabel) {
        levelLabel.textContent = level;
        levelLabel.className = 'risk-level-label ' + level.toLowerCase();
    }
    
    // Update Risk score on snapshot
    const snapThreat = document.getElementById('snap-threat');
    if (snapThreat) snapThreat.textContent = level;

    // Escalation flash only when score increases
    if (score > state.prevRiskScore) {
        const panel = document.querySelector('.panel-risk');
        if (panel) {
            panel.classList.remove('escalating');
            void panel.offsetWidth;
            panel.classList.add('escalating');
            setTimeout(() => panel.classList.remove('escalating'), 300);
        }
    }
    state.prevRiskScore = score;
    
    // NEW: AI Threat Panel updates
    const aiScoreEl = document.getElementById('ai-threat-current');
    if (aiScoreEl) {
        aiScoreEl.textContent = score.toFixed(0);
        aiScoreEl.parentElement?.classList.add('updated');
        setTimeout(() => aiScoreEl.parentElement?.classList.remove('updated'), 600);
    }
    
    const aiChangeEl = document.getElementById('ai-threat-change');
    if (aiChangeEl) {
        const changeSign = change > 0 ? '+' : '';
        const changeClass = change > 0 ? 'positive' : (change < 0 ? 'negative' : 'neutral');
        aiChangeEl.textContent = `${changeSign}${change.toFixed(1)}`;
        aiChangeEl.className = `ai-threat-change ${changeClass}`;
        aiChangeEl.parentElement?.classList.add('updated');
        setTimeout(() => aiChangeEl.parentElement?.classList.remove('updated'), 600);
    }
    
    const aiLevelEl = document.getElementById('ai-threat-level');
    if (aiLevelEl) {
        aiLevelEl.textContent = level;
        aiLevelEl.className = `ai-threat-level ${level.toLowerCase()}`;
        aiLevelEl.parentElement?.classList.add('updated');
        setTimeout(() => aiLevelEl.parentElement?.classList.remove('updated'), 600);
    }
    
    const aiAptEl = document.getElementById('ai-apt-likelihood');
    if (aiAptEl) {
        const aptScore = parseFloat(apt_likelihood) || 0;
        aiAptEl.textContent = `${Math.round(aptScore * 100)}%`;
        aiAptEl.parentElement?.classList.add('updated');
        setTimeout(() => aiAptEl.parentElement?.classList.remove('updated'), 600);
    }
    
    const aiReasonEl = document.getElementById('ai-threat-reasoning');
    if (aiReasonEl) {
        aiReasonEl.textContent = reasoning || '—';
        aiReasonEl.parentElement?.classList.add('updated');
        setTimeout(() => aiReasonEl.parentElement?.classList.remove('updated'), 600);
    }
}

/* mitre ───────────────────────────────────────── */
function handleMitre(data) {
    // Handle legacy MITRE heat grid (single technique per event)
    const { tactic, technique_id, confidence, techniques } = data;
    
    // If this is the old format (single technique)
    if (technique_id && tactic) {
        const conf = parseFloat(confidence) || 0;

        // Accumulate per technique (cumulative, clamped at 3.0)
        state.mitreHits[technique_id] = Math.min((state.mitreHits[technique_id] || 0) + conf, 3.0);
        // Accumulate per tactic for cell intensity
        state.tacticHits[tactic] = Math.min((state.tacticHits[tactic] || 0) + conf, 3.0);

        updateMitreCell(tactic);
        updateMitreCount();
    }
    
    // NEW: Populate AI MITRE Panel with techniques list (new format)
    if (techniques && Array.isArray(techniques)) {
        const techniquesList = document.getElementById('ai-mitre-techniques-list');
        if (techniquesList) {
            // Clear previous items (unless appending)
            if (techniquesList.children.length === 0 || techniquesList.innerHTML.includes('empty')) {
                techniquesList.innerHTML = '';
            }
            
            techniques.forEach(tech => {
                // Check if technique already displayed
                const existingId = `ai-tech-${tech.id}`;
                if (document.getElementById(existingId)) return;
                
                const item = document.createElement('div');
                item.id = existingId;
                item.className = 'ai-technique-item updated';
                
                const confidence = Math.round((parseFloat(tech.confidence) || 0) * 100);
                item.innerHTML = `
                    <div class="ai-technique-name">${esc(tech.name || tech.id)}</div>
                    <div class="ai-technique-meta">
                        <span>${esc(tech.tactic || '—')}</span>
                        <span>${confidence}% confidence</span>
                    </div>
                    ${tech.description ? `<div style="font-size: 10px; color: var(--text-dim); margin-top: 3px;">${esc(tech.description)}</div>` : ''}
                `;
                
                techniquesList.appendChild(item);
                
                // Trigger animation
                setTimeout(() => item.classList.remove('updated'), 600);
            });
            
            // Update techniques count
            const techCount = document.getElementById('ai-mitre-count');
            if (techCount) {
                techCount.textContent = techniquesList.children.length;
            }
        }
    }
}

/* ai_summary ──────────────────────────────────── */
function handleAiSummary(data) {
    const { 
        narrative,
        command_context,
        attacker_profile,
        primary_goal,
        threat_level
    } = data;
    
    const summaryNarrativeEl = document.getElementById('ai-summary-narrative');
    if (summaryNarrativeEl) {
        summaryNarrativeEl.textContent = narrative || '—';
        
        // Style based on threat level if available
        if (threat_level) {
            summaryNarrativeEl.className = `ai-summary-narrative ${threat_level.toLowerCase()}`;
        }
        
        // Trigger animation
        summaryNarrativeEl.parentElement?.classList.add('updated');
        setTimeout(() => summaryNarrativeEl.parentElement?.classList.remove('updated'), 600);
    }
}

/* attack_timeline ─────────────────────────────– */
function handleAttackTimeline(timestamp, data) {
   const out = document.getElementById('timeline-output');
    const ph = out.querySelector('.empty-state');
    if (ph) ph.remove();

    while (out.children.length >= MAX_TIMELINE_ENTRIES) out.removeChild(out.firstChild);

    const { timestamp_short, event_type, command, intent, mitre_technique, mitre_tactic, threat_score, threat_level, description, ai_confidence } = data;
    
    const ts = timestamp_short || formatTime(timestamp);
    const tag = INTENT_TAGS[intent?.toLowerCase().replace(' ', '_')] || (intent || '');
    const techniqueStr = mitre_technique ? ` [${mitre_technique}]` : '';
    
    const row = document.createElement('div');
    row.className = 'tl-row';
    row.innerHTML =
        `<span class="tl-time">${esc(ts)}</span>` +
        `<span class="tl-text">` +
        `<strong>${esc(command || description)}</strong><br/>` +
        `<small>${tag}${techniqueStr} · Score: ${threat_score}/${threat_level}</small>` +
        `</span>`;
    out.prepend(row);
}

/* timeline ────────────────────────────────────── */
function handleTimeline(timestamp, data) {
    const out = document.getElementById('timeline-output');
    const ph = out.querySelector('.empty-state');
    if (ph) ph.remove();

    while (out.children.length >= MAX_TIMELINE_ENTRIES) out.removeChild(out.firstChild);

    const row = document.createElement('div');
    row.className = 'tl-row';
    row.innerHTML =
        `<span class="tl-time">${formatTime(timestamp)}</span>` +
        `<span class="tl-text">${esc(data.event_text || '')}</span>`;
    out.prepend(row);   // newest at top
}

/* beacon ───────────────────────────────────────── */
function handleBeacon(timestamp, data) {
    const { token_id, triggered_ip, user_agent } = data;
    const out = document.getElementById('beacon-output');
    const ph = out.querySelector('.empty-state');
    if (ph) ph.remove();

    while (out.children.length >= MAX_BEACON_ENTRIES) out.removeChild(out.firstChild);

    const card = document.createElement('div');
    card.className = 'beacon-alert';
    card.innerHTML =
        `<div class="beacon-title">🚨 CANARY TRIGGERED</div>` +
        `<div class="beacon-detail">` +
        `Token: ${esc(token_id)}<br>` +
        `IP: ${esc(triggered_ip || '—')}<br>` +
        `Time: ${formatTime(timestamp)}<br>` +
        `UA: ${esc(user_agent || '—')}` +
        `</div>`;
    out.prepend(card);

    state.beaconCount++;
    const badge = document.getElementById('beacon-count');
    badge.textContent = String(state.beaconCount);
}

/* ═══════════════════════════════════════════════
   MITRE GRID INIT & UPDATE
═══════════════════════════════════════════════ */

function buildMitreGrid() {
    const grid = document.getElementById('mitre-grid');
    TACTICS.forEach(tactic => {
        const cell = document.createElement('div');
        cell.className = 'mc';
        cell.id = 'mc-' + slugify(tactic);
        cell.title = tactic;
        cell.innerHTML =
            `<div class="mc-name">${TACTIC_SHORT[tactic] || tactic}</div>` +
            `<div class="mc-count" id="mcc-${slugify(tactic)}">0</div>`;
        grid.appendChild(cell);
    });
}

function updateMitreCell(tactic) {
    const id = slugify(tactic);
    const cell = document.getElementById('mc-' + id);
    const cnt = document.getElementById('mcc-' + id);
    if (!cell) return;

    const score = state.tacticHits[tactic] || 0;
    
    // Assign heat class based on accumulated count
    cell.className = 'mc ' + heatClass(score);
    if (cnt) cnt.textContent = score > 0 ? score : '—';
}

function updateMitreCount() {
    const n = Object.keys(state.mitreHits).length;
    const el = document.getElementById('mitre-count');
    if (el) el.textContent = `${n} technique${n !== 1 ? 's' : ''}`;
}

function heatClass(score) {
    if (score <= 0) return '';
    if (score < 0.5) return 'heat-1';
    if (score < 1.0) return 'heat-2';
    if (score < 1.5) return 'heat-3';
    if (score < 2.5) return 'heat-4';
    return 'heat-5';
}

/* ═══════════════════════════════════════════════
   GAUGE INIT
═══════════════════════════════════════════════ */

function buildGaugeSegments() {
    const wrap = document.getElementById('gauge-segments');
    if (!wrap) return;
    for (let i = 0; i < 10; i++) {
        const s = document.createElement('div');
        s.className = 'gs';
        wrap.appendChild(s);
    }
}

/* ═══════════════════════════════════════════════
   SESSION MANAGEMENT
═══════════════════════════════════════════════ */

function selectSession(session_id) {
    state.selectedSession = session_id;
    const select = document.getElementById('session-select');
    if (select) select.value = session_id;
    
    // Fetch and display snapshot
    if (session_id) {
        fetchSessionSnapshot(session_id);
        fetchAttackSummary(session_id);
        fetchSessionLogs(session_id);
    }
    
    // Clear displays on select change
    clearDashboard();
}

async function fetchSessionSnapshot(session_id) {
    try {
        const response = await fetch(`/snapshot/${session_id}`);
        if (!response.ok) throw new Error('Failed to fetch snapshot');
        const snap = await response.json();
        
        state.sessionData[session_id] = snap;
        
        // Update snapshot display
        const objEl = document.getElementById('snap-objective');
        if (objEl) objEl.textContent = snap.primary_objective || '—';
        
        const typeEl = document.getElementById('snap-type');
        if (typeEl) typeEl.textContent = snap.attacker_type || '—';
        
        const threatEl = document.getElementById('snap-threat');
        if (threatEl) threatEl.textContent = snap.threat_level || 'UNKNOWN';
        
        const cmdsEl = document.getElementById('snap-cmds');
        if (cmdsEl) cmdsEl.textContent = String(snap.commands_executed);
        
        const durationEl = document.getElementById('snap-duration');
        if (durationEl) durationEl.textContent = snap.session_duration;
        
        const techEl = document.getElementById('snap-techniques');
        if (techEl) techEl.textContent = String(snap.mitre_techniques.length);
    } catch (err) {
        console.warn('[ghost] snapshot fetch error:', err);
    }
}

async function fetchAttackSummary(session_id) {
    try {
        const response = await fetch(`/attack-summary/${session_id}`);
        if (!response.ok) throw new Error('Failed to fetch summary');
        const data = await response.json();
        
        const summaryEl = document.getElementById('summary-text');
        if (summaryEl) summaryEl.innerHTML = `<p>${esc(data.summary)}</p>`;
    } catch (err) {
        console.warn('[ghost] summary fetch error:', err);
    }
}

async function fetchSessionLogs(session_id, filter = 'all') {
    try {
        const response = await fetch(`/logs/${session_id}?event_type=${filter}&limit=500`);
        if (!response.ok) throw new Error('Failed to fetch logs');
        const data = await response.json();
        
        state.logsCache[session_id] = data.logs;
        displayLogs(data.logs);
    } catch (err) {
        console.warn('[ghost] logs fetch error:', err);
    }
}

function displayLogs(logs) {
    const tbody = document.getElementById('logs-tbody');
    if (!tbody) return;
    
    tbody.innerHTML = '';
    
    if (!logs || logs.length === 0) {
        const tr = document.createElement('tr');
        tr.innerHTML = '<td colspan="3" class="empty-msg">No logs available</td>';
        tbody.appendChild(tr);
        return;
    }
    
    logs.forEach(log => {
        const tr = document.createElement('tr');
        tr.innerHTML =
            `<td>${esc(log.timestamp)}</td>` +
            `<td>${esc(log.event_type)}</td>` +
            `<td>${esc(log.details)}</td>`;
        tbody.appendChild(tr);
    });
}

function handleVPNSecurityAlert(data) {
    if (!data) return;
    state.vpnFindings.push(data);
    if (state.vpnFindings.length > 200) {
        state.vpnFindings = state.vpnFindings.slice(-200);
    }
    renderVPNFindings(state.vpnFindings.slice(-30).reverse());
}

async function fetchVPNSecurityStatus() {
    try {
        const response = await fetch('/vpn-security/status');
        if (!response.ok) return;
        const status = await response.json();

        const runningEl = document.getElementById('vpn-running');
        if (runningEl) runningEl.textContent = status.running ? 'ONLINE' : 'OFFLINE';

        const intfEl = document.getElementById('vpn-interface');
        if (intfEl) intfEl.textContent = status.interface || '—';

        const countEl = document.getElementById('vpn-findings-count');
        if (countEl) countEl.textContent = String(status.findings_count || 0);

        const detRateEl = document.getElementById('vpn-detection-rate');
        const detectionRate = status?.vpn_detector?.detection_rate || 0;
        if (detRateEl) detRateEl.textContent = `${Math.round(detectionRate * 100)}%`;
    } catch (err) {
        console.warn('[ghost] vpn status fetch error:', err);
    }
}

async function fetchVPNSecurityFindings() {
    try {
        const response = await fetch('/vpn-security/recent?limit=30');
        if (!response.ok) return;
        const payload = await response.json();
        const findings = payload.findings || [];
        state.vpnFindings = findings;
        renderVPNFindings(findings.slice().reverse());
    } catch (err) {
        console.warn('[ghost] vpn findings fetch error:', err);
    }
}

function renderVPNFindings(findings) {
    const tbody = document.getElementById('vpn-findings-tbody');
    if (!tbody) return;

    tbody.innerHTML = '';
    if (!findings.length) {
        tbody.innerHTML = '<tr><td colspan="5" class="empty-msg">No VPN security findings.</td></tr>';
        return;
    }

    findings.forEach((f) => {
        const tr = document.createElement('tr');

        const riskSignals = [];
        if (f.vpn_detected) riskSignals.push('VPN');
        if (f.compromised) riskSignals.push('COMPROMISED');
        if ((f.leak_findings || []).length) riskSignals.push('LEAK');
        if ((f.misconfiguration_issues || []).length) riskSignals.push('MISCONFIG');
        if (f.anomaly_label === 'anomaly') riskSignals.push('ANOMALY');

        tr.innerHTML =
            `<td>${esc(formatTime(f.timestamp))}</td>` +
            `<td>${esc(f.src_ip || '—')} → ${esc(f.dst_ip || '—')}:${esc(f.dst_port ?? '—')}</td>` +
            `<td>${esc(f.protocol || 'Unknown')} (${Math.round((f.protocol_confidence || 0) * 100)}%)</td>` +
            `<td>${esc(riskSignals.join(', ') || 'none')}</td>` +
            `<td>${esc((f.zero_trust && f.zero_trust.action) || 'allow')}</td>`;
        tbody.appendChild(tr);
    });
}

function addSessionOption(session_id, source_ip, username) {
    const select = document.getElementById('session-select');
    if (!select) return;
    if (select.querySelector(`option[value="${session_id}"]`)) return; // Already there
    
    const opt = document.createElement('option');
    opt.value = session_id;
    opt.textContent = `${source_ip} (${username})`;
    select.appendChild(opt);
}

function updateSessionPill() {
    const active = Object.values(state.sessions).filter(s => s.status === 'active').length;
    const pill = document.getElementById('session-count');
    if (pill) pill.textContent = `${active} active`;
}

function clearDashboard() {
    state.cmdCount = 0;
    state.beaconCount = 0;
    state.mitreHits = {};
    state.tacticHits = {};
    state.prevRiskScore = 0;
    
    const cntEl = document.getElementById('cmd-count');
    if (cntEl) cntEl.textContent = '0 cmds';
    
    const bcnEl = document.getElementById('beacon-count');
    if (bcnEl) bcnEl.textContent = '0';
    
    const termEl = document.getElementById('terminal-output');
    if (termEl) termEl.innerHTML = '<div class="empty-state">Waiting for session…</div>';
    
    const tlineEl = document.getElementById('timeline-output');
    if (tlineEl) tlineEl.innerHTML = '<div class="empty-state">No events recorded.</div>';
    
    const beaconEl = document.getElementById('beacon-output');
    if (beaconEl) beaconEl.innerHTML = '<div class="empty-state">No canary triggers.</div>';
    
    // Clear snapshot
    const objEl = document.getElementById('snap-objective');
    if (objEl) objEl.textContent = '—';
    
    const typeEl = document.getElementById('snap-type');
    if (typeEl) typeEl.textContent = '—';
    
    const threatEl = document.getElementById('snap-threat');
    if (threatEl) threatEl.textContent = 'LOW';
    
    const cmdsEl = document.getElementById('snap-cmds');
    if (cmdsEl) cmdsEl.textContent = '0';
    
    const techEl = document.getElementById('snap-techniques');
    if (techEl) techEl.textContent = '0';
    
    // Clear intelligence
    const intelObjEl = document.getElementById('intel-objective');
    if (intelObjEl) intelObjEl.textContent = '—';
    
    const sophEl = document.getElementById('intel-soph');
    if (sophEl) sophEl.textContent = '—';
    
    const confEl = document.getElementById('intel-conf-pct');
    if (confEl) confEl.textContent = '—';
    
    // Clear risk gauge
    const scoreEl = document.getElementById('risk-score');
    if (scoreEl) scoreEl.textContent = '0';
    
    const fillEl = document.getElementById('risk-fill');
    if (fillEl) fillEl.style.width = '0%';
    
    const levelEl = document.getElementById('risk-level-label');
    if (levelEl) levelEl.textContent = 'LOW';
    
    // Clear AI Intelligence Panels
    const aiTypeEl = document.getElementById('ai-attacker-type');
    if (aiTypeEl) aiTypeEl.textContent = '—';
    
    const aiObjEl = document.getElementById('ai-primary-objective');
    if (aiObjEl) aiObjEl.textContent = '—';
    
    const aiSophEl = document.getElementById('ai-sophistication');
    if (aiSophEl) aiSophEl.textContent = '—';
    
    const aiConfEl = document.getElementById('ai-intent-confidence');
    if (aiConfEl) aiConfEl.textContent = '—';
    
    const aiReasonEl = document.getElementById('ai-intent-reasoning');
    if (aiReasonEl) aiReasonEl.textContent = '—';
    
    const aiScoreEl = document.getElementById('ai-threat-current');
    if (aiScoreEl) aiScoreEl.textContent = '0';
    
    const aiChangeEl = document.getElementById('ai-threat-change');
    if (aiChangeEl) {
        aiChangeEl.textContent = '—';
        aiChangeEl.className = 'ai-threat-change neutral';
    }
    
    const aiLevelEl = document.getElementById('ai-threat-level');
    if (aiLevelEl) {
        aiLevelEl.textContent = 'LOW';
        aiLevelEl.className = 'ai-threat-level low';
    }
    
    const aiAptEl = document.getElementById('ai-apt-likelihood');
    if (aiAptEl) aiAptEl.textContent = '—';
    
    const aiThreatReasonEl = document.getElementById('ai-threat-reasoning');
    if (aiThreatReasonEl) aiThreatReasonEl.textContent = '—';
    
    const aiTechListEl = document.getElementById('ai-mitre-techniques-list');
    if (aiTechListEl) aiTechListEl.innerHTML = '<div style="color: var(--text-dim); font-size: 11px; padding: 8px; text-align: center;">No techniques detected yet.</div>';
    
    const aiSummaryEl = document.getElementById('ai-summary-narrative');
    if (aiSummaryEl) {
        aiSummaryEl.textContent = '—';
        aiSummaryEl.className = 'ai-summary-narrative';
    }
    
    buildMitreGrid();
}

/* ═══════════════════════════════════════════════
   SESSION SELECTOR
═══════════════════════════════════════════════ */

/* ═══════════════════════════════════════════════
   INITIAL STATE SYNC (REST)
═══════════════════════════════════════════════ */

async function loadInitialSessions() {
    try {
        const resp = await fetch('/sessions');
        if (!resp.ok) return;
        const sessions = await resp.json();
        sessions.forEach(s => {
            state.sessions[s.session_id] = {
                source_ip: s.source_ip,
                username: s.username,
                status: s.status,
            };
            addSessionOption(s.session_id, s.source_ip, s.username);
        });
        updateSessionPill();
        // Auto-select first active
        const active = sessions.find(s => s.status === 'active') || sessions[0];
        if (active && !state.selectedSession) selectSession(active.session_id);
    } catch (e) {
        console.warn('[ghost] initial session sync failed:', e);
    }
}

/* ═══════════════════════════════════════════════
   DEMO MODE
═══════════════════════════════════════════════ */

async function runDemo(buttonId = 'demo-btn') {
    const btn = document.getElementById(buttonId);
    const companionBtn = buttonId === 'demo-btn' ? document.getElementById('demo-btn-top') : document.getElementById('demo-btn');
    if (!btn) return;
    const originalText = btn.textContent;
    btn.textContent = '⏳ Running Demo...';
    btn.disabled = true;
    if (companionBtn) {
        companionBtn.disabled = true;
    }
    
    try {
        // Call the new full demo script endpoint
        const response = await fetch('/api/demo/run-full-script', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
        });
        
        if (!response.ok) {
            throw new Error(`Demo failed: ${response.statusText}`);
        }
        
        const result = await response.json();
        
        if (result.status === 'success') {
            btn.textContent = '✓ Demo Complete!';
            
            // Display success notification
            showNotification(
                'Demo Script Completed Successfully',
                `Session: ${result.session_id.slice(0, 8)}...\n` +
                `Commands: ${result.commands_executed}\n` +
                `Threat Level: ${result.threat_level}\n` +
                `Risk Score: ${result.risk_score.toFixed(1)}`,
                'success'
            );
            
            // Display the intelligence report
            if (result.report) {
                displayIntelligenceReport(result.report, result.session_id);
            }
            
            // Refresh sessions and auto-focus the demo session in the UI.
            setTimeout(() => {
                loadInitialSessions();
                selectSession(result.session_id);
            }, 1000);
            
        } else {
            btn.textContent = '✗ Demo Failed';
            showNotification(
                'Demo Script Failed',
                result.message || result.error || 'Unknown error',
                'error'
            );
        }
        
    } catch (err) {
        console.error('[ghost] Demo script error:', err);
        btn.textContent = '✗ Demo Failed';
        showNotification(
            'Demo Script Error',
            err.message || 'Network or server error',
            'error'
        );
    } finally {
        // Reset button after 5 seconds
        setTimeout(() => {
            btn.textContent = originalText;
            btn.disabled = false;
            if (companionBtn) {
                companionBtn.disabled = false;
            }
        }, 5000);
    }
}

function showNotification(title, message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.innerHTML = `
        <div class="notification-header">
            <strong>${esc(title)}</strong>
            <button class="notification-close" onclick="this.parentElement.parentElement.remove()">×</button>
        </div>
        <div class="notification-body">${esc(message).replace(/\n/g, '<br>')}</div>
    `;
    
    // Add to page
    let container = document.getElementById('notification-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'notification-container';
        container.style.position = 'fixed';
        container.style.top = '80px';
        container.style.right = '20px';
        container.style.zIndex = '10000';
        document.body.appendChild(container);
    }
    
    container.appendChild(notification);
    
    // Auto-remove after 8 seconds
    setTimeout(() => {
        if (notification.parentElement) {
            notification.style.opacity = '0';
            notification.style.transform = 'translateX(400px)';
            setTimeout(() => notification.remove(), 300);
        }
    }, 8000);
}

function displayIntelligenceReport(report, sessionId) {
    // Create report modal/overlay
    const overlay = document.createElement('div');
    overlay.className = 'report-overlay';
    overlay.innerHTML = `
        <div class="report-modal">
            <div class="report-header">
                <h2>🎯 Intelligence Report</h2>
                <button class="report-close" onclick="this.closest('.report-overlay').remove()">×</button>
            </div>
            <div class="report-content">
                <div class="report-section">
                    <h3>Executive Summary</h3>
                    <p>${esc(report.executive_summary || 'No summary available')}</p>
                </div>
                
                ${report.techniques_used && report.techniques_used.length > 0 ? `
                <div class="report-section">
                    <h3>MITRE ATT&CK Techniques</h3>
                    <ul class="technique-list">
                        ${report.techniques_used.map(t => `
                            <li><strong>${esc(t.id || 'Unknown')}</strong>: ${esc(t.name || 'Unknown technique')}</li>
                        `).join('')}
                    </ul>
                </div>
                ` : ''}
                
                ${report.intent_analysis ? `
                <div class="report-section">
                    <h3>Intent Analysis</h3>
                    <p><strong>Attacker Type:</strong> ${esc(report.intent_analysis.attacker_type || 'Unknown')}</p>
                    <p><strong>Objective:</strong> ${esc(report.intent_analysis.primary_objective || 'Unknown')}</p>
                    <p><strong>Sophistication:</strong> ${esc(report.intent_analysis.sophistication_level || 'Unknown')}</p>
                </div>
                ` : ''}
                
                ${report.threat_score ? `
                <div class="report-section">
                    <h3>Threat Assessment</h3>
                    <p><strong>Risk Score:</strong> ${report.threat_score.risk_score || 0} / 100</p>
                    <p><strong>Threat Level:</strong> <span class="threat-badge threat-${(report.threat_score.threat_level || 'unknown').toLowerCase()}">${esc(report.threat_score.threat_level || 'UNKNOWN')}</span></p>
                </div>
                ` : ''}
                
                ${report.mitigation_suggestions && report.mitigation_suggestions.length > 0 ? `
                <div class="report-section">
                    <h3>Mitigation Recommendations</h3>
                    <ul class="mitigation-list">
                        ${report.mitigation_suggestions.map(m => `<li>${esc(m)}</li>`).join('')}
                    </ul>
                </div>
                ` : ''}
            </div>
            <div class="report-footer">
                <button class="btn-primary" onclick="downloadReport('${sessionId}')">Download Report</button>
                <button class="btn-secondary" onclick="this.closest('.report-overlay').remove()">Close</button>
            </div>
        </div>
    `;
    
    document.body.appendChild(overlay);
}

function downloadReport(sessionId) {
    // Trigger PDF download of the intelligence report
    window.open(`/report/${sessionId}/pdf`, '_blank');
}

/* report_generated ─────────────────────────────── */
function handleReportGenerated(sessionId, data) {
    const report = data.report;
    if (report) {
        displayIntelligenceReport(report, sessionId);
    }
}

/* session_closed ──────────────────────────────── */
function handleSessionClosed(sessionId, data) {
    if (state.sessions[sessionId]) {
        state.sessions[sessionId].status = 'closed';
    }
    updateSessionPill();

    // Add terminal notification
    const out = document.getElementById('terminal-output');
    const div = document.createElement('div');
    div.className = 't-entry';
    div.innerHTML = `<div style="color: #ff2d55; font-weight: bold;">
        [SESSION ENDED] Attacker disconnected — Duration: ${data.duration || 0}s | 
        Commands: ${data.command_count || 0} | Threat: ${esc(data.threat_level || 'UNKNOWN')} | 
        Risk: ${(data.risk_score || 0).toFixed(0)}/100
    </div>
    <div style="color: #00f0ff; margin-top: 4px;">
        📄 Intelligence report generated — <a href="/report/${sessionId}/pdf" target="_blank" 
        style="color: #00f0ff; text-decoration: underline; cursor: pointer;">Download PDF Report</a>
    </div>`;
    out.appendChild(div);
    out.scrollTop = out.scrollHeight;

    // Auto-fetch and display the report
    fetch(`/report/${sessionId}`)
        .then(r => r.json())
        .then(result => {
            if (result.report) {
                displayIntelligenceReport(result.report, sessionId);
            }
        })
        .catch(err => console.warn('[ghost] failed to fetch report:', err));
}

/* ═══════════════════════════════════════════════
   UI HELPERS
═══════════════════════════════════════════════ */

function setLive(online) {
    const el = document.getElementById('live-indicator');
    const text = document.getElementById('live-text');
    el.className = 'live-indicator ' + (online ? 'online' : 'offline');
    text.textContent = online ? 'LIVE' : 'OFFLINE';
}

function setText(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
}

function formatTime(iso) {
    if (!iso) return '--:--:--';
    try { return new Date(iso).toLocaleTimeString('en-GB', { hour12: false }); }
    catch { return iso.slice(11, 19) || '--:--:--'; }
}

function esc(str) {
    return String(str ?? '')
        .replace(/&/g, '&amp;').replace(/</g, '&lt;')
        .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function slugify(str) {
    return str.toLowerCase().replace(/[^a-z0-9]+/g, '-');
}

/* Clock */
function startClock() {
    const tick = () => {
        const now = new Date();
        document.getElementById('clock').textContent =
            now.toLocaleTimeString('en-GB', { hour12: false });
    };
    tick();
    setInterval(tick, 1000);
}

/* ═══════════════════════════════════════════════
   INIT
═══════════════════════════════════════════════ */

/* ═══════════════════════════════════════════════
   INITIALIZATION
═══════════════════════════════════════════════ */

document.addEventListener('DOMContentLoaded', () => {
    // Connect early so live updates can start even if some optional UI init fails.
    connect();

    // Tab switching
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const tabName = e.target.dataset.tab;
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            const tab = document.getElementById(tabName);
            if (tab) tab.classList.add('active');
            e.target.classList.add('active');
        });
    });

    // Logs filtering
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const { filter } = e.target.dataset;
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            e.target.classList.add('active');
            if (state.selectedSession) {
                fetchSessionLogs(state.selectedSession, filter);
            }
        });
    });

    // Session select
    const sessionSelect = document.getElementById('session-select');
    if (sessionSelect) {
        sessionSelect.addEventListener('change', (e) => {
            selectSession(e.target.value || null);
        });
    }

    // MITRE grid init
    buildMitreGrid();
    buildGaugeSegments();
    startClock();

    // Load initial sessions and connect
    loadInitialSessions();

    // VPN security polling
    fetchVPNSecurityStatus();
    fetchVPNSecurityFindings();
    setInterval(fetchVPNSecurityStatus, 8000);
    setInterval(fetchVPNSecurityFindings, 10000);
});

