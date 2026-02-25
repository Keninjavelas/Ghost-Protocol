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

const WS_URL = `ws://${location.host}/ws`;
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
    prevRiskScore: 0,
    cmdCount: 0,
    beaconCount: 0,
    mitreHits: {},            // technique_id → cumulative confidence
    tacticHits: {},            // tactic → cumulative confidence (for cell intensity)
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

    // Session events always processed (they update the selector itself)
    if (type === 'session') { handleSession(session_id, data); return; }

    // All other events filtered by selected session
    if (state.selectedSession && session_id !== state.selectedSession) return;

    switch (type) {
        case 'command': handleCommand(timestamp, data); break;
        case 'intent': handleIntent(data); break;
        case 'threat': handleThreat(data); break;
        case 'mitre': handleMitre(data); break;
        case 'timeline': handleTimeline(timestamp, data); break;
        case 'beacon': handleBeacon(timestamp, data); break;
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

/* intent ──────────────────────────────────────── */
function handleIntent(data) {
    const { attacker_type, primary_intent, sophistication, confidence } = data;
    setText('i-type', attacker_type ?? '—');
    setText('i-intent', primary_intent ?? '—');
    setText('i-soph', sophistication ?? '—');
    setText('i-conf', confidence != null ? `${Math.round(confidence * 100)}%` : '—');

    const pct = Math.round((confidence ?? 0) * 100);
    document.getElementById('conf-bar').style.width = pct + '%';
    document.getElementById('intent-conf-badge').textContent = pct + '%';
}

/* threat ──────────────────────────────────────── */
function handleThreat(data) {
    // Backend is sole authority for risk_score and threat_level — no frontend computation.
    const { risk_score, threat_level } = data;
    const score = parseFloat(risk_score) || 0;
    const level = (threat_level || 'LOW').toUpperCase();

    // Update score display
    document.getElementById('gauge-score').textContent = score.toFixed(1);

    // Update badge
    const badge = document.getElementById('threat-level-badge');
    badge.textContent = level;
    badge.className = 'panel-badge threat-badge ' + level.toLowerCase();

    // Animate segments
    const segs = document.querySelectorAll('.gs');
    const filled = Math.round(score);
    segs.forEach((s, i) => {
        s.className = 'gs';
        if (i < filled) {
            s.classList.add(i < 3 ? 'low' : i < 6 ? 'med' : 'high');
        }
    });

    // Escalation flash — only when score increases
    if (score > state.prevRiskScore) {
        const panel = document.getElementById('panel-threat');
        panel.classList.remove('escalating');
        void panel.offsetWidth; // reflow to restart animation
        panel.classList.add('escalating');
        setTimeout(() => panel.classList.remove('escalating'), 300);
    }
    state.prevRiskScore = score;
}

/* mitre ───────────────────────────────────────── */
function handleMitre(data) {
    const { tactic, technique_id, confidence } = data;
    const conf = parseFloat(confidence) || 0;

    // Accumulate per technique (cumulative, clamped at 3.0)
    state.mitreHits[technique_id] = Math.min((state.mitreHits[technique_id] || 0) + conf, 3.0);
    // Accumulate per tactic for cell intensity
    state.tacticHits[tactic] = Math.min((state.tacticHits[tactic] || 0) + conf, 3.0);

    updateMitreCell(tactic);
    updateMitreCount();
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
    // Count how many technique IDs map to this tactic
    const hits = Object.keys(state.mitreHits).length;

    // Assign heat class based on accumulated confidence
    cell.className = 'mc ' + heatClass(score);
    if (cnt) cnt.textContent = Math.ceil(score).toString();
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
    for (let i = 0; i < 10; i++) {
        const s = document.createElement('div');
        s.className = 'gs';
        wrap.appendChild(s);
    }
}

/* ═══════════════════════════════════════════════
   SESSION SELECTOR
═══════════════════════════════════════════════ */

function addSessionOption(session_id, source_ip, username) {
    const sel = document.getElementById('session-select');
    // Remove placeholder
    const ph = sel.querySelector('option[value=""]');
    if (ph) ph.remove();

    // Avoid duplicates
    if (document.getElementById('opt-' + session_id)) return;

    const opt = document.createElement('option');
    opt.id = 'opt-' + session_id;
    opt.value = session_id;
    opt.textContent = `${source_ip} (${username})`;
    sel.appendChild(opt);
}

function selectSession(session_id) {
    state.selectedSession = session_id;
    const sel = document.getElementById('session-select');
    sel.value = session_id;
}

function updateSessionPill() {
    const active = Object.values(state.sessions).filter(s => s.status === 'active').length;
    document.getElementById('session-count').textContent = `${active} active`;
}

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

async function runDemo() {
    const btn = document.getElementById('demo-btn');
    btn.textContent = '⏳ Running…';
    btn.disabled = true;
    try {
        await fetch('/ws-test');
    } finally {
        setTimeout(() => {
            btn.textContent = '▶ DEMO MODE';
            btn.disabled = false;
        }, 10000);
    }
}

/* ═══════════════════════════════════════════════
   UI HELPERS
═══════════════════════════════════════════════ */

function setLive(online) {
    const el = document.getElementById('live-indicator');
    const text = document.getElementById('live-text');
    el.className = 'live-indicator ' + (online ? 'live' : 'offline');
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

document.addEventListener('DOMContentLoaded', () => {
    buildMitreGrid();
    buildGaugeSegments();
    startClock();

    // Session change → update state filter
    document.getElementById('session-select').addEventListener('change', (e) => {
        state.selectedSession = e.target.value || null;
    });

    loadInitialSessions();
    connect();
});
