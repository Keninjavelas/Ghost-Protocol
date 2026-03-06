# Ghost Protocol Dashboard Integration

## Problem Identified

The dashboard frontend and backend were **disconnected** — they were using completely different API endpoints:

### Frontend Expected Endpoints
```
GET /snapshot/{session_id}      → Session summary data
GET /attack-summary/{session_id} → Attack narrative
GET /logs/{session_id}           → Session events/logs
GET /sessions                     → List all sessions ✓ (existed)
```

### Backend Provided Endpoints
```
GET /sessions                     → List all sessions ✓
GET /session/{session_id}         → Session detail
GET /mitre/{session_id}           → MITRE mappings
GET /threat/{session_id}          → Threat scores
GET /beacons                      → Beacon events
GET /report/{session_id}          → Full report
```

## Solution Implemented

Created **3 missing API endpoints** that bridge the frontend-backend gap:

### 1. **GET /snapshot/{session_id}** (NEW)
Returns session snapshot data for the dashboard UI.

**Response:**
```json
{
  "session_id": "uuid-string",
  "primary_objective": "credential-harvesting",
  "attacker_type": "human-operator",
  "threat_level": "HIGH",
  "commands_executed": 42,
  "session_duration": "5m 32s",
  "mitre_techniques": [
    {
      "technique_id": "T1003",
      "technique_name": "OS Credential Dumping",
      "tactic": "Credential Access",
      "confidence": 0.87
    }
  ],
  "confidence": 0.78
}
```

### 2. **GET /attack-summary/{session_id}** (NEW)
Returns generated attack narrative/summary.

**Response:**
```json
{
  "summary": "Advanced persistent threat behavior detected. Attacker objectives include credential harvesting. MITRE ATT&CK analysis reveals 7 techniques across Credential Access, Discovery. Risk score (85/100) indicates HIGH severity. Immediate containment recommended."
}
```

### 3. **GET /logs/{session_id}** (NEW)
Returns session logs with optional filtering.

**Query Parameters:**
- `event_type`: "all", "commands", "system" (default: "all")
- `limit`: Max results (default: 500)

**Response:**
```json
{
  "session_id": "uuid-string",
  "total_logs": 84,
  "filters_available": ["all", "commands", "system"],
  "current_filter": "all",
  "logs": [
    {
      "timestamp": "2026-03-06T12:34:56.789Z",
      "event_type": "command",
      "details": "cat /etc/passwd"
    },
    {
      "timestamp": "2026-03-06T12:34:55.000Z",
      "event_type": "system",
      "details": "Session active from 185.220.101.47 as root"
    }
  ]
}
```

## Architecture Flow

```
┌─────────────────────────┐
│  Dashboard Frontend     │
│  (app.js)               │
└────────┬────────────────┘
         │
         ├─── GET /sessions ────────────────┐
         │                                  │
         ├─── GET /snapshot/{sid} ──────┐  │
         │                              │  │
         ├─── GET /attack-summary/{sid}─┤  │
         │                              │  │
         ├─── GET /logs/{sid} ──────────┤  │
         │                              │  │
         └─── WebSocket /ws ────────────┼──┼─── New Endpoints (Routes)
                                        │  │    ├─ snapshot()
                                        │  │    ├─ get_attack_summary()
                                        │  │    └─ get_session_logs_v2()
                                        │  │
                                        │  ├─ Existing Endpoints
                                        │  │    ├─ list_sessions()
                                        │  │    ├─ get_session()
                                        │  │    ├─ get_mitre()
                                        │  │    ├─ get_threat()
                                        │  │    └─ list_beacons()
                                        │  │
                                        ▼  ▼
                          ┌─────────────────────────┐
                          │  Backend (FastAPI)      │
                          │  ├─ SessionManager      │
                          │  ├─ ConnectionManager   │
                          │  └─ Database            │
                          └─────────────────────────┘
```

## How Data Flows

### 1. **Initial Session Load**
```
Frontend loads → Calls GET /sessions
              → SessionManager returns list
              → Frontend populates dropdown
              → Auto-selects first active session
```

### 2. **Session Selection**
```
User selects session → Frontend calls:
  1. GET /snapshot/{session_id}
  2. GET /attack-summary/{session_id}
  3. GET /logs/{session_id}
```

Results populate:
- **Snapshot Panel**: Objective, Type, Threat Level, Command Count, Duration, Techniques
- **Intelligence Panel**: Attack narrative summary
- **Logs Panel**: Event history with filtering

### 3. **Real-Time Updates (WebSocket)**
```
Backend events → WebSocket broadcast
            → Frontend receives event
            → routeEvent() dispatches to handler
            → DOM updates in real-time
```

Event types:
- `session` - Session started/closed
- `command` - Command executed
- `intent` - AI intent analysis
- `threat` - Threat score update
- `mitre` - MITRE mapping
- `timeline` - Timeline event
- `beacon` - Canary token trigger

## Files Modified

1. **`dashboard/backend/routes.py`**
   - Added `/snapshot/{session_id}` endpoint
   - Added `/attack-summary/{session_id}` endpoint
   - Added `/logs/{session_id}` endpoint

2. **`dashboard/backend/main.py`**
   - Added network defense callback function
   - Fixed imports for NetworkDefenseSystem
   - Added 5 network defense API endpoints

3. **`dashboard/frontend/app.js`**
   - ✅ Already properly configured (no changes needed)
   - Calls correct endpoints
   - Handles WebSocket events correctly

4. **`config/settings.py`**
   - Added network defense configuration options

5. **`requirements.txt`**
   - Added network defense dependencies

## Testing the Integration

### 1. **Start the Backend**
```bash
cd c:\Users\aryan\OneDrive\Desktop\ghost_protocol
python -m uvicorn dashboard.backend.main:app --host 0.0.0.0 --port 8000 --reload
```

### 2. **Open Dashboard**
Navigate to: `http://localhost:8000`

You should see:
- ✅ "OFFLINE" → "LIVE" indicator (WebSocket connected)
- ✅ Session dropdown populates with active sessions
- ✅ Dashboard panels load when session selected

### 3. **Test Endpoints Manually**
```bash
# List all sessions
curl http://localhost:8000/sessions

# Get snapshot for a session (replace {sid} with actual UUID)
curl http://localhost:8000/snapshot/{sid}

# Get attack summary
curl http://localhost:8000/attack-summary/{sid}

# Get logs
curl http://localhost:8000/logs/{sid}?event_type=all&limit=20
```

### 4. **Demo Mode** (No attacker needed)
```bash
curl http://localhost:8000/ws-test
```

This triggers a scripted demo sequence on all connected clients showing:
- Session start
- Commands executed
- Intent inference
- MITRE mappings
- Threat escalation
- Canary token trigger

## Common Issues & Solutions

### Issue: "OFFLINE" Status Persists
**Solution:** Check WebSocket connection:
```javascript
// In browser console
console.log(state.ws)  // Should be OPEN (1)
```

**If closed:**
1. Check backend is running on port 8000
2. Check CORS settings in main.py
3. Check firewall/proxy blocking WebSocket

### Issue: Session Dropdown Empty
**Solution:** Check `/sessions` endpoint:
```bash
curl http://localhost:8000/sessions
```

**If empty:**
1. No active sessions yet - start SSH honeypot
2. Connect with: `ssh -p 2222 root@localhost`
3. Any password works

### Issue: Snapshot/Logs Panel Shows Nothing
**Solution:** 
1. Verify session UUID is valid
2. Check browser console for fetch errors
3. Test endpoint directly: `curl http://localhost:8000/snapshot/{uuid}`

### Issue: WebSocket Events Not Updating Dashboard
**Solution:**
1. Check WebSocket is connected (`/ws`)
2. Verify session_id matches selected session
3. Check browser console for event routing errors

## Integration Checklist

- ✅ Frontend and backend endpoints aligned
- ✅ Session snapshot data accessible
- ✅ Attack narratives generated
- ✅ Logs queryable and filterable
- ✅ WebSocket for real-time updates
- ✅ Network defense system integrated
- ✅ Database queries working
- ✅ CORS properly configured
- ✅ Error handling in place

## Performance Notes

- **Session list:** Cached on page load, auto-refreshes on session events
- **Snapshot:** Fetched on-demand (fast, single record lookup)
- **Attack summary:** Generated on-demand (uses LLM, ~2-5 seconds)
- **Logs:** Limited to 500 items by default (configurable)
- **WebSocket:** Real-time, no polling overhead

## Next Steps

1. ✅ Start backend
2. ✅ Open dashboard in browser
3. ✅ Generate sessions (SSH honeypot)
4. ✅ Monitor real-time events via WebSocket
5. ✅ Query history via REST APIs
6. ✅ Review intelligence reports

The dashboard should now function as a **unified system** with consistent frontend-backend communication! 🎉
