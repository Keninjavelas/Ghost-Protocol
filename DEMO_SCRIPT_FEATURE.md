# Demo Script Feature Documentation

## Overview
Added a "Run Demo Script" button to the Ghost Protocol dashboard that executes a complete attacker simulation and generates an intelligent security report.

## User Experience Flow

### 1. **Dashboard Button**
- Location: Attack Timeline panel header
- Label: "▶ Run Demo Script"
- Visual feedback:
  - "⏳ Running Demo..." while executing
  - "✓ Demo Complete!" on success
  - "✗ Demo Failed" on error

### 2. **Demo Execution**
The script simulates a realistic attacker session with 12 commands:

```
1. whoami                                      # Initial orientation
2. pwd                                          # Current location
3. uname -a                                    # System info
4. ls -la                                      # Directory listing
5. cat /etc/passwd                             # Credential recon
6. history                                     # Command history
7. ps aux                                      # Process discovery
8. netstat -tulpn                              # Network connections
9. find / -name '*password*' 2>/dev/null      # Credential hunting
10. cat /home/admin/.ssh/id_rsa               # SSH key access
11. cat /var/backups/customer_db.sql          # Database access
12. sudo su -                                  # Privilege escalation
```

Each command is processed through the full AI pipeline:
- Intent inference
- MITRE ATT&CK mapping
- Threat scoring
- Response generation
- Real-time dashboard updates via WebSocket

### 3. **Success Notification**
On completion, a notification displays:
- Session ID (truncated)
- Commands executed count
- Final threat level
- Final risk score

### 4. **Intelligence Report Modal**
A comprehensive report modal appears with sections:

#### **Executive Summary**
AI-generated narrative summary of the attack

#### **MITRE ATT&CK Techniques**
List of detected techniques with IDs and names

#### **Intent Analysis**
- Attacker type classification
- Primary objective
- Sophistication level assessment

#### **Threat Assessment**
- Risk score (0-100)
- Threat level badge (LOW/MEDIUM/HIGH/CRITICAL)

#### **Mitigation Recommendations**
Actionable security recommendations

### 5. **Report Actions**
- **Download Report**: Opens full report in new tab
- **Close**: Dismisses modal

## Technical Implementation

### Backend Endpoint
**POST** `/api/demo/run-full-script`

**Response:**
```json
{
  "status": "success",
  "session_id": "<uuid>",
  "commands_executed": 12,
  "source_ip": "203.0.113.42",
  "username": "admin",
  "threat_level": "HIGH",
  "risk_score": 85.3,
  "attacker_type": "professional",
  "primary_objective": "credential-harvesting",
  "report": {
    "executive_summary": "...",
    "techniques_used": [...],
    "intent_analysis": {...},
    "threat_score": {...},
    "mitigation_suggestions": [...]
  }
}
```

### Files Modified

#### Backend
- `dashboard/backend/routes.py`
  - Added `/api/demo/run-full-script` endpoint
  - Creates new session, processes commands, generates report

#### Frontend
- `dashboard/frontend/index.html`
  - Updated button text to "Run Demo Script"

- `dashboard/frontend/app.js`
  - Enhanced `runDemo()` function to call new endpoint
  - Added `showNotification()` for user feedback
  - Added `displayIntelligenceReport()` for report modal
  - Added `downloadReport()` for report download

- `dashboard/frontend/style.css`
  - Notification system styles
  - Report modal/overlay styles
  - Button and badge styles
  - Animations (slide-in, fade-in, slide-up)

## User Benefits

1. **One-Click Demo**: No need to manually SSH in or run commands
2. **Complete Pipeline Test**: Tests all AI components end-to-end
3. **Instant Report**: Generates and displays intelligence report immediately
4. **Visual Feedback**: Real-time notifications and progress indicators
5. **Professional Presentation**: Polished modal UI for showcasing to stakeholders/judges

## Demo Readiness

This feature is specifically designed for:
- Live demonstrations
- Stakeholder presentations
- System validation
- Competition judging scenarios
- Quick smoke testing

The entire demo completes in approximately **4-6 seconds**, making it perfect for timed presentations or rapid validation cycles.

## Usage

1. Ensure backend is running on port 8002
2. Open dashboard in browser
3. Locate "Run Demo Script" button in Attack Timeline panel
4. Click button
5. Watch real-time updates in dashboard
6. Review intelligence report in modal
7. Download or close report as needed

## Error Handling

- Network failures display error notification
- Backend failures return error status with details
- Failed commands are logged but don't block demo completion
- Report generation failures return safe fallback response

## Future Enhancements

Potential improvements for future iterations:
- Customizable command sequences
- Multiple demo scenarios (recon-only, exfiltration-focused, etc.)
- Export report to PDF/JSON
- Demo replay functionality
- Parameter customization (attacker IP, username, command set)
