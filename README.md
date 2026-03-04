# Ghost Protocol — AI Deception & Attribution Engine

**An AI-driven cyber deception platform that transforms attacker intrusions into actionable threat intelligence.**

---

## 🎯 The Problem

Traditional security tools detect attacks **after damage occurs**. They rely on known signatures, behavioral baselines, and reactive alerting — all of which assume defenders are permanently on the back foot.

**Ghost Protocol takes a different approach:**

Instead of blocking or ignoring intrusion attempts, Ghost Protocol **invites attackers in** — and transforms every command they execute into structured intelligence. By deploying high-fidelity deception environments and routing attacker activity through an AI inference pipeline, the platform converts hostile reconnaissance into real-time threat attribution.

> **From passive detection → to active intelligence gathering**

---

## ✨ Key Features

Ghost Protocol delivers enterprise-grade cyber deception intelligence through eight core capabilities:

| Feature | Description |
|---------|-------------|
| 🪤 **SSH Deception Gateway** | Full SSH honeypot accepting any credentials, capturing attacker fingerprints and TTPs |
| 🧠 **AI-Driven Intent Inference** | Local LLM analyzes commands to infer attacker objectives and sophistication level |
| 🗺️ **MITRE ATT&CK Behavior Mapping** | Automatic classification of observed techniques to ATT&CK tactics (T1552, T1005, etc.) |
| 📊 **Dynamic Threat Scoring** | Real-time risk assessment updated per command with escalation rules |
| 🎭 **Adaptive Deception Environment** | AI shapes fake filesystem to match attacker profile and sustain engagement |
| 🔦 **Canary Token Tracking** | Planted credentials, URLs, and files that beacon home when accessed |
| 📡 **Live SOC Dashboard** | WebSocket-powered real-time interface with session timelines and MITRE heatmaps |
| 📋 **Automated Attribution Reports** | Full intelligence reports generated per session with threat narrative |

---

## 🏗️ Architecture

Ghost Protocol operates as a multi-stage AI inference pipeline:

```
┌─────────────┐
│   Attacker  │
│ (SSH Client)│
└──────┬──────┘
       │ ssh -p 2222 root@server
       ▼
┌─────────────────────────────────┐
│   SSH Honeypot Gateway          │
│   • Accept any credentials      │
│   • Log connection metadata     │
│   • Simulate Ubuntu 22.04 shell │
└──────┬──────────────────────────┘
       │
       ▼
┌─────────────────────────────────┐
│   Command Interceptor           │
│   • Capture every command       │
│   • Route to AI pipeline        │
│   • Never execute real code     │
└──────┬──────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────────────────────┐
│         AI Intelligence Core (Ollama + LLaMA)            │
│  ┌───────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │ Intent        │  │ Environment  │  │ MITRE ATT&CK │  │
│  │ Inference     │  │ Shaper       │  │ Mapper       │  │
│  └───────────────┘  └──────────────┘  └──────────────┘  │
│  ┌───────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │ Threat        │  │ Response     │  │ Report       │  │
│  │ Scorer        │  │ Generator    │  │ Generator    │  │
│  └───────────────┘  └──────────────┘  └──────────────┘  │
└────────┬─────────────────────────┬───────────────────────┘
         │                         │
         ▼                         ▼
┌──────────────────┐      ┌──────────────────┐
│  Telemetry &     │      │  Response to     │
│  Database        │      │  Attacker        │
│  • PostgreSQL    │      │  (Fake shell)    │
│  • Session logs  │      └──────────────────┘
│  • MITRE events  │
└────────┬─────────┘
         │
         ▼
┌──────────────────────────────────┐
│   Dashboard (FastAPI + WebSockets) │
│   • Real-time session monitoring   │
│   • MITRE technique visualization  │
│   • Threat score timeline          │
│   • Intelligence report viewer     │
└────────────────────────────────────┘
```

### Key Subsystems

**1. SSH Gateway (`gateway/`)**
- AsyncSSH-based honeypot listening on port 2222
- Accepts all authentication attempts (any username/password)
- Logs connection metadata (IP, credentials attempted, client fingerprint)
- Presents realistic Ubuntu 22.04 LTS terminal environment

**2. Command Interceptor (`interception/`)**
- Captures every command typed by the attacker
- Routes commands through the AI pipeline
- Returns simulated terminal output (never executes real code)
- Maintains session state and command history

**3. AI Intelligence Core (`ai_core/`)**
- **Intent Inference**: LLM analyzes command patterns to determine attacker objectives
- **Environment Shaper**: Dynamically populates fake filesystem with believable data
- **MITRE Mapper**: Classifies commands to ATT&CK techniques (T1552.001, T1005, etc.)
- **Threat Scorer**: Computes risk score (0-100) with escalation rules
- **Response Generator**: Creates realistic terminal output
- **Report Generator**: Produces structured attribution intelligence

**4. Session Manager (`session/`)**
- Tracks all active attacker sessions
- Maintains threat profiles per session
- Coordinates Docker sandbox lifecycle
- Triggers automatic report generation on disconnect

**5. Deception Environment**
- Preloaded corporate filesystem with trap files:
  - AWS credentials (`/root/.aws/credentials`)
  - Database backups (`/var/backups/customer_db.sql`)
  - Kubernetes configs (`/home/devops/kubeconfig.yaml`)
  - Deployment scripts with embedded passwords
  - Employee payroll data, HR records
- Deterministic directory listings for demo reliability
- Canary tokens embedded in sensitive files

**6. Dashboard (`dashboard/`)**
- FastAPI backend with WebSocket support
- Real-time event streaming (command execution, threat escalation, MITRE mappings)
- Session timeline visualization
- Threat score gauge and MITRE heatmap
- Intelligence report viewer

**7. Telemetry & Persistence (`database/`, `telemetry/`)**
- PostgreSQL for session persistence
- Structured JSON logging via structlog
- Beacon tracking for canary token activations
- Full audit trail for attribution analysis

---

## 🎭 Example Attack Scenario

**Setup:** Security researcher connects to the honeypot to test the system.

### Step 1: Initial Connection

```bash
$ ssh -p 2222 root@demo.ghostprotocol.local
root@demo.ghostprotocol.local's password: [any password works]

Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)

Last login: Mon Mar  4 09:45:12 2026 from 192.168.1.100
root@ip-10-0-4-12:~# 
```

**What Ghost Protocol detects:**
- ✅ Connection logged (IP: 192.168.1.100, username: root)
- ✅ Session created with unique ID
- ✅ Fake filesystem preloaded with 25+ trap files

---

### Step 2: Reconnaissance

```bash
root@ip-10-0-4-12:~# ls -la
drwxr-xr-x  2 root root     4096 Mar  4 10:30 .aws
drwxr-xr-x  2 root root     4096 Mar  4 10:30 .docker
drwxr-xr-x  2 root root     4096 Mar  4 10:30 .ssh
-rw-------  2 root root     2048 Mar  4 10:30 .bash_history

root@ip-10-0-4-12:~# cd /home/admin
root@ip-10-0-4-12:/home/admin# ls
.env  passwords.txt

root@ip-10-0-4-12:/home/admin# cat passwords.txt
# Production Server Credentials
# DO NOT SHARE EXTERNALLY

admin:HP_DEMO_AdminPassword_7F8E
backup_user:HP_DEMO_BackupPassword_3C4D
database_admin:HP_DEMO_MYSQL_PASSWORD_91A2
```

**What Ghost Protocol detects:**
- ✅ **Command Classification**: `ls`, `cd`, `cat` — Information Discovery
- ✅ **Intent Inference**: Attacker type: `opportunistic_attacker`, Objective: `credential_harvesting`
- ✅ **MITRE Mapping**: **T1552.001** (Unsecured Credentials: Credentials In Files)
- ✅ **Threat Escalation**: Risk score increases from 25 → 50 (+25 per credential file)
- ✅ **Dashboard Alert**: 🔴 "Credential access detected: /home/admin/passwords.txt"

**Note:** All credentials use the `HP_DEMO_` prefix — synthetic honeypot credentials that won't trigger GitHub secret scanning.

---

### Step 3: Database Exfiltration Attempt

```bash
root@ip-10-0-4-12:/home/admin# cd /var/backups
root@ip-10-0-4-12:/var/backups# ls
customer_db.sql  db_backup.sql  migrations

root@ip-10-0-4-12:/var/backups# cat customer_db.sql | head -20
-- Customer Database Backup
-- WARNING: Contains PII - Handle with care

INSERT INTO customers (id, email, password_hash, full_name, credit_card_last4) VALUES
(1, 'john.doe@example.com', 'hashed_pw_1', 'John Doe', '4532'),
(2, 'alice@company.com', 'hashed_pw_2', 'Alice Smith', '8765'),
(3, 'bob@financecorp.com', 'hashed_pw_3', 'Bob Johnson', '2198');
```

**What Ghost Protocol detects:**
- ✅ **MITRE Mapping**: **T1005** (Data from Local System)
- ✅ **Threat Escalation**: Risk score 50 → 75 → **CRITICAL**
- ✅ **Sophistication Assessment**: Upgraded to `medium` (targets database backups)
- ✅ **Dashboard Alert**: 🔴 "PII exfiltration attempt: customer_db.sql"

---

### Step 4: Session Termination & Report Generation

```bash
root@ip-10-0-4-12:/var/backups# exit
Connection to demo.ghostprotocol.local closed.
```

**What Ghost Protocol delivers:**

Automatic intelligence report generated with:

```json
{
  "session_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "duration": "8m 47s",
  "source_ip": "192.168.1.100",
  "threat_assessment": {
    "risk_score": 75,
    "threat_level": "CRITICAL",
    "attacker_type": "opportunistic_attacker",
    "sophistication": "medium",
    "primary_objective": "credential_harvesting"
  },
  "mitre_techniques": [
    {"id": "T1552.001", "name": "Unsecured Credentials: Credentials In Files", "confidence": 1.0},
    {"id": "T1005", "name": "Data from Local System", "confidence": 0.95}
  ],
  "credential_theft_timeline": [
    {"timestamp": "2026-03-04T10:30:15Z", "file": "/home/admin/passwords.txt"},
    {"timestamp": "2026-03-04T10:32:08Z", "file": "/var/backups/customer_db.sql"}
  ],
  "commands_executed": 12,
  "intelligence_summary": "Attacker demonstrated opportunistic credential harvesting behavior. Targeted password files and database backups containing PII. Moderate technical sophistication evidenced by direct navigation to /var/backups."
}
```

📊 **Report persisted to PostgreSQL**  
📡 **Dashboard updated with session summary**  
🔔 **SOC team receives structured alert**

---

## 🛠️ Technology Stack

Ghost Protocol is built with production-grade infrastructure:

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Language** | Python 3.11+ | Core platform implementation |
| **Web Framework** | FastAPI | Dashboard API with async support |
| **Database** | PostgreSQL 16 | Session persistence & telemetry storage |
| **Caching** | Redis | (Future) WebSocket pub/sub for multi-node scale |
| **AI Inference** | Ollama + LLaMA 3 | Local LLM for intent inference & MITRE mapping |
| **SSH Server** | AsyncSSH | High-performance async SSH honeypot |
| **Real-time Comms** | WebSockets | Live dashboard event streaming |
| **Containerization** | Docker + Docker Compose | Isolated attacker sandboxes |
| **ORM** | SQLAlchemy 2.0 | Async database operations |
| **Logging** | structlog | Structured JSON telemetry |
| **Migrations** | Alembic | Database schema versioning |

---

## 📸 Screenshots

### Dashboard Overview
![Dashboard placeholder - Real-time session monitoring with threat timeline](docs/images/dashboard-overview.png)

*Real-time session monitoring showing active attacker connections, threat scores, and command timelines*

---

### MITRE ATT&CK Heatmap
![MITRE heatmap placeholder - Technique frequency visualization](docs/images/mitre-heatmap.png)

*MITRE ATT&CK technique distribution across all sessions with confidence scoring*

---

### Threat Timeline
![Threat timeline placeholder - Chronological threat escalation](docs/images/threat-timeline.png)

*Session threat score progression showing escalation triggers and credential access events*

---

### Intelligence Report
![Report placeholder - Structured attribution report](docs/images/intelligence-report.png)

*Automated attribution report with session summary, MITRE mappings, and threat narrative*

---

## 🚀 Demo Instructions for Judges

**Objective:** Experience Ghost Protocol's threat intelligence pipeline by acting as an attacker.

### Prerequisites

Ensure the Ghost Protocol platform is running:
- ✅ PostgreSQL database online
- ✅ Ollama LLM service running (`ollama serve`)
- ✅ Dashboard API running on port 8000
- ✅ SSH honeypot listening on port 2222

### Demo Workflow

#### 1. Open the Dashboard

Navigate to: **http://localhost:8000**

You should see:
- Sessions panel (currently empty)
- Live threat score gauge
- MITRE technique tracker
- Event timeline

---

#### 2. Connect via SSH

**From another machine or terminal:**

```bash
ssh -p 2222 root@<honeypot-ip>
```

**Enter ANY password** — all credentials are accepted.

You'll see a realistic Ubuntu server prompt:
```bash
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)
root@ip-10-0-4-12:~# 
```

---

#### 3. Explore the Environment

Try these reconnaissance commands:

```bash
# Basic enumeration
whoami
pwd
uname -a
ls -la

# Discover sensitive directories
cd /root
ls -la
cd /home/admin
ls
cd /var/backups
ls -la
```

**Watch the dashboard** — it updates in real-time as you type commands!

---

#### 4. Attempt to Steal Credentials

Access high-value trap files:

```bash
# AWS credentials
cat /root/.aws/credentials

# Plain text passwords
cat /home/admin/passwords.txt

# Database with customer PII
cat /var/backups/customer_db.sql

# Kubernetes cluster access
cat /home/devops/kubeconfig.yaml

# Deployment script with embedded passwords
cat /opt/company/devops/deploy.sh
```

**Observe the dashboard:**
- 🔴 Red alerts appear for each credential file accessed
- 📊 Threat score escalates (+25 per file)
- 🗺️ MITRE techniques populate (T1552.001, T1005)
- 📈 Session timeline updates

---

#### 5. Disconnect and Review Intelligence

```bash
exit
```

**On the dashboard:**
- Session moves to "Completed" status
- Click "View Report" to see full intelligence analysis
- Review:
  - Threat assessment (risk score, sophistication level)
  - MITRE technique breakdown
  - Credential theft timeline
  - AI-generated threat narrative

---

### Expected Demo Results

After completing the attack simulation:

| Metric | Expected Value |
|--------|---------------|
| **Risk Score** | 75-100 (CRITICAL) |
| **MITRE Techniques Detected** | 3-5 techniques |
| **Credential Files Accessed** | 3+ files |
| **Attacker Classification** | Opportunistic → Medium sophistication |
| **Session Duration** | 5-10 minutes |
| **Intelligence Report** | Auto-generated with full attribution |

---

## 🔬 Research Vision

Ghost Protocol represents a **paradigm shift** in cybersecurity — from reactive detection to **proactive intelligence gathering**.

### Current State

The platform demonstrates:
- ✅ AI-driven attacker profiling at the command level
- ✅ Real-time MITRE ATT&CK classification
- ✅ Automated threat intelligence report generation
- ✅ Dynamic deception environment adaptation
- ✅ Production-ready single-node deployment

### Future Research Directions

#### 1. Multi-Node Distributed Deception Networks
- Deploy Ghost Protocol across multiple cloud regions
- Create interconnected deception environments
- Share threat intelligence across deployment clusters
- Implement global attacker tracking

#### 2. Advanced Behavioral Modeling
- Long-term attacker campaign tracking
- Session correlation across multiple connection attempts
- Predictive models for attacker next-move inference
- Automated adversary playbook generation

#### 3. Enterprise SIEM Integration
- Splunk, Sentinel, QRadar connectors
- Structured alert forwarding (CEF, STIX/TAXII)
- Bi-directional threat feed enrichment
- SOC workflow automation

#### 4. Autonomous Re-Engagement
- Automated lure generation based on attacker profile
- Dynamic credential rotation in trap files
- Adaptive difficulty scaling to sustain engagement
- Canary token callback analysis

#### 5. Research Applications
- Academic publication on AI-assisted deception
- Open datasets of anonymized attacker sessions
- Benchmarking against traditional honeypot solutions
- Contribution to MITRE ATT&CK knowledge base

---

## 📁 Project Structure

```
ghost_protocol/
├── gateway/                    # SSH honeypot server
│   ├── ssh_server.py          # AsyncSSH gateway (port 2222)
│   └── auth_handler.py        # Accept-all authentication
│
├── session/                    # Session lifecycle management
│   ├── session_manager.py     # Thread-safe session coordinator
│   └── session_model.py       # Runtime session state
│
├── interception/               # Command processing pipeline
│   └── command_interceptor.py # AI pipeline orchestrator
│
├── ai_core/                    # AI intelligence engine
│   ├── llm_client.py          # Ollama API wrapper
│   ├── intent_inference.py    # Attacker intent classification
│   ├── environment_shaper.py  # Dynamic filesystem generation
│   ├── mitre_mapper.py        # ATT&CK technique mapping
│   ├── threat_scorer.py       # Risk score calculation
│   ├── response_generator.py  # Terminal output simulation
│   ├── report_generator.py    # Attribution report generation
│   ├── bait_files.py          # Credential trap definitions
│   └── mitre_registry.py      # Valid ATT&CK technique IDs
│
├── sandbox/                    # Docker container manager
│   └── docker_manager.py      # Isolated attacker environments
│
├── tracking/                   # Canary token system
│   ├── canary_manager.py      # Token generation & tracking
│   └── beacon_listener.py     # HTTP callback handler
│
├── telemetry/                  # Structured logging
│   └── logger.py              # JSON telemetry with structlog
│
├── database/                   # Data persistence
│   ├── db.py                  # Async SQLAlchemy engine
│   └── models.py              # ORM models (Session, Command, etc.)
│
├── dashboard/                  # Web interface
│   ├── backend/
│   │   ├── main.py            # FastAPI application
│   │   ├── routes.py          # REST API endpoints
│   │   └── websocket.py       # Real-time event streaming
│   └── frontend/
│       ├── index.html         # Dashboard UI
│       ├── app.js             # WebSocket client
│       └── style.css          # Styling
│
├── config/                     # Configuration
│   ├── settings.py            # Pydantic settings model
│   └── ssh_host_rsa_key       # SSH server key (generated)
│
├── alembic/                    # Database migrations
│   ├── env.py
│   └── versions/
│
├── docker-compose.yml          # Infrastructure stack
├── Dockerfile                  # Honeypot container image
├── requirements.txt            # Python dependencies
├── alembic.ini                 # Migration configuration
└── README.md                   # This file
```

---

## 🚀 Quickstart

### Prerequisites

Before deploying Ghost Protocol, ensure you have:

- **Docker Desktop** (for PostgreSQL and sandbox management)
- **Ollama** with LLaMA model: `ollama pull llama3`
- **Python 3.11+** with pip and venv support
- **SSH client** (for testing the honeypot)

---

### Installation Steps

#### 1. Clone the Repository

```bash
git clone https://github.com/Keninjavelas/Ghost-Protocol.git
cd Ghost-Protocol
```

---

#### 2. Generate SSH Host Key

The SSH gateway requires a server key:

```bash
python -c "import asyncssh; asyncssh.generate_private_key('ssh-rsa').write_private_key('config/ssh_host_rsa_key')"
```

**⚠️ Security Note:** Never commit `ssh_host_rsa_key` to version control! It's already in `.gitignore`.

---

#### 3. Start Infrastructure

Launch PostgreSQL and Redis via Docker Compose:

```bash
docker-compose up -d postgres redis
```

Verify containers are running:

```bash
docker ps
```

You should see `postgres` and `redis` containers active.

---

#### 4. Set Up Python Environment

Create virtual environment and install dependencies:

**Windows:**
```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

**macOS/Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

#### 5. Initialize Database

Run Alembic migrations to create tables:

```bash
alembic upgrade head
```

Expected output:
```
INFO  [alembic.runtime.migration] Running upgrade -> a1b2c3d4, Initial schema
INFO  [alembic.runtime.migration] Running upgrade a1b2c3d4 -> e5f6g7h8, Add reports table
```

---

#### 6. Configure Environment (Optional)

Default settings work out-of-the-box. To customize, create `.env`:

```bash
cp .env.example .env
```

Edit `.env` to modify:
- `OLLAMA_MODEL`: LLM model name (default: `llama3`)
- `SSH_PORT`: Honeypot listen port (default: `2222`)
- `POSTGRES_PORT`: Database port (default: `5433`)

---

#### 7. Start the Platform

Open **three separate terminals** (all with venv activated):

**Terminal 1 — Start Ollama:**
```bash
ollama serve
```

**Terminal 2 — Start Dashboard API:**
```bash
uvicorn dashboard.backend.main:app --host 0.0.0.0 --port 8000 --reload
```

**Terminal 3 — Start SSH Honeypot:**
```bash
python -m gateway.ssh_server
```

---

#### 8. Verify Installation

**Check Dashboard:**
- Open browser: **http://localhost:8000**
- You should see the Ghost Protocol dashboard

**Check API Docs:**
- Open browser: **http://localhost:8000/docs**
- FastAPI interactive documentation

**Test SSH Connection:**
```bash
ssh -p 2222 root@localhost
```

Enter any password — you'll see:
```
Welcome to Ubuntu 22.04.3 LTS
root@ip-10-0-4-12:~# 
```

**🎉 Ghost Protocol is now running!**

---

### Quick Test Commands

Once connected to the honeypot, try:

```bash
whoami              # Returns: root
pwd                 # Returns: /root
uname -a            # Returns: Ubuntu 22.04 system info
ls -la              # Shows directory with trap files
cat .aws/credentials   # Triggers credential theft detection
```

Watch the dashboard at **http://localhost:8000** for real-time alerts!

---

## ⚙️ Configuration Reference

All settings are managed via environment variables (`.env` file):

| Variable | Default | Description |
|----------|---------|-------------|
| `OLLAMA_BASE_URL` | `http://localhost:11434/v1` | Ollama API endpoint |
| `OLLAMA_MODEL` | `llama3` | LLM model for AI inference |
| `POSTGRES_HOST` | `localhost` | PostgreSQL hostname |
| `POSTGRES_PORT` | `5433` | PostgreSQL port (avoids conflict with system installs) |
| `POSTGRES_USER` | `ghost` | Database username |
| `POSTGRES_PASSWORD` | `ghost123` | Database password |
| `POSTGRES_DB` | `ghost_protocol` | Database name |
| `SSH_PORT` | `2222` | Honeypot SSH listen port |
| `SSH_HOST_KEY` | `config/ssh_host_rsa_key` | SSH server private key path |
| `DASHBOARD_PORT` | `8000` | Dashboard API port |
| `BEACON_BASE_URL` | `http://localhost:8000/beacon` | Canary token callback URL |
| `LOG_LEVEL` | `INFO` | Logging verbosity (DEBUG, INFO, WARNING, ERROR) |

---

## 🔒 Security Considerations

Ghost Protocol is a **controlled deception environment** — security is paramount:

### ✅ What Ghost Protocol Does

- Accepts SSH connections on a non-standard port (2222)
- Never executes attacker commands on the host system
- Isolates attackers in Docker sandboxes with `--network none`
- Logs all activity to structured telemetry
- Generates threat intelligence reports

### ⚠️ What Ghost Protocol Does NOT Do

- **Does not provide shell access to the host OS**
- **Does not execute arbitrary code**
- **Does not expose production credentials** (all trap files contain fake data)
- **Does not connect to external networks from sandboxes**

### 🔐 Synthetic Credential System

Ghost Protocol uses **honeypot-safe synthetic credentials** that appear realistic to attackers but are cryptographically safe and non-functional:

**Why Synthetic Credentials?**

Traditional honeypots that use realistic-looking fake credentials (e.g., AWS keys starting with `AKIA`, Stripe keys with `sk_live_`, GitHub tokens with `ghp_`) face critical problems:

1. **GitHub Secret Scanning**: Pushing code with realistic credential patterns triggers GitHub's secret scanning and blocks commits
2. **False Positives**: Security tools flag these as real leaked credentials
3. **Accidental Use**: Realistic-looking credentials might be mistakenly used against production services
4. **Legal Risk**: Credentials resembling real formats could be misinterpreted as actual leaked secrets

**Our Solution: HP_DEMO_ Prefix**

All credentials in Ghost Protocol use the `HP_DEMO_` (Honeypot Demo) prefix:

```python
# Traditional approach (BLOCKED by GitHub):
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE  ❌ Triggers secret scanning

# Ghost Protocol approach (SAFE):
AWS_ACCESS_KEY_ID=HP_DEMO_AWS_ACCESS_KEY_7A3F19  ✅ Safe for Git commits
```

**Example Synthetic Credentials:**

| Credential Type | Format | Example |
|----------------|--------|---------|
| AWS Access Key | `HP_DEMO_AWS_ACCESS_KEY_<hex>` | `HP_DEMO_AWS_ACCESS_KEY_91F2A7` |
| API Keys | `HP_DEMO_<SERVICE>_KEY_<hex>` | `HP_DEMO_STRIPE_KEY_8F7E6D` |
| Database Password | `HP_DEMO_<DB>_PASSWORD_<hex>` | `HP_DEMO_MYSQL_PASSWORD_3C4D5E` |
| JWT Secret | `HP_DEMO_JWT_SECRET_<hex>` | `HP_DEMO_JWT_SECRET_A1B2C3D4E5F6` |
| User Password | `HP_DEMO_<User>Password_<hex>` | `HP_DEMO_AdminPassword_7F8E` |

**Internal Detection Benefits:**

The `HP_DEMO_` prefix enables Ghost Protocol to:

- **Reliably detect credential exfiltration** — any access to files containing `HP_DEMO_` credentials triggers T1552 MITRE mapping
- **Track credential spread** — if synthetic credentials appear in external systems, we know they came from the honeypot
- **Audit trail** — clear distinction between honeypot artifacts and real infrastructure

**Attacker Perception:**

From an attacker's perspective, the credentials still appear valuable:

- Located in realistic file paths (`/root/.aws/credentials`, `/home/admin/passwords.txt`)
- Embedded in configuration files, deployment scripts, and database backups
- Accompanied by warning comments like "DO NOT SHARE EXTERNALLY"
- Match the format of environment variables and connection strings

Attackers unfamiliar with Ghost Protocol will treat these as legitimate credentials worth exfiltrating, triggering full threat attribution.

**Implementation:**

All credentials are dynamically generated using the `ai_core/demo_credentials.py` module, which provides:

- `generate_aws_access_key()` — AWS-style keys with HP_DEMO_ prefix
- `generate_api_key(service)` — Service-specific API keys (Stripe, SendGrid, etc.)
- `generate_db_password(db_type)` — Database passwords
- `generate_connection_string(db_type)` — Full connection strings
- `generate_user_password(username)` — User account passwords
- And more...

This approach follows **OWASP honeypot best practices** and ensures Ghost Protocol can be safely developed, shared, and deployed without triggering credential leak detection tools.

### Security Best Practices

1. **Never expose on port 22** — keep the honeypot on a non-standard port to avoid confusion with legitimate SSH
2. **Isolate the honeypot host** — deploy on a dedicated VM or container, not on production infrastructure
3. **Monitor resource consumption** — attackers may attempt resource exhaustion attacks
4. **Review `.env` secrets** — ensure PostgreSQL passwords are strong and unique
5. **Rotate SSH host keys** — regenerate `ssh_host_rsa_key` periodically
6. **Backup the database** — session data and intelligence reports are valuable research artifacts

---

## 🧪 Testing & Validation

### Unit Tests (Future Work)

```bash
pytest tests/ -v
```

### Integration Tests

Test the full pipeline:

```bash
# Terminal 1: Start the platform
python -m gateway.ssh_server

# Terminal 2: Run automated attack simulation
python tests/integration/test_full_pipeline.py
```

### Manual Testing Checklist

- [ ] SSH connection accepted with any credentials
- [ ] Basic commands return realistic output (`pwd`, `whoami`, `ls`, `uname -a`)
- [ ] Directory listings show preloaded trap files
- [ ] Accessing sensitive files triggers dashboard alerts
- [ ] MITRE techniques appear in real-time on dashboard
- [ ] Threat score escalates when credentials accessed
- [ ] Session disconnect generates intelligence report
- [ ] Report persisted to PostgreSQL with correct structure

---

## 🤝 Contributing

Ghost Protocol is a research project developed for cybersecurity education and threat intelligence advancement. Contributions are welcome!

### Development Setup

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-improvement`
3. Make your changes
4. Run tests and verify dashboard functionality
5. Submit a pull request with detailed description

### Areas for Contribution

- **AI Models**: Experiment with different LLMs (Mistral, CodeLlama, GPT-4)
- **MITRE Coverage**: Expand technique detection patterns
- **Dashboard**: Improve visualizations and real-time analytics
- **Deception Content**: Add more realistic trap files and scenarios
- **Performance**: Optimize LLM inference latency
- **Documentation**: Tutorial videos, deep-dive blog posts

---

## 📄 License

This project is released under the **MIT License**. See [LICENSE](LICENSE) for details.

**TL;DR:** You can use, modify, and distribute Ghost Protocol freely, including for commercial purposes. Attribution appreciated but not required.

---

## 👥 Credits

**Ghost Protocol** is developed by **Team A.S.E.A** as a cybersecurity research platform.

### Acknowledgments

- **MITRE ATT&CK** framework for structured threat classification
- **Ollama** for local LLM infrastructure
- **AsyncSSH** for high-performance honeypot implementation
- **FastAPI** for modern async web framework

---

## 📧 Contact

For questions, research collaborations, or security disclosures:

- **GitHub Issues**: [Report bugs or request features](https://github.com/Keninjavelas/Ghost-Protocol/issues)
- **Project Owner**: [@Keninjavelas](https://github.com/Keninjavelas)

---

## 🎓 Citation

If you use Ghost Protocol in academic research, please cite:

```bibtex
@software{ghostprotocol2026,
  title = {Ghost Protocol: AI-Driven Cyber Deception and Attribution Engine},
  author = {Team A.S.E.A},
  year = {2026},
  url = {https://github.com/Keninjavelas/Ghost-Protocol}
}
```

---

<p align="center">
  <strong>Ghost Protocol</strong><br>
  <em>Because the best defense is deception.</em>
</p>

<p align="center">
  🔒 <strong>Turning attacker intrusions into threat intelligence, one session at a time.</strong>
</p>
