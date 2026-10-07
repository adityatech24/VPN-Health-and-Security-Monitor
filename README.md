# VPN Health and Security Monitor

**An academic cybersecurity monitoring project for ICT Academy submission.**

---

## 1. Project Title
**VPN Health and Security Monitor**

---

## 2. Introduction
This project is a defensive cybersecurity monitoring system that monitors authorized VPN logs and server health information. It helps identify failed login attempts, unusual login activity, repeated authentication failures, and VPN server/tunnel availability issues.

The system is a web-based dashboard built with Python (Flask), SQLite, Bootstrap 5, and Chart.js.

---

## 3. Problem Statement
Network administrators and security analysts need a simple way to:
- Monitor VPN server availability
- Detect suspicious login activities (brute force, unusual hours)
- Receive automated security alerts
- Analyze login trends and patterns

This project provides a simple but professional solution suitable for small to medium environments.

---

## 4. Objectives
1. Monitor VPN server status and availability
2. Parse and store VPN login/connection logs
3. Automatically detect security threats from log data
4. Generate severity-based security alerts
5. Display a real-time dashboard with statistics and charts
6. Provide an admin interface for alert management

---

## 5. Features
- **Dashboard** with live statistics (servers, logins, alerts, availability)
- **VPN Server Management** – Add, monitor, and health-check VPN servers
- **VPN Health Page** – Availability percentages, failure counts, response times
- **VPN Logs** – View, search, filter, and upload logs (CSV/JSON)
- **Security Analysis Engine** – Auto-detects 5 types of threats
- **Security Alerts** – Full CRUD: view, acknowledge, resolve
- **Analytics** – Charts for trends, top IPs, server targets, failure reasons
- **Settings** – Configurable detection thresholds
- **REST API** – JSON endpoints for all major features
- **Demo Data** – One-click load of realistic sample data with auto-analysis

---

## 6. Technology Used
| Component | Technology |
|-----------|-----------|
| Backend | Python 3, Flask |
| Database | SQLite (built-in) |
| Frontend | HTML5, CSS3, JavaScript |
| UI Framework | Bootstrap 5 |
| Charts | Chart.js 4 |
| Icons | Bootstrap Icons |
| Config | python-dotenv |

---

## 7. System Requirements
- Python 3.8 or higher
- pip (Python package manager)
- Web browser (Chrome, Firefox, Edge)
- No external VPN server required

---

## 8. Project Structure
```
vpn-health-monitor/
│
├── app.py                  # Main Flask application
├── config.py               # Configuration settings
├── requirements.txt        # Python dependencies
├── .env.example            # Environment variable template
├── README.md               # This file
│
├── database/
│   └── database.py         # DB init, connection, settings helpers
│
├── models/
│   ├── vpn_server.py       # VPN server CRUD operations
│   ├── vpn_log.py          # VPN log CRUD operations
│   └── alert.py            # Security alert CRUD operations
│
├── services/
│   ├── log_parser.py       # CSV/JSON log file parser
│   ├── analyzer.py         # Security analysis engine
│   ├── health_monitor.py   # VPN server health check simulation
│   └── demo_data.py        # Demo data loader
│
├── routes/
│   ├── dashboard.py        # Dashboard page
│   ├── servers.py          # Servers + Health pages
│   ├── logs.py             # Logs page + upload
│   ├── alerts.py           # Alerts + Analytics pages
│   ├── settings_route.py   # Settings page
│   └── api.py              # REST API endpoints
│
├── templates/
│   ├── base.html           # Master layout with sidebar
│   ├── dashboard.html      # Main dashboard
│   ├── servers.html        # VPN server list
│   ├── health.html         # Server health page
│   ├── logs.html           # Log viewer
│   ├── alerts.html         # Alert list
│   ├── alert_detail.html   # Alert detail view
│   ├── analytics.html      # Analytics & charts
│   ├── settings.html       # Settings form
│   └── error.html          # Error page
│
├── static/
│   ├── css/style.css       # Custom cybersecurity theme
│   └── js/dashboard.js     # Dashboard auto-refresh
│
├── sample_data/
│   ├── vpn_logs.csv        # Sample CSV logs (50 entries)
│   └── vpn_logs.json       # Sample JSON logs (25 entries)
│
└── tests/
    └── test_analyzer.py    # Unit tests for the analyzer
```

---

## 9. Installation

### Step 1: Create a virtual environment
```bash
python -m venv venv
```

### Step 2: Activate the virtual environment

**Windows:**
```
venv\Scripts\activate
```

**Linux/macOS:**
```bash
source venv/bin/activate
```

### Step 3: Install dependencies
```bash
pip install -r requirements.txt
```

---

## 10. How to Run

```bash
python app.py
```

Then open your browser and navigate to:

```
http://127.0.0.1:5000
```

The database (`vpn_monitor.db`) will be created automatically on first run.

---

## 11. How to Load Demo Data

### Option 1: Using the Dashboard Button
Click the **"Load Demo Data"** button in the top navigation bar on any page.

### Option 2: Using the API
```bash
curl -X POST http://127.0.0.1:5000/api/demo/load
```

**What happens when you load demo data:**
1. Existing logs and alerts are cleared
2. 3 demo VPN servers are added (if not present)
3. 85+ realistic log entries are inserted
4. Simulated health checks are created
5. The security analysis engine runs automatically
6. Security alerts are generated based on the logs

---

## 12. How Log Analysis Works

The analysis engine (`services/analyzer.py`) examines all stored logs and detects 5 types of suspicious activity:

### Rule A: Repeated Failed Login Attempts
- Checks if the same IP has more than N failed logins within M minutes
- Default: 5 failures in 10 minutes
- Generates: **HIGH** severity alert

### Rule B: Multiple Usernames from One IP
- Checks if one IP tries more than N different usernames within the time window
- Default: 3 different usernames in 10 minutes
- Generates: **MEDIUM** severity alert

### Rule C: Unusual Login Times
- Checks if successful logins occur outside configured working hours
- Default: 08:00 to 22:00
- Generates: **MEDIUM** severity alert

### Rule D: VPN Server Downtime
- Triggered when a health check marks a server offline
- Generates: **LOW** severity alert

### Rule E: Repeated Server Failures
- Triggered when a server fails health checks N or more times
- Default: 3 failures
- Generates: **HIGH** severity alert

---

## 13. Alert Detection Rules

| Rule | Condition | Severity |
|------|-----------|----------|
| Repeated Failed Login | >5 failures from same IP in 10 min | HIGH |
| Multi-Username from IP | >3 usernames from same IP in 10 min | MEDIUM |
| Unusual Login Time | Login success outside 08:00–22:00 | MEDIUM |
| Server Downtime | Server health check returns offline | LOW |
| Repeated Server Failure | ≥3 offline checks for same server | HIGH |

---

## 14. API Information

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/dashboard` | Dashboard statistics |
| GET | `/api/servers` | All VPN servers |
| POST | `/api/servers` | Add a VPN server |
| GET | `/api/logs` | Paginated logs |
| POST | `/api/logs/upload` | Upload CSV/JSON log file |
| GET | `/api/alerts` | All alerts |
| POST | `/api/alerts/<id>/acknowledge` | Acknowledge an alert |
| POST | `/api/alerts/<id>/resolve` | Resolve an alert |
| GET | `/api/health` | Server health summary |
| POST | `/api/health/check-all` | Run health checks |
| POST | `/api/analyze` | Run security analysis |
| POST | `/api/demo/load` | Load demo data |
| GET | `/api/settings` | Get current settings |
| POST | `/api/settings` | Update settings |

---

## 15. Testing

### Run unit tests
```bash
python -m pytest tests/ -v
```

### Manual test checklist
- [ ] Application starts without errors
- [ ] Database and tables created on first run
- [ ] Demo data loads and alerts are generated
- [ ] CSV upload works (use `sample_data/vpn_logs.csv`)
- [ ] JSON upload works (use `sample_data/vpn_logs.json`)
- [ ] Failed login detection triggers HIGH alert
- [ ] Unusual login time detection triggers MEDIUM alert
- [ ] Multi-username detection triggers MEDIUM alert
- [ ] Server health check runs and updates status
- [ ] Alert acknowledge/resolve buttons work
- [ ] Dashboard statistics update from database
- [ ] All API endpoints return JSON

---

## 16. Future Scope
1. **Real VPN Integration** – Connect to actual OpenVPN/WireGuard logs
2. **Email Notifications** – Send email alerts for critical events
3. **User Authentication** – Login page for the monitoring dashboard
4. **Export Reports** – Download alert/log reports as PDF or Excel
5. **Geolocation** – Map source IPs to geographic locations
6. **Scheduled Analysis** – Run analysis automatically every hour
7. **Multi-tenant Support** – Multiple organizations on one instance
8. **SIEM Integration** – Forward alerts to Splunk/ELK Stack

---

## Disclaimer
This project is developed strictly for **educational and defensive cybersecurity purposes** as part of an ICT Academy academic submission.

It does **not** include any feature for unauthorized access, password cracking, credential stealing, exploitation, or attacking real VPN systems.
