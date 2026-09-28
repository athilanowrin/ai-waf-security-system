# 🛡️ AI-Powered Web Application Firewall & Security Monitoring System

An advanced security monitoring and Web Application Firewall (WAF) system built with **Python, Flask, Machine Learning, and Security Detection Techniques**.

The system inspects incoming HTTP requests, detects common web attacks, identifies abnormal request behaviour using **Isolation Forest**, blocks suspicious IP addresses, performs local threat-intelligence checks, applies rate limiting, records security events, and provides a real-time security dashboard.

---

## 🎯 Project Objective

The main objective of this project is to develop a security layer capable of:

* Inspecting HTTP requests
* Detecting common web application attacks
* Blocking malicious requests
* Identifying anomalous request behaviour using Machine Learning
* Blocking suspicious IP addresses
* Applying IP-based rate limiting
* Performing threat-intelligence checks
* Recording security events
* Providing centralized security monitoring through a web dashboard

---

## 🚀 Key Features

### 🔐 Web Application Firewall

The WAF engine analyzes incoming request parameters and detects:

* SQL Injection
* Cross-Site Scripting (XSS)
* Path Traversal
* Command Injection

Malicious requests are automatically blocked with an appropriate HTTP response.

---

### 🤖 AI-Based Anomaly Detection

The system uses the **Isolation Forest** Machine Learning algorithm to identify unusual HTTP request behaviour.

The feature extraction process considers:

* Request length
* Special-character count
* Digit count
* Space count
* Parameter count
* Special-character ratio

The model is trained using normal request behaviour and identifies requests that significantly differ from the learned baseline.

---

### 🌐 Threat Intelligence

A local threat-intelligence module maintains a list of known suspicious IP addresses.

For each IP address, the system can maintain:

* Threat level
* Threat category
* Intelligence source

Example categories include:

* Scanner
* Brute Force
* Malicious Bot
* Suspicious Activity

Requests from known threat IP addresses are blocked before reaching the application.

---

### 🚫 IP Blocking

Suspicious IP addresses can be temporarily blocked after malicious activity.

The system maintains:

* IP address
* Block time
* Expiration time
* Blocking reason

This provides an additional security layer after attack detection.

---

### ⚡ Rate Limiting

The system implements IP-based request rate limiting.

Current configuration:

```text
Limit: 100 requests
Window: 60 seconds
```

When the limit is exceeded:

```text
HTTP 429 → Rate Limit Exceeded
       ↓
IP temporarily blocked
```

---

### 📋 Security Logging

Security events are stored as structured JSON records.

Logged information includes:

* Timestamp
* Source IP
* HTTP method
* Request path
* Attack type
* Severity
* Action
* Matched rule
* User-Agent

Log file:

```text
logs/security.log
```

---

### 📊 Security Dashboard

The Flask dashboard provides centralized monitoring of:

* Total Requests
* Blocked Requests
* Detected Attacks
* AI Anomalies
* Threat Intelligence Events
* Blocked IP Events
* Rate Limit Events
* Recent Security Events

The dashboard automatically refreshes every five seconds.

---

## 🏗️ System Architecture

```text
                    CLIENT
                       │
                       ▼
                Flask Web Server
                       │
                       ▼
              Security Middleware
                       │
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
 Threat Intelligence  IP Blocker   Rate Limiter
        │              │              │
        └──────────────┼──────────────┘
                       ▼
                   WAF Engine
                       │
       ┌───────────────┼────────────────┐
       ▼               ▼                ▼
 SQL Injection        XSS        Path Traversal
       │
       └───────────────┬────────────────┘
                       ▼
                Command Injection
                       │
                       ▼
              AI Anomaly Detection
                Isolation Forest
                       │
                       ▼
                Security Logger
                       │
                       ▼
              Security Dashboard
```

---

## 📁 Project Structure

```text
ai-waf-security-system/
│
├── app/
│   ├── __init__.py
│   ├── routes.py
│   │
│   ├── waf/
│   │   ├── __init__.py
│   │   └── engine.py
│   │
│   ├── detectors/
│   │   ├── __init__.py
│   │   └── xss.py
│   │
│   ├── ai/
│   │   ├── __init__.py
│   │   └── anomaly_detector.py
│   │
│   └── utils/
│       ├── __init__.py
│       ├── logger.py
│       ├── rate_limiter.py
│       ├── ip_blocker.py
│       └── threat_intelligence.py
│
├── templates/
│   └── dashboard.html
│
├── static/
│
├── logs/
│   └── security.log
│
├── tests/
│
├── config.py
├── run.py
├── requirements.txt
├── README.md
└── .gitignore
```

---

## 🧰 Technologies Used

| Technology          | Purpose                                 |
| ------------------- | --------------------------------------- |
| Python              | Core programming language               |
| Flask               | Web application and security middleware |
| Scikit-learn        | Machine Learning                        |
| Isolation Forest    | Anomaly detection                       |
| Pandas              | Data processing                         |
| Requests            | HTTP testing                            |
| HTML/CSS            | Dashboard interface                     |
| JSON                | Security event storage                  |
| Regular Expressions | Attack pattern detection                |
| Git/GitHub          | Version control                         |

---

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone <your-github-repository-url>
cd ai-waf-security-system
```

### 2. Create a virtual environment

```bash
python -m venv venv
```

### 3. Activate the virtual environment

Windows PowerShell:

```powershell
.\venv\Scripts\Activate.ps1
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

### 5. Start the application

```bash
python run.py
```

The application runs at:

```text
http://127.0.0.1:5000
```

---

## 🧪 Security Testing

The implemented security controls were tested using controlled local requests.

### SQL Injection

```text
SQL Injection
      ↓
WAF Rule Engine
      ↓
HIGH Severity
      ↓
BLOCK
      ↓
HTTP 403
```

### XSS

```text
XSS Payload
      ↓
XSS Detector
      ↓
HIGH Severity
      ↓
BLOCK
```

### Path Traversal

```text
Path Traversal Request
      ↓
WAF Engine
      ↓
HIGH Severity
      ↓
BLOCK
```

### Command Injection

```text
Command Injection Request
      ↓
WAF Engine
      ↓
CRITICAL Severity
      ↓
BLOCK
```

### AI Anomaly Detection

A request with unusual characteristics is processed by the Isolation Forest model.

```text
HTTP Request
     ↓
Feature Extraction
     ↓
Isolation Forest
     ↓
Anomaly Score
     ↓
Anomaly / Normal
```

### Rate Limiting

Controlled local testing demonstrated:

```text
Requests 1–99
     ↓
HTTP 200

Request 100
     ↓
HTTP 429
     ↓
Rate Limit Exceeded

Subsequent Requests
     ↓
HTTP 403
     ↓
IP Temporarily Blocked
```

---

## 🔄 Security Processing Flow

Every incoming request follows the security pipeline:

```text
Incoming Request
       ↓
Threat Intelligence Check
       ↓
IP Block Check
       ↓
Rate Limiting
       ↓
Request Data Collection
       ↓
WAF Rule Inspection
       ↓
AI Anomaly Detection
       ↓
Security Logging
       ↓
Application Response
       ↓
Dashboard Monitoring
```

---

## 📊 Severity Classification

| Attack / Event      | Severity             |
| ------------------- | -------------------- |
| SQL Injection       | HIGH                 |
| XSS                 | HIGH                 |
| Path Traversal      | HIGH                 |
| Command Injection   | CRITICAL             |
| AI Anomaly          | MEDIUM               |
| Threat Intelligence | Based on threat feed |
| Blocked IP          | HIGH                 |
| Rate Limit Exceeded | MEDIUM               |

---

## 🔒 Security Design

The system follows a layered security approach.

```text
Layer 1 → Threat Intelligence
Layer 2 → IP Blocking
Layer 3 → Rate Limiting
Layer 4 → Signature-Based WAF
Layer 5 → AI Anomaly Detection
Layer 6 → Security Logging
Layer 7 → Security Monitoring Dashboard
```

This layered architecture provides multiple security controls instead of depending on a single detection mechanism.

---

## ⚠️ Current Limitations

This project is designed as a security research and portfolio implementation.

Current limitations include:

* Threat intelligence is currently based on a local threat feed
* IP blocking uses in-memory storage
* Rate limiting uses in-memory state
* The AI model currently uses a relatively small normal-request training dataset
* Detection rules are primarily pattern-based
* The system is intended for controlled environments and development testing

---

## 🔮 Future Enhancements

Potential future improvements include:

* External threat-intelligence API integration
* Redis-based distributed rate limiting
* Persistent IP reputation database
* PostgreSQL/MySQL security event storage
* Advanced ML feature engineering
* Automated model retraining
* GeoIP analysis
* Authentication and role-based dashboard access
* Email/SMS security alerts
* SIEM integration
* Docker deployment
* HTTPS support
* Reverse-proxy deployment
* Advanced attack correlation
* MITRE ATT&CK mapping
* Automated incident-response actions

---

## 🎓 Learning Outcomes

This project demonstrates practical understanding of:

* Web Application Security
* WAF Architecture
* HTTP Request Inspection
* Attack Detection
* Security Logging
* Threat Intelligence
* IP Reputation
* Rate Limiting
* Machine Learning for Security
* Flask Middleware
* Security Monitoring
* Incident Detection
* Defensive Cybersecurity

---

## 👩‍💻 Author

**Athila Nowrin**

BCA Graduate | Cybersecurity Enthusiast

Areas of Interest:

* SOC Operations
* Ethical Hacking
* Web Application Security
* Vulnerability Assessment
* Security Monitoring
* AI-Based Cybersecurity

---

## ⚠️ Disclaimer

This project is developed for **educational, defensive security, and authorized testing purposes only**.

Only test security controls against systems and applications that you own or have explicit permission to assess.
