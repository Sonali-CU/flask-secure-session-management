# Flask Secure Session Management & Automated Security Audit Suite

An enterprise-grade, OWASP ASVS compliant implementation and testing laboratory for **Secure Session Management** in Python Flask. This repository demonstrates defense-in-depth session lifecycle controls, cryptographic unpredictability, anti-fixation countermeasures, hardened cookie configurations, and automated session security testing with audit reporting.

---

## 🌟 Key Features & Implementation Scope

1. **Secure Session Creation & Dashboard Access** (Task 1 & 11)
   - User authentication backed by Werkzeug password hashing.
   - Server-side cryptographic session store binding identity, creation timestamp, and last activity.
2. **Unpredictable Session Identifiers** (Task 2)
   - 256-bit CSPRNG token generation using Python's `secrets.token_urlsafe(32)` (5.998 bits/char Shannon entropy, 0 collisions across 1,000 samples).
3. **Session ID Regeneration & Fixation Protection** (Task 3 & 9)
   - Immediate regeneration of session identifiers upon login.
   - Pre-login session tokens are purged from memory, defeating session fixation attacks.
4. **Dual-Tier Session Expiration & Timeouts** (Task 4)
   - **Inactivity Timeout**: Automatically expires after 2 minutes (120s) of user idle time.
   - **Absolute Timeout**: Enforces a strict 10-minute (600s) maximum session lifetime regardless of continuous activity.
5. **Complete Session Invalidation on Logout** (Task 5)
   - Synchronous server-side memory purge and client-side cookie deletion (`Max-Age=0`).
   - Prior session tokens immediately return `401 / 302` on subsequent access attempts.
6. **Hardened Cookie Security Attributes** (Task 6, 7, 8)
   - **`Secure`**: Cookie restricted exclusively to encrypted HTTPS/TLS connections.
   - **`HttpOnly`**: JavaScript access via `document.cookie` is strictly blocked, neutralizing XSS session exfiltration.
   - **`SameSite=Strict`**: Completely isolates the session cookie from cross-site requests, mitigating CSRF.
7. **Zero Session Identifiers in URLs** (Task 10)
   - Strict cookie-only session handling. URLs, query parameters, and Referer headers never leak tokens.
8. **Session Hijacking Mitigation & Client Fingerprinting** (Task 13)
   - User-Agent and client telemetry validation detecting anomalous token reuse.
9. **Role-Based Session Management & Privilege Elevation Regeneration** (Task 14)
   - RBAC restricting `/admin` to authorized administrators (HTTP `403 Forbidden` for normal users).
   - Mandatory session ID regeneration whenever user clearance or privileges change.
10. **Automated Security Testing & CSV Audit Report** (Task 12 & 15)
    - Full automated test suite powered by `pytest` and `requests`.
    - Automated compliance generator exporting `reports/session_security_report.csv` across all 15 security requirements.

---

## 📂 Project Architecture

```
flask-secure-session-management/
├── app/
│   ├── __init__.py                  # Application factory & session store initialization
│   ├── config.py                    # Hardened cookie flags, credentials & timeout constants
│   ├── session_store.py             # Cryptographic session manager (secrets, dual timeouts, rotation)
│   ├── routes.py                    # Authentication, dashboard, admin, and test routes
│   ├── static/
│   │   └── css/style.css            # Dark cybersecurity-themed interface
│   └── templates/
│       ├── base.html                # Navigation shell with OWASP security indicators
│       ├── login.html               # Authentication portal with pre-login token display
│       ├── dashboard.html           # Live telemetry, dual countdown timers & cookie badges
│       ├── admin.html               # Admin control panel with session metrics
│       ├── error.html               # Custom 403 Forbidden response template
│       ├── test_cookie.html         # Live JavaScript document.cookie HttpOnly test page
│       └── samesite_demo.html       # SameSite policy comparison matrix
├── certs/
│   ├── generate_certs.py            # Local TLS/SSL certificate generator
│   ├── cert.pem                     # Self-signed X.509 certificate
│   └── key.pem                      # RSA 2048-bit private key
├── tests/
│   ├── conftest.py                  # Pytest fixtures and client configuration
│   └── test_all_security_tasks.py   # Unit & integration tests for all 15 tasks (12/12 passing)
├── scripts/
│   ├── generate_security_report.py  # Automated security test runner exporting CSV audit report
│   └── capture_screenshots.py       # Automated Edge headless browser screenshot generator
├── reports/
│   ├── session_security_report.csv  # Required CSV audit report (16/16 PASSED)
│   ├── audit_report.html            # Visual audit dashboard
│   └── SESSION_SECURITY_REPORT.md   # Comprehensive technical report
├── screenshots/                     # UI verification screenshots
├── requirements.txt                 # Dependencies
├── run.py                           # Application runner (HTTP & HTTPS)
└── README.md                        # Project documentation
```

---

## 🚀 Quickstart & Setup Guide

### 1. Prerequisites
- Windows 10/11 or Linux/macOS
- Python 3.11+ (verified on Python 3.13)

### 2. Installation
```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/flask-secure-session-management.git
cd flask-secure-session-management

# Install dependencies
pip install -r requirements.txt
```

### 3. Generate TLS Certificates (for HTTPS testing)
```bash
python certs/generate_certs.py
```

### 4. Run the Web Application

**HTTP Mode (Evaluation):**
```bash
python run.py --port 5000
```
Open [http://127.0.0.1:5000](http://127.0.0.1:5000)

**HTTPS Mode (Production Hardened with Secure Cookie):**
```bash
python run.py --https --port 5000
```
Open [https://127.0.0.1:5000](https://127.0.0.1:5000)

---

## 👥 Demo User Accounts

| Username | Password | Role | Description |
| :--- | :--- | :--- | :--- |
| `alice` | `AliceUser@2026!` | `user` | Normal User (can test privilege elevation) |
| `bob` | `BobUserPass#456` | `user` | Normal User |
| `admin` | `SuperAdminKey$999` | `admin` | System Administrator (access to `/admin`) |

---

## 🧪 Running Security Tests

### Run Unit Tests via Pytest
```bash
python -m pytest -v tests/
```
*Expected Result:* `12 passed in ~5s`

### Run Automated Security Audit & Generate CSV Report
```bash
python scripts/generate_security_report.py
```
*Expected Result:* `16/16 PASSED (100% Compliance)`, saving `reports/session_security_report.csv`.

---

## 📊 Summary of Automated Test Results

| Test ID | Task Description | Expected Result | Actual Result | Status |
| :--- | :--- | :--- | :--- | :--- |
| **TC-01** | Secure Session Creation | HTTP 302 redirect, session cookie set, HTTP 200 on dashboard | Status: 302, Cookie set, Dash Status: 200 | **PASS** |
| **TC-02** | Unpredictable Session IDs | Zero collisions in 1,000 tokens, Shannon entropy >= 5.5 | 1,000 unique tokens (0 collisions), Entropy: 5.998 bits/char | **PASS** |
| **TC-03** | Session ID Regeneration | Pre-login ID regenerated on auth; pre-login ID rejected | Pre != Post, Pre-ID access returned 302 to login | **PASS** |
| **TC-04A**| Inactivity Timeout | Auto logout after 2 minutes idle time | Session terminated; redirected with `EXPIRED_INACTIVITY` | **PASS** |
| **TC-04B**| Absolute Timeout | Auto logout after 10 minutes max lifetime | Session terminated; redirected with `EXPIRED_ABSOLUTE` | **PASS** |
| **TC-05** | Session Invalidation on Logout | Server session wiped, cookie cleared, old session rejected | Store entry: None, Dashboard re-access returned 302 | **PASS** |
| **TC-06** | Secure Cookie Attribute | Cookie transmitted exclusively over HTTPS | `Secure` attribute verified in `Set-Cookie` header | **PASS** |
| **TC-07** | HttpOnly Cookie Attribute | JavaScript cannot access session cookie via `document.cookie` | `HttpOnly` verified in `Set-Cookie`; `document.cookie` empty | **PASS** |
| **TC-08** | SameSite Cookie Policy | Mitigate CSRF via Strict policy | `SameSite=Strict` verified in `Set-Cookie` header | **PASS** |
| **TC-09** | Session Fixation Prevention | Pre-set attacker token replaced on auth; attacker rejected | Victim received fresh token; attacker token returned 302 | **PASS** |
| **TC-10** | Zero Session IDs in URLs | Tokens stored only in cookies; never exposed in query strings | Authenticated URL: `/dashboard` (No session params) | **PASS** |
| **TC-11** | Full Authentication Lifecycle | Login -> Dashboard -> API -> Logout -> Re-access Denied | Full lifecycle executed and verified over HTTPS | **PASS** |
| **TC-12** | Automated Testing via Requests | Automated HTTP/HTTPS audit harness | Automated runner executed and passed all vectors | **PASS** |
| **TC-13** | Session Hijacking Simulation | Stolen token with altered fingerprint rejected | Fingerprint mismatch detected; forged token returned 302 | **PASS** |
| **TC-14** | Role-Based Session Management | 403 on `/admin` for normal user; session regenerated on elevation | Normal user got 403; session regenerated on elevation | **PASS** |
| **TC-15** | CSV Audit Report Generation | Export CSV with ID, Description, Expected, Actual, Status | `session_security_report.csv` generated (16/16 PASS) | **PASS** |

---

## 📷 Screenshots

### 1. User Dashboard & Session Telemetry
![User Dashboard](screenshots/02_user_dashboard.png)

### 2. HttpOnly Cookie JavaScript Inspection
![HttpOnly Inspection](screenshots/03_httponly_cookie_inspection.png)

### 3. Role-Based Access Control (403 Forbidden for Normal User)
![403 Forbidden](screenshots/05_access_denied_403.png)

### 4. Admin Panel (Post-Privilege Elevation with Regenerated Session)
![Admin Panel](screenshots/06_admin_panel_rbac.png)

### 5. SameSite Cookie Policy Comparison
![SameSite Matrix](screenshots/04_samesite_policy_matrix.png)

### 6. Automated Security Audit Report Matrix
![Audit Report](screenshots/07_automated_security_audit_report.png)
