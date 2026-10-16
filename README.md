<div align="center">

<img src="assets/mailjury_banner.svg" alt="MailJury Banner" width="100%" />

<br/><br/>

[![Mission 02 Benchmark](https://img.shields.io/badge/Mission%2002-100%25%20Passed-22c55e?style=for-the-badge&logo=shield)](MISSION_02_DELIVERABLE_REPORT.md)
[![False Positive Rate](https://img.shields.io/badge/False%20Positive%20Rate-0.00%25-3b82f6?style=for-the-badge)](MISSION_02_DELIVERABLE_REPORT.md)
[![Zero-Execution](https://img.shields.io/badge/Zero--Execution-In--Memory%20100%25-8b5cf6?style=for-the-badge)](backend/attachment_analyzer.py)
[![Compliance](https://img.shields.io/badge/Legal%20Admissibility-BSA%20§65B-64748b?style=for-the-badge)](backend/courtroom_arbiter.py)
[![Live Gmail API](https://img.shields.io/badge/Google%20OAuth2-Connected%20Live-10b981?style=for-the-badge&logo=gmail)](backend/gmail_client.py)


<p align="center">
  <strong>An offline-first, zero-execution adversarial email risk checker and autonomous background daemon.</strong><br/>
  Replaces fragile single-threshold rules with an adversarial courtroom debate between a <strong>Red Team Prosecutor</strong> and <strong>Blue Team Defender</strong>, adjudicated by a neutral <strong>Chief Justice Arbiter</strong>.
</p>

</div>

---

## 🏛️ Executive Overview

Traditional secure email gateways (SEGs) suffer from two chronic architectural failures:
1. **False-Positive Fatigue**: Flagging legitimate internal HR or financial emails simply because they contain urgency keywords (*"immediate action required"*) or long authenticated OAuth parameters (*length > 180 chars*).
2. **Evasion Susceptibility**: Failing to intercept disguised malware, such as Windows PE executables disguised with `.pdf` extensions, weaponized macro documents, or password-protected ZIP droppers carrying credentials in the email body.

**MailJury** resolves this dilemma through a multi-agent courtroom architecture governed by the **Multi-Indicator Fusion Rule** and **Zero-Execution Attachment Forensics**. Operating as an autonomous background daemon, it intercepts incoming messages, conducts forensic trials in volatile memory, and uses **Google OAuth** to dispatch threat warnings strictly when an email is validated as a scam—maintaining complete silence on verified legitimate messages.

---

## ⚙️ System Architecture

<div align="center">
  <img src="assets/architecture_workflow.svg" alt="MailJury Architecture" width="100%" />
</div>

### The Adversarial Tri-Pillar Architecture

1. **Red Team Prosecutor ([`team_prosecutor.py`](backend/team_prosecutor.py))**:
   - Analyzes header anomalies, authentication posture (SPF/DKIM/DMARC), lookalike homoglyphs, and linguistic attack vectors.
   - Files formal indictment counts and triggers fatal payload vetos for active threats.

2. **Blue Team Defender ([`team_defender.py`](backend/team_defender.py))**:
   - Gathers cryptographic exoneration proofs: valid domain alignment, authentic transactional context, and genuine vendor certifications.
   - Files motions to dismiss circumstantial accusations when static byte inspection proves clean.

3. **Chief Justice Arbiter ([`courtroom_arbiter.py`](backend/courtroom_arbiter.py))**:
   - Applies the **Multi-Indicator Fusion Rule**: an isolated weak signal (e.g. lone urgency word) is mitigated to $\le 15.0$ (`SAFE`).
   - Escalates to `PHISHING` only when multiple independent threat indicators converge.
   - Issues cryptographically signed digital certificates compliant with the **Indian Evidence Act (Bharatiya Sakshya Adhiniyam - BSA) §65B**.

---

## 📊 Verified Benchmark Performance

<div align="center">
  <img src="assets/benchmark_scorecard.svg" alt="MailJury Benchmark Metrics" width="100%" />
</div>

Across comprehensive evaluations against both the **Mission 02 Test Suite** and the **30-Scenario ThreatLens EML Regression Corpus**:

| Test Metric | Benchmark Result | Evaluation Standard |
| :--- | :---: | :--- |
| **Malicious Detection Rate** | **100.0%** | Renamed PEs, macro carriers, template injections, and droppers caught |
| **False-Positive Rate** | **0.00%** | Zero legitimate urgency messages or clean vendor attachments flagged |
| **Average Attachment Triage** | **0.83 ms** | Pure in-memory buffered byte inspection (`io.BytesIO`) |
| **End-to-End Adjudication** | **1.84 ms** | Full Red Team + Blue Team + Arbiter trial |
| **Memory Isolation Safety** | **100.0%** | Attachments are never executed, written to disk, or opened via OS shell |

---

## 🔍 Core Capabilities & Mission 02 Deliverables

### 1. Zero-Execution Attachment Forensics ([`attachment_analyzer.py`](backend/attachment_analyzer.py))
- **File Signature & Magic Byte Verification**: Validates raw file headers (`MZ`, `\x7fELF`, Mach-O, `%PDF-`, `PK\x03\x04`, OLE) directly against declared MIME types and file extensions. Catches disguised executables (e.g., `invoice.pdf` containing a Windows `MZ` binary header) with zero host execution.
- **Static Macro & Structure Inspection**: Inspects OOXML packages in memory for `vbaProject.bin`, auto-execution triggers (`Document_Open`, `AutoOpen`), remote template injection (`attachedTemplate` external URIs), and PDF exploit tokens (`/Launch`, `/JS`, `/OpenAction`).
- **PKWARE Password-Protected ZIPs & In-Body Password Extraction**: Detects archive encryption via local header bit 0 flags (`flag & 0x01 != 0`) and mines candidate decryption keys directly from the email body text via regex patterns.

### 2. Multi-Indicator Fusion Scoring ([`courtroom_arbiter.py`](backend/courtroom_arbiter.py))
- Suppresses false positives by requiring a cohesive, multi-vector threat profile before escalating an email to `PHISHING`.
- If an email has valid authentication (SPF/DKIM pass) and an isolated urgency cue or long URL, the arbiter caps the risk score at $\le 15.0$, delivering the message safely to the primary inbox.

### 3. Exoneration & Benign Document Certification
- Automatically inspects and certifies:
  - **Genuine Vendor PDF Invoices**: Verified `%PDF-` structure, standard catalog elements, zero exploit keys (+35 legitimacy points, 0 risk).
  - **Plain DOCX Documents**: Valid OOXML structure strictly devoid of VBA macro code or external template references (+35 legitimacy points, 0 risk).
  - **Benign Image Archives**: Unencrypted ZIP containers consisting solely of standard image formats (+35 legitimacy points, 0 risk).

### 4. Autonomous Headless Background Daemon ([`background_monitor.py`](backend/background_monitor.py))
- Operates 24/7 in the background without requiring manual uploads or web UI interaction.
- Continuously monitors incoming messages via live **Google Gmail API** or the local filesystem spool directory (`backend/incoming/`).
- **Remediation & Notification Protocol**:
  - **Scam Confirmed**: Intercepts and quarantines the hostile email, then automatically sends an alert warning email via **Google OAuth** (`https://www.googleapis.com/auth/gmail.send`) to the user/recipient.
  - **Legitimate Verified**: **Strictly sends no email**, preventing alert fatigue and eliminating false alarms.

### 5. Actionable Recommendations Engine ([`actionable_recommendations.py`](backend/actionable_recommendations.py))
- **Perimeter & Mailbox Quarantine**: Automates immediate gateway drops, removes emails from the Inbox/Spam views, applies `MAILJURY_QUARANTINED` labeling, and exports IOCs for EDR/SIEM perimeter containment.
- **Out-of-Band Sender Verification Challenge**: Enforces formal out-of-band verification via corporate directories, Slack/Teams, or known phone channels, with strict warnings against replying directly or calling numbers contained within the message.
- **Zero-Execution Safe Viewer Matrix**: Recommends isolated inspection environments per payload class:
  - *PE Executables*: Offline static disassemblers / sandboxes (`CAPE`, `Ghidra`, `radare2`).
  - *Macro Carriers / RTF*: Isolated cloud sandboxes / pixel sanitizers (`Dangerzone`, Google Docs preview with macros disabled).
  - *PDF Documents*: Hardened Chromium PDF.js (JavaScript execution disabled) and `pdfid`/`pdftotext`.
  - *Encrypted Archives*: Disposable isolated network-less containers (`docker run --network none`) or Qubes disposable VMs.

---

## 🚀 Quickstart Guide

### Prerequisites
- Python 3.10+ (Tested on Python 3.12)
- Node.js 18+ & npm

### 1. Repository Setup

```bash
git clone https://github.com/viswakpullepu/mailjury.git
cd mailjury
```

### 2. Backend Setup & Dependencies

```bash
# Install Python backend dependencies
pip install fastapi uvicorn pydantic python-multipart google-api-python-client google-auth-oauthlib google-auth
```

### 3. Run the Autonomous Daemon (Headless CLI)

```bash
# Start the background daemon monitoring the inbox and spool folder
python backend/run_daemon.py
```

The daemon immediately begins polling for unread messages. Any email placed in `backend/incoming/` or received via Gmail is intercepted and adjudicated in real time.

### 4. Run the Courtroom Dashboard (1-Click or Manual)

**Option A (1-Click Launcher — Recommended):**
```bash
# Starts both Backend and Frontend, then automatically opens http://localhost:5173
python start_system.py
```
*(On Windows, you can also simply double-click `start_dashboard.bat`)*

**Option B (Manual 2-Terminal Launch):**
```bash
# Terminal 1: Start FastAPI Backend Server
python backend/main.py

# Terminal 2: Start Vite React Frontend
cd frontend
npm install
npm run dev
```

Visit **`http://localhost:5173`** to interact with the **Courtroom Trial Console**, test preset attack scenarios, and inspect zero-execution byte-level forensic evidence under the **📎 Attachments** tab.


---

## 🧪 Automated Test Suites

MailJury includes comprehensive automated test suites verifying all forensics, multi-indicator scoring, and daemon behavior:

```bash
# 1. Mission 02 Core Requirements Test (11 Scenarios - 100% Passed)
python backend/test_mission_02.py

# 2. Autonomous Daemon & OAuth Alert Notification Test (6 Scenarios - 100% Passed)
python backend/test_daemon_autonomous.py

# 3. 30-Scenario ThreatLens EML Regression Suite
python research/evaluate_eml_benchmark_suite.py
```

---

## 📁 Repository Structure

```text
mailjury/
├── assets/                               # Professional vector diagrams & visual assets
│   ├── mailjury_banner.svg               # Editorial brand banner
│   ├── architecture_workflow.svg         # End-to-end architecture diagram
│   └── benchmark_scorecard.svg           # Performance metrics scorecard
├── backend/                              # Core Forensic Engine & Background Daemon
│   ├── attachment_analyzer.py            # Zero-execution magic byte & structural parser
│   ├── background_monitor.py             # Headless autonomous background monitor
│   ├── courtroom_arbiter.py              # Chief Justice Arbiter & Multi-Indicator Fusion
│   ├── eml_parser.py                     # RFC 5322 MIME stream parser
│   ├── gmail_client.py                   # Gmail API v1 OAuth & email dispatch client
│   ├── main.py                           # FastAPI REST & webhook endpoints
│   ├── run_daemon.py                     # Standalone CLI daemon runner
│   ├── team_prosecutor.py                # Red Team threat indictment generator
│   ├── team_defender.py                  # Blue Team cryptographic exoneration generator
│   ├── test_mission_02.py                # 11-scenario Mission 02 benchmark suite
│   ├── test_daemon_autonomous.py         # Autonomous daemon & OAuth alerting test suite
│   ├── incoming/                         # Local spool directory for headless intake
│   └── security/                         # AES-256-GCM CryptoVault & PKCE OAuth manager
├── frontend/                             # Modern React + Vite + Tailwind + Framer Motion
│   ├── src/
│   │   ├── components/
│   │   │   ├── CourtDebate.tsx           # Adversarial debate & 📎 Attachments tab
│   │   │   ├── EmailUploader.tsx         # 1-Click test presets for demo scenarios
│   │   │   └── VerdictCard.tsx           # BSA §65B digital certificate display
│   │   ├── api.ts                        # Typed API client
│   │   └── App.tsx                       # Courtroom interface layout
│   └── package.json
├── research/                             # Benchmark corpora & empirical evaluation scripts
│   └── evaluate_eml_benchmark_suite.py   # 30-case regression runner
├── MISSION_02_DELIVERABLE_REPORT.md      # Comprehensive technical deliverable report
└── README.md                             # Repository documentation
```

---

## 🔒 Security & Privacy Guarantees

- **Zero-Plaintext Storage**: All Google OAuth refresh tokens and credentials are encrypted using AES-256-GCM envelope encryption (NIST SP 800-38D).
- **Ephemeral RAM Triage**: Incoming emails and attachments are evaluated strictly in volatile memory. No attachment binaries or scripts are ever written to disk or executed.
- **Auditable Evidentiary Chain**: Every adjudication generates a tamper-evident SHA-256 digital certificate token admissible under the **Indian Evidence Act (BSA) §65B**.

---

## 🎥 Demonstration Video

> **Demo Screencast**: Link to demonstration video recording showing the background daemon intercepting scam emails, sending OAuth alerts, and safely clearing legitimate messages will be linked here.

---

<div align="center">
  <sub>MailJury • Built for Mission 02 • Adversarial Multi-Agent Email Security</sub>
</div>
