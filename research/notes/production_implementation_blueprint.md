# Mission #73: Production Implementation Blueprint
## Technical Architecture, Directory Layout & Component Specifications

---

### 1. Technology Stack
- **Backend**: Python 3.12, FastAPI, Pydantic v2, Uvicorn, Python standard libraries (`email`, `zipfile`, `hashlib`, `io`, `re`, `urllib.parse`), `RapidFuzz` / `Levenshtein`.
- **Frontend**: React 18, TypeScript, Vite, Tailwind CSS, Lucide React, Framer Motion, Canvas Confetti.
- **Packaging**: Containerized via Docker / Docker Compose + zero-dependency local startup script.

---

### 2. Directory Structure
```
wise-bell/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                     # FastAPI entrypoint & router
│   │   ├── config.py                   # Limits: max_size=25MB, max_depth=2, max_attachments=10
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   ├── schemas.py              # Pydantic request/response models
│   │   ├── analyzers/
│   │   │   ├── __init__.py
│   │   │   ├── headers.py              # RFC 8601 offline auth, display name, reply-to
│   │   │   ├── body_urls.py            # Link mismatch, homoglyphs, typosquatting, urgency
│   │   │   ├── attachments.py          # Magic bytes, RTLO, macros, PDF, HTML, archives
│   │   │   ├── scoring.py              # Non-linear threat scoring & security floors
│   │   │   └── guidance.py             # Actionable remediation steps & triage guidance
│   │   └── data/
│   │       ├── top_brands.json         # Top 100 enterprise brand targets
│   │       └── known_threat_hashes.json# Local offline hash indicators
│   ├── tests/
│   │   └── test_engine.py              # Pytest test suite across all 11 scenarios
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── RiskGauge.tsx           # Radial score dial with animated SVG arc
│   │   │   ├── ScoreCard.tsx           # Multi-pillar sub-scores (Header, Body, Attachment)
│   │   │   ├── EvidenceViewer.tsx      # Accordion view of flagged signals with severity
│   │   │   ├── AttachmentTable.tsx     # MIME inventory with magic bytes & SHA-256
│   │   │   ├── ActionableGuidance.tsx  # Interactive triage checklist
│   │   │   ├── PresetSelector.tsx      # 1-click test cases (attacks & benign lookalikes)
│   │   │   ├── EmailRawViewer.tsx      # Raw EML & header inspector
│   │   │   └── ExportReportModal.tsx   # JSON / Print-to-PDF export generator
│   │   ├── App.tsx
│   │   ├── main.tsx
│   │   └── index.css
│   ├── package.json
│   ├── vite.config.ts
│   └── tailwind.config.js
├── samples/
│   ├── attack_01_ceo_fraud.eml
│   ├── attack_02_link_mismatch.eml
│   ├── attack_03_homoglyph_paypal.eml
│   ├── attack_04_double_ext_pdf_exe.eml
│   ├── attack_05_rtlo_filename.eml
│   ├── attack_06_macro_docm.eml
│   ├── attack_07_pdf_exploit.eml
│   ├── attack_08_html_smuggling.eml
│   ├── attack_09_password_zip.eml
│   ├── benign_10_github_security.eml
│   └── benign_11_marketing_newsletter.eml
└── README.md
```
