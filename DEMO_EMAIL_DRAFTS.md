# ✉️ MailJury Demo Email Drafts & Test Scenarios

This directory provides 5 standalone `.eml` test email files located in [`demo_emails/`](file:///c:/Users/vishw/Documents/antigravity/wise-bell/demo_emails) mapped directly to the **Mission 02** requirements.

Use these files to test the **Autonomous Background Daemon**, upload directly via the Web UI at `http://localhost:5173`, or copy-paste their contents as live email drafts.

---

## 📋 Quick Test Commands

```bash
# Drop scenario 1 into the background spool folder (daemon picks it up automatically)
python backend/send_demo_email.py --drop 1

# Drop all 5 scenarios simultaneously into the background spool
python backend/send_demo_email.py --drop-all

# Directly adjudicate scenario 1 in volatile memory and print the verdict
python backend/send_demo_email.py --adjudicate 1

# Inject scenario 1 directly into your live Gmail inbox via OAuth
python backend/send_demo_email.py --send-gmail 1
```

---

## 🚨 SCENARIO 01: Disguised Executable Inside PDF
- **File**: `demo_emails/01_SCAM_disguised_exe_in_pdf.eml`
- **Mission 02 Requirement**: Requirement 2 (MIME & File-Signature Checks) & Requirement 7 (Zero-Execution Display).
- **Attack Vector**: Masquerading Windows Portable Executable (PE) renamed with a `.pdf` extension.

### Email Draft Fields:
```text
From: "Judicial Enforcement Office" <legal-notice@summons-enforcement-court.com>
To: victim@company.com
Subject: URGENT: Legal Court Notice of Impending Foreclosure - Immediate Response Required
Authentication-Results: spf=fail; dkim=fail; dmarc=fail

Body:
CONFIDENTIAL LEGAL NOTICE

You are hereby served notice regarding case #CR-984102-2026.
Immediate appearance or response is mandatory within 24 hours to avoid a bench warrant.
Please review the attached official court summons PDF immediately.

Office of the Clerk of the Court
State Judicial Center

Attachment:
• Filename: Official_Court_Summons_Notice.pdf
• Magic Bytes: 4D 5A (MZ DOS Header) + "This program cannot be run in DOS mode."
```

### Expected Autonomous Outcome:
- **Verdict**: `FAKE / MALICIOUS` (Risk Score: `98.0 / 100`)
- **Action**: Intercepted & quarantined $\rightarrow$ **OAuth Alert Warning Email Dispatched**.

---

## 🚨 SCENARIO 02: Weaponized Macro Document
- **File**: `demo_emails/02_SCAM_macro_word_doc.eml`
- **Mission 02 Requirement**: Requirement 3 (Static Macro Detection & Suspicious Structure).
- **Attack Vector**: OOXML Word document containing `vbaProject.bin` with `AutoOpen` shell execution triggers.

### Email Draft Fields:
```text
From: "Acme Corporate Billing" <accounts-receivable@supplier-portal-payments.com>
To: finance@target-corp.com
Subject: OVERDUE INVOICE #INV-49219 - Final Demand Before Legal Action
Authentication-Results: spf=softfail; dkim=none; dmarc=fail

Body:
Dear Accounts Payable,

Your payment for Invoice #INV-49219 ($48,250.00) is now 45 days past due.
Please open the attached Word invoice and enable content/macros to view the digitally certified cryptographic payment authorization slip.

Failure to remit funds by 5:00 PM will trigger credit reporting.

Regards,
Collections Department

Attachment:
• Filename: Overdue_Invoice_INV49219.docm
• Structure: OpenXML package with word/vbaProject.bin (AutoOpen trigger embedded)
```

### Expected Autonomous Outcome:
- **Verdict**: `FAKE / MALICIOUS` (Risk Score: `95.0 / 100`)
- **Action**: Intercepted & quarantined $\rightarrow$ **OAuth Alert Warning Email Dispatched**.

---

## 🚨 SCENARIO 03: Password-Protected ZIP with In-Body Password
- **File**: `demo_emails/03_SCAM_encrypted_zip_body_password.eml`
- **Mission 02 Requirement**: Requirement 4 (Detect Password-Protected ZIPs & Mine Body Passwords).
- **Attack Vector**: Encrypted ZIP container hiding a dropper executable, with decryption password provided in email text to bypass gateway scanners.

### Email Draft Fields:
```text
From: "Human Resources Payroll" <hr-confidential@global-payroll-portal.com>
To: executive@target-corp.com
Subject: STRICTLY CONFIDENTIAL: Executive Salary Adjustments & Q1 Bonus Matrix
Authentication-Results: spf=fail; dkim=none; dmarc=fail

Body:
Dear Colleague,

Attached is the encrypted payroll spreadsheet containing the approved Q1 executive compensation and bonus adjustments.

To comply with corporate privacy guidelines, this archive is password protected.
Your archive extraction password is: Payroll#2026!Bonus

Please extract and review your details immediately.

Corporate Compensation Committee

Attachment:
• Filename: Executive_Bonus_Matrix.zip
• Structure: PKWARE General Purpose Bit 0 Encrypted container
```

### Expected Autonomous Outcome:
- **Verdict**: `FAKE / MALICIOUS` (Risk Score: `90.0 / 100`)
- **Extracted Evidence**: `Password mined from body: Payroll#2026!Bonus`
- **Action**: Intercepted & quarantined $\rightarrow$ **OAuth Alert Warning Email Dispatched**.

---

## 🛡️ SCENARIO 04: Genuine Vendor PDF Invoice (False-Positive Elimination)
- **File**: `demo_emails/04_LEGIT_clean_vendor_invoice.eml`
- **Mission 02 Requirement**: Requirement 5 (Distinguish Genuine Vendor Invoices).
- **Characteristics**: Legitimate vendor sending standard monthly invoice with valid SPF/DKIM authentication.

### Email Draft Fields:
```text
From: "Cloudflare Billing Department" <billing@cloudflare.com>
To: billing-admin@target-corp.com
Subject: Invoice #INV-88912 from Cloudflare Enterprise Services
Authentication-Results: spf=pass; dkim=pass header.i=@cloudflare.com; dmarc=pass

Body:
Dear Customer,

Thank you for choosing Cloudflare Enterprise Services.
Attached is your monthly billing statement for Invoice #INV-88912 covering period Oct 1 - Oct 31, 2026.
Your account on file will be automatically charged on October 25, 2026.

For billing inquiries or questions, contact support@cloudflare.com.

Best regards,
Cloudflare Financial Operations Team

Attachment:
• Filename: Cloudflare_Invoice_INV88912.pdf
• Structure: Pure %PDF-1.4 standard catalog, zero executable elements, zero JavaScript
```

### Expected Autonomous Outcome:
- **Verdict**: `LEGITIMATE / SAFE` (Risk Score: `0.0 / 100`)
- **Action**: Verified Safe $\rightarrow$ **ZERO EMAILS SENT (Complete silence, no false alarms)**.

---

## 🛡️ SCENARIO 05: Urgent HR Notice with Long Benign Single-Sign-On URL
- **File**: `demo_emails/05_LEGIT_urgent_hr_benefits_review.eml`
- **Mission 02 Requirement**: Requirement 1 (Urgency Phrasing + Long Benign URLs) & Requirement 6 (Multi-Indicator Fusion).
- **Characteristics**: Internal enterprise HR announcement containing urgent deadlines and complex authentication URLs (> 150 chars).

### Email Draft Fields:
```text
From: "Corporate Human Resources" <hr-benefits@company.internal>
To: all-staff@company.internal
Subject: URGENT: Mandatory 2026 Annual Health Benefits Open Enrollment Closes Today
Authentication-Results: spf=pass; dkim=pass header.i=@company.internal; dmarc=pass

Body:
ATTENTION ALL EMPLOYEES: IMMEDIATE ACTION REQUIRED BY 5:00 PM TODAY

This is your final notice regarding the mandatory 2026 Annual Health Benefits Open Enrollment.
If you do not complete your enrollment verification today, your current medical and dental elections will default to basic coverage.

Please click the secure corporate single-sign-on link below to confirm your elections:
https://intranet.company.internal/identity/auth/saml2/sso?idp_entity_id=https%3A%2F%2Fokta.company.internal%2Fapp%2Fsso&session_state=b8a92f019c4d8e72a1&target_relay_state=https%3A%2F%2Fbenefits.portal.company.internal%2Fannual-enrollment%2F2026%2Femployee-selection-confirmation%3Fdepartment_code%3DENG%26location%3DUS-WEST

Attached is the official 2026 Benefits Guidebook for your reference.

Corporate People & Culture Department

Attachment:
• Filename: 2026_Benefits_Guidebook.docx
• Structure: Clean OOXML document devoid of VBA macros
```

### Expected Autonomous Outcome:
- **Verdict**: `LEGITIMATE / SAFE` (Risk Score: `10.0 / 100`)
- **Mitigation Reason**: Multi-Indicator Fusion suppresses isolated urgency keywords when cryptographic authentication passes and URLs match the sender domain.
- **Action**: Verified Safe $\rightarrow$ **ZERO EMAILS SENT (Complete silence, no false alarms)**.
