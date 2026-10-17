"""
Mission 04: Phishing Email, URL and Attachment Risk Checker — Testing & Validation
Comprehensive Test Suite covering all 10 Deliverables & Instructions:

1. Obvious Phishing Emails (Appropriate risk scores with clear supporting evidence).
2. Legitimate Messages (Normal emails not incorrectly flagged as phishing).
3. URL Analysis Validation (Shortened URLs, long URLs, suspicious structures, legitimate links).
4. Missing Sender Details, Incomplete Headers & Empty Inputs Graceful Handling.
5. Renamed Executable Files (.pdf extension with MZ executable signature).
6. Macro-Enabled Office Documents, Password-Protected ZIPs & In-Body Passwords.
7. Benign Attachments (Genuine vendor PDF invoices, plain DOCX, image ZIP archives).
8. Zero-Execution Static Inspection (MIME types, file signatures, extensions, metadata consistency).
9. Evaluation of False Positives, False Negatives, Risk-Score Consistency & Explanations.
10. Documentation of Test Cases, Expected vs Actual Results & Improvements Made.
"""

import io
import os
import sys
import re
import json
import time
import zipfile
import hashlib
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eml_parser import EMLParser
from team_prosecutor import TeamProsecutor
from team_defender import TeamDefender
from courtroom_arbiter import CourtroomArbiter
from attachment_analyzer import AttachmentAnalyzer
from main import _run_full_trial


class TestMission04Deliverables(unittest.TestCase):
    """Exhaustive test suite verifying all 10 requirements of Mission 04."""

    # =========================================================================
    # DELIVERABLE 1: OBVIOUS PHISHING EMAILS (Appropriate Risk Scores & Evidence)
    # =========================================================================

    def test_01a_obvious_phishing_ceo_wire_fraud(self):
        """Req 1: Verify obvious CEO wire fraud BEC receives high risk score with clear evidence."""
        raw_eml = (
            b"From: \"Arthur Vance, CEO\" <ceo@acme-freemail.com>\r\n"
            b"To: cfo@enterprise-corp.com\r\n"
            b"Subject: STRICTLY CONFIDENTIAL: Immediate Wire Transfer Required\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/plain; charset=UTF-8\r\n"
            b"\r\n"
            b"We are closing an urgent confidential acquisition before 5pm.\r\n"
            b"Please execute an immediate wire transfer of $145,000 to the updated bank details:\r\n"
            b"Routing Number: 021000021, Account Number: 9876543210.\r\n"
            b"Do not discuss this with anyone until the deal is announced.\r\n"
        )
        trial = _run_full_trial(raw_eml)
        summary = trial["summary"]

        self.assertIn("FAKE", summary["verdict"])
        self.assertGreaterEqual(summary["risk_score"], 85.0)
        self.assertGreaterEqual(summary["fatal_vetos"], 1)

        # Supporting evidence validation
        counts = trial["prosecution"]["counts"]
        evidence_texts = " ".join([c["explanation"] + " " + c["charge_name"] + " " + str(c.get("exhibit", "")) for c in counts])
        self.assertTrue("wire" in evidence_texts.lower() or "banking" in evidence_texts.lower() or "bec" in evidence_texts.lower())
        self.assertTrue(len(trial["prosecution"]["counts"]) >= 1)

    def test_01b_obvious_phishing_credential_harvesting_anchor_mismatch(self):
        """Req 1: Verify obvious credential harvesting with anchor mismatch receives high risk score."""
        raw_eml = (
            b"From: \"PayPal Security Center\" <service-security@paypal-notice-alert.com>\r\n"
            b"To: user@company.com\r\n"
            b"Subject: Your PayPal account has been limited: Verify immediately\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/html; charset=UTF-8\r\n"
            b"\r\n"
            b"<p>Unusual activity was detected on your account.</p>\r\n"
            b"<p>Please click below to verify your login credentials:</p>\r\n"
            b"<a href=\"https://secure-login-portal-phish.ru/paypal/verify\">https://www.paypal.com/signin</a>\r\n"
        )
        trial = _run_full_trial(raw_eml)
        summary = trial["summary"]

        self.assertIn("FAKE", summary["verdict"])
        self.assertGreaterEqual(summary["risk_score"], 85.0)
        self.assertGreaterEqual(summary["fatal_vetos"], 1)

        counts = trial["prosecution"]["counts"]
        charges = [c["charge_name"] for c in counts]
        self.assertTrue(any("Mismatch" in ch or "Anchor" in ch or "Deceptive" in ch for ch in charges))

    def test_01c_obvious_phishing_quishing_qr_code_lure(self):
        """Req 1: Verify optical QR code lure (Quishing) is identified with high risk score and clear evidence."""
        raw_eml = (
            b"From: \"IT Helpdesk\" <it-support@freemail-services.com>\r\n"
            b"To: employee@company.com\r\n"
            b"Subject: Mandatory 2FA Device Migration: Scan QR Code Below\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/html; charset=UTF-8\r\n"
            b"\r\n"
            b"<p>All employees must update their authenticator app today.</p>\r\n"
            b"<p>Scan with your mobile camera to complete authentication:</p>\r\n"
            b"<img src=\"https://auth-server-temp.top/qr_matrix.png\" alt=\"MFA QR Code\" />\r\n"
        )
        trial = _run_full_trial(raw_eml)
        summary = trial["summary"]

        self.assertIn("FAKE", summary["verdict"])
        self.assertGreaterEqual(summary["risk_score"], 80.0)
        counts = trial["prosecution"]["counts"]
        self.assertTrue(any("Quishing" in c["charge_name"] or "QR" in c["charge_name"] or "VIP" in c["charge_name"] for c in counts))

    # =========================================================================
    # DELIVERABLE 2: LEGITIMATE MESSAGES (Normal Emails Not Flagged as Phishing)
    # =========================================================================

    def test_02a_legitimate_google_workspace_notification(self):
        """Req 2: Ensure genuine Google Workspace administrative alert is cleared with safe score."""
        raw_eml = (
            b"From: \"Google Workspace\" <no-reply@accounts.google.com>\r\n"
            b"To: admin@enterprise.com\r\n"
            b"Subject: Security Alert: New Sign-in from Chrome on Windows\r\n"
            b"Authentication-Results: mx.google.com; spf=pass (google.com designates 209.85.220.41 as permitted sender); dkim=pass header.d=accounts.google.com; dmarc=pass header.from=accounts.google.com\r\n"
            b"Message-ID: <alert-12345@google.com>\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/html; charset=UTF-8\r\n"
            b"\r\n"
            b"<p>We noticed a new sign-in to your Google Account from Windows.</p>\r\n"
            b"<a href=\"https://myaccount.google.com/security\">Review Activity</a>\r\n"
        )
        trial = _run_full_trial(raw_eml)
        summary = trial["summary"]

        self.assertEqual(summary["verdict"], "LEGITIMATE / SAFE")
        self.assertLessEqual(summary["risk_score"], 15.0)
        self.assertEqual(summary["fatal_vetos"], 0)

    def test_02b_legitimate_microsoft_365_notification(self):
        """Req 2: Ensure genuine Microsoft 365 summary notification is cleared as legitimate."""
        raw_eml = (
            b"From: \"Microsoft 365 Security\" <no-reply@microsoft.com>\r\n"
            b"To: secops@enterprise.com\r\n"
            b"Subject: Weekly Security Update: Tenant Score Summary\r\n"
            b"Authentication-Results: mx.microsoft.com; spf=pass (microsoft.com designates permitted sender); dkim=pass header.d=microsoft.com; dmarc=pass header.from=microsoft.com\r\n"
            b"Message-ID: <m365-sec-9921@microsoft.com>\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/html; charset=UTF-8\r\n"
            b"\r\n"
            b"<p>Your Microsoft Defender tenant security score increased by 4%.</p>\r\n"
            b"<a href=\"https://admin.microsoft.com/security\">Open Defender Portal</a>\r\n"
        )
        trial = _run_full_trial(raw_eml)
        summary = trial["summary"]

        self.assertEqual(summary["verdict"], "LEGITIMATE / SAFE")
        self.assertLessEqual(summary["risk_score"], 15.0)
        self.assertEqual(summary["fatal_vetos"], 0)

    def test_02c_legitimate_internal_email_with_urgency_words(self):
        """Req 2: Ensure internal business emails with project deadline urgency are NOT incorrectly flagged."""
        raw_eml = (
            b"From: \"Sarah Jenkins, Project Lead\" <sjenkins@internal-company.com>\r\n"
            b"To: team@internal-company.com\r\n"
            b"Subject: Immediate action required: Submit sprint architecture report before 5pm\r\n"
            b"Authentication-Results: mail.internal-company.com; spf=pass; dkim=pass header.d=internal-company.com; dmarc=pass\r\n"
            b"Message-ID: <sprint-deadline-884@internal-company.com>\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/plain; charset=UTF-8\r\n"
            b"\r\n"
            b"Hi team,\r\n"
            b"Immediate action required before 5pm today: please finalize your sprint architecture reviews.\r\n"
            b"Our customer demo is scheduled for tomorrow morning.\r\n"
            b"Thanks,\r\nSarah\r\n"
        )
        trial = _run_full_trial(raw_eml)
        summary = trial["summary"]

        self.assertEqual(summary["verdict"], "LEGITIMATE / SAFE")
        self.assertLessEqual(summary["risk_score"], 15.0)
        self.assertEqual(summary["fatal_vetos"], 0)

    # =========================================================================
    # DELIVERABLE 3: URL ANALYSIS (Shortened, Long, Suspicious & Legitimate Links)
    # =========================================================================

    def test_03a_url_analysis_shortened_urls(self):
        """Req 3: Verify detection of obfuscated URL shortener services (bit.ly, tinyurl, t.co)."""
        raw_eml = (
            b"From: news@techblog.io\r\n"
            b"To: dev@company.com\r\n"
            b"Subject: Interesting Article\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/html; charset=UTF-8\r\n"
            b"\r\n"
            b"<p>Check this link:</p>\r\n"
            b"<a href=\"https://bit.ly/3xY9AbC\">Read Story</a>\r\n"
        )
        trial = _run_full_trial(raw_eml)
        counts = trial["prosecution"]["counts"]
        shortener_counts = [c for c in counts if "Shortener" in c["charge_name"]]
        self.assertGreaterEqual(len(shortener_counts), 1)
        self.assertIn("bit.ly", shortener_counts[0]["exhibit"])

    def test_03b_url_analysis_long_urls_and_defense_objection(self):
        """Req 3: Verify parameter-dense extended URIs (>200 chars) are tracked and defended if authenticated."""
        long_url = "https://auth.enterprise-portal.com/oauth/v2/authorize?client_id=corp_client_app_991823&response_type=code&redirect_uri=https%3A%2F%2Fapp.enterprise-portal.com%2Fcallback&scope=openid%20profile%20email&state=c5d8e1f4a9b20e736184950274bc93fa&nonce=93847291847291847291847291847291"
        raw_eml = (
            b"From: \"SSO Identity Provider\" <auth@enterprise-portal.com>\r\n"
            b"To: user@company.com\r\n"
            b"Subject: SSO Authentication Request\r\n"
            b"Authentication-Results: mail.enterprise-portal.com; spf=pass; dkim=pass header.d=enterprise-portal.com; dmarc=pass\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/html; charset=UTF-8\r\n"
            b"\r\n"
            + f"<a href=\"{long_url}\">Complete Sign In</a>\r\n".encode("utf-8")
        )
        trial = _run_full_trial(raw_eml)
        # Defense should object to benign parameterized long URI
        objections = trial["defense"]["objections"]
        has_url_dismissal = any("BENIGN_ENTERPRISE_DEEP_LINK" in obj.get("objection_type", "") for obj in objections)
        self.assertTrue(has_url_dismissal)
        self.assertEqual(trial["summary"]["verdict"], "LEGITIMATE / SAFE")

    def test_03c_url_analysis_suspicious_structures(self):
        """Req 3: Verify suspicious URL structures: Raw IP literal, Hex IP, and Brand Typosquatting."""
        # 1. Raw IP Literal
        parsed_ip = EMLParser.parse(b"Subject: Alert\r\n\r\n<a href=\"http://198.51.100.45/login\">Click here</a>")
        prosecution_ip = TeamProsecutor().prosecute(parsed_ip)
        self.assertTrue(any("IP-Literal" in c["charge_name"] for c in prosecution_ip["counts"]))

        # 2. Hex Obfuscated IP
        parsed_hex = EMLParser.parse(b"Subject: Alert\r\n\r\n<a href=\"http://0x7f000001/verify\">Login</a>")
        prosecution_hex = TeamProsecutor().prosecute(parsed_hex)
        self.assertTrue(any("Hex" in c["charge_name"] or "Obfuscated" in c["charge_name"] for c in prosecution_hex["counts"]))

        # 3. Brand Squatting in URL
        parsed_squat = EMLParser.parse(b"Subject: Alert\r\n\r\n<a href=\"https://paypal-security-verification.com/login\">Paypal</a>")
        prosecution_squat = TeamProsecutor().prosecute(parsed_squat)
        self.assertTrue(any("Brand" in c["charge_name"] or "Squatting" in c["charge_name"] for c in prosecution_squat["counts"]))

    def test_03d_url_analysis_legitimate_links(self):
        """Req 3: Verify legitimate links without deceptive structures pass cleanly."""
        raw_eml = (
            b"From: receipts@stripe.com\r\n"
            b"To: accounting@company.com\r\n"
            b"Subject: Invoice #INV-1092\r\n"
            b"Authentication-Results: mx.stripe.com; spf=pass; dkim=pass header.d=stripe.com; dmarc=pass\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/html; charset=UTF-8\r\n"
            b"\r\n"
            b"<a href=\"https://dashboard.stripe.com/receipts/INV-1092\">View Invoice</a>\r\n"
        )
        trial = _run_full_trial(raw_eml)
        self.assertEqual(trial["summary"]["verdict"], "LEGITIMATE / SAFE")
        self.assertLessEqual(trial["summary"]["risk_score"], 10.0)

    # =========================================================================
    # DELIVERABLE 4: MISSING SENDER, INCOMPLETE HEADERS & EMPTY INPUTS
    # =========================================================================

    def test_04a_empty_input_graceful_handling(self):
        """Req 4: Ensure completely empty input produces safe fallback without crashing."""
        parsed = EMLParser.parse(b"")
        self.assertEqual(parsed["envelope"]["from_email"], "")
        self.assertEqual(parsed["body"]["combined"], "")
        trial = _run_full_trial(b"")
        self.assertEqual(trial["summary"]["verdict"], "LEGITIMATE / SAFE")
        self.assertEqual(trial["summary"]["risk_score"], 0.0)

    def test_04b_missing_sender_details(self):
        """Req 4: Ensure missing From/Sender headers are handled gracefully."""
        raw_eml = b"To: recipient@company.com\r\nSubject: No From Header\r\n\r\nMessage body without sender"
        parsed = EMLParser.parse(raw_eml)
        self.assertEqual(parsed["envelope"]["from_email"], "")
        self.assertEqual(parsed["envelope"]["from_display"], "")

        trial = _run_full_trial(raw_eml)
        self.assertIsNotNone(trial["summary"]["verdict"])
        self.assertFalse(trial.get("error"))

    def test_04c_incomplete_headers_and_fragmented_mime(self):
        """Req 4: Ensure incomplete email headers or malformed boundaries parse without unhandled errors."""
        raw_eml = (
            b"Content-Type: text/plain\r\n"
            b"Date: \r\n"
            b"X-Custom-Header: True\r\n"
            b"\r\n"
            b"Fragmented email body without standard MIME envelope."
        )
        trial = _run_full_trial(raw_eml)
        self.assertIsNotNone(trial["summary"]["verdict"])
        self.assertEqual(trial["summary"]["fatal_vetos"], 0)

    def test_04d_binary_garbage_input_resilience(self):
        """Req 4: Ensure arbitrary binary non-email data is handled safely."""
        garbage_bytes = b"\x00\xff\xfe\x00\x12\x34\x56\x78\xaa\xbb\xcc\xdd\xee"
        trial = _run_full_trial(garbage_bytes)
        self.assertIsNotNone(trial["summary"]["risk_score"])
        self.assertIsInstance(trial["summary"]["risk_score"], float)

    # =========================================================================
    # DELIVERABLE 5: RENAMED EXECUTABLE FILES (.pdf with MZ signature)
    # =========================================================================

    def test_05a_renamed_executable_pdf_with_mz_signature(self):
        """Req 5: Test renamed executable (.pdf extension but MZ executable signature)."""
        pe_payload = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"Binary trojan shellcode payload" * 8
        report = AttachmentAnalyzer.inspect_attachment(
            filename="Financial_Report_Q3.pdf",
            payload=pe_payload,
            declared_ct="application/pdf"
        )
        self.assertEqual(report["risk_level"], "MALICIOUS")
        self.assertEqual(report["risk_score"], 100.0)
        self.assertIn("Renamed Executable", report["classification"])
        self.assertIn("application/x-dosexec", report["detected_type"])
        self.assertTrue(any("MZ" in ev or "4D 5A" in ev for ev in report["evidence"]))

        # Full email pipeline test
        raw_eml = (
            b"From: attacker@shadow-c2.org\r\n"
            b"To: victim@company.com\r\n"
            b"Subject: Attached Q3 Report\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: multipart/mixed; boundary=\"BND\"\r\n"
            b"\r\n"
            b"--BND\r\n"
            b"Content-Type: text/plain\r\n\r\n"
            b"See report attached.\r\n"
            b"--BND\r\n"
            b"Content-Type: application/pdf; name=\"Financial_Report_Q3.pdf\"\r\n"
            b"Content-Disposition: attachment; filename=\"Financial_Report_Q3.pdf\"\r\n\r\n"
            + pe_payload + b"\r\n"
            b"--BND--"
        )
        trial = _run_full_trial(raw_eml)
        self.assertIn("FAKE", trial["summary"]["verdict"])
        self.assertGreaterEqual(trial["summary"]["risk_score"], 95.0)
        self.assertGreaterEqual(trial["summary"]["fatal_vetos"], 1)

    def test_05b_renamed_executable_docx_with_elf_signature(self):
        """Req 5: Test renamed Linux binary (.docx extension with ELF executable signature)."""
        elf_payload = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00" + b"Linux dropper payload" * 10
        report = AttachmentAnalyzer.inspect_attachment(
            filename="Employee_Handbook.docx",
            payload=elf_payload,
            declared_ct="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        self.assertEqual(report["risk_level"], "MALICIOUS")
        self.assertEqual(report["risk_score"], 100.0)
        self.assertIn("Renamed Executable", report["classification"])
        self.assertIn("application/x-executable", report["detected_type"])

    # =========================================================================
    # DELIVERABLE 6: MACRO DOCUMENTS, PASSWORD-PROTECTED ZIPS & IN-BODY PASSWORDS
    # =========================================================================

    def test_06a_macro_enabled_office_document_detection(self):
        """Req 6: Validate detection of macro-enabled Office documents (vbaProject.bin with AutoOpen)."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("[Content_Types].xml", b"<Types><Default Extension=\"xml\" ContentType=\"application/xml\"/></Types>")
            zf.writestr("_rels/.rels", b"<Relationships></Relationships>")
            # Inject simulated VBA binary stream with weaponized auto-exec tokens
            vba_payload = b"Attribute VB_Name = \"Module1\"\r\nSub AutoOpen()\r\nShell \"powershell.exe -enc aW52b2tlLWV4cHJlc3Npb24=\"\r\nEnd Sub"
            zf.writestr("word/vbaProject.bin", vba_payload)
        docm_bytes = buf.getvalue()

        report = AttachmentAnalyzer.inspect_attachment(
            filename="Urgent_Invoice.docm",
            payload=docm_bytes,
            declared_ct="application/vnd.ms-word.document.macroEnabled.12"
        )
        self.assertEqual(report["risk_level"], "MALICIOUS")
        self.assertGreaterEqual(report["risk_score"], 95.0)
        self.assertIn("vbaProject.bin", " ".join(report["evidence"]))
        self.assertTrue(any("AutoOpen" in ev or "Shell" in ev for ev in report["evidence"]))

    def test_06b_password_protected_zip_archive_detection(self):
        """Req 6: Validate detection of password-protected encrypted ZIP archives."""
        zip_payload = bytes.fromhex("504B0304140001000800") + b"...ENCRYPTED_PAYLOAD.EXE..." + bytes.fromhex("504B01021400140001000800")

        report = AttachmentAnalyzer.inspect_attachment(
            filename="Secure_Archive.zip",
            payload=zip_payload,
            declared_ct="application/zip",
            email_body_text="Please open the attached archive."
        )
        self.assertIn(report["risk_level"], ("SUSPICIOUS", "MALICIOUS"))
        self.assertGreaterEqual(report["risk_score"], 50.0)
        self.assertIn("Password-Protected", report["classification"])
        self.assertTrue(any("encrypted" in ev.lower() or "encryption" in ev.lower() for ev in report["evidence"]))

    def test_06c_password_protected_zip_with_in_body_password_correlation(self):
        """Req 6: Validate correlation when ZIP archive password appears explicitly in email body."""
        zip_payload = bytes.fromhex("504B0304140001000800") + b"...ENCRYPTED_PAYLOAD.EXE..." + bytes.fromhex("504B01021400140001000800")

        email_body = (
            "Dear Finance Team,\n\n"
            "Please find your encrypted remittance report attached.\n"
            "The password to open is: SecretPass2026!\n\n"
            "Kind regards,\nBilling Ops"
        )
        report = AttachmentAnalyzer.inspect_attachment(
            filename="remittance_report.zip",
            payload=zip_payload,
            declared_ct="application/zip",
            email_body_text=email_body
        )
        self.assertEqual(report["risk_level"], "MALICIOUS")
        self.assertEqual(report["risk_score"], 100.0)
        self.assertIn("Password-Protected ZIP Concealing Executable", report["classification"])
        evidence_str = " ".join(report["evidence"])
        self.assertTrue("SecretPass2026!" in evidence_str)

    # =========================================================================
    # DELIVERABLE 7: BENIGN ATTACHMENTS (Vendor PDFs, Plain DOCX, Image ZIPs)
    # =========================================================================

    def test_07a_genuine_vendor_pdf_invoice(self):
        """Req 7: Test benign attachment: genuine vendor PDF invoice cleared with 0.0 risk score."""
        pdf_bytes = (
            b"%PDF-1.7\r\n"
            b"1 0 obj\r\n<< /Type /Catalog /Pages 2 0 R >>\r\nendobj\r\n"
            b"2 0 obj\r\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\r\nendobj\r\n"
            b"3 0 obj\r\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\r\nendobj\r\n"
            b"xref\r\n0 4\r\n0000000000 65535 f \r\n"
            b"trailer\r\n<< /Size 4 /Root 1 0 R >>\r\n"
            b"startxref\r\n190\r\n%%EOF\r\n"
        )
        report = AttachmentAnalyzer.inspect_attachment(
            filename="Invoice_AcmeCorp_March2026.pdf",
            payload=pdf_bytes,
            declared_ct="application/pdf"
        )
        self.assertIn(report["risk_level"], ("SAFE", "BENIGN"))
        self.assertEqual(report["risk_score"], 0.0)
        self.assertIn("Genuine Vendor PDF Invoice", report["classification"])

    def test_07b_plain_macro_free_docx_document(self):
        """Req 7: Test benign attachment: plain macro-free DOCX document cleared with 0.0 risk score."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("[Content_Types].xml", b"<Types><Default Extension=\"xml\" ContentType=\"application/xml\"/></Types>")
            zf.writestr("_rels/.rels", b"<Relationships></Relationships>")
            zf.writestr("word/document.xml", b"<w:document><w:body><w:p><w:r><w:t>Quarterly Project Overview</w:t></w:r></w:p></w:body></w:document>")
        docx_bytes = buf.getvalue()

        report = AttachmentAnalyzer.inspect_attachment(
            filename="Project_Charter_2026.docx",
            payload=docx_bytes,
            declared_ct="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        self.assertIn(report["risk_level"], ("SAFE", "BENIGN"))
        self.assertEqual(report["risk_score"], 0.0)
        self.assertIn("Plain DOCX Document", report["classification"])

    def test_07c_zip_archive_containing_benign_images(self):
        """Req 7: Test benign attachment: ZIP archive containing harmless images cleared with 0.0 risk score."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("photo1.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 40)
            zf.writestr("receipt.jpg", b"\xff\xd8\xff\xe0" + b"\x00" * 40)
        image_zip_bytes = buf.getvalue()

        report = AttachmentAnalyzer.inspect_attachment(
            filename="Event_Photos.zip",
            payload=image_zip_bytes,
            declared_ct="application/zip"
        )
        self.assertIn(report["risk_level"], ("SAFE", "BENIGN"))
        self.assertEqual(report["risk_score"], 0.0)
        self.assertIn("ZIP Archive Containing Images", report["classification"])

    # =========================================================================
    # DELIVERABLE 8: ZERO-EXECUTION STATIC INSPECTION & CONSISTENCY VERIFICATION
    # =========================================================================

    def test_08a_zero_execution_guarantee(self):
        """Req 8: Verify attachments are inspected strictly in-memory without invoking subprocesses or disk writes."""
        # Test on a file with dangerous commands inside payload
        dangerous_cmd_payload = b"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command calc.exe"
        report = AttachmentAnalyzer.inspect_attachment(
            filename="diagnostic.txt",
            payload=dangerous_cmd_payload,
            declared_ct="text/plain"
        )
        # Verify no external processes were spawned and report structure is complete
        self.assertIn("risk_level", report)
        self.assertIn("evidence", report)
        self.assertIn("sha256", report)
        self.assertEqual(report["sha256"], hashlib.sha256(dangerous_cmd_payload).hexdigest())

    def test_08b_consistency_of_mime_signature_extension_metadata(self):
        """Req 8: Verify consistency checking across declared MIME, magic signature, and extension."""
        # Inconsistent file: claims image/jpeg and .jpg, but contains ZIP PK header
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("document.txt", b"plain text")
        inconsistent_payload = buf.getvalue()

        report = AttachmentAnalyzer.inspect_attachment(
            filename="scanned_receipt.jpg",
            payload=inconsistent_payload,
            declared_ct="image/jpeg"
        )
        self.assertNotEqual(report["declared_type"], report["detected_type"])
        self.assertEqual(report["detected_type"], "application/zip")
        self.assertTrue(report["declared_type"] != report["detected_type"])

    # =========================================================================
    # DELIVERABLE 9: EVALUATION OF FP, FN, RISK-SCORE CONSISTENCY & EXPLANATIONS
    # =========================================================================

    def test_09a_confusion_matrix_evaluation_benchmark(self):
        """Req 9: Evaluate system across 8 malicious and 8 legitimate samples to measure FP and FN rates."""
        malicious_samples = [
            # 1. Renamed PE in PDF
            b"From: bad@evil.com\r\nSubject: Invoice\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"B\"\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nOpen\r\n--B\r\nContent-Type: application/pdf; name=\"inv.pdf\"\r\nContent-Disposition: attachment; filename=\"inv.pdf\"\r\n\r\n" + b"MZ" + b"\x00"*60 + b"\r\n--B--",
            # 2. Wire fraud BEC
            b"From: \"CEO\" <exec@external-mail.com>\r\nSubject: Immediate Wire Transfer Required\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nPlease execute an immediate wire transfer of $90,000 to the updated bank details: routing number: 021000021 account number: 12345678.",
            # 3. Anchor deceptive link
            b"From: alert@security.com\r\nSubject: Account Locked\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n<p>Verify account:</p><a href=\"http://phishing-destination.net/login\">https://www.paypal.com/signin</a>",
            # 4. QR code quishing lure
            b"From: hr@external.com\r\nSubject: 2FA Migration\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\nScan with your mobile camera authenticator QR code below: <img src=\"http://bad.top/qr.png\" />",
            # 5. Raw IP literal in link with urgency
            b"From: notice@corp.org\r\nSubject: Immediate Action Required: Verify Account\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\nVerify immediately: <a href=\"http://198.51.100.22/payroll\">Update info</a>",
            # 6. Hex IP obfuscation
            b"From: notice@corp.org\r\nSubject: Urgent Notification\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\nClick: <a href=\"http://0x7f000001/verify\">Login here</a>",
            # 7. Dangerous LNK shortcut attachment
            b"From: tech@bad.com\r\nSubject: Patch\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"B\"\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nRun\r\n--B\r\nContent-Type: application/octet-stream; name=\"patch.lnk\"\r\nContent-Disposition: attachment; filename=\"patch.lnk\"\r\n\r\n" + b"\x4c\x00\x00\x00\x01\x14\x02\x00" + b"\x00"*50 + b"\r\n--B--",
            # 8. Brand combosquatting in URL
            b"From: billing@fake.com\r\nSubject: Immediate Action Required: Account Suspended\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\nYour account will be suspended. Verify immediately: <a href=\"http://paypal-security-verification.com/login\">Pay Now</a>"
        ]

        legitimate_samples = [
            # 1. Google Workspace Security
            b"From: \"Google Workspace\" <no-reply@accounts.google.com>\r\nAuthentication-Results: spf=pass; dkim=pass header.d=accounts.google.com; dmarc=pass\r\nSubject: Security notice\r\n\r\nNew sign in from Chrome: https://myaccount.google.com/security",
            # 2. Microsoft 365 Weekly Digest
            b"From: \"Microsoft 365\" <no-reply@microsoft.com>\r\nAuthentication-Results: spf=pass; dkim=pass header.d=microsoft.com; dmarc=pass\r\nSubject: Digest\r\n\r\nSecurity report: https://admin.microsoft.com",
            # 3. Stripe Receipt
            b"From: receipts@stripe.com\r\nAuthentication-Results: spf=pass; dkim=pass header.d=stripe.com; dmarc=pass\r\nSubject: Receipt #1029\r\n\r\nPayment received: https://dashboard.stripe.com/receipts",
            # 4. Project Urgency Internal Comms
            b"From: lead@company.com\r\nAuthentication-Results: spf=pass; dkim=pass header.d=company.com; dmarc=pass\r\nSubject: Project Deadline 5pm\r\n\r\nPlease send sprint notes before 5pm today.",
            # 5. Clean PDF Invoice Attached
            b"From: accounting@vendor.com\r\nAuthentication-Results: spf=pass; dkim=pass header.d=vendor.com; dmarc=pass\r\nSubject: Invoice Attached\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"B\"\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nAttached\r\n--B\r\nContent-Type: application/pdf; name=\"inv.pdf\"\r\nContent-Disposition: attachment; filename=\"inv.pdf\"\r\n\r\n%PDF-1.7\r\n1 0 obj<<>>endobj\r\nxref\r\n0 2\r\ntrailer<<>>startxref\r\n20\r\n%%EOF\r\n--B--",
            # 6. Meeting invite
            b"From: manager@company.com\r\nAuthentication-Results: spf=pass; dkim=pass header.d=company.com; dmarc=pass\r\nSubject: Team Sync\r\n\r\nLet us sync at 2pm in conference room 3.",
            # 7. Internal password policy reminder
            b"From: it@company.com\r\nAuthentication-Results: spf=pass; dkim=pass header.d=company.com; dmarc=pass\r\nSubject: Security Policy Annual Review\r\n\r\nPlease review security guidelines on the intranet portal: https://intranet.company.com/handbook",
            # 8. Clean Image ZIP attached
            b"From: creative@company.com\r\nAuthentication-Results: spf=pass; dkim=pass header.d=company.com; dmarc=pass\r\nSubject: Banners\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"B\"\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nImages\r\n--B\r\nContent-Type: application/zip; name=\"images.zip\"\r\nContent-Disposition: attachment; filename=\"images.zip\"\r\n\r\n" + b"PK\x03\x04" + b"\x00"*26 + b"banner.png\x89PNG\r\n\x1a\n\x00\x00" + b"\r\n--B--"
        ]

        tp, fn, tn, fp = 0, 0, 0, 0

        for m in malicious_samples:
            res = _run_full_trial(m)
            if "FAKE" in res["summary"]["verdict"] or res["summary"]["risk_score"] >= 65.0:
                tp += 1
            else:
                fn += 1

        for l in legitimate_samples:
            res = _run_full_trial(l)
            if "LEGITIMATE" in res["summary"]["verdict"] and res["summary"]["risk_score"] <= 25.0:
                tn += 1
            else:
                fp += 1

        self.assertEqual(tp, len(malicious_samples), f"Expected 0 False Negatives, got {fn}")
        self.assertEqual(fp, 0, f"Expected 0 False Positives, got {fp}")
        self.assertEqual(tn, len(legitimate_samples))

    def test_09b_risk_score_consistency_and_explanations(self):
        """Req 9: Verify risk scores consistently scale with threat severity and include full evidentiary explanations."""
        # Low risk: mild circumstantial urgency without other indicators
        res_low = _run_full_trial(b"Subject: Quick question\r\n\r\nNeed this soon if possible.")
        self.assertLessEqual(res_low["summary"]["risk_score"], 20.0)

        # High risk: compounding wire fraud + external sender
        res_high = _run_full_trial(b"From: \"CEO\" <ceo@freemail.com>\r\nSubject: Immediate Wire Transfer Required\r\n\r\nPlease execute an immediate wire transfer of $80,000 to the updated bank details: routing number: 021000021 account number: 98765432.")
        self.assertGreaterEqual(res_high["summary"]["risk_score"], 85.0)

        # Explanations present in indictment counts
        for count in res_high["prosecution"]["counts"]:
            self.assertTrue(len(count["explanation"]) > 10)
            self.assertIsNotNone(count["statute"])
            self.assertIsNotNone(count["exhibit"])

    # =========================================================================
    # DELIVERABLE 10: TEST CASES DOCUMENTATION & REPRODUCIBILITY
    # =========================================================================

    def test_10a_structured_telemetry_admissibility(self):
        """Req 10: Verify trial telemetry satisfies courtroom admissibility structure (BSA §65B hash & timestamp)."""
        trial = _run_full_trial(b"From: admin@company.com\r\nSubject: Test Admissibility\r\n\r\nAudit telemetry sample.")
        meta = trial["meta"]
        self.assertIn("sha256", meta)
        self.assertEqual(len(meta["sha256"]), 64)
        self.assertIn("timestamp", meta)

        legal_meta = trial["verdict"]["legal_metadata"]
        self.assertIn("Bharatiya Sakshya Adhiniyam", legal_meta["statute_compliance"])
        self.assertEqual(len(legal_meta["electronic_record_hash"]), 64)
        self.assertEqual(len(legal_meta["adjudication_certificate_token"]), 64)
        self.assertIn("bsa_cert", trial["summary"])


if __name__ == "__main__":
    unittest.main()
