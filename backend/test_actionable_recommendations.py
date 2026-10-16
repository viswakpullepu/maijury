"""
Unit & Integration Test Suite for Actionable Recommendations:
1. Quarantine Recommendations (Mandatory Immediate vs Precautionary Hold vs No Quarantine)
2. Verify Sender Through Official Channel (Out-of-band directory phone, corporate chat, anti-reply rules)
3. Safe Viewer Inspection (PE Disassembly Sandbox, Office Web Sandbox/Dangerzone, Hardened PDF.js, Ephemeral Container)
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from attachment_analyzer import AttachmentAnalyzer
from courtroom_arbiter import CourtroomArbiter
from main import _run_full_trial
from actionable_recommendations import (
    ActionableRecommendationEngine,
    RecommendationCategory,
    RecommendationPriority,
    SafeViewerType
)


class TestActionableRecommendations(unittest.TestCase):
    """Verifies all aspects of Requirement 3: Actionable Recommendations."""

    def test_01_quarantine_recommendation_on_malicious_pe(self):
        """Verify immediate gateway drop and mailbox quarantine recommendation for renamed PE."""
        mz_payload = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"PE payload" * 20
        rep = AttachmentAnalyzer.inspect_attachment("Quarterly_Report.pdf", mz_payload, "application/pdf")

        # Attachment level quarantine
        self.assertEqual(rep["risk_level"], "MALICIOUS")
        self.assertIn("quarantine_guidance", rep)
        self.assertEqual(rep["quarantine_guidance"]["status"], "IMMEDIATE_QUARANTINE_REQUIRED")
        self.assertIn("Quarantine attachment 'Quarterly_Report.pdf' immediately", rep["quarantine_guidance"]["instructions"])

        # End-to-end trial quarantine
        raw_eml = (
            b"From: ceo@impersonated-corp.com\r\n"
            b"To: accountant@company.com\r\n"
            b"Subject: URGENT: Q3 Wire Instructions\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: multipart/mixed; boundary=\"B\"\r\n\r\n"
            b"--B\r\nContent-Type: text/plain\r\n\r\nPlease review payment.\r\n"
            b"--B\r\nContent-Type: application/pdf; name=\"invoice.pdf\"\r\n\r\n"
            + mz_payload + b"\r\n--B--"
        )
        trial = _run_full_trial(raw_eml)
        recs = trial.get("actionable_recommendations", {})

        self.assertEqual(recs.get("primary_action"), "QUARANTINE_AND_ISOLATE")
        self.assertEqual(recs["quarantine"]["status"], "MANDATORY_IMMEDIATE_QUARANTINE")
        self.assertEqual(recs["quarantine"]["action"], "GATEWAY_DROP_AND_QUARANTINE")
        self.assertEqual(recs["quarantine"]["soc_priority"], "P1_CRITICAL")
        self.assertTrue(any("MAILJURY_QUARANTINED" in step for step in recs["quarantine"]["mailbox_actions"]))
        self.assertTrue(any("EDR/SIEM blocklist" in step for step in recs["quarantine"]["gateway_actions"]))

    def test_02_verify_sender_through_official_channel(self):
        """Verify out-of-band sender verification recommendation on spoofed/suspicious email."""
        raw_eml = (
            b"From: \"IT Helpdesk\" <helpdesk@company-internal-support.xyz>\r\n"
            b"To: employee@company.com\r\n"
            b"Reply-To: credential-collector@attacker-c2.net\r\n"
            b"Subject: URGENT: Password Expiring Immediately - Verify Credentials\r\n"
            b"Authentication-Results: mx.company.com; spf=fail dkim=fail dmarc=fail\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/html; charset=utf-8\r\n\r\n"
            b"<html><body>Your password will expire today. Call 1-800-FAKE-NUM or verify at <a href=\"http://attacker-c2.net/login\">Verify Account</a></body></html>\r\n"
        )
        trial = _run_full_trial(raw_eml)
        recs = trial.get("actionable_recommendations", {})
        verif = recs.get("verify_sender", {})

        self.assertTrue(verif.get("verification_required"))
        self.assertIn("Verified Out-of-Band Channel", verif.get("title", ""))
        self.assertIn("helpdesk@company-internal-support.xyz", verif.get("purported_sender", ""))
        checklist = verif.get("protocol_checklist", [])

        # Must mandate NOT replying and NOT calling numbers inside email
        self.assertTrue(any("DO NOT reply" in item for item in checklist))
        self.assertTrue(any("DO NOT call phone numbers printed in the message body" in item for item in checklist))
        self.assertTrue(any("internal HR directory" in item or "verified" in item for item in checklist))

    def test_03_safe_viewer_inspection_pe_binary(self):
        """Verify safe viewer recommendation for Windows PE executable payload."""
        mz_payload = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"X" * 100
        rep = AttachmentAnalyzer.inspect_attachment("bonus_calc.exe", mz_payload, "application/octet-stream")
        viewer_guide = rep.get("safe_viewer_guidance", {})

        self.assertEqual(viewer_guide.get("viewer_type"), SafeViewerType.DISASSEMBLY_SANDBOX)
        self.assertIn("Static Disassembly", viewer_guide.get("recommended_viewer", ""))
        self.assertTrue(any("DO NOT double-click" in p for p in viewer_guide.get("prohibited_actions", [])))
        self.assertTrue(any("Ghidra" in t or "radare2" in t for t in viewer_guide.get("safe_inspection_tools", [])))

    def test_04_safe_viewer_inspection_macro_office_document(self):
        """Verify safe viewer recommendation for macro-enabled document (Dangerzone / Cloud Sandbox)."""
        import io, zipfile
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("[Content_Types].xml", b"<Types></Types>")
            zf.writestr("word/document.xml", b"<document></document>")
            zf.writestr("word/vbaProject.bin", b"AutoOpen shell powershell.exe VirtualAlloc")
        macro_payload = buf.getvalue()

        rep = AttachmentAnalyzer.inspect_attachment("Invoice_Details.docm", macro_payload, "application/vnd.ms-word.document.macroEnabled.12")
        viewer_guide = rep.get("safe_viewer_guidance", {})

        self.assertEqual(viewer_guide.get("viewer_type"), SafeViewerType.ISOLATED_WEB_VIEWER)
        self.assertIn("Dangerzone", viewer_guide.get("recommended_viewer", ""))
        self.assertTrue(any("DO NOT enable macros" in p for p in viewer_guide.get("prohibited_actions", [])))
        self.assertTrue(any("Dangerzone" in t or "Google Docs" in t for t in viewer_guide.get("safe_inspection_tools", [])))

    def test_05_safe_viewer_inspection_pdf_document(self):
        """Verify safe viewer recommendation for PDF file (Hardened PDF.js / JS Disabled)."""
        pdf_payload = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n" + b"X" * 50
        rep = AttachmentAnalyzer.inspect_attachment("statement.pdf", pdf_payload, "application/pdf")
        viewer_guide = rep.get("safe_viewer_guidance", {})

        self.assertIn(viewer_guide.get("viewer_type"), (SafeViewerType.HARDENED_PDF_VIEWER, SafeViewerType.STANDARD_SAFE_VIEWER))
        self.assertTrue(len(viewer_guide.get("safe_inspection_tools", [])) > 0)

    def test_06_safe_viewer_inspection_encrypted_zip_archive(self):
        """Verify safe viewer recommendation for password-protected ZIP archive."""
        enc_zip_payload = b"PK\x03\x04\x14\x00\x01\x00\x08\x00" + b"ENCRYPTED_DATA_BYTES" * 10
        rep = AttachmentAnalyzer.inspect_attachment(
            "Confidential_Files.zip",
            enc_zip_payload,
            "application/zip",
            email_body_text="Password to extract is: Winter2026!"
        )
        viewer_guide = rep.get("safe_viewer_guidance", {})

        self.assertEqual(viewer_guide.get("viewer_type"), SafeViewerType.DISPOSABLE_CONTAINER)
        self.assertIn("Disposable VM or Docker Container", viewer_guide.get("recommended_viewer", ""))
        self.assertTrue(any("DO NOT extract archive using desktop Windows Explorer" in p for p in viewer_guide.get("prohibited_actions", [])))
        self.assertTrue(any("Docker" in t or "Qubes" in t for t in viewer_guide.get("safe_inspection_tools", [])))

    def test_07_safe_vendor_invoice_cleared_recommendations(self):
        """Verify recommendations for certified genuine vendor PDF invoice."""
        clean_pdf = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n" + b"Genuine billing invoice content"
        rep = AttachmentAnalyzer.inspect_attachment("Vendor_Invoice_Q3.pdf", clean_pdf, "application/pdf")

        self.assertEqual(rep["risk_level"], "SAFE")
        self.assertEqual(rep["quarantine_guidance"]["status"], "CLEARED_NO_QUARANTINE")
        self.assertFalse(rep["sender_verification_guidance"]["verification_required"])
        self.assertEqual(rep["safe_viewer_guidance"]["viewer_type"], SafeViewerType.STANDARD_SAFE_VIEWER)

    def test_08_prioritized_checklist_ordering(self):
        """Verify that the trial checklist presents prioritized, numbered actionable steps."""
        mz_payload = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"MALWARE" * 15
        raw_eml = (
            b"From: payroll@fake-spoofed.com\r\n"
            b"To: employee@victim.com\r\n"
            b"Subject: Direct Deposit Update\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: multipart/mixed; boundary=\"XYZ\"\r\n\r\n"
            b"--XYZ\r\nContent-Type: text/plain\r\n\r\nOpen attached update.\r\n"
            b"--XYZ\r\nContent-Type: application/pdf; name=\"payroll_update.pdf\"\r\n\r\n"
            + mz_payload + b"\r\n--XYZ--"
        )
        trial = _run_full_trial(raw_eml)
        recs = trial.get("actionable_recommendations", {})
        checklist = recs.get("prioritized_checklist", [])

        self.assertGreaterEqual(len(checklist), 3)
        categories = [item["category"] for item in checklist]
        self.assertIn(RecommendationCategory.QUARANTINE, categories)
        self.assertIn(RecommendationCategory.VERIFY_SENDER, categories)
        self.assertIn(RecommendationCategory.SAFE_VIEWER, categories)

        # Step 1 must be Quarantine for critical threats
        self.assertEqual(checklist[0]["category"], RecommendationCategory.QUARANTINE)
        self.assertEqual(checklist[0]["priority"], RecommendationPriority.IMMEDIATE)


if __name__ == "__main__":
    unittest.main()
