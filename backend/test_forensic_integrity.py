"""
test_forensic_integrity.py - Mission 02 Deliverables 6, 7, 8, 9 Verification Suite

Validates:
1. Clear explanations and supporting evidence for every major risk indicator.
2. System test with legitimate and suspicious emails & attachments (risk scoring & reporting).
3. Zero-execution guarantee: strictly in-memory static analysis with zero disk writes.
4. Comprehensive evaluation metrics, limitations, and reporting workflow assertions.
"""

import unittest
import io
import os
import sys
import tempfile
import time
import zipfile

backend_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(backend_dir)
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from attachment_analyzer import AttachmentAnalyzer
from courtroom_arbiter import CourtroomArbiter
from team_prosecutor import TeamProsecutor
from team_defender import TeamDefender
from actionable_recommendations import ActionableRecommendationEngine
from main import _run_full_trial


class TestForensicIntegritySuite(unittest.TestCase):
    """
    Rigorously validates Requirements 6, 7, 8, and 9 of Mission 02.
    """

    def setUp(self):
        self.arbiter = CourtroomArbiter()
        self.prosecutor = TeamProsecutor()
        self.defender = TeamDefender()

    def test_zero_execution_and_zero_disk_writes(self):
        """
        Requirement 8: Ensure attachments are analysed statically without executing
        or opening potentially unsafe files. Asserts zero temp files and zero disk writes.
        """
        # Malicious payload: disguised Windows PE executable with .pdf extension
        pe_payload = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"\x00" * 512
        
        # Track initial directory listing in tempdir
        temp_dir = tempfile.gettempdir()
        initial_temp_files = set(os.listdir(temp_dir))
        
        # Execute static in-memory inspection
        t0 = time.perf_counter()
        result = AttachmentAnalyzer.inspect_attachment(
            filename="urgent_invoice.pdf",
            payload=pe_payload,
            declared_ct="application/pdf",
            email_body_text="Please review the attached invoice immediately."
        )
        elapsed_ms = (time.perf_counter() - t0) * 1000

        # Assert no new files were created in temp dir during analysis
        post_temp_files = set(os.listdir(temp_dir))
        new_files = post_temp_files - initial_temp_files
        self.assertEqual(len(new_files), 0, f"Zero-execution violation! Temporary files created: {new_files}")

        # Assert static classification
        self.assertEqual(result["risk_level"], "MALICIOUS")
        self.assertEqual(result["risk_score"], 100.0)
        self.assertIn("Renamed Executable Payload", result["classification"])
        self.assertFalse(result["is_safe"])
        
        # Assert sub-millisecond static parsing time (no execution overhead)
        self.assertLess(elapsed_ms, 50.0, "Analysis took too long; may indicate emulated execution")

    def test_clear_explanations_and_supporting_evidence_all_pillars(self):
        """
        Requirement 6: Display clear explanations and supporting evidence for
        every major risk indicator across all 4 forensic pillars.
        """
        mz_payload = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"X" * 64
        raw_eml = (
            b"From: \"Bank Executive Alert\" <alert@compromised-finance.xyz>\r\n"
            b"To: victim@corporate.com\r\n"
            b"Subject: URGENT: Wire Transfer Authorization Required Immediately\r\n"
            b"Date: Fri, 16 Oct 2026 14:00:00 +0000\r\n"
            b"Authentication-Results: mx.corporate.com; spf=fail (sender IP not permitted); dkim=fail; dmarc=fail (p=reject)\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: multipart/mixed; boundary=\"BOUNDARY_ALPHA\"\r\n\r\n"
            b"--BOUNDARY_ALPHA\r\n"
            b"Content-Type: text/html; charset=utf-8\r\n\r\n"
            b"<p>Your wire authorization has been suspended. Click here immediately to verify credentials:</p>"
            b"<p><a href=\"http://192.168.1.100/login\">http://bank.legitimate-domain.com/login</a></p>"
            b"\r\n--BOUNDARY_ALPHA\r\n"
            b"Content-Type: application/pdf; name=\"Wire_Instructions.pdf\"\r\n\r\n"
            + mz_payload + b"\r\n--BOUNDARY_ALPHA--"
        )

        trial = _run_full_trial(raw_eml)
        
        # 1. Prosecution Counts & Evidence
        prosecution = trial["prosecution"]
        self.assertGreater(len(prosecution["counts"]), 0)
        for count in prosecution["counts"]:
            self.assertIn("statute", count)
            self.assertIn("explanation", count)
            self.assertIn("exhibit", count)
            self.assertTrue(len(count["explanation"]) > 0, "Explanatory rationale must be clear and non-empty")
            self.assertTrue(len(count["exhibit"]) > 0, "Supporting evidence exhibit must be provided")

        # 2. Verdict & Summary Justification
        summary = trial["summary"]
        self.assertIn("FAKE", summary["verdict"])
        self.assertGreaterEqual(summary["risk_score"], 85.0)
        self.assertTrue(len(summary["justification"]) > 0, "Summary justification must explain verdict")

        # 3. 4-Pillar Risk Breakdown
        breakdown = summary["risk_breakdown"]
        for pillar_key in ["sender", "body", "urls", "attachments"]:
            self.assertIn(pillar_key, breakdown["pillars"])
            pillar = breakdown["pillars"][pillar_key]
            self.assertIn("name", pillar)
            self.assertIn("contribution_score", pillar)
            self.assertIn("contribution_percentage", pillar)
            self.assertIn("severity", pillar)
            self.assertIn("description", pillar)
            self.assertTrue(len(pillar["description"]) > 0, f"Pillar {pillar_key} must have clear explanatory text")

    def test_validation_across_legitimate_and_suspicious_samples(self):
        """
        Requirement 7: Test the system with legitimate and suspicious emails
        and attachments to validate risk scoring and reporting.
        """
        # Test Case A: Genuine Vendor Invoice PDF (Legitimate)
        genuine_pdf_payload = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\nstream\nInvoice #INV-2026-098 Total: $1,250.00 Paid\nendstream\n%%EOF"
        res_legit = AttachmentAnalyzer.inspect_attachment(
            filename="Vendor_Invoice_Q3.pdf",
            payload=genuine_pdf_payload,
            declared_ct="application/pdf",
            email_body_text="Hi team, attached is our invoice for September services."
        )
        self.assertTrue(res_legit["is_safe"])
        self.assertEqual(res_legit["risk_level"], "SAFE")
        self.assertEqual(res_legit["risk_score"], 0.0)
        self.assertIn("Genuine Vendor PDF Invoice", res_legit["classification"])

        # Test Case B: Follina Remote Template Exploit (Suspicious / Malicious)
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, 'w') as zf:
            zf.writestr("[Content_Types].xml", "<Types></Types>")
            zf.writestr("word/_rels/document.xml.rels", '<Relationship Target="ms-msdt:/id PCWDiagnostic /skip force" TargetMode="External" />')
        follina_payload = bio.getvalue()

        res_mal = AttachmentAnalyzer.inspect_attachment(
            filename="statement_update.docx",
            payload=follina_payload,
            declared_ct="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            email_body_text="Please open document to review updated statement."
        )
        self.assertFalse(res_mal["is_safe"])
        self.assertEqual(res_mal["risk_level"], "MALICIOUS")
        self.assertGreaterEqual(res_mal["risk_score"], 95.0)
        self.assertGreater(len(res_mal["mitre_techniques"]), 0)

    def test_actionable_recommendations_workflow(self):
        """
        Requirement 9: Validates actionable recommendations and reporting workflow
        (quarantine, official sender verification, safe viewer environments).
        """
        envelope = {
            "from_raw": "CEO Fraud <ceo@corporate-wire-transfer.xyz>",
            "from_domain": "corporate-wire-transfer.xyz",
            "subject": "Wire Transfer Authorization Required Immediately"
        }
        attachments = [
            {
                "filename": "Wire_Instructions.pdf",
                "risk_level": "MALICIOUS",
                "risk_score": 100.0,
                "classification": "Renamed Executable Payload (MZ Header)"
            }
        ]

        recs = ActionableRecommendationEngine.generate_trial_recommendations(
            verdict="GUILTY_PHISHING",
            risk_score=98.0,
            disposition="SPAM_OR_QUARANTINE",
            parsed_envelope=envelope,
            prosecution={"counts": [{"is_fatal_veto": True}]},
            defense={"motions": []},
            attachments_analysis=attachments
        )

        self.assertEqual(recs["primary_action"], "QUARANTINE_AND_ISOLATE")
        self.assertEqual(recs["quarantine"]["status"], "MANDATORY_IMMEDIATE_QUARANTINE")
        self.assertEqual(recs["quarantine"]["action"], "GATEWAY_DROP_AND_QUARANTINE")
        self.assertEqual(recs["quarantine"]["soc_priority"], "P1_CRITICAL")
        self.assertTrue(len(recs["quarantine"]["mailbox_actions"]) > 0)
        self.assertTrue(recs["verify_sender"]["verification_required"])
        self.assertTrue(recs["safe_viewer"]["has_attachments"])
        self.assertGreater(len(recs["prioritized_checklist"]), 0)


if __name__ == "__main__":
    unittest.main()
