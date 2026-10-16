"""
Comprehensive Test Suite for Multi-Vector Risk Breakdown
Verifies that Sender, Email Body, URLs, and Attachments correctly contribute to the overall risk score.
"""
import io
import os
import sys
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(__file__))

from main import _run_full_trial
from courtroom_arbiter import CourtroomArbiter
from team_prosecutor import TeamProsecutor
from team_defender import TeamDefender
from eml_parser import EMLParser


class TestRiskBreakdown(unittest.TestCase):
    """Test verification for the 4-pillar risk breakdown engine."""

    def test_01_risk_breakdown_structure_present(self):
        """Verifies that risk_breakdown is present and contains all 4 required pillars."""
        raw_eml = (
            b"From: noreply@example.com\r\n"
            b"To: user@example.com\r\n"
            b"Subject: Test Email\r\n"
            b"Date: Fri, 17 Oct 2026 00:00:00 +0000\r\n"
            b"Content-Type: text/plain\r\n\r\n"
            b"Hello world\r\n"
        )
        trial = _run_full_trial(raw_eml)
        summary = trial["summary"]
        self.assertIn("risk_breakdown", summary)
        rb = summary["risk_breakdown"]

        # Check required fields
        self.assertIn("pillars", rb)
        self.assertIn("total_risk_score", rb)
        self.assertIn("highest_contributor", rb)
        self.assertIn("highest_contributor_name", rb)
        self.assertIn("summary_text", rb)
        self.assertIn("attribution_formula", rb)

        pillars = rb["pillars"]
        for p in ["sender", "body", "urls", "attachments"]:
            self.assertIn(p, pillars)
            p_data = pillars[p]
            self.assertIn("name", p_data)
            self.assertIn("risk_score", p_data)
            self.assertIn("contribution_score", p_data)
            self.assertIn("contribution_percentage", p_data)
            self.assertIn("severity", p_data)
            self.assertIn("status", p_data)
            self.assertIn("has_fatal_veto", p_data)
            self.assertIn("factors", p_data)
            self.assertIn("context_highlights", p_data)
            self.assertIn("summary", p_data)

    def test_02_clean_authenticated_email(self):
        """Verifies 100% clean email yields 0.0 contribution across all 4 pillars."""
        raw_eml = (
            b"From: \"GitHub Team\" <support@github.com>\r\n"
            b"To: engineer@corp.com\r\n"
            b"Subject: Your repository digest\r\n"
            b"Date: Fri, 17 Oct 2026 01:00:00 +0000\r\n"
            b"Message-ID: <digest-123@github.com>\r\n"
            b"Authentication-Results: mx.corp.com; spf=pass (github.com); dkim=pass (github.com); dmarc=pass\r\n"
            b"Content-Type: text/plain\r\n\r\n"
            b"Here is your weekly code review summary. All repositories are healthy.\r\n"
        )
        trial = _run_full_trial(raw_eml)
        rb = trial["summary"]["risk_breakdown"]
        pillars = rb["pillars"]

        self.assertEqual(trial["summary"]["risk_score"], 0.0)
        self.assertEqual(rb["total_risk_score"], 0.0)
        self.assertEqual(rb["highest_contributor"], "none")

        for p_name in ["sender", "body", "urls", "attachments"]:
            p = pillars[p_name]
            self.assertEqual(p["contribution_score"], 0.0)
            self.assertEqual(p["contribution_percentage"], 0.0)
            self.assertEqual(p["severity"], "SAFE")
            self.assertEqual(p["status"], "PASS")
            self.assertFalse(p["has_fatal_veto"])

        # Check SPF / DKIM / DMARC in context highlights
        sender_highlights = " ".join(pillars["sender"]["context_highlights"])
        self.assertIn("SPF: PASS", sender_highlights)
        self.assertIn("DKIM: PASS", sender_highlights)
        self.assertIn("DMARC: PASS", sender_highlights)

    def test_03_attachment_driven_malicious_risk(self):
        """Verifies a disguised executable payload drives 100% of risk to the Attachments pillar."""
        mz_payload = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"PE payload disguised as PDF" * 10
        raw_eml = (
            b"From: accounting@trusted-partner.com\r\n"
            b"To: victim@company.com\r\n"
            b"Subject: Attached invoice\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\r\n\r\n"
            b"--BOUNDARY\r\n"
            b"Content-Type: text/plain\r\n\r\n"
            b"Please find attached your invoice.\r\n"
            b"--BOUNDARY\r\n"
            b"Content-Type: application/pdf; name=\"invoice.pdf\"\r\n"
            b"Content-Disposition: attachment; filename=\"invoice.pdf\"\r\n\r\n"
            + mz_payload + b"\r\n"
            b"--BOUNDARY--"
        )
        trial = _run_full_trial(raw_eml)
        rb = trial["summary"]["risk_breakdown"]
        pillars = rb["pillars"]

        self.assertGreaterEqual(trial["summary"]["risk_score"], 95.0)
        self.assertEqual(rb["highest_contributor"], "attachments")
        self.assertIn("Attachments", rb["highest_contributor_name"])

        # Attachments pillar must be FATAL_VETO
        att_p = pillars["attachments"]
        self.assertTrue(att_p["has_fatal_veto"])
        self.assertEqual(att_p["severity"], "FATAL_VETO")
        self.assertEqual(att_p["status"], "CRITICAL")
        self.assertGreaterEqual(att_p["contribution_percentage"], 90.0)
        self.assertEqual(att_p["risk_score"], 100.0)

        # Sender, body, URLs should have 0 contribution
        self.assertEqual(pillars["sender"]["contribution_score"], 0.0)
        self.assertEqual(pillars["body"]["contribution_score"], 0.0)
        self.assertEqual(pillars["urls"]["contribution_score"], 0.0)

        # Mathematical attribution identity: sum(contributions) == final_risk_score
        total_contrib = round(sum(pillars[p]["contribution_score"] for p in pillars), 1)
        self.assertEqual(total_contrib, trial["summary"]["risk_score"])

    def test_04_url_driven_phishing_risk(self):
        """Verifies deceptive URL anchor mismatch drives the majority of the risk score to URLs."""
        raw_eml = (
            b"From: support@paypal-service.com\r\n"
            b"To: victim@company.com\r\n"
            b"Subject: Account Security Alert\r\n"
            b"Content-Type: text/html; charset=utf-8\r\n\r\n"
            b"<html><body>"
            b"<p>Please verify your account destination: "
            b"<a href=\"http://192.168.1.50/login.php\">https://www.paypal.com/signin</a></p>"
            b"</body></html>"
        )
        trial = _run_full_trial(raw_eml)
        rb = trial["summary"]["risk_breakdown"]
        pillars = rb["pillars"]

        self.assertGreaterEqual(trial["summary"]["risk_score"], 90.0)
        urls_p = pillars["urls"]
        self.assertTrue(urls_p["has_fatal_veto"])
        self.assertEqual(urls_p["severity"], "FATAL_VETO")
        self.assertEqual(urls_p["status"], "CRITICAL")
        self.assertGreaterEqual(urls_p["contribution_score"], 50.0)

        # Mathematical sum preservation
        total_contrib = round(sum(pillars[p]["contribution_score"] for p in pillars), 1)
        self.assertEqual(total_contrib, trial["summary"]["risk_score"])
        total_pct = round(sum(pillars[p]["contribution_percentage"] for p in pillars), 1)
        self.assertEqual(total_pct, 100.0)

    def test_05_body_driven_vec_wire_fraud(self):
        """Verifies Vendor Email Compromise wire fraud wording drives risk to the Body pillar."""
        raw_eml = (
            b"From: vendor@contractor-services.com\r\n"
            b"To: accounts-payable@firm.com\r\n"
            b"Subject: Updated wire transfer instructions for pending invoice\r\n"
            b"Content-Type: text/plain\r\n\r\n"
            b"Please disregard our prior banking instructions. "
            b"We have updated banking remittance details for direct deposit: "
            b"new account number: 981247012, routing number: 021000021. "
            b"Please send wire transfer immediately.\r\n"
        )
        trial = _run_full_trial(raw_eml)
        rb = trial["summary"]["risk_breakdown"]
        pillars = rb["pillars"]

        body_p = pillars["body"]
        self.assertTrue(body_p["has_fatal_veto"])
        self.assertEqual(body_p["severity"], "FATAL_VETO")
        self.assertIn(rb["highest_contributor"], ["body", "sender"])

        # Check factor itemization
        self.assertTrue(any("VEC" in f["title"] or "Wire Fraud" in f["title"] for f in body_p["factors"]))

        # Mathematical sum preservation
        total_contrib = round(sum(pillars[p]["contribution_score"] for p in pillars), 1)
        self.assertEqual(total_contrib, trial["summary"]["risk_score"])

    def test_06_sender_driven_vip_masquerade(self):
        """Verifies VIP display name masquerade with freemail drives risk to Sender pillar."""
        raw_eml = (
            b"From: \"CEO & President\" <executive.officer.corp@gmail.com>\r\n"
            b"To: employee@victim-firm.com\r\n"
            b"Subject: Quick task needed\r\n"
            b"Content-Type: text/plain\r\n\r\n"
            b"Are you at your desk right now?\r\n"
        )
        trial = _run_full_trial(raw_eml)
        rb = trial["summary"]["risk_breakdown"]
        pillars = rb["pillars"]

        sender_p = pillars["sender"]
        self.assertTrue(sender_p["has_fatal_veto"])
        self.assertEqual(sender_p["severity"], "FATAL_VETO")
        self.assertEqual(rb["highest_contributor"], "sender")
        self.assertEqual(rb["highest_contributor_name"], "Sender & Authentication")

        # Mathematical sum preservation
        total_contrib = round(sum(pillars[p]["contribution_score"] for p in pillars), 1)
        self.assertEqual(total_contrib, trial["summary"]["risk_score"])

    def test_07_dismissed_charges_with_defense_grounds(self):
        """Verifies that legitimate emails have dismissed charges clearly recorded in the breakdown."""
        long_legit_url = (
            "https://click.marketing.github.com/track/click/v2?user_id=usr_998124&token=d3b07384d113edec49eaa6238ad5ff00"
            "&session_depth=12&campaign_id=security_bulletin_2026_q4&utm_source=alert&utm_medium=email"
            "&utm_campaign=urgent_security_update&target=https%3A%2F%2Fgithub.com%2Fsettings%2Fsecurity"
        )
        raw_eml = (
            f"From: \"GitHub Security Team\" <support@github.com>\r\n"
            f"To: engineer@company.com\r\n"
            f"Subject: URGENT: Immediate action required to update security credentials\r\n"
            f"Date: Fri, 16 Oct 2026 14:00:00 +0000\r\n"
            f"Message-ID: <sec-alert-991@github.com>\r\n"
            f"Authentication-Results: mx.company.com; spf=pass (github.com); dkim=pass (github.com); dmarc=pass\r\n"
            f"Content-Type: text/html; charset=utf-8\r\n\r\n"
            f"<html><body>"
            f"<p>Immediate action required: review bulletin: <a href=\"{long_legit_url}\">https://github.com/settings/security</a></p>"
            f"</body></html>"
        ).encode('utf-8')

        trial = _run_full_trial(raw_eml)
        rb = trial["summary"]["risk_breakdown"]
        pillars = rb["pillars"]

        # Body had urgency charge filed, but dismissed
        body_p = pillars["body"]
        self.assertGreaterEqual(body_p["dismissed_charges_count"], 1)
        dismissed_body_factors = [f for f in body_p["factors"] if f["status"] == "DISMISSED"]
        self.assertGreaterEqual(len(dismissed_body_factors), 1)
        self.assertIsNotNone(dismissed_body_factors[0]["dismissal_grounds"])

        # URLs had extended URI charge filed, but dismissed
        urls_p = pillars["urls"]
        self.assertGreaterEqual(urls_p["dismissed_charges_count"], 1)
        dismissed_url_factors = [f for f in urls_p["factors"] if f["status"] == "DISMISSED"]
        self.assertGreaterEqual(len(dismissed_url_factors), 1)
        self.assertIsNotNone(dismissed_url_factors[0]["dismissal_grounds"])

        # Total risk score remains clean/safe
        self.assertLessEqual(trial["summary"]["risk_score"], 10.0)

    def test_08_multi_indicator_proportional_attribution(self):
        """Verifies multi-vector email correctly partitions risk across converging vectors."""
        raw_eml = (
            b"From: spoofed@bad-domain.xyz\r\n"
            b"To: victim@company.com\r\n"
            b"Subject: URGENT: Wire transfer required within 24 hours\r\n"
            b"Authentication-Results: mx.company.com; spf=fail (bad-domain.xyz); dkim=fail\r\n"
            b"Content-Type: text/html; charset=utf-8\r\n\r\n"
            b"<html><body>"
            b"<p>Your account will be suspended! Immediate action required!</p>"
            b"<p>Click <a href=\"http://185.220.101.5/confirm\">here</a> to verify.</p>"
            b"</body></html>"
        )
        trial = _run_full_trial(raw_eml)
        rb = trial["summary"]["risk_breakdown"]
        pillars = rb["pillars"]

        self.assertGreaterEqual(trial["summary"]["risk_score"], 60.0)
        # Multiple pillars must have non-zero contribution
        contributing_pillars = [p for p in pillars if pillars[p]["contribution_score"] > 0]
        self.assertGreaterEqual(len(contributing_pillars), 2)

        # Sum of contributions must strictly equal the overall risk score
        total_contrib = round(sum(pillars[p]["contribution_score"] for p in pillars), 1)
        self.assertEqual(total_contrib, trial["summary"]["risk_score"])
        total_pct = round(sum(pillars[p]["contribution_percentage"] for p in pillars), 1)
        self.assertEqual(total_pct, 100.0)


if __name__ == "__main__":
    unittest.main()
