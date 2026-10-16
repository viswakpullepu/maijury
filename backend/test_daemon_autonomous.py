"""
UNIT & INTEGRATION TESTS: AUTONOMOUS BACKGROUND DAEMON & OAUTH EMAIL DISPATCH
Validates:
1. Daemon activates automatically in background upon email arrival.
2. Scams trigger autonomous warning email dispatch via OAuth.
3. Legitimate emails trigger ZERO outbound emails (no false alarms).
4. Local spool directory (backend/incoming/) auto-ingestion operates headlessly.
"""
import os
import sys
import unittest
import time

sys.path.insert(0, os.path.dirname(__file__))

from background_monitor import BackgroundMonitorDaemon

class TestAutonomousDaemonWorkflow(unittest.TestCase):

    def setUp(self):
        self.daemon = BackgroundMonitorDaemon(poll_interval_seconds=1)
        self.daemon.gmail.sent_outbox.clear()

    def test_01_scam_email_triggers_oauth_alert_send(self):
        """
        When a scam email arrives, daemon activates testing, detects the threat,
        and sends a warning email using OAuth send mail.
        """
        scam_email = (
            b"From: \"IT Security Alerts\" <security@fake-support-microsoft.com>\r\n"
            b"To: victim_employee@company.com\r\n"
            b"Subject: URGENT: Account Suspension in 1 hour - Verify credentials\r\n"
            b"Date: Fri, 16 Oct 2026 12:00:00 +0000\r\n"
            b"Authentication-Results: mx.company.com; spf=fail dkim=fail dmarc=fail\r\n"
            b"Content-Type: text/html; charset=utf-8\r\n\r\n"
            b"<html><body>"
            b"<h2>Immediate Action Required</h2>"
            b"<p>Your password expired. Click here to login: "
            b"<a href='http://microsoft.xn--e1afmkfd.com/login'>http://microsoft.com/verify</a></p>"
            b"</body></html>"
        )

        initial_sent_count = len(self.daemon.gmail.sent_outbox)
        result = self.daemon.process_single_email_bytes(scam_email, source_id="test-scam-01")
        record = result["trial_record"]

        # 1. Verification of scam detection
        self.assertTrue(record["is_scam"], "Scam email should be classified as is_scam=True")
        self.assertGreaterEqual(record["final_risk_score"], 70.0, "Risk score must reflect high severity threat")

        # 2. Verification that email was sent using OAuth send mail
        self.assertTrue(record["oauth_alert_sent"], "OAuth alert email MUST be sent for verified scams")
        self.assertEqual(len(self.daemon.gmail.sent_outbox), initial_sent_count + 1)

        sent_msg = self.daemon.gmail.sent_outbox[0]
        self.assertEqual(sent_msg["to"], "victim_employee@company.com")
        self.assertIn("[MailJury Threat Alert] SCAM Email Blocked", sent_msg["subject"])
        self.assertIn("SCAM DETECTED", sent_msg["body_snippet"])
        self.assertEqual(sent_msg["status"], "SENT_SUCCESS")

    def test_02_legit_email_sends_no_email(self):
        """
        When a legitimate email arrives, daemon activates testing, validates it as clean,
        and strictly DOES NOT send any email (zero false-alarm noise).
        """
        legit_email = (
            b"From: \"AWS Billing\" <no-reply@amazon.com>\r\n"
            b"To: accounting@company.com\r\n"
            b"Subject: Amazon Web Services Monthly Invoice\r\n"
            b"Date: Fri, 16 Oct 2026 12:00:00 +0000\r\n"
            b"Authentication-Results: mx.company.com; spf=pass dkim=pass dmarc=pass\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\r\n\r\n"
            b"--BOUNDARY\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
            b"Please find attached your genuine AWS monthly invoice.\r\n\r\n"
            b"--BOUNDARY\r\n"
            b"Content-Type: application/pdf; name=\"invoice.pdf\"\r\n"
            b"Content-Disposition: attachment; filename=\"invoice.pdf\"\r\n"
            b"Content-Transfer-Encoding: base64\r\n\r\n"
            b"JVBERi0xLjcKMSAwIG9iago8PCAvVHlwZSAvQ2F0YWxvZyA+PgplbmRvYmoKdHJhaWxlcgo8PCAvUm9vdCAxIDAgUiA+PgolJUVPRg==\r\n"
            b"--BOUNDARY--"
        )

        initial_sent_count = len(self.daemon.gmail.sent_outbox)
        result = self.daemon.process_single_email_bytes(legit_email, source_id="test-legit-01")
        record = result["trial_record"]

        # 1. Verification of legitimate classification
        self.assertFalse(record["is_scam"], "Genuine invoice must NOT be flagged as scam")
        self.assertLessEqual(record["final_risk_score"], 25.0, "Risk score must be safe")
        self.assertIn("LEGITIMATE", record["verdict"])

        # 2. Verification that NO email was sent
        self.assertFalse(record["oauth_alert_sent"], "NO email should be sent when email is validated as legit")
        self.assertEqual(len(self.daemon.gmail.sent_outbox), initial_sent_count, "Outbox count must not increase")

    def test_03_renamed_executable_scam_triggers_oauth_alert(self):
        """
        When an email with a renamed executable (.pdf with MZ header) arrives,
        daemon activates, flags the PE payload, and sends an alert email via OAuth.
        """
        pe_email = (
            b"From: \"Contractor Services\" <vendor@untrusted-network.com>\r\n"
            b"To: hr@company.com\r\n"
            b"Subject: Signed Employment Contract PDF\r\n"
            b"Date: Fri, 16 Oct 2026 14:00:00 +0000\r\n"
            b"Authentication-Results: mx.company.com; spf=fail dkim=none\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: multipart/mixed; boundary=\"PE-BOUNDARY\"\r\n\r\n"
            b"--PE-BOUNDARY\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
            b"Please open the attached contract.\r\n\r\n"
            b"--PE-BOUNDARY\r\n"
            b"Content-Type: application/pdf; name=\"contract.pdf\"\r\n"
            b"Content-Disposition: attachment; filename=\"contract.pdf\"\r\n"
            b"Content-Transfer-Encoding: base64\r\n\r\n"
            b"TVqQAAMAAAAEAAAA//8AAA==\r\n"
            b"--PE-BOUNDARY--"
        )

        initial_sent_count = len(self.daemon.gmail.sent_outbox)
        result = self.daemon.process_single_email_bytes(pe_email, source_id="test-pe-01")
        record = result["trial_record"]

        self.assertTrue(record["is_scam"])
        self.assertGreaterEqual(record["final_risk_score"], 90.0)
        self.assertTrue(record["oauth_alert_sent"])
        self.assertEqual(len(self.daemon.gmail.sent_outbox), initial_sent_count + 1)
        self.assertIn("Signed Employment Contract PDF", self.daemon.gmail.sent_outbox[0]["subject"])

    def test_04_incoming_spool_directory_autonomous_processing(self):
        """
        When an email file is placed into backend/incoming/ spool directory,
        daemon's sync_once() automatically detects it, runs the trial, and dispatches OAuth alert.
        """
        spool_dir = self.daemon.incoming_dir
        test_file = os.path.join(spool_dir, f"test_arrival_{int(time.time()*1000)}.eml")

        scam_content = (
            b"From: \"Payroll Alert\" <phish@payroll-wire-scam.com>\r\n"
            b"To: executive@company.com\r\n"
            b"Subject: IMMEDIATE ACTION: Updated Wire Instructions\r\n"
            b"Date: Fri, 16 Oct 2026 15:00:00 +0000\r\n"
            b"Authentication-Results: mx.company.com; spf=fail dkim=fail\r\n\r\n"
            b"Wire transfer immediately to routing number 123456789."
        )

        with open(test_file, "wb") as f:
            f.write(scam_content)

        # Trigger sync_once (representing background daemon poll)
        records = self.daemon.sync_once(batch_size=5)

        # Confirm the file was picked up and processed
        self.assertFalse(os.path.exists(test_file), "File in incoming spool should be ingested and moved")
        spool_records = [r for r in records if "test_arrival_" in r.get("source_id", "")]
        self.assertTrue(len(spool_records) > 0, "Spool record must be present in sync_once results")
        self.assertTrue(spool_records[0]["is_scam"], "Spool scam must be flagged")
        self.assertTrue(spool_records[0]["oauth_alert_sent"], "OAuth alert must be sent for spool scam")

    def test_05_password_protected_zip_scam_triggers_oauth_alert(self):
        """
        When an email with a password-protected ZIP archive and in-body password arrives,
        daemon activates, flags the evasion dropper, and sends an alert email via OAuth.
        """
        zip_enc_payload = bytes.fromhex("504B0304140001000800") + b"...ENCRYPTED_PAYLOAD.EXE..." + bytes.fromhex("504B01021400140001000800")
        import base64
        enc_b64 = base64.b64encode(zip_enc_payload).decode('ascii')

        pw_email = (
            f'From: "HR Payroll" <hr@external-payroll-audit.com>\r\n'
            f'To: finance@company.com\r\n'
            f'Subject: Confidential Q3 Bonus Schedule - Encrypted\r\n'
            f'Date: Fri, 16 Oct 2026 16:00:00 +0000\r\n'
            f'Authentication-Results: mx.company.com; spf=fail dkim=fail\r\n'
            f'MIME-Version: 1.0\r\n'
            f'Content-Type: multipart/mixed; boundary="ZIP-PW-BOUND"\r\n\r\n'
            f'--ZIP-PW-BOUND\r\n'
            f'Content-Type: text/plain; charset=utf-8\r\n\r\n'
            f'Attached is the encrypted bonus schedule.\r\n'
            f'The password to open is: SecretPass2026!\r\n\r\n'
            f'--ZIP-PW-BOUND\r\n'
            f'Content-Type: application/zip; name="Bonus_Q3.zip"\r\n'
            f'Content-Disposition: attachment; filename="Bonus_Q3.zip"\r\n'
            f'Content-Transfer-Encoding: base64\r\n\r\n'
            f'{enc_b64}\r\n'
            f'--ZIP-PW-BOUND--'
        ).encode('utf-8')

        initial_sent = len(self.daemon.gmail.sent_outbox)
        res = self.daemon.process_single_email_bytes(pw_email, source_id="test-zip-pw")
        rec = res["trial_record"]

        self.assertTrue(rec["is_scam"], "Encrypted ZIP with in-body password must be flagged as scam")
        self.assertTrue(rec["oauth_alert_sent"], "OAuth alert email must be dispatched")
        self.assertEqual(len(self.daemon.gmail.sent_outbox), initial_sent + 1)

    def test_06_legitimate_urgency_and_long_url_sends_no_alert(self):
        """
        When an authenticated internal email arrives with urgency words and a long OAuth URL,
        daemon validates it as safe under Multi-Indicator Fusion and DOES NOT send any email.
        """
        legit_urgent_email = (
            b"From: \"Acme Corp Benefits\" <benefits@acme-corp.com>\r\n"
            b"To: employee@acme-corp.com\r\n"
            b"Subject: URGENT: Open enrollment deadline expires at 5:00 PM today\r\n"
            b"Date: Fri, 16 Oct 2026 16:30:00 +0000\r\n"
            b"Authentication-Results: mx.acme-corp.com; spf=pass dkim=pass dmarc=pass\r\n"
            b"Content-Type: text/html; charset=utf-8\r\n\r\n"
            b"<html><body>"
            b"<p>Please take action immediately. Open enrollment closes today.</p>"
            b"<a href='https://identity.acme-corp.com/oauth2/v1/authorize?client_id=0oa1234567890abcdef&response_type=code&scope=openid%20profile%20email&redirect_uri=https%3A%2F%2Fbenefits.workday.com%2Fauth%2Fcallback&state=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiIxMjg0OSIsInRpbWVzdGFtcCI6MTc2MDYyMjAwMH0.benign_signature_token_sample_string_value_verification_1234567890'>"
            b"Click here to finalize benefits</a>"
            b"</body></html>"
        )

        initial_sent = len(self.daemon.gmail.sent_outbox)
        res = self.daemon.process_single_email_bytes(legit_urgent_email, source_id="test-legit-urgent")
        rec = res["trial_record"]

        self.assertFalse(rec["is_scam"], "Legitimate urgency email must NOT be flagged as scam")
        self.assertLessEqual(rec["final_risk_score"], 15.0, "Isolated weak signals must be capped <= 15.0")
        self.assertFalse(rec["oauth_alert_sent"], "NO email must be sent for legitimate messages")
        self.assertEqual(len(self.daemon.gmail.sent_outbox), initial_sent, "Outbox count must not increase")

if __name__ == "__main__":
    unittest.main()
