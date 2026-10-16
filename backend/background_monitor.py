"""
AUTONOMOUS BACKGROUND EMAIL MONITOR DAEMON
Continuously monitors inbox in the background, pulls raw messages,
submits each message to the Adversarial Courtroom (Prosecutor vs Defender),
executes automatic remediation, and records immutable BSA 2023 §65B audit trails.
"""
import os
import sys
import time
import json
import threading
from typing import Dict, List, Any, Optional

sys.path.insert(0, os.path.dirname(__file__))

from eml_parser import EMLParser
from team_prosecutor import TeamProsecutor
from team_defender import TeamDefender
from courtroom_arbiter import CourtroomArbiter
from attachment_analyzer import AttachmentAnalyzer
from gmail_client import GmailClient

class BackgroundMonitorDaemon:
    """Singleton background daemon that operates headlessly without any UI interaction."""

    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(BackgroundMonitorDaemon, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, poll_interval_seconds: int = 5):
        if getattr(self, '_initialized', False):
            return

        self.poll_interval = poll_interval_seconds
        self.gmail = GmailClient()
        self.prosecutor = TeamProsecutor()
        self.defender = TeamDefender()
        self.arbiter = CourtroomArbiter()

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # Telemetry & Metrics
        self.start_time: Optional[float] = None
        self.total_scanned = 0
        self.quarantined_fake = 0
        self.certified_safe = 0
        self.suspicious_count = 0
        self.total_scams_detected = 0
        self.total_oauth_alerts_sent = 0
        self.last_poll_time: Optional[float] = None
        self.recent_trials: List[Dict[str, Any]] = []

        # Audit Log & Spool Directories
        self.log_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "logs"))
        self.incoming_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "incoming"))
        self.processed_dir = os.path.join(self.incoming_dir, "processed")
        os.makedirs(self.log_dir, exist_ok=True)
        os.makedirs(self.incoming_dir, exist_ok=True)
        os.makedirs(self.processed_dir, exist_ok=True)
        self.audit_log_path = os.path.join(self.log_dir, "audit_trail.jsonl")

        self._initialized = True

    def start(self):
        """Starts the autonomous background worker loop."""
        with self._lock:
            if self._running:
                return "Daemon is already running."

            self._running = True
            self.start_time = time.time()
            self._thread = threading.Thread(target=self._worker_loop, daemon=True, name="MailJury-Monitor-Daemon")
            self._thread.start()
            return "Autonomous Background Monitor Daemon started successfully."

    def stop(self):
        """Signals the background worker loop to terminate."""
        with self._lock:
            if not self._running:
                return "Daemon is not running."
            self._running = False
            return "Autonomous Background Monitor Daemon stopped."

    def is_running(self) -> bool:
        return self._running

    def get_status(self) -> Dict[str, Any]:
        """Returns live telemetry, uptime, and processing metrics."""
        uptime = round(time.time() - self.start_time, 1) if self.start_time and self._running else 0
        return {
            "daemon_active": self._running,
            "is_live_gmail": self.gmail.is_live,
            "uptime_seconds": uptime,
            "total_scanned": self.total_scanned,
            "quarantined_fake": self.quarantined_fake,
            "certified_safe": self.certified_safe,
            "suspicious_count": self.suspicious_count,
            "total_scams_detected": self.total_scams_detected,
            "total_oauth_alerts_sent": self.total_oauth_alerts_sent,
            "incoming_spool_dir": self.incoming_dir,
            "last_poll_timestamp": self.last_poll_time,
            "recent_trials_cached": len(self.recent_trials),
            "audit_log_file": self.audit_log_path
        }

    def process_single_email_bytes(self, raw_bytes: bytes, source_id: str = "manual") -> Dict[str, Any]:
        """
        Processes a raw email byte stream through the complete adversarial trial pipeline.
        Autonomous Testing & OAuth Email Notification Rule:
        - If validated as SCAM / PHISHING: An alert email is sent via OAuth send mail.
        - If validated as LEGITIMATE / SAFE: NO EMAIL IS SENT (zero false alarms).
        """
        t0 = time.perf_counter()

        parsed = EMLParser.parse(raw_bytes)

        # 1. Zero-execution attachment forensic inspection
        attachments_analysis = []
        for att in parsed.get("attachments", []):
            rep = att.get("analysis")
            if not rep:
                rep = AttachmentAnalyzer.inspect_attachment(
                    filename=att.get("filename", ""),
                    payload=att.get("raw_payload", b""),
                    declared_ct=att.get("declared_type", ""),
                    email_body_text=parsed.get("body", {}).get("combined", "")
                )
                att["analysis"] = rep
            attachments_analysis.append(rep)

        # 2. Adversarial Courtroom Adjudication
        prosecution = self.prosecutor.prosecute(parsed)
        defense = self.defender.defend(parsed, prosecution)
        adjudication = self.arbiter.adjudicate(parsed, prosecution, defense)

        # 3. Autonomous Scam Evaluation
        is_scam = (
            ("FAKE" in adjudication["verdict"]) or
            ("PHISHING" in adjudication["verdict"]) or
            ("MALICIOUS" in adjudication["verdict"]) or
            (adjudication["final_risk_score"] >= 70.0) or
            (adjudication["stats"]["fatal_vetos"] > 0)
        )

        alert_email_sent = False
        alert_details: Dict[str, Any] = {}

        if is_scam:
            # ── SCAM CONFIRMED: TRANSMIT WARNING EMAIL VIA OAUTH ──
            target_recipient = (
                parsed["envelope"].get("to") or
                parsed["envelope"].get("reply_to") or
                os.getenv("MAILJURY_ALERT_RECIPIENT", "user@company.com")
            )
            subj_clean = parsed["envelope"].get("subject", "Hostile Email").strip() or "Hostile Email"
            alert_subject = f"🚨 [MailJury Threat Alert] SCAM Email Blocked: {subj_clean}"

            charges_summary = "\n".join([
                f"  • [{c.get('severity', 'WARN')}] {c.get('name', 'Violation')}: {c.get('description', '')}"
                for c in prosecution.get("counts", [])[:5]
            ])
            att_summary = "\n".join([
                f"  • {a.get('filename', 'file')}: {a.get('classification', 'Unknown')} (Risk: {a.get('risk_level', 'UNKNOWN')})"
                for a in attachments_analysis
            ]) or "  • No attachments detected"

            alert_body = f"""⚠️ MAILJURY AUTONOMOUS CYBER COURTROOM: SCAM DETECTED & QUARANTINED ⚠️

The MailJury Autonomous Daemon has intercepted and quarantined a hostile email.

================================================================================
INCIDENT FORENSICS SUMMARY:
================================================================================
• Subject: {parsed['envelope'].get('subject', '(No Subject)')}
• Sender: {parsed['envelope'].get('from_raw', 'Unknown')}
• Return-Path: {parsed['envelope'].get('return_path', 'None')}
• Date: {parsed['envelope'].get('date', 'Unknown')}
• Message-ID: {parsed['envelope'].get('message_id', 'Unknown')}
• Verdict: {adjudication['verdict']}
• Final Risk Score: {adjudication['final_risk_score']} / 100.0
• Action Taken: {adjudication['disposition']} (Quarantined & Removed from Inbox)
• BSA §65B Certificate: {adjudication['legal_metadata']['adjudication_certificate_token']}

================================================================================
PROSECUTION CHARGES SUSTAINED:
================================================================================
{charges_summary or '  • Multiple suspicious indicators detected'}

================================================================================
ATTACHMENT FORENSICS:
================================================================================
{att_summary}

================================================================================
SAFETY INSTRUCTIONS:
================================================================================
1. DO NOT open, download, or inspect any attachments from this message.
2. DO NOT click any links or reply to the sender.
3. This message has been automatically quarantined from your primary inbox.
4. Cryptographically signed under Indian Evidence Act (BSA) §65B.
"""
            alert_details = self.gmail.send_email(
                to=target_recipient,
                subject=alert_subject,
                body_text=alert_body
            )
            alert_email_sent = True
        else:
            # ── LEGITIMATE EMAIL: NO EMAIL IS SENT ──
            alert_email_sent = False
            alert_details = {
                "sent": False,
                "reason": "Email validated as LEGITIMATE / SAFE. Zero outbound alerts sent (false-positive prevention)."
            }

        # Apply remediation to mailbox (labeling, quarantine, or delivering)
        remediation = self.gmail.apply_remediation(
            source_id, adjudication["verdict"], adjudication["final_risk_score"]
        )
        remediation["oauth_alert_sent"] = alert_email_sent
        remediation["oauth_alert_details"] = alert_details

        t1 = time.perf_counter()
        elapsed_ms = round((t1 - t0) * 1000.0, 2)

        trial_record = {
            "timestamp": time.time(),
            "source_id": source_id,
            "sha256": parsed["sha256"],
            "subject": parsed["envelope"]["subject"],
            "from": parsed["envelope"]["from_raw"],
            "to": parsed["envelope"]["to"],
            "verdict": adjudication["verdict"],
            "final_risk_score": adjudication["final_risk_score"],
            "is_scam": is_scam,
            "oauth_alert_sent": alert_email_sent,
            "oauth_alert_details": alert_details,
            "color": adjudication["verdict_color"],
            "disposition": adjudication["disposition"],
            "remediation": remediation,
            "fatal_vetos": adjudication["stats"]["fatal_vetos"],
            "sustained_charges": adjudication["stats"]["sustained_charges"],
            "dismissed_charges": adjudication["stats"]["dismissed_charges"],
            "defense_proofs": adjudication["stats"]["defense_proofs_entered"],
            "pipeline_ms": elapsed_ms,
            "bsa_cert_token": adjudication["legal_metadata"]["adjudication_certificate_token"]
        }

        # Update metrics
        with self._lock:
            self.total_scanned += 1
            if is_scam:
                self.quarantined_fake += 1
                self.total_scams_detected += 1
                if alert_email_sent:
                    self.total_oauth_alerts_sent += 1
            elif "LEGITIMATE" in adjudication["verdict"]:
                self.certified_safe += 1
            else:
                self.suspicious_count += 1

            self.recent_trials.insert(0, trial_record)
            if len(self.recent_trials) > 100:
                self.recent_trials.pop()

        # Write to immutable BSA 2023 Section 65B JSONL log
        try:
            with open(self.audit_log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(trial_record) + "\n")
        except Exception:
            pass

        return {
            "trial_record": trial_record,
            "parsed": parsed,
            "prosecution": prosecution,
            "defense": defense,
            "adjudication": adjudication,
            "attachments_analysis": attachments_analysis
        }

    def sync_once(self, batch_size: int = 5) -> List[Dict[str, Any]]:
        """
        Executes a single synchronous poll and trial pass on:
        1. Files placed into the incoming spool directory (backend/incoming/).
        2. Pending unread messages from Gmail (or sandbox queue).
        """
        self.last_poll_time = time.time()
        results = []

        # 1. Ingest from local filesystem spool directory (MTA / direct delivery)
        if os.path.exists(self.incoming_dir):
            try:
                for fname in sorted(os.listdir(self.incoming_dir)):
                    fpath = os.path.join(self.incoming_dir, fname)
                    if os.path.isfile(fpath) and fname.endswith((".eml", ".msg", ".txt")):
                        try:
                            with open(fpath, "rb") as f:
                                raw_bytes = f.read()
                            res = self.process_single_email_bytes(raw_bytes, source_id=f"spool-{fname}")
                            results.append(res["trial_record"])

                            # Archive processed email
                            target_path = os.path.join(self.processed_dir, f"{int(time.time())}_{fname}")
                            os.rename(fpath, target_path)
                        except Exception as e:
                            pass
            except Exception:
                pass

        # 2. Ingest unread messages from Gmail API / sandbox queue
        unread_msgs = self.gmail.fetch_unread_messages(max_results=batch_size)
        for msg_info in unread_msgs:
            mid = msg_info.get("id")
            raw_bytes = self.gmail.get_raw_email_bytes(mid)
            if raw_bytes:
                res = self.process_single_email_bytes(raw_bytes, source_id=mid)
                results.append(res["trial_record"])

        return results

    def _worker_loop(self):
        """Daemon thread loop executing continuous inbox protection."""
        while self._running:
            try:
                self.sync_once(batch_size=5)
            except Exception as e:
                pass
            time.sleep(self.poll_interval)
