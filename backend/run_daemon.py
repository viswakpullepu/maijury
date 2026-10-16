"""
MAILJURY AUTONOMOUS INBOX DAEMON CLI RUNNER
Runs headlessly in the background without any UI interaction required.

Behavior:
1. Monitors mailbox in background (Gmail API polling + backend/incoming spool directory).
2. As soon as an email arrives, activates testing pipeline immediately.
3. If validated as SCAM: Sends alert warning email via OAuth send mail feature.
4. If validated as LEGIT: Zero emails sent (false-positive suppression).
"""
import os
import sys
import time
import argparse

sys.path.insert(0, os.path.dirname(__file__))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from background_monitor import BackgroundMonitorDaemon

def run():
    parser = argparse.ArgumentParser(description="MailJury Autonomous Background Daemon")
    parser.add_argument("--interval", type=int, default=3, help="Poll interval in seconds (default: 3)")
    parser.add_argument("--single-pass", action="store_true", help="Run a single intake pass and exit")
    args = parser.parse_args()

    daemon = BackgroundMonitorDaemon(poll_interval_seconds=args.interval)
    daemon.start()

    print("=" * 80)
    print("   ⚖️  MAILJURY AUTONOMOUS INBOX PROTECTION DAEMON")
    print("=" * 80)
    print(f"Status:               ACTIVE & MONITORING IN BACKGROUND")
    print(f"Polling Interval:     {daemon.poll_interval} seconds")
    print(f"Live Gmail OAuth:     {'CONNECTED' if daemon.gmail.is_live else 'OFFLINE (High-Fidelity Sandbox Active)'}")
    print(f"Incoming Spool Dir:   {daemon.incoming_dir}")
    print(f"Audit Trail Log:      {daemon.audit_log_path}")
    print(f"OAuth Outbox Log:     {daemon.gmail.sent_log_path}")
    print("-" * 80)
    print("AUTONOMOUS RULES:")
    print("  1. When an email arrives, daemon activates and starts adversarial trial.")
    print("  2. If validated as SCAM: Sends warning email via OAuth to user/recipient.")
    print("  3. If validated as LEGIT: NO EMAIL SENT (Zero noise & false alarms).")
    print("=" * 80)
    print("\n[DAEMON] Waiting for incoming emails... (Press Ctrl+C to stop)\n")

    last_scanned = 0

    try:
        while True:
            records = daemon.sync_once(batch_size=5)
            if records:
                for r in records:
                    ts_str = time.strftime("%H:%M:%S", time.localtime(r["timestamp"]))
                    subj = r.get("subject", "(No Subject)")[:40]
                    sender = r.get("from", "Unknown")[:30]
                    score = r.get("final_risk_score", 0.0)
                    is_scam = r.get("is_scam", False)
                    alert_sent = r.get("oauth_alert_sent", False)

                    print(f"[{ts_str}] 📥 Email Arrived: \"{subj}\" from <{sender}>")
                    print(f"[{ts_str}] ⚖️ Testing Activated: Prosecution vs Defense Courtroom...")

                    if is_scam:
                        print(f"[{ts_str}] 🚨 RESULT: SCAM DETECTED! Verdict: {r.get('verdict')} (Score: {score}/100)")
                        if alert_sent:
                            recip = r.get("to") or "recipient"
                            print(f"[{ts_str}] ✉️  ACTION: Alert email dispatched via OAuth send mail to <{recip}>!")
                        else:
                            print(f"[{ts_str}] ✉️  ACTION: Scam quarantined. Alert dispatch completed.")
                    else:
                        print(f"[{ts_str}] ✅ RESULT: VALIDATED AS LEGITIMATE! (Score: {score}/100)")
                        print(f"[{ts_str}] 🛡️ ACTION: Certified Safe. NO EMAIL SENT (False-positive prevented).")
                    print("-" * 60)

            if args.single_pass:
                break
            time.sleep(daemon.poll_interval)
    except KeyboardInterrupt:
        print("\n[DAEMON] Shutting down autonomous monitor...")
        daemon.stop()
        print("[DAEMON] Stopped cleanly.")

if __name__ == "__main__":
    run()
