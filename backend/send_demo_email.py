"""
MAILJURY DEMO EMAIL SENDER & SPOOL INTAKE UTILITY
Enables 1-command dispatch of demo scenarios into the background spool directory or live Gmail.
"""
import os
import sys
import shutil
import argparse
from email import message_from_bytes

sys.path.insert(0, os.path.dirname(__file__))

def main():
    parser = argparse.ArgumentParser(description="MailJury Demo Email Utility")
    parser.add_argument("--drop", type=int, choices=[1, 2, 3, 4, 5], help="Drop scenario (1-5) into backend/incoming/ spool directory")
    parser.add_argument("--drop-all", action="store_true", help="Drop all 5 demo scenarios into backend/incoming/")
    parser.add_argument("--adjudicate", type=int, choices=[1, 2, 3, 4, 5], help="Directly adjudicate scenario (1-5) in volatile RAM")
    parser.add_argument("--send-gmail", type=int, choices=[1, 2, 3, 4, 5], help="Send scenario (1-5) to live Gmail inbox using OAuth")
    args = parser.parse_args()

    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    demo_dir = os.path.join(root_dir, "demo_emails")
    spool_dir = os.path.join(root_dir, "backend", "incoming")
    os.makedirs(spool_dir, exist_ok=True)

    file_map = {
        1: "01_SCAM_disguised_exe_in_pdf.eml",
        2: "02_SCAM_macro_word_doc.eml",
        3: "03_SCAM_encrypted_zip_body_password.eml",
        4: "04_LEGIT_clean_vendor_invoice.eml",
        5: "05_LEGIT_urgent_hr_benefits_review.eml"
    }

    if args.drop:
        fn = file_map[args.drop]
        src = os.path.join(demo_dir, fn)
        dst = os.path.join(spool_dir, fn)
        shutil.copyfile(src, dst)
        print(f"[SUCCESS] Dropped {fn} into background spool: {dst}")
        print("The background daemon will process it within seconds!")
        return

    if args.drop_all:
        for idx, fn in file_map.items():
            src = os.path.join(demo_dir, fn)
            dst = os.path.join(spool_dir, fn)
            shutil.copyfile(src, dst)
            print(f"  [+] Spooled: {fn}")
        print(f"[SUCCESS] Dropped all 5 demo emails into {spool_dir}")
        return

    if args.adjudicate:
        fn = file_map[args.adjudicate]
        src = os.path.join(demo_dir, fn)
        with open(src, "rb") as f:
            raw = f.read()

        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")

        from background_monitor import BackgroundMonitorDaemon
        daemon = BackgroundMonitorDaemon()
        print(f"\nAdjudicating {fn} through Tri-Pillar Courtroom...")
        result = daemon.process_single_email_bytes(raw, source_id=fn)
        record = result.get("trial_record", result)

        print("=" * 60)
        print(f"Subject:    {record.get('subject')}")
        print(f"Verdict:    {record.get('verdict')}")
        print(f"Risk Score: {record.get('final_risk_score')}/100")
        print(f"Action:     {'[!] OAUTH ALERT EMAIL DISPATCHED' if record.get('oauth_alert_sent') else '[OK] SILENCE MAINTAINED (ZERO NOISE)'}")
        print(f"Latency:    {record.get('pipeline_ms')} ms")
        print(f"BSA Token:  {record.get('bsa_cert_token')}")
        print("=" * 60)
        return


    if args.send_gmail:
        fn = file_map[args.send_gmail]
        src = os.path.join(demo_dir, fn)
        with open(src, "rb") as f:
            raw = f.read()

        from gmail_client import GmailClient
        gc = GmailClient()
        ok, msg = gc.authenticate()
        if not ok or not gc.is_live:
            print(f"[ERROR] Live Gmail OAuth not active: {msg}")
            return

        import base64
        profile = gc.service.users().getProfile(userId='me').execute()
        my_email = profile.get('emailAddress')
        
        # Insert into inbox
        encoded_msg = base64.urlsafe_b64encode(raw).decode('utf-8')
        created = gc.service.users().messages().insert(userId='me', body={'raw': encoded_msg, 'labelIds': ['INBOX', 'UNREAD']}).execute()
        print(f"[SUCCESS] Injected {fn} into live inbox of {my_email}! Message ID: {created.get('id')}")
        print("Run 'python backend/run_daemon.py' to watch the daemon intercept it!")
        return

    parser.print_help()

if __name__ == "__main__":
    main()
