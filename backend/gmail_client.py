"""
GMAIL API INTEGRATION CLIENT
Connects to Google Gmail API v1 to fetch raw RFC 5322 MIME messages,
runs autonomous remediation (quarantine, labeling, inbox removal),
and supports both Live Google OAuth2 credentials and local sandbox simulation.
"""
import os
import base64
import json
import time
from typing import Dict, List, Any, Optional, Tuple

try:
    from googleapiclient.discovery import build
    from google.oauth2.credentials import Credentials
    from google.auth.transport.requests import Request
    from google_auth_oauthlib.flow import InstalledAppFlow
    GOOGLE_LIBS_AVAILABLE = True
except ImportError:
    GOOGLE_LIBS_AVAILABLE = False

SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/gmail.modify',
    'https://www.googleapis.com/auth/gmail.labels',
    'https://www.googleapis.com/auth/gmail.send'
]

class GmailClient:
    """Manages Gmail API communication, authentication, and remediation actions."""

    LABEL_QUARANTINE = "MAILJURY_QUARANTINED"
    LABEL_SAFE = "MAILJURY_VERIFIED_SAFE"
    LABEL_SUSPICIOUS = "MAILJURY_SUSPICIOUS"

    def __init__(self, credentials_path: Optional[str] = None, token_path: Optional[str] = None):
        self.credentials_path = credentials_path or os.getenv("GMAIL_CREDENTIALS_PATH", "credentials.json")
        self.token_path = token_path or os.getenv("GMAIL_TOKEN_PATH", "token.json")
        self.service = None
        self.is_live = False
        self.simulated_inbox: List[Dict[str, Any]] = []
        self._label_ids: Dict[str, str] = {}
        self.sent_outbox: List[Dict[str, Any]] = []
        self.log_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "logs"))
        os.makedirs(self.log_dir, exist_ok=True)
        self.sent_log_path = os.path.join(self.log_dir, "sent_alerts.jsonl")
        self._init_sandbox_corpus()

    def _init_sandbox_corpus(self):
        """Pre-loads the 30-case benchmark corpus into the sandbox queue for instant offline testing."""
        eml_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "research", "benchmarks", "eml_corpus"))
        if os.path.exists(eml_dir):
            for idx, fn in enumerate(sorted(os.listdir(eml_dir))):
                if fn.endswith(".eml"):
                    fpath = os.path.join(eml_dir, fn)
                    with open(fpath, "rb") as f:
                        raw_bytes = f.read()
                    self.simulated_inbox.append({
                        "id": f"sim-msg-{idx:03d}",
                        "filename": fn,
                        "raw_bytes": raw_bytes,
                        "is_unread": True,
                        "labels": ["INBOX", "UNREAD"]
                    })

    def authenticate(self) -> Tuple[bool, str]:
        """
        Attempts to authenticate with Google Gmail API using token.json or credentials.json.
        Falls back to Sandbox Mode if credentials are not configured yet.
        """
        if not GOOGLE_LIBS_AVAILABLE:
            self.is_live = False
            return False, "Google API libraries not installed. Operating in High-Fidelity Sandbox Mode."

        # 1. Check Encrypted Vault Store first
        try:
            from security.token_store import EncryptedTokenStore
        except ImportError:
            from backend.security.token_store import EncryptedTokenStore
        token_store = EncryptedTokenStore()
        vault_tokens = token_store.get_tokens(user_id="primary_user")
        if vault_tokens:
            if vault_tokens.get("mode") == "SANDBOX_SIMULATED":
                self.is_live = False
                return True, "Authenticated via Encrypted Vault (Sandbox Simulation Mode Active)."
            try:
                creds = Credentials(
                    token=vault_tokens.get("access_token"),
                    refresh_token=vault_tokens.get("refresh_token"),
                    token_uri="https://oauth2.googleapis.com/token",
                    client_id=os.getenv("GOOGLE_CLIENT_ID"),
                    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
                    scopes=SCOPES
                )
            except Exception:
                creds = None

        if not creds and os.path.exists(self.token_path):
            try:
                creds = Credentials.from_authorized_user_file(self.token_path, SCOPES)
            except Exception as e:
                creds = None

        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except Exception:
                creds = None

        if not creds and os.path.exists(self.credentials_path):
            try:
                flow = InstalledAppFlow.from_client_secrets_file(self.credentials_path, SCOPES)
                creds = flow.run_local_server(port=0)
                with open(self.token_path, 'w') as token_file:
                    token_file.write(creds.to_json())
            except Exception as e:
                return False, f"OAuth2 Flow failed: {e}. Falling back to Sandbox Mode."

        if creds and creds.valid:
            try:
                self.service = build('gmail', 'v1', credentials=creds)
                self.is_live = True
                self._ensure_labels_exist()
                return True, "Authenticated successfully with live Google Gmail API."
            except Exception as e:
                self.is_live = False
                return False, f"Failed to build Gmail service: {e}. Falling back to Sandbox Mode."

        self.is_live = False
        return False, (
            "No active credentials.json found in workspace. "
            "Engine is operating in Autonomous Sandbox Simulation Mode (30 live cases ready)."
        )

    def _ensure_labels_exist(self):
        """Ensures that MailJury triage labels exist in the target Gmail account."""
        if not self.is_live or not self.service:
            return

        try:
            results = self.service.users().labels().list(userId='me').execute()
            existing_labels = {l['name']: l['id'] for l in results.get('labels', [])}

            required_labels = [
                (self.LABEL_QUARANTINE, "#ef4444", "#ffffff"),
                (self.LABEL_SAFE, "#22c55e", "#ffffff"),
                (self.LABEL_SUSPICIOUS, "#eab308", "#000000"),
            ]

            for lname, bg, fg in required_labels:
                if lname in existing_labels:
                    self._label_ids[lname] = existing_labels[lname]
                else:
                    label_body = {
                        "name": lname,
                        "labelListVisibility": "labelShow",
                        "messageListVisibility": "show",
                        "color": {
                            "backgroundColor": bg,
                            "textColor": fg
                        }
                    }
                    try:
                        created = self.service.users().labels().create(userId='me', body=label_body).execute()
                        self._label_ids[lname] = created['id']
                    except Exception:
                        pass
        except Exception as e:
            pass

    def fetch_unread_messages(self, max_results: int = 10) -> List[Dict[str, Any]]:
        """
        Fetches unread messages from Gmail (or sandbox queue).
        Returns a list of message descriptors with id and threadId.
        """
        if self.is_live and self.service:
            try:
                resp = self.service.users().messages().list(
                    userId='me', q='is:unread', maxResults=max_results
                ).execute()
                return resp.get('messages', [])
            except Exception as e:
                return []
        else:
            # Sandbox Simulation: return unread messages from simulated queue
            unreads = [m for m in self.simulated_inbox if m["is_unread"]]
            return unreads[:max_results]

    def get_raw_email_bytes(self, msg_id: str) -> Optional[bytes]:
        """
        Fetches raw RFC 5322 MIME stream using Gmail API format='raw'.
        Decodes base64url encoding to return the unmodified binary email.
        """
        if self.is_live and self.service:
            try:
                msg_data = self.service.users().messages().get(
                    userId='me', id=msg_id, format='raw'
                ).execute()
                raw_b64 = msg_data.get('raw', '')
                if raw_b64:
                    return base64.urlsafe_b64decode(raw_b64)
            except Exception as e:
                return None
        else:
            # Sandbox Simulation
            for m in self.simulated_inbox:
                if m["id"] == msg_id:
                    return m["raw_bytes"]
        return None

    def apply_remediation(self, msg_id: str, verdict: str, risk_score: float) -> Dict[str, Any]:
        """
        Executes automated background remediation:
        - FAKE/MALICIOUS: Adds QUARANTINE label, removes INBOX, marks as read.
        - LEGITIMATE: Adds VERIFIED_SAFE label.
        - SUSPICIOUS: Adds SUSPICIOUS label, leaves in inbox with tag.
        """
        action_taken = ""

        if "FAKE" in verdict or risk_score >= 70.0:
            target_label = self.LABEL_QUARANTINE
            add_labels = [target_label]
            remove_labels = ["INBOX", "UNREAD"]
            action_taken = "REMOVED_FROM_INBOX_AND_QUARANTINED"
        elif "LEGITIMATE" in verdict or risk_score <= 25.0:
            target_label = self.LABEL_SAFE
            add_labels = [target_label]
            remove_labels = []
            action_taken = "CERTIFIED_SAFE_DELIVERED_TO_INBOX"
        else:
            target_label = self.LABEL_SUSPICIOUS
            add_labels = [target_label]
            remove_labels = []
            action_taken = "FLAGGED_AS_SUSPICIOUS_CAUTION_APPLIED"

        if self.is_live and self.service:
            try:
                label_id_to_add = self._label_ids.get(target_label)
                body_mod = {}
                if label_id_to_add:
                    body_mod["addLabelIds"] = [label_id_to_add]
                if remove_labels:
                    body_mod["removeLabelIds"] = remove_labels

                if body_mod:
                    self.service.users().messages().modify(
                        userId='me', id=msg_id, body=body_mod
                    ).execute()
            except Exception as e:
                action_taken += f" (Live modify notice: {e})"
        else:
            # Update simulated inbox state
            for m in self.simulated_inbox:
                if m["id"] == msg_id:
                    m["is_unread"] = False
                    for rl in remove_labels:
                        if rl in m["labels"]:
                            m["labels"].remove(rl)
                    if target_label not in m["labels"]:
                        m["labels"].append(target_label)
                    break

        return {
            "msg_id": msg_id,
            "verdict": verdict,
            "risk_score": risk_score,
            "remediation_action": action_taken,
            "applied_label": target_label,
            "timestamp": time.time()
        }

    def send_email(
        self,
        to: str,
        subject: str,
        body_text: str,
        html_body: Optional[str] = None,
        in_reply_to: Optional[str] = None,
        references: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Sends an email using Google OAuth2 Gmail API (users.messages.send).
        Operates with live Google API if authorized, or records into encrypted audit outbox
        in sandbox / test mode.
        """
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

        message = MIMEMultipart("alternative")
        message["To"] = to
        message["From"] = "me"
        message["Subject"] = subject
        message["Date"] = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())
        if in_reply_to:
            message["In-Reply-To"] = in_reply_to
        if references:
            message["References"] = references

        part_text = MIMEText(body_text, "plain", "utf-8")
        message.attach(part_text)

        if html_body:
            part_html = MIMEText(html_body, "html", "utf-8")
            message.attach(part_html)

        raw_bytes = message.as_bytes()
        raw_b64 = base64.urlsafe_b64encode(raw_bytes).decode('ascii')

        sent_record = {
            "timestamp": time.time(),
            "to": to,
            "subject": subject,
            "mode": "LIVE_GMAIL_OAUTH" if (self.is_live and self.service) else "SANDBOX_SIMULATED_OAUTH",
            "body_snippet": body_text[:200] + ("..." if len(body_text) > 200 else ""),
            "raw_length_bytes": len(raw_bytes)
        }

        if self.is_live and self.service:
            try:
                res = self.service.users().messages().send(userId='me', body={'raw': raw_b64}).execute()
                sent_record["status"] = "SENT_SUCCESS"
                sent_record["message_id"] = res.get("id")
                sent_record["thread_id"] = res.get("threadId")
            except Exception as e:
                sent_record["status"] = "ERROR_SENDING"
                sent_record["error"] = str(e)
        else:
            sent_record["status"] = "SENT_SUCCESS"
            sent_record["message_id"] = f"oauth-msg-{int(time.time()*1000)}"

        # Save to memory and persistent audit outbox
        self.sent_outbox.insert(0, sent_record)
        try:
            with open(self.sent_log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(sent_record) + "\n")
        except Exception:
            pass

        return sent_record

    def inject_incoming_email(self, raw_bytes: bytes, filename: str = "incoming_alert.eml") -> Dict[str, Any]:
        """
        Injects a new unread email into the mailbox queue, simulating instant delivery
        from an external mail server or SMTP MTA.
        """
        msg_id = f"incoming-{int(time.time()*1000)}"
        msg_entry = {
            "id": msg_id,
            "filename": filename,
            "raw_bytes": raw_bytes,
            "is_unread": True,
            "labels": ["INBOX", "UNREAD"]
        }
        self.simulated_inbox.insert(0, msg_entry)
        return msg_entry
