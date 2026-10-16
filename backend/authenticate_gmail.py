"""
MAILJURY GMAIL API OAUTH ONE-TIME AUTHENTICATOR
Prints and saves the exact authorization URL, opens browser, and catches the callback.
"""
import os
import sys
from google_auth_oauthlib.flow import InstalledAppFlow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/gmail.modify',
    'https://www.googleapis.com/auth/gmail.labels',
    'https://www.googleapis.com/auth/gmail.send'
]

def main():
    backend_dir = os.path.dirname(os.path.abspath(__file__))
    root_dir = os.path.dirname(backend_dir)
    cred_path = os.path.join(backend_dir, "credentials.json")
    if not os.path.exists(cred_path):
        cred_path = os.path.join(root_dir, "credentials.json")
    token_path = os.path.join(backend_dir, "token.json")
    root_token_path = os.path.join(root_dir, "token.json")

    sys.stdout.reconfigure(line_buffering=True)
    print("=" * 60, flush=True)
    print("MAILJURY GMAIL API OAUTH AUTHENTICATION", flush=True)
    print("=" * 60, flush=True)
    print(f"Reading credentials from: {cred_path}", flush=True)

    flow = InstalledAppFlow.from_client_secrets_file(cred_path, SCOPES)
    auth_url, _ = flow.authorization_url(prompt='consent', access_type='offline')
    
    with open(os.path.join(root_dir, "auth_url.txt"), "w") as f:
        f.write(auth_url)

    print("\n--- GOOGLE AUTH LINK ---", flush=True)
    print(auth_url, flush=True)
    print("------------------------\n", flush=True)

    creds = flow.run_local_server(port=8080, open_browser=True)

    token_json = creds.to_json()
    with open(token_path, "w") as f:
        f.write(token_json)
    with open(root_token_path, "w") as f:
        f.write(token_json)
    print(f"\n[OK] Token saved successfully to: {token_path}", flush=True)

    service = build('gmail', 'v1', credentials=creds)
    profile = service.users().getProfile(userId='me').execute()
    email_addr = profile.get('emailAddress')
    print(f"[SUCCESS] Connected to live Gmail account: {email_addr}", flush=True)
    print("=" * 60, flush=True)

if __name__ == "__main__":
    main()
