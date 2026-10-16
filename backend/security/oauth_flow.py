"""
GOOGLE OAUTH 2.0 PKCE FLOW MANAGER
RFC 7636 PKCE (Proof Key for Code Exchange) + Cryptographic Anti-CSRF State Validation.
Handles authorization redirect generation, code exchange, and encrypted vault storage.
"""
import os
import time
import base64
import secrets
import hashlib
import hmac
import json
import urllib.parse
import urllib.request
from typing import Dict, Any, Tuple, Optional

from .crypto_vault import CryptoVault
from .token_store import EncryptedTokenStore

class GoogleOAuthManager:
    """Enterprise OAuth2 flow controller with PKCE and encrypted token lifecycle."""

    AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
    TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
    
    # Principle of Least Privilege: Gmail modify + send allows triage, quarantine, and scam alert notifications
    DEFAULT_SCOPES = [
        "https://www.googleapis.com/auth/gmail.modify",
        "https://www.googleapis.com/auth/gmail.send"
    ]

    def __init__(
        self,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        redirect_uri: Optional[str] = None,
        token_store: Optional[EncryptedTokenStore] = None
    ):
        # Load from credentials.json if available
        creds_path = os.getenv("GMAIL_CREDENTIALS_PATH", "credentials.json")
        loaded_id, loaded_secret = self._load_credentials_file(creds_path)

        self.client_id = client_id or os.getenv("GOOGLE_CLIENT_ID") or loaded_id or "MOCK_CLIENT_ID_MAILJURY"
        self.client_secret = client_secret or os.getenv("GOOGLE_CLIENT_SECRET") or loaded_secret or "MOCK_SECRET"
        self.redirect_uri = redirect_uri or os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/api/auth/google/callback")
        
        self.token_store = token_store or EncryptedTokenStore()
        self.vault = self.token_store.vault
        
        # In-memory PKCE state cache: {state: (code_verifier, timestamp)}
        self._pending_flows: Dict[str, Tuple[str, float]] = {}

    def _load_credentials_file(self, path: str) -> Tuple[Optional[str], Optional[str]]:
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                client_info = data.get("installed") or data.get("web") or {}
                return client_info.get("client_id"), client_info.get("client_secret")
            except Exception:
                pass
        return None, None

    def is_configured(self) -> bool:
        """Returns True if legitimate Google Cloud OAuth credentials are set."""
        return bool(self.client_id and self.client_secret and not self.client_id.startswith("MOCK_CLIENT_ID"))

    def create_authorization_url(self, user_id: str = "primary_user") -> Dict[str, str]:
        """
        Generates RFC 7636 PKCE code_verifier, code_challenge, anti-CSRF state,
        and returns the complete Google consent redirect URL.
        """
        # 1. Generate RFC 7636 PKCE code_verifier (high entropy)
        code_verifier = secrets.token_urlsafe(64) # ~86 chars, base64url-safe
        # code_challenge = BASE64URL-ENCODE(SHA256(code_verifier))
        sha256_digest = hashlib.sha256(code_verifier.encode('ascii')).digest()
        code_challenge = base64.urlsafe_b64encode(sha256_digest).decode('ascii').rstrip('=')

        # 2. Generate Cryptographic Anti-CSRF State
        state_nonce = secrets.token_urlsafe(24)
        state_payload = {
            "nonce": state_nonce,
            "ts": time.time(),
            "uid": user_id
        }
        # Encrypt state token via Vault to prevent forgery or tampering
        state_token = self.vault.encrypt_json(state_payload, context="MailJury-OAuth-State")

        # Cache pending PKCE verifier (valid for 10 minutes)
        self._pending_flows[state_token] = (code_verifier, time.time())
        self._purge_expired_flows()

        # 3. Construct OAuth URL
        if not self.is_configured():
            # Return Mock Sandbox Consent URL for instantaneous testing
            mock_url = f"http://localhost:8000/api/auth/google/mock-consent?state={urllib.parse.quote(state_token)}"
            return {
                "authorization_url": mock_url,
                "mode": "SANDBOX_SIMULATION",
                "state": state_token,
                "code_challenge": code_challenge
            }

        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": " ".join(self.DEFAULT_SCOPES),
            "access_type": "offline",
            "prompt": "consent",
            "state": state_token,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256"
        }
        auth_url = f"{self.AUTH_ENDPOINT}?{urllib.parse.urlencode(params)}"
        return {
            "authorization_url": auth_url,
            "mode": "LIVE_GOOGLE_CLOUD",
            "state": state_token,
            "code_challenge": code_challenge
        }

    def exchange_code(self, code: str, state: str) -> Dict[str, Any]:
        """
        Validates anti-CSRF state, exchanges authorization code for tokens,
        and immediately encrypts them into the CryptoVault.
        """
        # 1. Validate State
        if state not in self._pending_flows:
            raise ValueError("Invalid or expired OAuth state token (CSRF defense triggered).")

        code_verifier, timestamp = self._pending_flows.pop(state)
        if time.time() - timestamp > 600:
            raise ValueError("OAuth authorization flow has expired (> 10 minutes).")

        try:
            state_data = self.vault.decrypt_json(state, context="MailJury-OAuth-State")
            user_id = state_data.get("uid", "primary_user")
        except Exception:
            raise ValueError("Corrupt or tampered OAuth state parameter.")

        # 2. Exchange Code for Tokens
        if not self.is_configured() or code.startswith("mock_"):
            # Mock Token Exchange for immediate sandbox demonstration
            token_response = {
                "access_token": f"mock_access_token_{secrets.token_hex(16)}",
                "refresh_token": f"mock_refresh_token_{secrets.token_hex(24)}",
                "expires_in": 3600,
                "token_type": "Bearer",
                "scope": "https://www.googleapis.com/auth/gmail.modify https://www.googleapis.com/auth/gmail.send",
                "obtained_at": time.time(),
                "mode": "SANDBOX_SIMULATED"
            }
        else:
            token_response = self._request_google_tokens(code, code_verifier)

        # 3. Encrypt Immediately into the Vault (Zero-Plaintext on Disk)
        token_record = {
            "access_token": token_response.get("access_token"),
            "refresh_token": token_response.get("refresh_token"),
            "expires_at": time.time() + token_response.get("expires_in", 3600),
            "token_type": token_response.get("token_type", "Bearer"),
            "scope": token_response.get("scope"),
            "mode": token_response.get("mode", "LIVE_GOOGLE"),
            "updated_at": time.time()
        }

        self.token_store.save_tokens(token_record, user_id=user_id)

        return {
            "status": "AUTHENTICATED_AND_ENCRYPTED",
            "user_id": user_id,
            "mode": token_record["mode"],
            "scopes": token_record["scope"],
            "vault_storage": "AES-256-GCM Envelope Protected"
        }

    def _request_google_tokens(self, code: str, code_verifier: str) -> Dict[str, Any]:
        data = urllib.parse.urlencode({
            "code": code,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "redirect_uri": self.redirect_uri,
            "grant_type": "authorization_code",
            "code_verifier": code_verifier
        }).encode('utf-8')

        req = urllib.request.Request(
            self.TOKEN_ENDPOINT,
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )

        try:
            with urllib.request.urlopen(req) as resp:
                raw_resp = resp.read().decode('utf-8')
                return json.loads(raw_resp)
        except Exception as e:
            raise RuntimeError(f"Google Token Exchange Error: {e}")

    def _purge_expired_flows(self):
        now = time.time()
        expired = [s for s, (_, ts) in self._pending_flows.items() if now - ts > 600]
        for s in expired:
            self._pending_flows.pop(s, None)
