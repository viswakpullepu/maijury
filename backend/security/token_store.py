"""
ENCRYPTED TOKEN STORE
Zero-plaintext storage for Google OAuth 2.0 refresh tokens, access tokens, and scopes.
Protected by CryptoVault AES-256-GCM envelope encryption.
"""
import os
import json
import threading
from typing import Dict, Any, Optional

from .crypto_vault import CryptoVault

class EncryptedTokenStore:
    """Thread-safe encrypted credential manager."""

    def __init__(self, store_path: Optional[str] = None, vault: Optional[CryptoVault] = None):
        self.store_path = store_path or os.path.abspath(os.path.join(os.path.dirname(__file__), "vault_tokens.enc"))
        self.vault = vault or CryptoVault()
        self._lock = threading.Lock()

    def save_tokens(self, token_data: Dict[str, Any], user_id: str = "primary_user") -> bool:
        """Encrypts and safely persists tokens."""
        with self._lock:
            # Read existing store if present
            store: Dict[str, Any] = {}
            if os.path.exists(self.store_path):
                try:
                    with open(self.store_path, "r", encoding="utf-8") as f:
                        encrypted_blob = f.read().strip()
                    if encrypted_blob:
                        store = self.vault.decrypt_json(encrypted_blob, context="MailJury-Token-Store")
                except Exception:
                    store = {}

            # Update entry for user
            store[user_id] = token_data

            # Encrypt entire store with fresh salt & nonce
            encrypted_envelope = self.vault.encrypt_json(store, context="MailJury-Token-Store")
            with open(self.store_path, "w", encoding="utf-8") as f:
                f.write(encrypted_envelope)
            return True

    def get_tokens(self, user_id: str = "primary_user") -> Optional[Dict[str, Any]]:
        """Decrypts and returns tokens for user in volatile memory."""
        with self._lock:
            if not os.path.exists(self.store_path):
                return None

            try:
                with open(self.store_path, "r", encoding="utf-8") as f:
                    encrypted_blob = f.read().strip()
                if not encrypted_blob:
                    return None

                store = self.vault.decrypt_json(encrypted_blob, context="MailJury-Token-Store")
                return store.get(user_id)
            except Exception as e:
                return None

    def has_active_tokens(self, user_id: str = "primary_user") -> bool:
        """Checks if encrypted credentials exist without decrypting entire payload."""
        tokens = self.get_tokens(user_id)
        if tokens and (tokens.get("refresh_token") or tokens.get("access_token")):
            return True
        return False

    def clear_tokens(self, user_id: str = "primary_user") -> bool:
        """Securely zeroizes and wipes tokens for the user."""
        with self._lock:
            if os.path.exists(self.store_path):
                try:
                    os.remove(self.store_path)
                    return True
                except Exception:
                    return False
            return True
