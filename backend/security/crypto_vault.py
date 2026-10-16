"""
CRYPTO VAULT — ZERO-TRUST ENVELOPE ENCRYPTION ENGINE
Implements AES-256-GCM authenticated cipher with HKDF-SHA256 key derivation.
NIST SP 800-38D & RFC 5869 compliant. Zero-plaintext persistence guarantee.
"""
import os
import json
import base64
import secrets
import hmac
import hashlib
from typing import Dict, Any, Tuple, Optional

from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import HKDF
from Cryptodome.Hash import SHA256

class CryptoVault:
    """Enterprise encryption vault for OAuth tokens, API secrets, and sensitive memory."""

    SALT_SIZE = 16    # 128-bit salt
    NONCE_SIZE = 12   # 96-bit GCM nonce (NIST SP 800-38D standard)
    KEY_SIZE = 32     # 256-bit AES key

    def __init__(self, master_secret: Optional[str] = None):
        # Derives or reads master secret from environment, or generates ephemeral secret
        env_secret = os.getenv("MAILJURY_MASTER_KEY") or os.getenv("THREATLENS_MASTER_KEY")
        if master_secret:
            self._master_secret = master_secret.encode('utf-8')
        elif env_secret:
            self._master_secret = env_secret.encode('utf-8')
        else:
            # Persistent key file or ephemeral derivation
            key_file = os.path.abspath(os.path.join(os.path.dirname(__file__), ".master.key"))
            if os.path.exists(key_file):
                with open(key_file, "rb") as f:
                    self._master_secret = f.read()
            else:
                self._master_secret = secrets.token_bytes(32)
                try:
                    with open(key_file, "wb") as f:
                        f.write(self._master_secret)
                except Exception:
                    pass

    def _derive_key(self, salt: bytes, context: str = "MailJury-Vault-Token") -> bytes:
        """Derives a distinct 256-bit key per encryption operation via HKDF-SHA256."""
        return HKDF(
            master=self._master_secret,
            key_len=self.KEY_SIZE,
            salt=salt,
            hashmod=SHA256,
            context=context.encode('utf-8')
        )

    def encrypt(self, plaintext: str | bytes, context: str = "MailJury-Vault-Token") -> str:
        """
        Encrypts plaintext with AES-256-GCM and returns a compact, serialized envelope:
        Format: v1.<salt_b64>.<nonce_b64>.<ciphertext_b64>.<tag_b64>
        """
        raw_data = plaintext.encode('utf-8') if isinstance(plaintext, str) else plaintext
        salt = secrets.token_bytes(self.SALT_SIZE)
        nonce = secrets.token_bytes(self.NONCE_SIZE)
        derived_key = self._derive_key(salt, context)

        cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(raw_data)

        # Base64url encode each component
        parts = [
            "v1",
            base64.urlsafe_b64encode(salt).decode('ascii'),
            base64.urlsafe_b64encode(nonce).decode('ascii'),
            base64.urlsafe_b64encode(ciphertext).decode('ascii'),
            base64.urlsafe_b64encode(tag).decode('ascii')
        ]
        return ".".join(parts)

    def decrypt(self, envelope: str, context: str = "MailJury-Vault-Token") -> bytes:
        """
        Decrypts an envelope. Raises ValueError if tampered, modified, or key is wrong.
        """
        parts = envelope.split('.')
        if len(parts) != 5 or parts[0] != "v1":
            raise ValueError("Invalid cryptographic envelope format.")

        try:
            salt = base64.urlsafe_b64decode(parts[1].encode('ascii'))
            nonce = base64.urlsafe_b64decode(parts[2].encode('ascii'))
            ciphertext = base64.urlsafe_b64decode(parts[3].encode('ascii'))
            tag = base64.urlsafe_b64decode(parts[4].encode('ascii'))
        except Exception as e:
            raise ValueError(f"Envelope decoding failure: {e}")

        derived_key = self._derive_key(salt, context)
        cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)

        try:
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)
            return decrypted
        except Exception:
            # Migration fallback for legacy context
            if context.startswith("MailJury-"):
                legacy_ctx = context.replace("MailJury-", "ThreatLens-")
                try:
                    legacy_key = self._derive_key(salt, legacy_ctx)
                    legacy_cipher = AES.new(legacy_key, AES.MODE_GCM, nonce=nonce)
                    return legacy_cipher.decrypt_and_verify(ciphertext, tag)
                except Exception:
                    pass
            raise ValueError("Integrity verification failed! Ciphertext or tag has been tampered with.")

    def encrypt_json(self, data: Dict[str, Any], context: str = "MailJury-Vault-JSON") -> str:
        """Helper to serialize and encrypt a JSON dictionary."""
        serialized = json.dumps(data, separators=(',', ':'))
        return self.encrypt(serialized, context)

    def decrypt_json(self, envelope: str, context: str = "MailJury-Vault-JSON") -> Dict[str, Any]:
        """Helper to decrypt and deserialize a JSON dictionary."""
        decrypted_bytes = self.decrypt(envelope, context)
        return json.loads(decrypted_bytes.decode('utf-8'))
