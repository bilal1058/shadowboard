"""Key Registry and Management System for ShadowBoard Evidence Signing.

Provides:
1. Public Key Infrastructure (PKI) registry for Ed25519 signing keys
2. Status tracking: ACTIVE, REVOKED, EXPIRED with timestamps and revocation reasons
3. Persistent private key loading and generation from configured SIGNING_KEY_PATH (PEM PKCS#8)
4. Key rotation and revocation management
5. Exportable/importable keyrings for offline third-party verification
"""

from typing import Dict, Any, List, Optional, Tuple
import os
import json
import time
from pathlib import Path
from pydantic import BaseModel, Field
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from app.core.config import settings


class KeyRecord(BaseModel):
    """Metadata record for a registered Ed25519 public signing key."""
    key_id: str
    public_key_hex: str
    algorithm: str = "ED25519"
    status: str = "ACTIVE"  # ACTIVE | REVOKED | EXPIRED
    created_at: float = Field(default_factory=time.time)
    revoked_at: Optional[float] = None
    revocation_reason: Optional[str] = None
    description: str = "ShadowBoard evidence signing key"


class KeyRegistry:
    """Manages trusted public signing keys and the active signing private key."""

    def __init__(self, key_store_path: Optional[str] = None):
        self._keys: Dict[str, KeyRecord] = {}
        self._private_keys: Dict[str, ed25519.Ed25519PrivateKey] = {}
        self._active_key_id: Optional[str] = None
        self._key_store_path = key_store_path

        # Initialize from environment / configuration
        self._initialize_from_config()

    def _initialize_from_config(self) -> None:
        """Initializes the active signing key from config or persistent storage."""
        key_id = settings.KEY_ID or "sb_key_primary"
        signing_key_path = settings.SIGNING_KEY_PATH

        if signing_key_path:
            p = Path(signing_key_path)
            if p.exists():
                try:
                    with open(p, "rb") as f:
                        key_bytes = f.read()
                    # Support PKCS8 PEM or raw private bytes
                    if b"BEGIN PRIVATE KEY" in key_bytes:
                        private_key = serialization.load_pem_private_key(key_bytes, password=None)
                    else:
                        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(key_bytes[:32])
                    self._register_private_key(key_id, private_key, description=f"Loaded from {signing_key_path}")
                    return
                except Exception as exc:
                    pass

            # If path specified but file doesn't exist, create it securely
            try:
                p.parent.mkdir(parents=True, exist_ok=True)
                new_key = ed25519.Ed25519PrivateKey.generate()
                pem_data = new_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
                with open(p, "wb") as f:
                    f.write(pem_data)
                self._register_private_key(key_id, new_key, description=f"Generated at {signing_key_path}")
                return
            except Exception:
                pass

        # Fallback to persistent local key directory if writable
        default_dir = Path("backend/.keys")
        default_pem = default_dir / "shadowboard_signing_key.pem"
        if default_pem.exists():
            try:
                with open(default_pem, "rb") as f:
                    pem_bytes = f.read()
                private_key = serialization.load_pem_private_key(pem_bytes, password=None)
                self._register_private_key(key_id, private_key, description="Persistent instance key")
                return
            except Exception:
                pass

        try:
            default_dir.mkdir(parents=True, exist_ok=True)
            fallback_key = ed25519.Ed25519PrivateKey.generate()
            pem_bytes = fallback_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            with open(default_pem, "wb") as f:
                f.write(pem_bytes)
            self._register_private_key(key_id, fallback_key, description="Instance default persistent key")
            return
        except Exception:
            # Memory-only fallback if filesystem is read-only
            ephemeral_key = ed25519.Ed25519PrivateKey.generate()
            self._register_private_key(key_id, ephemeral_key, description="Ephemeral memory key")

    def _register_private_key(
        self,
        key_id: str,
        private_key: ed25519.Ed25519PrivateKey,
        description: str = "",
    ) -> KeyRecord:
        """Registers a private key and its corresponding public key record."""
        pub_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        record = KeyRecord(
            key_id=key_id,
            public_key_hex=pub_bytes.hex(),
            status="ACTIVE",
            created_at=time.time(),
            description=description,
        )
        self._keys[key_id] = record
        self._private_keys[key_id] = private_key
        self._active_key_id = key_id
        return record

    def register_public_key(self, record: KeyRecord) -> None:
        """Registers a public key record for verification without private key."""
        self._keys[record.key_id] = record

    def get_active_signing_key(self) -> Tuple[ed25519.Ed25519PrivateKey, str]:
        """Returns the active private key and its key_id for signing."""
        if not self._active_key_id or self._active_key_id not in self._private_keys:
            # Re-initialize if missing
            self._initialize_from_config()
        key_id = self._active_key_id or "sb_key_primary"
        return self._private_keys[key_id], key_id

    def get_key(self, key_id: str) -> Optional[KeyRecord]:
        """Retrieves public key record by key_id."""
        return self._keys.get(key_id)

    def is_key_active(self, key_id: str) -> bool:
        """Checks if a key is registered and in ACTIVE status."""
        record = self._keys.get(key_id)
        return record is not None and record.status == "ACTIVE"

    def is_key_revoked(self, key_id: str) -> bool:
        """Checks if a key exists and has been REVOKED."""
        record = self._keys.get(key_id)
        return record is not None and record.status == "REVOKED"

    def revoke_key(self, key_id: str, reason: str = "Key rotated or compromised") -> KeyRecord:
        """Revokes a key by key_id."""
        record = self._keys.get(key_id)
        if not record:
            raise KeyError(f"Key ID '{key_id}' not found in registry")
        record.status = "REVOKED"
        record.revoked_at = time.time()
        record.revocation_reason = reason

        # If active key was revoked, generate a fresh active key
        if self._active_key_id == key_id:
            new_key_id = f"sb_key_{int(time.time())}"
            new_key = ed25519.Ed25519PrivateKey.generate()
            self._register_private_key(new_key_id, new_key, description=f"Automatic rollover after revoking {key_id}")

        return record

    def rotate_key(self, new_key_id: Optional[str] = None) -> Tuple[ed25519.Ed25519PrivateKey, KeyRecord]:
        """Rotates to a newly generated private signing key, keeping old key registered."""
        kid = new_key_id or f"sb_key_{int(time.time())}"
        new_key = ed25519.Ed25519PrivateKey.generate()
        record = self._register_private_key(kid, new_key, description=f"Rotated key at {time.strftime('%Y-%m-%d %H:%M:%SZ')}")
        return new_key, record

    def list_keys(self) -> List[KeyRecord]:
        """Returns all registered public key records."""
        return list(self._keys.values())

    def export_keyring(self) -> Dict[str, Any]:
        """Exports all public key records as a JSON-serializable keyring dictionary."""
        return {
            "version": "1.0",
            "active_key_id": self._active_key_id,
            "keys": [k.model_dump() for k in self._keys.values()],
        }

    def import_keyring(self, keyring_data: Dict[str, Any]) -> int:
        """Imports public key records from a keyring dictionary. Returns count of imported keys."""
        count = 0
        for kd in keyring_data.get("keys", []):
            try:
                record = KeyRecord(**kd)
                self.register_public_key(record)
                count += 1
            except Exception:
                pass
        return count


# Singleton KeyRegistry instance
_GLOBAL_KEY_REGISTRY: Optional[KeyRegistry] = None


def get_active_key_registry() -> KeyRegistry:
    """Returns the shared singleton KeyRegistry instance."""
    global _GLOBAL_KEY_REGISTRY
    if _GLOBAL_KEY_REGISTRY is None:
        _GLOBAL_KEY_REGISTRY = KeyRegistry()
    return _GLOBAL_KEY_REGISTRY


def reset_key_registry() -> KeyRegistry:
    """Resets the singleton KeyRegistry instance (used in tests)."""
    global _GLOBAL_KEY_REGISTRY
    _GLOBAL_KEY_REGISTRY = KeyRegistry()
    return _GLOBAL_KEY_REGISTRY
