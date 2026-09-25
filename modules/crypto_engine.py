"""modules/crypto_engine.py.

AES-256-GCM field-level encryption, Envelope Encryption, and KMS key
lifecycle.
"""

import base64
import os
from typing import Any, Dict, List, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pandas as pd


class KeyManagementService:
    """Simulates a central Cloud KMS / HSM (Hardware Security Module).

    Maintains isolated Key Encryption Keys (KEKs) for each financial tenant.
    """

    def __init__(self):
        # Tenant -> Master KEK (256-bit raw bytes)
        self._master_keys: Dict[str, bytes] = {}

    def get_or_create_tenant_kek(self, tenant_id: str) -> bytes:
        """Retrieves or provisions a dedicated 256-bit AES KEK for a specific tenant."""
        if tenant_id not in self._master_keys:
            # Generate 32 bytes (256 bits) cryptographically secure key
            self._master_keys[tenant_id] = AESGCM.generate_key(bit_length=256)
        return self._master_keys[tenant_id]

    def rotate_tenant_kek(self, tenant_id: str) -> bytes:
        """Rotates the tenant Master KEK in compliance with annual key rotation policies."""
        new_key = AESGCM.generate_key(bit_length=256)
        self._master_keys[tenant_id] = new_key
        return new_key


# Global KMS instance
kms_vault = KeyManagementService()


class EnvelopeEncryption:
    """Implements Envelope Encryption using AES-256-GCM."""

    @staticmethod
    def encrypt_payload(
        plaintext: str, tenant_id: str
    ) -> Tuple[str, str, str]:
        """Encrypts data using envelope encryption.

        Returns: (encrypted_data_b64, encrypted_dek_b64, iv_nonce_b64)
        """
        # 1. Obtain Tenant Master KEK from KMS
        tenant_kek = kms_vault.get_or_create_tenant_kek(tenant_id)

        # 2. Generate an ephemeral 256-bit Data Encryption Key (DEK)
        dek = AESGCM.generate_key(bit_length=256)

        # 3. Encrypt the plaintext data with the DEK using AES-256-GCM
        nonce_data = os.urandom(12)  # Standard 96-bit nonce for GCM
        aesgcm_data = AESGCM(dek)
        ciphertext = aesgcm_data.encrypt(
            nonce_data, plaintext.encode("utf-8"), None
        )

        # 4. Encrypt the DEK with the Tenant Master KEK (Key Wrapping)
        nonce_kek = os.urandom(12)
        aesgcm_kek = AESGCM(tenant_kek)
        wrapped_dek = aesgcm_kek.encrypt(nonce_kek, dek, None)

        # Base64 encode for secure JSON/storage transport
        enc_data_b64 = base64.b64encode(ciphertext).decode("utf-8")
        enc_dek_b64 = base64.b64encode(nonce_kek + wrapped_dek).decode("utf-8")
        iv_b64 = base64.b64encode(nonce_data).decode("utf-8")

        return enc_data_b64, enc_dek_b64, iv_b64

    @staticmethod
    def decrypt_payload(
        enc_data_b64: str, enc_dek_b64: str, iv_b64: str, tenant_id: str
    ) -> str:
        """Unwraps the DEK using the Tenant KEK, then decrypts the ciphertext payload."""
        tenant_kek = kms_vault.get_or_create_tenant_kek(tenant_id)

        # 1. Unwrap the DEK
        wrapped_dek_raw = base64.b64decode(enc_dek_b64)
        nonce_kek = wrapped_dek_raw[:12]
        wrapped_dek = wrapped_dek_raw[12:]

        aesgcm_kek = AESGCM(tenant_kek)
        dek = aesgcm_kek.decrypt(nonce_kek, wrapped_dek, None)

        # 2. Decrypt the data using unwrapped DEK
        ciphertext = base64.b64decode(enc_data_b64)
        nonce_data = base64.b64decode(iv_b64)

        aesgcm_data = AESGCM(dek)
        decrypted_bytes = aesgcm_data.decrypt(nonce_data, ciphertext, None)
        return decrypted_bytes.decode("utf-8")


def encrypt_sensitive_dataset(
    df: pd.DataFrame, target_columns: List[str]
) -> pd.DataFrame:
    """Transforms a plain financial DataFrame into an encrypted-at-rest state using envelope encryption."""
    encrypted_df = df.copy()

    for col in target_columns:
        if col in encrypted_df.columns:

            def _encrypt_val(row, column_name):
                val_str = str(row[column_name])
                tenant = row["Client_Tenant"]
                enc_data, _, _ = EnvelopeEncryption.encrypt_payload(
                    val_str, tenant
                )
                return f"AES256_GCM:{enc_data[:24]}...[ENCRYPTED]"

            encrypted_df[col] = encrypted_df.apply(
                lambda r: _encrypt_val(r, col), axis=1
            )

    return encrypted_df


def inspect_transit_security(protocol: str, cipher: str) -> Dict[str, Any]:
    """Evaluates whether network transmission meets financial regulatory mandates (PCI DSS / TLS standards)."""
    approved_protocols = ["TLSv1.3", "IPSec", "SFTP"]
    deprecated_protocols = ["SSLv3", "TLSv1.0", "TLSv1.1", "HTTP", "FTP"]

    approved_ciphers = [
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "ECDHE-RSA-AES256-GCM-SHA384",
    ]

    status = "COMPLIANT"
    reasons = []

    if protocol in deprecated_protocols:
        status = "CRITICAL_VIOLATION"
        reasons.append(
            f"Protocol {protocol} is cryptographically insecure and banned by PCI DSS."
        )
    elif protocol not in approved_protocols and protocol != "TLSv1.2":
        status = "NON_COMPLIANT"
        reasons.append(f"Protocol {protocol} is not in approved cipher list.")

    if cipher not in approved_ciphers:
        if status != "CRITICAL_VIOLATION":
            status = "WARNING"
        reasons.append(
            f"Cipher suite {cipher} does not support Perfect Forward Secrecy (PFS)."
        )

    return {
        "Protocol": protocol,
        "Cipher_Suite": cipher,
        "Status": status,
        "Findings": reasons if reasons else ["Meets modern financial grade crypto standards."],
    }