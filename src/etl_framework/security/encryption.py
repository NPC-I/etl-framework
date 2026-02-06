"""
Data encryption for ETL operations.
"""
import base64
import os
from typing import Any, List, Optional

import pandas as pd
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class SecurityError(Exception):
    """Base exception for security-related errors."""

    pass


class DataEncryptor:
    """Encrypts/decrypts sensitive data in ETL pipelines."""

    def __init__(self, encryption_key: Optional[str] = None):
        """
        Initialize encryptor with encryption key.

        Args:
            encryption_key: Base64-encoded encryption key.
                          If None, uses environment variable ETL_ENCRYPTION_KEY.
        """
        key = encryption_key or os.getenv("ETL_ENCRYPTION_KEY")
        if not key:
            raise SecurityError(
                "Encryption key required. "
                "Set ETL_ENCRYPTION_KEY environment variable."
            )

        # Derive key from password
        password = key.encode()
        salt = b"etl_framework_salt_"  # Should be unique per installation
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key_bytes = base64.urlsafe_b64encode(kdf.derive(password))
        self.cipher = Fernet(key_bytes)

    def encrypt_column(self, df: pd.DataFrame, column_name: str) -> pd.DataFrame:
        """
        Encrypt a specific column in DataFrame.

        Args:
            df: Input DataFrame.
            column_name: Column to encrypt.

        Returns:
            DataFrame with encrypted column.
        """
        df = df.copy()
        if column_name in df.columns:
            df[column_name] = df[column_name].apply(
                lambda x: self.cipher.encrypt(str(x).encode()).decode()
                if pd.notnull(x)
                else x
            )
        return df

    def decrypt_column(self, df: pd.DataFrame, column_name: str) -> pd.DataFrame:
        """
        Decrypt a specific column in DataFrame.

        Args:
            df: Input DataFrame.
            column_name: Column to decrypt.

        Returns:
            DataFrame with decrypted column.
        """
        df = df.copy()
        if column_name in df.columns:
            df[column_name] = df[column_name].apply(
                lambda x: self.cipher.decrypt(x.encode()).decode()
                if pd.notnull(x) and isinstance(x, str)
                else x
            )
        return df

    def encrypt_dataframe(
        self, df: pd.DataFrame, columns: Optional[List[str]] = None
    ) -> pd.DataFrame:
        """
        Encrypt sensitive columns in DataFrame.

        Args:
            df: Input DataFrame.
            columns: List of columns to encrypt. If None, auto-detect sensitive columns.

        Returns:
            DataFrame with encrypted columns.
        """
        df = df.copy()
        columns_to_encrypt = columns or self._identify_sensitive_columns(df)

        for col in columns_to_encrypt:
            if col in df.columns:
                df = self.encrypt_column(df, col)

        return df

    def _identify_sensitive_columns(self, df: pd.DataFrame) -> List[str]:
        """
        Identify potentially sensitive columns based on naming patterns.

        Args:
            df: DataFrame to analyze.

        Returns:
            List of column names identified as potentially sensitive.
        """
        sensitive_patterns = [
            "password",
            "secret",
            "key",
            "token",
            "credential",
            "ssn",
            "social",
            "security",
            "credit",
            "card",
            "email",
            "phone",
            "address",
            "birth",
            "dob",
            "medical",
            "health",
            "patient",
            "diagnosis",
            "salary",
            "income",
            "bank",
            "account",
            "pin",
        ]

        sensitive_cols = []
        for col in df.columns:
            col_lower = col.lower()
            if any(pattern in col_lower for pattern in sensitive_patterns):
                sensitive_cols.append(col)

        return sensitive_cols

    def encrypt_value(self, value: Any) -> str:
        """
        Encrypt a single value.

        Args:
            value: Value to encrypt.

        Returns:
            Encrypted string.
        """
        return self.cipher.encrypt(str(value).encode()).decode()

    def decrypt_value(self, encrypted_value: str) -> str:
        """
        Decrypt a single value.

        Args:
            encrypted_value: Encrypted string.

        Returns:
            Decrypted string.
        """
        return self.cipher.decrypt(encrypted_value.encode()).decode()
