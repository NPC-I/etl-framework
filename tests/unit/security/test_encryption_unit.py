"""
Unit tests for encryption module (isolated, fast tests).
"""
import pandas as pd
import pytest

from etl_framework.security.encryption import DataEncryptor, SecurityError


class TestEncryptionUnit:
    """Unit tests for DataEncryptor."""

    @pytest.mark.unit
    @pytest.mark.security
    def test_encryptor_initialization(self):
        """Test encryptor initialization with environment key."""
        import os

        os.environ["ETL_ENCRYPTION_KEY"] = "test-encryption-key-12345"

        encryptor = DataEncryptor()
        assert encryptor is not None

        # Clean up
        del os.environ["ETL_ENCRYPTION_KEY"]

    @pytest.mark.unit
    @pytest.mark.security
    def test_encryptor_missing_key_error(self):
        """Test error when encryption key is missing."""
        import os

        # Ensure key is not set
        if "ETL_ENCRYPTION_KEY" in os.environ:
            del os.environ["ETL_ENCRYPTION_KEY"]

        with pytest.raises(SecurityError, match="Encryption key required"):
            DataEncryptor()

    @pytest.mark.unit
    @pytest.mark.security
    def test_encrypt_decrypt_value(self, encryptor_fixture):
        """Test encryption and decryption of single value."""
        plaintext = "sensitive-data-123"

        # Encrypt
        encrypted = encryptor_fixture.encrypt_value(plaintext)

        # Verify encryption changed the value
        assert encrypted != plaintext
        assert isinstance(encrypted, str)

        # Decrypt
        decrypted = encryptor_fixture.decrypt_value(encrypted)

        # Verify roundtrip
        assert decrypted == plaintext

    @pytest.mark.unit
    @pytest.mark.security
    def test_encrypt_decrypt_column(self, encryptor_fixture, sensitive_dataframe):
        """Test encryption and decryption of DataFrame column."""
        df = sensitive_dataframe

        # Encrypt SSN column
        encrypted_df = encryptor_fixture.encrypt_column(df, "ssn")

        # Verify encryption
        assert encrypted_df["ssn"].iloc[0] != df["ssn"].iloc[0]
        assert (
            "encrypted" not in str(encrypted_df["ssn"].iloc[0]).lower()
        )  # Not a simple prefix

        # Decrypt SSN column
        decrypted_df = encryptor_fixture.decrypt_column(encrypted_df, "ssn")

        # Verify roundtrip
        pd.testing.assert_series_equal(decrypted_df["ssn"], df["ssn"])

    @pytest.mark.unit
    @pytest.mark.security
    def test_encrypt_dataframe(self, encryptor_fixture, sensitive_dataframe):
        """Test encryption of entire DataFrame with sensitive columns."""
        df = sensitive_dataframe

        # Encrypt sensitive columns
        encrypted_df = encryptor_fixture.encrypt_dataframe(df)

        # Verify sensitive columns are encrypted
        sensitive_cols = ["ssn", "credit_card", "phone"]
        for col in sensitive_cols:
            if col in df.columns:
                assert encrypted_df[col].iloc[0] != df[col].iloc[0]

        # Verify non-sensitive columns are unchanged
        non_sensitive_cols = ["name", "amount", "quantity"]
        for col in non_sensitive_cols:
            if col in df.columns:
                pd.testing.assert_series_equal(encrypted_df[col], df[col])

    @pytest.mark.unit
    @pytest.mark.security
    def test_identify_sensitive_columns(self, encryptor_fixture, sensitive_dataframe):
        """Test automatic identification of sensitive columns."""
        df = sensitive_dataframe

        sensitive_cols = encryptor_fixture._identify_sensitive_columns(df)

        # Verify sensitive columns are identified
        assert "ssn" in sensitive_cols
        assert "credit_card" in sensitive_cols
        assert "phone" in sensitive_cols

        # Verify non-sensitive columns are not identified
        assert "name" not in sensitive_cols
        assert "amount" not in sensitive_cols

    @pytest.mark.unit
    @pytest.mark.security
    @pytest.mark.parametrize(
        "plaintext",
        [
            "simple",
            "with-special-chars!@#$%^&*()",
            "with spaces",
            "with\nnewlines",
            "with\ttabs",
            "",  # Empty string
            "x" * 1000,  # Long string
        ],
    )
    def test_encrypt_various_inputs(self, encryptor_fixture, plaintext):
        """Test encryption with various input types."""
        encrypted = encryptor_fixture.encrypt_value(plaintext)
        decrypted = encryptor_fixture.decrypt_value(encrypted)

        assert decrypted == plaintext

    @pytest.mark.unit
    @pytest.mark.security
    def test_encrypt_none_values(self, encryptor_fixture, sample_dataframe):
        """Test encryption with None/NaN values."""
        df = sample_dataframe.copy()

        # Add a column with None values
        df["nullable"] = [None, "value", None, "another", None]

        # Encrypt the column
        encrypted_df = encryptor_fixture.encrypt_column(df, "nullable")

        # Verify None values are preserved (use pd.isna for NaN compatibility)
        assert pd.isna(encrypted_df["nullable"].iloc[0])
        assert pd.isna(encrypted_df["nullable"].iloc[2])
        assert pd.isna(encrypted_df["nullable"].iloc[4])

        # Verify non-None values are encrypted
        assert encrypted_df["nullable"].iloc[1] != "value"
        assert encrypted_df["nullable"].iloc[3] != "another"

    @pytest.mark.unit
    @pytest.mark.security
    def test_encrypt_specific_columns(self, encryptor_fixture, sensitive_dataframe):
        """Test encryption of specific columns only."""
        df = sensitive_dataframe

        # Encrypt only specific columns
        columns_to_encrypt = ["ssn", "credit_card"]
        encrypted_df = encryptor_fixture.encrypt_dataframe(
            df, columns=columns_to_encrypt
        )

        # Verify specified columns are encrypted
        for col in columns_to_encrypt:
            if col in df.columns:
                assert encrypted_df[col].iloc[0] != df[col].iloc[0]

        # Verify other columns are unchanged
        other_cols = [col for col in df.columns if col not in columns_to_encrypt]
        for col in other_cols:
            pd.testing.assert_series_equal(encrypted_df[col], df[col])

    @pytest.mark.unit
    @pytest.mark.security
    def test_decrypt_non_encrypted_column(self, encryptor_fixture, sample_dataframe):
        """Test decrypting a column that wasn't encrypted."""
        df = sample_dataframe

        # Try to decrypt a non-encrypted column
        # This should either fail or return the original values
        try:
            result_df = encryptor_fixture.decrypt_column(df, "name")
            # If it doesn't fail, verify values are unchanged
            pd.testing.assert_series_equal(result_df["name"], df["name"])
        except Exception as e:
            # Decryption of non-encrypted data may fail
            # Check exception type or message
            from cryptography.fernet import InvalidToken

            if isinstance(e, InvalidToken):
                # This is the expected error for non-encrypted data
                pass
            else:
                # For other exceptions, check the message
                error_msg = str(e).lower()
                assert any(
                    keyword in error_msg
                    for keyword in ["decrypt", "padding", "token", "invalid", "fernet"]
                ), f"Expected encryption-related error, got: {type(e).__name__}: {error_msg}"

    @pytest.mark.unit
    @pytest.mark.security
    @pytest.mark.slow
    def test_encryption_performance(self, encryptor_fixture, large_dataframe):
        """Test encryption performance with large dataset."""
        df = large_dataframe

        import time

        start_time = time.time()

        # Encrypt a column
        encrypted_df = encryptor_fixture.encrypt_column(df, "value")

        end_time = time.time()
        execution_time = end_time - start_time

        # Verify encryption completed
        assert encrypted_df is not None
        assert encrypted_df["value"].iloc[0] != df["value"].iloc[0]

        # Performance check (should complete in reasonable time)
        # 10,000 rows should encrypt in under 5 seconds
        assert execution_time < 5.0, f"Encryption took {execution_time:.2f} seconds"

        print(f"Encrypted {len(df)} rows in {execution_time:.2f} seconds")
        print(f"Rate: {len(df) / execution_time:.0f} rows/second")
