"""
Data cleaning transformer with security features.
"""
import re
from typing import Dict, Optional

import pandas as pd

from etl_framework.core.transformer import Transformer


class DataCleaner(Transformer):
    """
    Performs common data cleaning operations with security:
      - Standardizes column names with security validation
      - Renames columns based on mapping with security checks
      - Handles missing values
      - Validates data for security issues
    """

    def __init__(
        self,
        column_mapping: Optional[Dict[str, str]] = None,
        enable_security: bool = True,
    ):
        """
        Args:
            column_mapping: Optional dictionary mapping original column names
                           to new names (applied after standardization).
            enable_security: Whether to enable security features.
        """
        self.column_mapping = column_mapping or {}
        self.enable_security = enable_security

        # SQL identifier pattern for validation
        self.sql_identifier_pattern = r"^[a-zA-Z_][a-zA-Z0-9_]*$"

    def _validate_column_name(self, column_name: str) -> bool:
        """
        Validate column name for security.

        Args:
            column_name: Column name to validate.

        Returns:
            True if valid, False otherwise.
        """
        if not self.enable_security:
            return True

        # Check for SQL injection patterns
        sql_injection_patterns = [
            ";",
            "--",
            "/*",
            "*/",
            "union",
            "select",
            "insert",
            "delete",
            "drop",
            "update",
            "exec",
            "execute",
        ]

        column_lower = column_name.lower()
        for pattern in sql_injection_patterns:
            if pattern in column_lower:
                return False

        # Check for path traversal patterns
        if ".." in column_name or "/" in column_name or "\\" in column_name:
            return False

        # Check length
        if len(column_name) > 100:
            return False

        return True

    def _sanitize_column_name(self, column_name: str) -> str:
        """
        Sanitize column name for security.

        Args:
            column_name: Column name to sanitize.

        Returns:
            Sanitized column name.
        """
        if not self.enable_security:
            # Basic standardization without security
            return str(column_name).strip().lower().replace(" ", "_").replace("-", "_")

        # Convert to string and strip
        col_str = str(column_name).strip()

        # Remove dangerous characters
        dangerous_chars = [";", "--", "/*", "*/", "..", "/", "\\", "`", '"', "'"]
        for char in dangerous_chars:
            col_str = col_str.replace(char, "")

        # Standardize: lower case, replace spaces and hyphens with underscores
        col_str = col_str.lower().replace(" ", "_").replace("-", "_")

        # Remove any remaining non-alphanumeric characters except underscores
        col_str = re.sub(r"[^a-zA-Z0-9_]", "", col_str)

        # Ensure it starts with a letter or underscore
        if not col_str or not (col_str[0].isalpha() or col_str[0] == "_"):
            col_str = "col_" + col_str

        # Limit length
        if len(col_str) > 50:
            col_str = col_str[:50]

        return col_str

    def _validate_column_mapping(self, mapping: Dict[str, str]) -> Dict[str, str]:
        """
        Validate column mapping for security.

        Args:
            mapping: Column mapping dictionary.

        Returns:
            Validated mapping dictionary.
        """
        if not self.enable_security:
            return mapping

        validated_mapping = {}
        for old_name, new_name in mapping.items():
            # Validate both old and new names
            if self._validate_column_name(old_name) and self._validate_column_name(
                new_name
            ):
                validated_mapping[old_name] = new_name
            else:
                print(
                    f"[Security Warning] Skipping invalid column mapping: {old_name} -> {new_name}"
                )

        return validated_mapping

    def _check_for_sensitive_data(self, df: pd.DataFrame) -> None:
        """
        Check for potentially sensitive data in DataFrame.

        Args:
            df: DataFrame to check.
        """
        if not self.enable_security:
            return

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
        ]

        for col in df.columns:
            col_lower = str(col).lower()
            if any(pattern in col_lower for pattern in sensitive_patterns):
                print(
                    f"[Security Info] DataFrame contains potentially sensitive column: {col}"
                )

                # Check sample data for actual sensitive content
                try:
                    sample_values = df[col].dropna().head(5).astype(str).str.lower()
                    for pattern in ["@", "password", "secret", "key", "token"]:
                        if sample_values.str.contains(pattern).any():
                            print(
                                f"[Security Warning] Column '{col}' may contain sensitive data"
                            )
                            break
                except Exception as sample_check_error:
                    print(
                        f"[Security Info] Could not check sample data in column '{col}': {sample_check_error}"
                    )

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Apply cleaning transformations with security."""
        if df.empty:
            return df

        df = df.copy()

        # Security: Check for sensitive data
        self._check_for_sensitive_data(df)

        # 1. Standardize column names with security
        new_columns = []
        for col in df.columns:
            sanitized_col = self._sanitize_column_name(col)
            if self.enable_security and not self._validate_column_name(sanitized_col):
                # If validation fails, use a safe default
                sanitized_col = f"col_{len(new_columns) + 1}"
            new_columns.append(sanitized_col)

        df.columns = new_columns

        # 2. Apply custom column mapping with validation
        validated_mapping = self._validate_column_mapping(self.column_mapping)
        if validated_mapping:
            df = df.rename(columns=validated_mapping)
            if self.enable_security:
                print(
                    f"[Security] Applied validated column mapping: {validated_mapping}"
                )

        # 3. Handle missing values: forward fill then backward fill
        # Security: Limit the amount of filling to prevent memory issues
        max_fill_limit = 1000
        if len(df) > max_fill_limit:
            # For large DataFrames, fill in chunks or limit
            print(
                f"[Security] Large DataFrame ({len(df)} rows), limiting fill operations"
            )
            # Fill only first max_fill_limit rows
            df_filled = df.head(max_fill_limit).ffill().bfill()
            df = pd.concat([df_filled, df.iloc[max_fill_limit:]], ignore_index=True)
        else:
            df = df.ffill().bfill()

        # 4. Drop completely empty rows
        df = df.dropna(how="all")

        # Security: Check final DataFrame
        if self.enable_security:
            print(
                f"[Security] Cleaning completed: {len(df)} rows, {len(df.columns)} columns"
            )

            # Check for duplicate column names (potential security issue)
            duplicate_columns = df.columns[df.columns.duplicated()].tolist()
            if duplicate_columns:
                print(
                    f"[Security Warning] Duplicate column names after cleaning: {duplicate_columns}"
                )
                # Ensure unique column names
                df.columns = pd.io.parsers.ParserBase(
                    {"names": df.columns}
                )._maybe_dedup_names(df.columns)

        return df
