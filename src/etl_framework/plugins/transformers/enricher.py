"""
Data enrichment transformer with security features.
"""
from typing import Any, Dict, Optional

import pandas as pd

from etl_framework.core.transformer import Transformer


class DataEnricher(Transformer):
    """
    Enriches the DataFrame with additional data with security validation.
    """

    def __init__(
        self,
        lookup_dict: Optional[Dict[Any, Any]] = None,
        new_column_name: str = "enriched",
        source_column: Optional[str] = None,
        enable_security: bool = True,
    ):
        """
        Args:
            lookup_dict: Dictionary mapping values from a column to enriched values.
            new_column_name: Name of the new column to add.
            source_column: Specific column to use for lookup (optional).
            enable_security: Whether to enable security features.
        """
        self.lookup_dict = lookup_dict or {}
        self.new_column_name = new_column_name
        self.source_column = source_column
        self.enable_security = enable_security

    def _validate_lookup_dict(self, lookup_dict: Dict[Any, Any]) -> Dict[Any, Any]:
        """
        Validate lookup dictionary for security.

        Args:
            lookup_dict: Lookup dictionary to validate.

        Returns:
            Validated lookup dictionary.
        """
        if not self.enable_security:
            return lookup_dict

        validated_dict = {}

        # Security: Check dictionary size
        if len(lookup_dict) > 10000:
            print(
                f"[Security Warning] Large lookup dictionary: {len(lookup_dict)} entries"
            )
            # Limit size for security
            items = list(lookup_dict.items())[:10000]
        else:
            items = lookup_dict.items()

        for key, value in items:
            # Security: Validate key and value types
            if not isinstance(key, (str, int, float, bool)):
                print(
                    f"[Security Warning] Skipping lookup key with invalid type: {type(key)}"
                )
                continue

            if not isinstance(value, (str, int, float, bool, type(None))):
                print(
                    f"[Security Warning] Skipping lookup value with invalid type: {type(value)}"
                )
                continue

            # Security: Check for dangerous patterns in strings
            if isinstance(key, str):
                dangerous_patterns = [";", "--", "/*", "*/", "union", "select", "exec"]
                key_lower = key.lower()
                if any(pattern in key_lower for pattern in dangerous_patterns):
                    print(
                        f"[Security Warning] Skipping lookup key with dangerous pattern: {key}"
                    )
                    continue

            if isinstance(value, str):
                # Limit string length
                if len(value) > 1000:
                    print(
                        f"[Security Warning] Truncating long lookup value: {len(value)} chars"
                    )
                    value = value[:1000]

                # Check for dangerous patterns
                value_lower = value.lower()
                dangerous_patterns = ["<script>", "javascript:", "onload=", "onerror="]
                if any(pattern in value_lower for pattern in dangerous_patterns):
                    print(
                        f"[Security Warning] Skipping lookup value with dangerous pattern"
                    )
                    continue

            validated_dict[key] = value

        return validated_dict

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

        # Basic validation
        if not isinstance(column_name, str):
            return False

        if len(column_name) > 50:
            return False

        # Check for dangerous patterns
        dangerous_patterns = [
            ";",
            "--",
            "/*",
            "*/",
            "union",
            "select",
            "drop",
            "delete",
        ]
        column_lower = column_name.lower()
        if any(pattern in column_lower for pattern in dangerous_patterns):
            return False

        # Check for path traversal
        if ".." in column_name or "/" in column_name or "\\" in column_name:
            return False

        return True

    def _find_source_column(self, df: pd.DataFrame) -> Optional[str]:
        """
        Find appropriate source column for lookup with security checks.

        Args:
            df: DataFrame to search.

        Returns:
            Column name to use for lookup, or None if not found.
        """
        if self.source_column:
            # Use specified source column if it exists
            if self.source_column in df.columns:
                return self.source_column
            else:
                print(
                    f"[Security Warning] Specified source column not found: {self.source_column}"
                )
                return None

        # Try to find a column that matches keys in the lookup dictionary
        validated_lookup = self._validate_lookup_dict(self.lookup_dict)
        if not validated_lookup:
            return None

        # Get sample keys from lookup dictionary
        sample_keys = list(validated_lookup.keys())[:10]

        for col in df.columns:
            # Security: Validate column name
            if not self._validate_column_name(col):
                continue

            try:
                # Check if any value in this column is a key in our lookup
                sample_values = df[col].dropna().unique()[:5]
                matches = sum(1 for val in sample_values if val in validated_lookup)

                # If we have at least one match, use this column
                if matches > 0:
                    print(
                        f"[Security] Using column '{col}' for enrichment ({matches} matches found)"
                    )
                    return col
            except Exception as e:
                if self.enable_security:
                    print(f"[Security Warning] Error checking column '{col}': {e}")
                continue

        return None

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Add enriched column based on lookup dictionary with security."""
        if df.empty or not self.lookup_dict:
            return df

        df = df.copy()

        # Security: Validate new column name
        if not self._validate_column_name(self.new_column_name):
            print(f"[Security Error] Invalid new column name: {self.new_column_name}")
            # Use safe default
            self.new_column_name = "enriched_data"

        # Security: Validate lookup dictionary
        validated_lookup = self._validate_lookup_dict(self.lookup_dict)
        if not validated_lookup:
            print("[Security] No valid lookup entries after validation")
            return df

        # Find source column for lookup
        source_column = self._find_source_column(df)
        if not source_column:
            print("[Security] No suitable source column found for enrichment")
            return df

        # Security: Validate source column
        if not self._validate_column_name(source_column):
            print(f"[Security Error] Invalid source column: {source_column}")
            return df

        try:
            # Apply enrichment
            df[self.new_column_name] = df[source_column].map(validated_lookup)

            # Security: Check enrichment results
            enriched_count = df[self.new_column_name].notna().sum()
            total_count = len(df)
            success_rate = enriched_count / total_count if total_count > 0 else 0

            if self.enable_security:
                print(
                    f"[Security] Enrichment completed: {enriched_count}/{total_count} rows enriched ({success_rate:.1%})"
                )

                # Check for potential data leakage
                if success_rate < 0.1 and total_count > 100:
                    print(
                        f"[Security Warning] Low enrichment success rate: {success_rate:.1%}"
                    )
                    print(
                        f"   This might indicate incorrect lookup dictionary or source column"
                    )

                # Check for sensitive data in enriched column
                if self.new_column_name.lower() in [
                    "password",
                    "secret",
                    "key",
                    "token",
                ]:
                    print(
                        f"[Security Warning] Enriched column name suggests sensitive data: {self.new_column_name}"
                    )
                    # Consider masking or encrypting this column

        except Exception as e:
            print(f"[Security Error] Enrichment failed: {e}")
            # Don't add the column if enrichment failed
            if self.new_column_name in df.columns:
                df = df.drop(columns=[self.new_column_name])

        return df
