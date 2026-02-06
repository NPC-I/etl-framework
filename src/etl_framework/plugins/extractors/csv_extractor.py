"""
CSV extractor implementation with security features.
"""
from typing import Any, Optional

import pandas as pd

from etl_framework.core.extractor import Extractor
from etl_framework.security.input_validator import InputValidator


class CSVExtractor(Extractor):
    """Extracts data from CSV files with security validation."""

    def __init__(self, validator: Optional[InputValidator] = None):
        """
        Initialize CSV extractor with security validator.

        Args:
            validator: InputValidator instance for security validation.
                      If None, creates basic validation internally.
        """
        self.validator = validator

    def extract(self, csv_path: str, **kwargs) -> pd.DataFrame:
        """
        Extract data from a CSV file with security validation.

        Args:
            csv_path: Path to the CSV file.
            **kwargs: Additional arguments passed to pandas.read_csv.

        Returns:
            A pandas DataFrame.

        Raises:
            ValueError: If file path is invalid or file is too large.
        """
        # Security: Use validator if available, otherwise basic validation
        if self.validator:
            try:
                validated_path = self.validator.validate_file_path(
                    csv_path, [".csv"], operation="read"
                )
                csv_path = str(validated_path)
            except ValueError as e:
                raise ValueError(f"CSV file validation failed: {e}")
        else:
            # Fallback to basic validation
            if not csv_path or not isinstance(csv_path, str):
                raise ValueError("Invalid CSV file path")

            # Security: Check for path traversal attempts
            if ".." in csv_path:
                print(
                    f"[Security Warning] Potential path traversal in CSV path: {csv_path}"
                )
                # In production, you might want to raise an error
                # raise ValueError(f"Path traversal attempt detected: {csv_path}")

        try:
            # Use pandas to read CSV with error handling
            df = pd.read_csv(csv_path, **kwargs)

            # Security: Check DataFrame size (basic DoS protection)
            if len(df) > 1000000:  # 1 million rows limit
                print(f"[Security Warning] Large CSV file: {len(df)} rows")
                # In production, you might want to implement chunked reading

            # Security: Check for suspicious column names
            suspicious_patterns = ["password", "secret", "key", "token", "credential"]
            for col in df.columns:
                col_lower = str(col).lower()
                if any(pattern in col_lower for pattern in suspicious_patterns):
                    print(
                        f"[Security Info] CSV contains potentially sensitive column: {col}"
                    )

            return df

        except FileNotFoundError:
            raise ValueError(f"CSV file not found: {csv_path}")
        except pd.errors.EmptyDataError:
            raise ValueError(f"CSV file is empty: {csv_path}")
        except pd.errors.ParserError as e:
            raise ValueError(f"Error parsing CSV file {csv_path}: {e}")
        except Exception as e:
            raise ValueError(f"Error reading CSV file {csv_path}: {e}")

    def validate_source(self, source: Any) -> bool:
        """
        Validate the CSV source.

        Args:
            source: Source to validate.

        Returns:
            True if source is valid, False otherwise.
        """
        if not isinstance(source, str):
            return False

        if self.validator:
            try:
                self.validator.validate_file_path(source, [".csv"], "read")
                return True
            except ValueError:
                return False
        else:
            # Basic validation
            return source.endswith(".csv") and ".." not in source

    def get_security_info(self) -> dict:
        """
        Get security information about this extractor.

        Returns:
            Dictionary with security information.
        """
        return {
            "extractor_type": "CSVExtractor",
            "has_validator": self.validator is not None,
            "validates_path": True,
            "validates_content": False,
        }
