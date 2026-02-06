"""
JSON string extractor implementation.
"""
import json
from typing import Any, Dict, Optional

import pandas as pd

from etl_framework.core.extractor import Extractor
from etl_framework.security.input_validator import InputValidator


class JSONStringExtractor(Extractor):
    """Extracts data from JSON strings with security validation."""

    def __init__(self, validator: Optional[InputValidator] = None):
        """
        Args:
            validator: InputValidator instance for security validation.
                      If None, creates one with default settings.
        """
        self.validator = validator or InputValidator()

    def extract(self, source: Any, **kwargs) -> pd.DataFrame:
        """
        Extract data from JSON string.

        Args:
            source: JSON string or dict containing JSON data.
            **kwargs: Additional options:
                - json_path: Path to data within JSON (e.g., "data.results")
                - flatten_nested: Whether to flatten nested structures
                - max_length: Maximum JSON string length (default: 10000)

        Returns:
            A pandas DataFrame containing the extracted data.

        Raises:
            ValueError: If JSON is invalid or security validation fails.
        """
        # Convert source to string if it's not already
        if isinstance(source, dict):
            # Already parsed JSON dict
            data = source
        elif isinstance(source, str):
            # JSON string - validate and parse
            max_length = kwargs.get("max_length", 10000)
            data = self.validator.validate_json_string(source, max_length=max_length)
        else:
            raise ValueError(f"Unsupported source type: {type(source)}")

        # Extract data based on json_path
        json_path = kwargs.get("json_path", "")
        if json_path:
            # Navigate to specified path
            for key in json_path.split("."):
                if key and key in data:
                    data = data[key]
                else:
                    raise ValueError(f"JSON path not found: {json_path}")

        # Convert to DataFrame
        df = self._convert_to_dataframe(data, **kwargs)

        # Security: Check DataFrame size
        if len(df) > 1000000:  # 1 million rows limit
            print(f"[Security Warning] Large JSON data: {len(df)} rows")

        # Security: Check for sensitive column names
        self._check_sensitive_columns(df)

        return df

    def _convert_to_dataframe(self, data: Any, **kwargs) -> pd.DataFrame:
        """
        Convert JSON data to pandas DataFrame.

        Args:
            data: Parsed JSON data.
            **kwargs: Conversion options.

        Returns:
            pandas DataFrame.
        """
        flatten_nested = kwargs.get("flatten_nested", True)

        if isinstance(data, list):
            # Array of objects
            if data and isinstance(data[0], dict):
                if flatten_nested:
                    df = pd.json_normalize(data)
                else:
                    df = pd.DataFrame(data)
            else:
                # Array of primitives
                df = pd.DataFrame({"value": data})
        elif isinstance(data, dict):
            # Single object
            if flatten_nested:
                # Flatten nested structures
                df = pd.json_normalize(data)
            else:
                df = pd.DataFrame([data])
        else:
            # Primitive value
            df = pd.DataFrame({"value": [data]})

        return df

    def _check_sensitive_columns(self, df: pd.DataFrame):
        """
        Check for potentially sensitive column names.

        Args:
            df: DataFrame to check.
        """
        suspicious_patterns = [
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
            if any(pattern in col_lower for pattern in suspicious_patterns):
                print(
                    f"[Security Info] JSON contains potentially sensitive column: {col}"
                )

    def validate_source(self, source: Any) -> bool:
        """
        Validate the JSON source.

        Args:
            source: Source to validate.

        Returns:
            True if source is valid, False otherwise.
        """
        try:
            if isinstance(source, str):
                # Try to parse to validate
                json.loads(source)
                return True
            elif isinstance(source, (dict, list)):
                # Already parsed dict
                return True
            else:
                return False
        except (json.JSONDecodeError, TypeError):
            return False

    def get_security_info(self) -> Dict[str, Any]:
        """
        Get security information about this extractor.

        Returns:
            Dictionary with security information.
        """
        return {
            "extractor_type": "JSONStringExtractor",
            "has_security_validation": True,
            "validates_json": True,
            "uses_input_validator": True,
        }
