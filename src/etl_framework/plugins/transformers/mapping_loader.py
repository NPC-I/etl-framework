"""
Mapping loader transformer that applies column mappings and executes JSON-defined calculations with security.
"""
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd

from etl_framework.core.load_strategy import LoadOptions
from etl_framework.core.transformer import Transformer

# Use secure JSON calculator
from .secure_json_calculator import SecureJSONBusinessCalculator


class MappingLoader(Transformer):
    """
    Loads and applies mappings from JSON configuration files with security.

    The JSON file should have:
    - column_mapping: Dict mapping source column names to target names
    - business_rules: Dict of business parameters
    - calculations: List of calculations to apply
    - loading_strategy: Optional loading strategy configuration
    """

    def __init__(self, mapping_file: str, enable_security: bool = True):
        """
        Args:
            mapping_file: Path to JSON mapping file
            enable_security: Whether to enable security features
        """
        self.mapping_file = mapping_file
        self.enable_security = enable_security
        self.config = self._load_config()

        # Create JSON calculator with security
        self.json_calculator = None
        if self.config.get("calculations"):
            # Always use secure calculator for consistency
            # The secure calculator has security features that can be disabled if needed
            self.json_calculator = SecureJSONBusinessCalculator(self.config)

        # Extract loading strategy from config
        self.loading_strategy_config = self.config.get("loading_strategy", {})

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from JSON file with security validation."""
        try:
            # Security: Check file path
            if self.enable_security:
                if ".." in self.mapping_file:
                    raise ValueError(
                        f"Path traversal attempt in mapping file: {self.mapping_file}"
                    )

            with open(self.mapping_file, "r") as f:
                content = f.read()

                # Security: Check file size
                if self.enable_security and len(content) > 10 * 1024 * 1024:  # 10MB
                    raise ValueError(f"Mapping file too large: {len(content)} bytes")

                config = json.loads(content)

                # Security: Validate configuration structure
                if self.enable_security:
                    self._validate_config(config)

                return config

        except FileNotFoundError:
            print(f"Warning: Mapping file '{self.mapping_file}' not found")
            return {}
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in '{self.mapping_file}': {e}")
            return {}
        except ValueError as e:
            print(f"Security Error in mapping file '{self.mapping_file}': {e}")
            return {}

    def _validate_config(self, config: Dict[str, Any]) -> None:
        """Validate configuration for security."""
        # Check for excessive calculations
        calculations = config.get("calculations", [])
        if len(calculations) > 100:
            raise ValueError(f"Too many calculations: {len(calculations)} > 100 limit")

        # Check column mapping
        column_mapping = config.get("column_mapping", {})
        if len(column_mapping) > 100:
            raise ValueError(
                f"Too many column mappings: {len(column_mapping)} > 100 limit"
            )

        # Check business rules size
        business_rules = config.get("business_rules", {})
        if len(str(business_rules)) > 10000:  # 10KB limit for business rules
            raise ValueError("Business rules too large")

    def get_loading_strategy_options(self) -> LoadOptions:
        """
        Extract loading strategy configuration from mapping file.

        Returns:
            LoadOptions object with strategy configuration, or None if not specified.
        """
        if not self.loading_strategy_config:
            return None

        return LoadOptions.from_dict(self.loading_strategy_config)

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Apply mappings and calculations from config with security."""
        if df.empty or not self.config:
            return df

        df = df.copy()

        # 1. Apply column mapping
        df = self._apply_column_mapping(df)

        # 2. Execute JSON-defined calculations
        if self.json_calculator:
            try:
                df = self.json_calculator.transform(df)
            except Exception as e:
                print(f"[MappingLoader Error] Failed to apply calculations: {e}")
                if self.enable_security:
                    # In secure mode, we might want to fail or log this as a security event
                    print("[Security] Calculation error logged")

        return df

    def _apply_column_mapping(self, df: pd.DataFrame) -> pd.DataFrame:
        """Apply column renaming from config with security validation."""
        column_mapping = self.config.get("column_mapping", {})
        if not column_mapping:
            return df

        rename_dict = {}
        for old_name, new_name in column_mapping.items():
            # Security: Validate column names
            if self.enable_security:
                # Basic validation - in production, use proper validation
                if not isinstance(old_name, str) or not isinstance(new_name, str):
                    print(
                        f"[Security Warning] Invalid column name in mapping: {old_name} -> {new_name}"
                    )
                    continue

                # Check for suspicious patterns
                suspicious_patterns = [
                    ";",
                    "--",
                    "/*",
                    "*/",
                    "union",
                    "select",
                    "insert",
                    "delete",
                    "drop",
                ]
                old_lower = old_name.lower()
                new_lower = new_name.lower()
                if any(pattern in old_lower for pattern in suspicious_patterns) or any(
                    pattern in new_lower for pattern in suspicious_patterns
                ):
                    print(
                        f"[Security Warning] Suspicious pattern in column mapping: {old_name} -> {new_name}"
                    )
                    continue

            if old_name in df.columns:
                rename_dict[old_name] = new_name
            else:
                # Try case-insensitive match
                old_name_lower = old_name.lower()
                for col in df.columns:
                    if col.lower() == old_name_lower:
                        rename_dict[col] = new_name
                        break

        if rename_dict:
            df = df.rename(columns=rename_dict)
            if self.enable_security:
                print(f"[Security] Applied column renaming: {rename_dict}")
            else:
                print(f"[MappingLoader] Renamed columns: {rename_dict}")

        return df
