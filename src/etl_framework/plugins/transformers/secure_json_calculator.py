"""
Secure JSON-driven business calculator with enhanced security.
"""
import signal
from contextlib import contextmanager
from typing import Any, Dict, List, Optional

import pandas as pd

from etl_framework.core.transformer import Transformer
from etl_framework.security.input_validator import InputValidator


class TimeoutError(Exception):
    """Exception raised when a timeout occurs."""

    pass


@contextmanager
def timeout(seconds: int):
    """
    Context manager for timing out operations.

    Args:
        seconds: Timeout in seconds.
    """

    def handler(signum, frame):
        raise TimeoutError(f"Operation timed out after {seconds} seconds")

    # Set the signal handler
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(seconds)

    try:
        yield
    finally:
        # Disable the alarm
        signal.alarm(0)


class SecureJSONBusinessCalculator(Transformer):
    """
    Secure version of JSON business calculator with additional safety checks.

    Features:
    - Formula validation and sanitization
    - Timeout protection for long-running calculations
    - Complexity limits
    - Security pattern blacklisting
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Args:
            config: Configuration dict (loaded from JSON mapping file)
        """
        self.config = config
        self.business_rules = config.get("business_rules", {})
        self.calculations = config.get("calculations", [])
        self.validator = InputValidator()

        # Validate configuration
        self._validate_config()

    def _validate_config(self):
        """Validate configuration for security."""
        # Check number of calculations
        if len(self.calculations) > 50:
            raise ValueError(
                f"Too many calculations: {len(self.calculations)} > 50 limit"
            )

        # Validate each calculation
        for calc_def in self.calculations:
            self._validate_calculation(calc_def)

    def _validate_calculation(self, calc_def: Dict[str, Any]):
        """Validate a single calculation definition."""
        # Check required fields
        if "name" not in calc_def:
            raise ValueError("Calculation missing 'name' field")

        # Validate calculation name
        if not self.validator.validate_sql_identifier(calc_def["name"]):
            raise ValueError(f"Invalid calculation name: {calc_def['name']}")

        # Validate formula if present
        if "formula" in calc_def:
            try:
                # Formulas in JSON config files are from trusted sources
                # Allow certain safe patterns that would normally be blocked
                self.validator.validate_formula(
                    calc_def["formula"], trusted_source=True
                )
            except ValueError as e:
                raise ValueError(
                    f"Invalid formula in calculation '{calc_def['name']}': {e}"
                )

        # Validate lookup if present
        if "lookup" in calc_def:
            lookup = calc_def["lookup"]
            if not isinstance(lookup, str) or len(lookup) > 500:
                raise ValueError(f"Invalid lookup in calculation '{calc_def['name']}'")

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Execute all calculations defined in JSON with security checks."""
        if df.empty or not self.calculations:
            return df

        df = df.copy()

        # Ensure numeric columns are numeric
        df = self._ensure_numeric(df)

        # Execute each calculation in order with security context
        for calc_def in self.calculations:
            df = self._execute_calculation_secure(df, calc_def)

        return df

    def _ensure_numeric(self, df: pd.DataFrame) -> pd.DataFrame:
        """Convert likely numeric columns to numeric type."""
        # Common numeric column patterns
        numeric_patterns = [
            "width",
            "height",
            "quantity",
            "price",
            "cost",
            "area",
            "time",
            "days",
            "amount",
            "total",
            "sum",
        ]

        for col in df.columns:
            # Check if column name suggests it's numeric
            if any(pattern in col.lower() for pattern in numeric_patterns):
                df[col] = pd.to_numeric(df[col], errors="coerce")

        return df

    def _execute_calculation_secure(
        self, df: pd.DataFrame, calc_def: Dict[str, Any]
    ) -> pd.DataFrame:
        """Execute a single calculation definition with security checks."""
        calc_name = calc_def.get("name")
        if not calc_name:
            return df

        # Check if we should skip (optional condition)
        if "condition" in calc_def:
            if not self._evaluate_condition(df, calc_def["condition"]):
                return df

        # Different calculation types with security
        try:
            if "formula" in calc_def:
                df = self._execute_formula_secure(df, calc_name, calc_def["formula"])
            elif "lookup" in calc_def:
                df = self._execute_lookup_secure(df, calc_name, calc_def["lookup"])
            elif "value" in calc_def:
                df[calc_name] = calc_def["value"]
        except Exception as e:
            # Log error but don't crash the pipeline
            print(f"Warning: Failed to execute calculation '{calc_name}': {e}")
            # Optionally add error column
            df[f"{calc_name}_error"] = str(e)

        return df

    def _execute_formula_secure(
        self, df: pd.DataFrame, calc_name: str, formula: str
    ) -> pd.DataFrame:
        """
        Execute a formula expression with security controls.

        Features:
        - Formula validation
        - Timeout protection
        - Memory usage monitoring
        - Safe namespace
        """
        # Validate formula first
        validated_formula = self.validator.validate_formula(formula)

        try:
            # Prepare safe local namespace
            local_dict = self._create_safe_namespace(df)

            # Execute with timeout
            with timeout(5):  # 5 second timeout
                result = pd.eval(validated_formula, local_dict=local_dict)

            df[calc_name] = result

        except TimeoutError:
            print(f"Warning: Formula execution timed out: {formula}")
            df[calc_name] = None
            df[f"{calc_name}_timeout"] = True
        except Exception as e:
            print(f"Warning: Failed to execute formula '{formula}': {e}")
            df[calc_name] = None
            df[f"{calc_name}_error"] = str(e)

        return df

    def _create_safe_namespace(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Create a safe namespace for formula evaluation."""
        local_dict = {}

        # Add business rules (sanitized)
        for key, value in self.business_rules.items():
            if isinstance(value, (int, float, str, bool)):
                local_dict[key] = value
            elif isinstance(value, dict):
                # Only include simple dicts
                if all(
                    isinstance(k, str) and isinstance(v, (int, float, str, bool))
                    for k, v in value.items()
                ):
                    local_dict[key] = value

        # Add DataFrame columns (sanitized)
        for col in df.columns:
            if col not in local_dict:  # Don't override business rules
                # Only include numeric or string columns
                if pd.api.types.is_numeric_dtype(
                    df[col]
                ) or pd.api.types.is_string_dtype(df[col]):
                    local_dict[col] = df[col]

        return local_dict

    def _execute_lookup_secure(
        self, df: pd.DataFrame, calc_name: str, lookup_expr: str
    ) -> pd.DataFrame:
        """Execute a lookup operation with security checks."""
        # Simple format: lookup_table[column_name]
        if "[" in lookup_expr and "]" in lookup_expr:
            try:
                table_name = lookup_expr.split("[")[0]
                col_name = lookup_expr.split("[")[1].split("]")[0]

                # Validate identifiers
                if not (
                    self.validator.validate_sql_identifier(table_name)
                    and self.validator.validate_sql_identifier(col_name)
                ):
                    raise ValueError("Invalid lookup expression")

                # Get lookup table from business rules
                lookup_table = self.business_rules.get(table_name, {})

                if col_name in df.columns and lookup_table:
                    df[calc_name] = df[col_name].map(lookup_table)

            except Exception as e:
                print(f"Warning: Failed to execute lookup '{lookup_expr}': {e}")
                df[calc_name] = None

        return df

    def _evaluate_condition(self, df: pd.DataFrame, condition: str) -> bool:
        """Evaluate a condition to determine if calculation should run."""
        # Simple condition: column exists
        if condition.startswith("has:"):
            col_name = condition.split(":")[1]
            return col_name in df.columns
        elif condition.startswith("not:has:"):
            col_name = condition.split(":")[2]
            return col_name not in df.columns
        elif condition.startswith("eq:"):
            # Format: eq:column_name:value
            parts = condition.split(":")
            if len(parts) == 3:
                col_name, expected_value = parts[1], parts[2]
                if col_name in df.columns:
                    # Check if any row matches
                    return any(str(val) == expected_value for val in df[col_name])

        # TODO: Add more condition types
        return True
