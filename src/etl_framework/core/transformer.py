"""
Abstract base class for data transformers with security support.
"""
from abc import ABC, abstractmethod
from typing import Any, Dict

import pandas as pd


class Transformer(ABC):
    """Interface for transforming a pandas DataFrame."""

    @abstractmethod
    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Apply transformations to the input DataFrame and return a new DataFrame.

        Args:
            df: Input pandas DataFrame.

        Returns:
            Transformed pandas DataFrame.
        """
        pass

    def validate_input(self, df: pd.DataFrame) -> bool:
        """
        Validate the input DataFrame for security before transformation.

        Args:
            df: The DataFrame to validate.

        Returns:
            True if DataFrame is valid, False otherwise.
        """
        # Base implementation
        if df is None:
            return False

        if not isinstance(df, pd.DataFrame):
            return False

        # Check for empty DataFrame (might be valid)
        if df.empty:
            print("[Security Info] Transforming empty DataFrame")
            return True

        # Check for excessive size
        if len(df) > 1000000:  # 1 million rows
            print(
                f"[Security Warning] Large DataFrame for transformation: {len(df)} rows"
            )
            # Still return True, but with warning

        return True

    def validate_output(self, df: pd.DataFrame) -> bool:
        """
        Validate the output DataFrame for security after transformation.

        Args:
            df: The transformed DataFrame to validate.

        Returns:
            True if DataFrame is valid, False otherwise.
        """
        # Base implementation - similar to input validation
        return self.validate_input(df)

    def transform_with_validation(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Apply transformation with input and output validation.

        Args:
            df: Input pandas DataFrame.

        Returns:
            Transformed pandas DataFrame.

        Raises:
            ValueError: If validation fails.
        """
        # Validate input
        if not self.validate_input(df):
            raise ValueError("Input DataFrame validation failed")

        # Apply transformation
        result = self.transform(df)

        # Validate output
        if not self.validate_output(result):
            raise ValueError("Output DataFrame validation failed")

        return result

    def get_security_info(self) -> Dict[str, Any]:
        """
        Get security information about this transformer.

        Returns:
            Dictionary with security information.
        """
        return {
            "transformer_type": self.__class__.__name__,
            "has_input_validation": hasattr(self, "validate_input")
            and self.validate_input != Transformer.validate_input,
            "has_output_validation": hasattr(self, "validate_output")
            and self.validate_output != Transformer.validate_output,
        }
