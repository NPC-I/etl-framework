"""
Abstract base class for data loaders with security support.
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

import pandas as pd

from .load_strategy import LoadOptions, LoadStrategy


class Loader(ABC):
    """Interface for loading a pandas DataFrame to a target destination."""

    @abstractmethod
    def load(
        self,
        df: pd.DataFrame,
        target: Any,
        strategy: LoadStrategy = LoadStrategy.REPLACE,
        key_columns: Optional[List[str]] = None,
        **kwargs,
    ) -> bool:
        """
        Load the DataFrame to the specified target.

        Args:
            df: The pandas DataFrame to load.
            target: The destination (e.g., table name, file path).
            strategy: How to handle existing data.
            key_columns: Columns to use for matching records (for UPDATE/UPSERT).
            **kwargs: Additional loader-specific options.

        Returns:
            True if loading succeeded, False otherwise.
        """
        pass

    def validate_target(
        self, target: Any, strategy: LoadStrategy = LoadStrategy.REPLACE
    ) -> bool:
        """
        Validate the target for security and correctness.

        Args:
            target: The target destination to validate.
            strategy: The loading strategy to use.

        Returns:
            True if target is valid, False otherwise.
        """
        # Base implementation - should be overridden by subclasses
        return target is not None

    def validate_dataframe(self, df: pd.DataFrame) -> bool:
        """
        Validate the DataFrame for security before loading.

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

        # Check for empty DataFrame (this might be valid depending on use case)
        if df.empty:
            print("[Security Warning] Loading empty DataFrame")
            return True  # Empty DataFrame might be valid

        # Check for excessive size (basic DoS protection)
        if len(df) > 1000000:  # 1 million rows
            print(f"[Security Warning] Large DataFrame: {len(df)} rows")
            # Still return True, but with warning

        return True

    def load_with_options(
        self, df: pd.DataFrame, target: Any, options: LoadOptions, **kwargs
    ) -> bool:
        """
        Load using a LoadOptions object for configuration.

        Args:
            df: The pandas DataFrame to load.
            target: The destination.
            options: LoadOptions configuration object.
            **kwargs: Additional loader-specific options.

        Returns:
            True if loading succeeded, False otherwise.
        """
        # Validate before loading
        if not self.validate_dataframe(df):
            print("[Security Error] DataFrame validation failed")
            return False

        if not self.validate_target(target, options.strategy):
            print("[Security Error] Target validation failed")
            return False

        return self.load(
            df=df,
            target=target,
            strategy=options.strategy,
            key_columns=options.key_columns,
            **{**options.extra_options, **kwargs},
        )

    # Backward compatibility method
    def load_legacy(self, df: pd.DataFrame, target: Any) -> bool:
        """
        Legacy load method for backward compatibility.
        Uses default REPLACE strategy.
        """
        return self.load(df, target, strategy=LoadStrategy.REPLACE)

    def get_security_info(self) -> Dict[str, Any]:
        """
        Get security information about this loader.

        Returns:
            Dictionary with security information.
        """
        return {
            "loader_type": self.__class__.__name__,
            "has_target_validation": hasattr(self, "validate_target")
            and self.validate_target != Loader.validate_target,
            "has_dataframe_validation": hasattr(self, "validate_dataframe")
            and self.validate_dataframe != Loader.validate_dataframe,
        }
