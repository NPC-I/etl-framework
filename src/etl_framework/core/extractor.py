"""
Abstract base class for data extractors with security support.
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

import pandas as pd


class Extractor(ABC):
    """Interface for extracting data from a source into a pandas DataFrame."""

    @abstractmethod
    def extract(self, source: Any, **kwargs) -> pd.DataFrame:
        """
        Extract data from the given source and return a pandas DataFrame.

        Args:
            source: The data source (e.g., file path, URL, database connection).
            **kwargs: Additional extractor-specific arguments.

        Returns:
            A pandas DataFrame containing the extracted data.
        """
        pass

    def validate_source(self, source: Any) -> bool:
        """
        Validate the source for security and correctness.

        Args:
            source: The data source to validate.

        Returns:
            True if source is valid, False otherwise.
        """
        # Base implementation - should be overridden by subclasses
        return source is not None

    def get_security_info(self) -> Dict[str, Any]:
        """
        Get security information about this extractor.

        Returns:
            Dictionary with security information.
        """
        return {
            "extractor_type": self.__class__.__name__,
            "has_security_validation": hasattr(self, "validate_source")
            and self.validate_source != Extractor.validate_source,
        }
