"""
Loading strategy definitions for controlling how data is written to targets.
"""
import re
from enum import Enum
from typing import Any, Dict, List, Optional


class LoadStrategy(Enum):
    """
    Defines how data should be loaded to the target.

    Strategies:
        FAIL: Raise an error if target already exists
        REPLACE: Delete existing data and insert new data (truncate + insert)
        APPEND: Add new rows to existing data
        UPDATE: Update existing rows matching key columns
        UPSERT: Update existing rows, insert new rows (update + append)
    """

    FAIL = "fail"
    REPLACE = "replace"
    APPEND = "append"
    UPDATE = "update"
    UPSERT = "upsert"

    @classmethod
    def from_string(cls, value: str) -> "LoadStrategy":
        """Convert string to LoadStrategy, case-insensitive with fallback to REPLACE."""
        if not value:
            return cls.REPLACE

        value_lower = value.lower().strip()
        for strategy in cls:
            if strategy.value == value_lower:
                return strategy

        # Default to REPLACE for unknown values (backward compatibility)
        return cls.REPLACE

    def __str__(self) -> str:
        return self.value

    def requires_key_columns(self) -> bool:
        """
        Check if this strategy requires key columns.

        Returns:
            True if strategy requires key columns, False otherwise.
        """
        return self in [LoadStrategy.UPDATE, LoadStrategy.UPSERT]

    def is_destructive(self) -> bool:
        """
        Check if this strategy is destructive (modifies existing data).

        Returns:
            True if strategy is destructive, False otherwise.
        """
        return self in [LoadStrategy.REPLACE, LoadStrategy.UPDATE, LoadStrategy.UPSERT]


class LoadOptions:
    """Configuration options for loading strategies with security validation."""

    def __init__(
        self,
        strategy: LoadStrategy = LoadStrategy.REPLACE,
        key_columns: Optional[List[str]] = None,
        batch_size: int = 1000,
        chunk_size: int = 500,
        create_index: bool = False,
        drop_duplicates: bool = True,
        enable_security: bool = True,
        **extra_options,
    ):
        self.strategy = (
            strategy
            if isinstance(strategy, LoadStrategy)
            else LoadStrategy.from_string(strategy)
        )
        self.key_columns = key_columns or []
        self.batch_size = batch_size
        self.chunk_size = chunk_size
        self.create_index = create_index
        self.drop_duplicates = drop_duplicates
        self.enable_security = enable_security
        self.extra_options = extra_options

        # Validate configuration
        if self.enable_security:
            self._validate()

    def _validate(self) -> None:
        """Validate configuration for security."""
        # Validate strategy
        if not isinstance(self.strategy, LoadStrategy):
            raise ValueError(f"Invalid load strategy: {self.strategy}")

        # Validate key columns if strategy requires them
        if self.strategy.requires_key_columns() and not self.key_columns:
            raise ValueError(f"Strategy {self.strategy} requires key_columns")

        # Validate key column names
        for col in self.key_columns:
            if not self._validate_column_name(col):
                raise ValueError(f"Invalid key column name: {col}")

        # Validate batch size
        if self.batch_size <= 0:
            raise ValueError(f"Batch size must be positive: {self.batch_size}")
        if self.batch_size > 100000:  # Security limit
            raise ValueError(f"Batch size too large: {self.batch_size} > 100000 limit")

        # Validate chunk size
        if self.chunk_size <= 0:
            raise ValueError(f"Chunk size must be positive: {self.chunk_size}")
        if self.chunk_size > 10000:  # Security limit
            raise ValueError(f"Chunk size too large: {self.chunk_size} > 10000 limit")

    def _validate_column_name(self, column_name: str) -> bool:
        """
        Validate column name for security.

        Args:
            column_name: Column name to validate.

        Returns:
            True if valid, False otherwise.
        """
        if not isinstance(column_name, str):
            return False

        # Check length
        if len(column_name) > 100:
            return False

        # SQL identifier pattern
        pattern = r"^[a-zA-Z_][a-zA-Z0-9_]*$"
        if not re.match(pattern, column_name):
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

        return True

    @classmethod
    def from_dict(cls, config: Dict[str, Any]) -> "LoadOptions":
        """Create LoadOptions from a dictionary (e.g., from JSON mapping)."""
        if not config:
            return cls()

        # Extract known parameters
        known_params = {}
        extra_params = {}

        known_keys = {
            "strategy",
            "key_columns",
            "batch_size",
            "chunk_size",
            "create_index",
            "drop_duplicates",
            "enable_security",
        }

        for key, value in config.items():
            if key in known_keys:
                known_params[key] = value
            else:
                extra_params[key] = value

        # Handle nested options dict
        if "options" in config and isinstance(config["options"], dict):
            for key, value in config["options"].items():
                if key in known_keys and key not in known_params:
                    known_params[key] = value
                else:
                    extra_params[key] = value

        return cls(**known_params, **extra_params)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "strategy": str(self.strategy),
            "key_columns": self.key_columns,
            "batch_size": self.batch_size,
            "chunk_size": self.chunk_size,
            "create_index": self.create_index,
            "drop_duplicates": self.drop_duplicates,
            "enable_security": self.enable_security,
            **self.extra_options,
        }

    def __repr__(self) -> str:
        return f"LoadOptions(strategy={self.strategy}, key_columns={self.key_columns})"

    def get_security_summary(self) -> Dict[str, Any]:
        """
        Get security summary of load options.

        Returns:
            Dictionary with security information.
        """
        return {
            "strategy": str(self.strategy),
            "requires_key_columns": self.strategy.requires_key_columns(),
            "is_destructive": self.strategy.is_destructive(),
            "key_columns_validated": all(
                self._validate_column_name(col) for col in self.key_columns
            ),
            "batch_size_within_limits": 0 < self.batch_size <= 100000,
            "chunk_size_within_limits": 0 < self.chunk_size <= 10000,
            "security_enabled": self.enable_security,
        }
