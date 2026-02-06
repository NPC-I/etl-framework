"""
File output loader (CSV, Excel) with support for multiple loading strategies and security.
"""
import os
from typing import Any, List, Optional

import pandas as pd

from etl_framework.core.load_strategy import LoadStrategy
from etl_framework.core.loader import Loader


class FileLoader(Loader):
    """Loads a DataFrame to a file (CSV or Excel) with various strategies and security."""

    def load(
        self,
        df: pd.DataFrame,
        target: Any,  # Changed from file_path to target to match abstract class
        strategy: LoadStrategy = LoadStrategy.REPLACE,
        key_columns: Optional[List[str]] = None,
        **kwargs,
    ) -> bool:
        """
        Save DataFrame to a file with specified strategy and security.

        Args:
            df: DataFrame to save.
            target: Output file path. Extension determines format:
                - .csv → CSV
                - .xlsx, .xls → Excel
                - .parquet → Parquet
                - .feather → Feather
            strategy: How to handle existing file.
            key_columns: For UPDATE strategy (not fully supported for files).
            **kwargs: Additional arguments passed to pandas writer.

        Returns:
            True on success, False on failure.
        """
        # Convert target to file_path for internal use
        file_path = str(target)

        # Security: Validate file path
        if not file_path or not isinstance(file_path, str):
            print("[Security Error] Invalid file path")
            return False

        # Security: Check for path traversal
        if ".." in file_path:
            print("[Security Error] Path traversal attempt detected")
            return False

        # Security: Check file extension
        allowed_extensions = [".csv", ".xlsx", ".xls", ".parquet", ".feather"]
        file_ext = os.path.splitext(file_path)[1].lower()
        if file_ext not in allowed_extensions:
            print(f"[Security Error] Invalid file extension: {file_ext}")
            return False

        try:
            if strategy == LoadStrategy.FAIL:
                return self._load_fail(df, file_path, **kwargs)
            elif strategy == LoadStrategy.REPLACE:
                return self._load_replace(df, file_path, **kwargs)
            elif strategy == LoadStrategy.APPEND:
                return self._load_append(df, file_path, **kwargs)
            elif strategy == LoadStrategy.UPDATE:
                return self._load_update(df, file_path, key_columns, **kwargs)
            elif strategy == LoadStrategy.UPSERT:
                return self._load_upsert(df, file_path, key_columns, **kwargs)
            else:
                # Default to REPLACE for unknown strategies
                return self._load_replace(df, file_path, **kwargs)

        except Exception as e:
            print(f"[File Loader Error] {e}")
            return False

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
        file_path = str(target)

        # Basic validation
        if not file_path or not isinstance(file_path, str):
            return False

        # Check for path traversal
        if ".." in file_path:
            return False

        # Check file extension
        allowed_extensions = [".csv", ".xlsx", ".xls", ".parquet", ".feather"]
        file_ext = os.path.splitext(file_path)[1].lower()
        if file_ext not in allowed_extensions:
            return False

        # For FAIL strategy, check if file already exists
        if strategy == LoadStrategy.FAIL and os.path.exists(file_path):
            return False

        return True

    def _load_fail(self, df: pd.DataFrame, file_path: str, **kwargs) -> bool:
        """Fail if file already exists."""
        if os.path.exists(file_path):
            raise FileExistsError(
                f"File '{file_path}' already exists. Use a different strategy."
            )
        return self._write_file(df, file_path, **kwargs)

    def _load_replace(self, df: pd.DataFrame, file_path: str, **kwargs) -> bool:
        """Replace existing file (overwrite)."""
        return self._write_file(df, file_path, **kwargs)

    def _load_append(self, df: pd.DataFrame, file_path: str, **kwargs) -> bool:
        """Append to existing file."""
        if os.path.exists(file_path):
            # Read existing data
            existing_df = self._read_file(file_path, **kwargs)
            if existing_df is not None:
                # Security: Check if schemas match before appending
                if not self._check_schema_compatibility(existing_df, df):
                    print("[Security Warning] Schema mismatch during append operation")
                    # Decide whether to proceed or fail
                    # For security, we might want to fail here

                # Combine with new data
                combined_df = pd.concat([existing_df, df], ignore_index=True)
                return self._write_file(combined_df, file_path, **kwargs)
        # File doesn't exist or couldn't be read, write new file
        return self._write_file(df, file_path, **kwargs)

    def _load_update(
        self, df: pd.DataFrame, file_path: str, key_columns: List[str], **kwargs
    ) -> bool:
        """
        Update existing records in file.

        Note: Limited support. For CSV/Excel, this reads entire file,
        updates matching rows, and rewrites. Not efficient for large files.
        """
        if not os.path.exists(file_path):
            # No file to update, just write new
            return self._write_file(df, file_path, **kwargs)

        if not key_columns:
            raise ValueError(
                "UPDATE strategy requires key_columns to identify records to update."
            )

        # Security: Validate key columns
        for col in key_columns:
            if col not in df.columns:
                print(f"[Security Warning] Key column '{col}' not in DataFrame")
                return False

        # Read existing data
        existing_df = self._read_file(file_path, **kwargs)
        if existing_df is None:
            return self._write_file(df, file_path, **kwargs)

        # For file-based UPDATE, we need to merge
        # This is a simplified implementation - assumes key columns exist in both DataFrames
        try:
            # Use merge to update existing rows
            # First, set index on key columns for merging
            existing_idx = existing_df.set_index(key_columns)
            new_idx = df.set_index(key_columns)

            # Update only rows that exist in both
            # Find common indices
            common_indices = new_idx.index.intersection(existing_idx.index)

            if len(common_indices) > 0:
                # Update existing rows with new values
                existing_idx.loc[common_indices] = new_idx.loc[common_indices]

            # Reset index and write back
            result_df = existing_idx.reset_index()
            return self._write_file(result_df, file_path, **kwargs)

        except Exception as e:
            print(f"[File Loader UPDATE Warning] {e}")
            print("  Falling back to REPLACE strategy")
            return self._load_replace(df, file_path, **kwargs)

    def _load_upsert(
        self, df: pd.DataFrame, file_path: str, key_columns: List[str], **kwargs
    ) -> bool:
        """
        Update existing records and append new ones.

        For files, this is similar to UPDATE but preserves all rows.
        """
        if not os.path.exists(file_path):
            # No file exists, just write new
            return self._write_file(df, file_path, **kwargs)

        if not key_columns:
            raise ValueError(
                "UPSERT strategy requires key_columns to identify records."
            )

        # Security: Validate key columns
        for col in key_columns:
            if col not in df.columns:
                print(f"[Security Warning] Key column '{col}' not in DataFrame")
                return False

        # Read existing data
        existing_df = self._read_file(file_path, **kwargs)
        if existing_df is None:
            return self._write_file(df, file_path, **kwargs)

        try:
            # For UPSERT, we want to:
            # 1. Update existing rows that match key columns
            # 2. Append rows that don't exist

            # Set index on key columns for both DataFrames
            existing_idx = existing_df.set_index(key_columns)
            new_idx = df.set_index(key_columns)

            # Find indices that exist in both (to update)
            common_indices = new_idx.index.intersection(existing_idx.index)

            # Update existing rows
            if len(common_indices) > 0:
                existing_idx.loc[common_indices] = new_idx.loc[common_indices]

            # Find new rows (not in existing)
            new_rows_mask = ~new_idx.index.isin(existing_idx.index)
            new_rows = new_idx[new_rows_mask]

            # Combine updated existing rows with new rows
            if not new_rows.empty:
                combined_idx = pd.concat([existing_idx, new_rows])
            else:
                combined_idx = existing_idx

            # Reset index and write back
            result_df = combined_idx.reset_index()
            return self._write_file(result_df, file_path, **kwargs)

        except Exception as e:
            print(f"[File Loader UPSERT Warning] {e}")
            print("  Falling back to APPEND strategy")
            return self._load_append(df, file_path, **kwargs)

    def _write_file(self, df: pd.DataFrame, file_path: str, **kwargs) -> bool:
        """Write DataFrame to file based on extension with security checks."""
        try:
            file_path_lower = file_path.lower()

            # Security: Check DataFrame size before writing
            if len(df) > 1000000:  # 1 million rows limit
                print(f"[Security Warning] Writing large DataFrame: {len(df)} rows")

            if file_path_lower.endswith(".csv"):
                df.to_csv(file_path, index=False, **kwargs)
            elif file_path_lower.endswith((".xlsx", ".xls")):
                df.to_excel(file_path, index=False, **kwargs)
            elif file_path_lower.endswith(".parquet"):
                df.to_parquet(file_path, index=False, **kwargs)
            elif file_path_lower.endswith(".feather"):
                df.to_feather(file_path, **kwargs)
            else:
                # Default to CSV
                df.to_csv(file_path, index=False, **kwargs)

            # Security: Set appropriate file permissions
            try:
                os.chmod(file_path, 0o600)  # Read/write for owner only
            except (PermissionError, OSError) as perm_error:
                print(
                    f"[Security Info] Could not set file permissions on {file_path}: {perm_error}"
                )
            except Exception as unexpected_error:
                print(
                    f"[Security Warning] Unexpected error setting file permissions: {unexpected_error}"
                )

            return True

        except Exception as e:
            print(f"[File Write Error] {e}")
            return False

    def _read_file(self, file_path: str, **kwargs) -> pd.DataFrame:
        """Read DataFrame from file based on extension."""
        try:
            file_path_lower = file_path.lower()

            if file_path_lower.endswith(".csv"):
                return pd.read_csv(file_path, **kwargs)
            elif file_path_lower.endswith((".xlsx", ".xls")):
                return pd.read_excel(file_path, **kwargs)
            elif file_path_lower.endswith(".parquet"):
                return pd.read_parquet(file_path, **kwargs)
            elif file_path_lower.endswith(".feather"):
                return pd.read_feather(file_path, **kwargs)
            else:
                # Try CSV as default
                return pd.read_csv(file_path, **kwargs)

        except Exception as e:
            print(f"[File Read Error] {e}")
            return None

    def _check_schema_compatibility(self, df1: pd.DataFrame, df2: pd.DataFrame) -> bool:
        """
        Check if two DataFrames have compatible schemas for append operations.

        Args:
            df1: First DataFrame.
            df2: Second DataFrame.

        Returns:
            True if schemas are compatible, False otherwise.
        """
        # Basic compatibility check
        if df1.columns.tolist() != df2.columns.tolist():
            print(f"[Schema Mismatch] Columns don't match:")
            print(f"  DF1 columns: {df1.columns.tolist()}")
            print(f"  DF2 columns: {df2.columns.tolist()}")
            return False

        # Check data types (optional, can be strict or lenient)
        for col in df1.columns:
            if col in df2.columns:
                dtype1 = df1[col].dtype
                dtype2 = df2[col].dtype
                if dtype1 != dtype2:
                    print(
                        f"[Schema Mismatch] Column '{col}' has different dtypes: {dtype1} vs {dtype2}"
                    )
                    # For security, we might want to be strict about this

        return True
