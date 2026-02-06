"""
SQL database loader using SQLAlchemy with full strategy support.
"""
import re
from typing import Any, Dict, List, Optional

import pandas as pd

from etl_framework.core.load_strategy import LoadStrategy
from etl_framework.core.loader import Loader

try:
    from sqlalchemy import MetaData, Table, create_engine, select, text
    from sqlalchemy.exc import SQLAlchemyError

    SQLALCHEMY_AVAILABLE = True
except ImportError:
    SQLALCHEMY_AVAILABLE = False


class SQLLoader(Loader):
    """Loads a DataFrame into a SQL database table with various strategies."""

    def __init__(self, connection_string: str):
        """
        Args:
            connection_string: SQLAlchemy connection string
                (e.g., 'postgresql://user:pass@localhost/dbname').
        """
        if not SQLALCHEMY_AVAILABLE:
            raise ImportError(
                "SQLAlchemy is required for SQL loading. "
                "Install with 'pip install etl-framework[sql]' or 'pip install sqlalchemy'."
            )
        self.engine = create_engine(connection_string)
        self.dialect = self.engine.dialect.name

    def load(
        self,
        df: pd.DataFrame,
        target: Any,  # Changed from table_name to target to match abstract Loader
        strategy: LoadStrategy = LoadStrategy.REPLACE,
        key_columns: Optional[List[str]] = None,
        **kwargs,
    ) -> bool:
        """
        Load DataFrame into a SQL table with specified strategy.

        Args:
            df: DataFrame to load.
            target: Target table name (string).
            strategy: How to behave if the table already exists.
            key_columns: Columns to use for matching records (for UPDATE/UPSERT).
            **kwargs: Additional arguments passed to pandas.DataFrame.to_sql or strategy methods.

        Returns:
            True on success, False on failure.
        """
        # Convert target to string table name for internal use
        table_name = str(target)

        try:
            # Validate table name for security
            self._validate_identifier(table_name)

            if strategy == LoadStrategy.FAIL:
                return self._load_fail(df, table_name, **kwargs)
            elif strategy == LoadStrategy.REPLACE:
                return self._load_replace(df, table_name, **kwargs)
            elif strategy == LoadStrategy.APPEND:
                return self._load_append(df, table_name, **kwargs)
            elif strategy == LoadStrategy.UPDATE:
                return self._load_update(df, table_name, key_columns, **kwargs)
            elif strategy == LoadStrategy.UPSERT:
                return self._load_upsert(df, table_name, key_columns, **kwargs)
            else:
                # Default to REPLACE for unknown strategies
                return self._load_replace(df, table_name, **kwargs)

        except Exception as e:
            print(f"[SQL Loader Error] {e}")
            return False

    def _validate_identifier(self, identifier: str) -> None:
        """
        Validate SQL identifier (table or column name) for security.

        Args:
            identifier: Table or column name to validate.

        Raises:
            ValueError: If identifier contains invalid characters.
        """
        # SQL identifier pattern: alphanumeric and underscores only
        pattern = r"^[a-zA-Z_][a-zA-Z0-9_]*$"
        if not re.match(pattern, identifier):
            raise ValueError(
                f"Invalid SQL identifier: '{identifier}'. "
                f"Must match pattern: {pattern}"
            )

    def _validate_column_names(self, columns: List[str]) -> None:
        """
        Validate list of column names for security.

        Args:
            columns: List of column names to validate.

        Raises:
            ValueError: If any column name contains invalid characters.
        """
        for column in columns:
            self._validate_identifier(column)

    def _ensure_columns_exist(self, table_name: str, df_columns: List[str]) -> None:
        """
        Ensure the table has all columns from the DataFrame.
        Add any missing columns.

        Args:
            table_name: Table name to check.
            df_columns: List of column names from DataFrame.

        Raises:
            ValueError: If table doesn't exist or column names are invalid.
        """
        # Validate all column names first
        self._validate_column_names(df_columns)

        with self.engine.connect() as conn:
            # Check if table exists
            if not self.engine.dialect.has_table(conn, table_name):
                # Table doesn't exist, it will be created with all columns
                return

            # Get existing columns from the table
            metadata = MetaData()
            table = Table(table_name, metadata, autoload_with=self.engine)
            existing_columns = {col.name for col in table.columns}

            # Find missing columns
            missing_columns = [col for col in df_columns if col not in existing_columns]

            if not missing_columns:
                return

            # Add missing columns
            for column in missing_columns:
                try:
                    # Determine column type from DataFrame (simplified)
                    # In a real implementation, you'd map pandas dtypes to SQL types
                    col_type = "TEXT"  # Default type for simplicity

                    # Add column to table
                    alter_stmt = (
                        f"ALTER TABLE {table_name} ADD COLUMN {column} {col_type}"
                    )
                    conn.execute(text(alter_stmt))
                    conn.commit()

                    print(
                        f"[SQL] Added missing column '{column}' to table '{table_name}'"
                    )

                except Exception as e:
                    print(f"[SQL Warning] Failed to add column '{column}': {e}")
                    # Continue with other columns

    def _load_fail(self, df: pd.DataFrame, table_name: str, **kwargs) -> bool:
        """Fail if table already exists."""
        # Validate table name
        self._validate_identifier(table_name)

        # Check if table exists
        with self.engine.connect() as conn:
            if self.engine.dialect.has_table(conn, table_name):
                raise ValueError(
                    f"Table '{table_name}' already exists. Use a different strategy."
                )

        # Table doesn't exist, create it
        # Remove batch_size from kwargs as it's not a valid parameter for to_sql()
        sql_kwargs = {k: v for k, v in kwargs.items() if k != "batch_size"}
        return (
            df.to_sql(
                table_name, self.engine, if_exists="fail", index=False, **sql_kwargs
            )
            is not None
        )

    def _load_replace(self, df: pd.DataFrame, table_name: str, **kwargs) -> bool:
        """Replace table (drop and recreate)."""
        # Validate table name
        self._validate_identifier(table_name)

        # Remove batch_size from kwargs as it's not a valid parameter for to_sql()
        sql_kwargs = {k: v for k, v in kwargs.items() if k != "batch_size"}
        return (
            df.to_sql(
                table_name, self.engine, if_exists="replace", index=False, **sql_kwargs
            )
            is not None
        )

    def _load_append(self, df: pd.DataFrame, table_name: str, **kwargs) -> bool:
        """Append to existing table."""
        # Validate table name
        self._validate_identifier(table_name)

        # Ensure table has all columns from DataFrame
        self._ensure_columns_exist(table_name, list(df.columns))

        # Remove batch_size from kwargs as it's not a valid parameter for to_sql()
        sql_kwargs = {k: v for k, v in kwargs.items() if k != "batch_size"}
        return (
            df.to_sql(
                table_name, self.engine, if_exists="append", index=False, **sql_kwargs
            )
            is not None
        )

    def _load_update(
        self, df: pd.DataFrame, table_name: str, key_columns: List[str], **kwargs
    ) -> bool:
        """Update existing records in table."""
        if not key_columns:
            raise ValueError(
                "UPDATE strategy requires key_columns to identify records to update."
            )

        # Validate identifiers
        self._validate_identifier(table_name)
        self._validate_column_names(key_columns)

        # Check if table exists
        with self.engine.connect() as conn:
            if not self.engine.dialect.has_table(conn, table_name):
                # Table doesn't exist, create it
                return self._load_replace(df, table_name, **kwargs)

        # Ensure table has all columns from DataFrame (except we only need non-key columns for updates)
        # We need all columns for the update statement
        self._ensure_columns_exist(table_name, list(df.columns))

        # Update records in batches
        batch_size = kwargs.get("batch_size", 1000)
        success = True

        for i in range(0, len(df), batch_size):
            batch = df.iloc[i : i + batch_size]
            if not self._update_batch(batch, table_name, key_columns):
                success = False

        return success

    def _load_upsert(
        self, df: pd.DataFrame, table_name: str, key_columns: List[str], **kwargs
    ) -> bool:
        """Update existing records and insert new ones (UPSERT/MERGE)."""
        if not key_columns:
            raise ValueError(
                "UPSERT strategy requires key_columns to identify records."
            )

        # Validate identifiers
        self._validate_identifier(table_name)
        self._validate_column_names(key_columns)

        # Check if table exists
        with self.engine.connect() as conn:
            if not self.engine.dialect.has_table(conn, table_name):
                # Table doesn't exist, create it with the data
                return self._load_replace(df, table_name, **kwargs)

        # Use database-specific UPSERT implementation
        if self.dialect == "postgresql":
            return self._upsert_postgresql(df, table_name, key_columns, **kwargs)
        elif self.dialect == "mysql":
            return self._upsert_mysql(df, table_name, key_columns, **kwargs)
        elif self.dialect == "sqlite":
            return self._upsert_sqlite(df, table_name, key_columns, **kwargs)
        else:
            # Generic fallback: UPDATE then INSERT for unmatched rows
            return self._upsert_generic(df, table_name, key_columns, **kwargs)

    def _update_batch(
        self, df: pd.DataFrame, table_name: str, key_columns: List[str]
    ) -> bool:
        """Update a batch of records in the table."""
        try:
            with self.engine.begin() as conn:
                metadata = MetaData()
                table = Table(table_name, metadata, autoload_with=self.engine)

                for _, row in df.iterrows():
                    # Build WHERE clause for key columns
                    where_clause = []
                    for key in key_columns:
                        if key in row:
                            where_clause.append(table.c[key] == row[key])

                    if not where_clause:
                        continue

                    # Build SET clause for non-key columns
                    update_values = {}
                    for col in df.columns:
                        if col not in key_columns and col in row:
                            update_values[col] = row[
                                col
                            ]  # Use string key, not Column object

                    if not update_values:
                        continue

                    # Execute UPDATE
                    stmt = table.update().where(*where_clause).values(**update_values)
                    conn.execute(stmt)

            return True

        except Exception as e:
            print(f"[SQL Update Batch Error] {e}")
            return False

    def _upsert_postgresql(
        self, df: pd.DataFrame, table_name: str, key_columns: List[str], **kwargs
    ) -> bool:
        """UPSERT for PostgreSQL using INSERT ... ON CONFLICT."""
        try:
            from sqlalchemy.dialects.postgresql import insert

            with self.engine.begin() as conn:
                metadata = MetaData()
                table = Table(table_name, metadata, autoload_with=self.engine)

                # Convert DataFrame to list of dicts
                records = df.to_dict("records")

                # Create INSERT statement with ON CONFLICT UPDATE
                stmt = insert(table).values(records)

                # Build update dictionary for non-key columns
                update_dict = {}
                for col in df.columns:
                    if col not in key_columns:
                        update_dict[col] = getattr(stmt.excluded, col)

                stmt = stmt.on_conflict_do_update(
                    index_elements=key_columns, set_=update_dict
                )

                conn.execute(stmt)
            return True

        except Exception as e:
            print(f"[PostgreSQL UPSERT Error] {e}")
            # Fallback to generic UPSERT
            return self._upsert_generic(df, table_name, key_columns, **kwargs)

    def _upsert_mysql(
        self, df: pd.DataFrame, table_name: str, key_columns: List[str], **kwargs
    ) -> bool:
        """UPSERT for MySQL using INSERT ... ON DUPLICATE KEY UPDATE."""
        try:
            # Validate all identifiers for security
            self._validate_identifier(table_name)
            self._validate_column_names(list(df.columns))
            self._validate_column_names(key_columns)

            batch_size = kwargs.get("batch_size", 1000)

            with self.engine.begin() as conn:
                metadata = MetaData()
                table = Table(table_name, metadata, autoload_with=self.engine)

                for i in range(0, len(df), batch_size):
                    batch = df.iloc[i : i + batch_size]

                    # Convert batch to list of dicts
                    records = batch.to_dict("records")

                    # Use MySQL dialect's Insert with on_duplicate_key_update
                    from sqlalchemy.dialects.mysql import insert

                    # Create insert statement
                    stmt = insert(table).values(records)

                    # Build update dictionary for non-key columns
                    update_dict = {}
                    for col in batch.columns:
                        if col not in key_columns:
                            # For MySQL, we need to use the VALUES() function
                            # This is safe because col has been validated
                            update_dict[table.c[col]] = text(f"VALUES({col})")

                    if not update_dict:
                        # No non-key columns to update, just insert
                        conn.execute(table.insert(), records)
                        continue

                    # Add ON DUPLICATE KEY UPDATE clause
                    stmt = stmt.on_duplicate_key_update(**update_dict)

                    # Execute the statement
                    conn.execute(stmt)

            return True

        except Exception as e:
            print(f"[MySQL UPSERT Error] {e}")
            # Fallback to generic UPSERT
            return self._upsert_generic(df, table_name, key_columns, **kwargs)

    def _upsert_sqlite(
        self, df: pd.DataFrame, table_name: str, key_columns: List[str], **kwargs
    ) -> bool:
        """UPSERT for SQLite using INSERT OR REPLACE."""
        try:
            # SQLite has INSERT OR REPLACE which acts as UPSERT
            # Note: This deletes and reinserts, which may not preserve non-updated columns

            # For proper UPSERT in SQLite 3.24+, we could use INSERT ... ON CONFLICT
            # But for compatibility, we'll use generic fallback
            return self._upsert_generic(df, table_name, key_columns, **kwargs)

        except Exception as e:
            print(f"[SQLite UPSERT Error] {e}")
            return False

    def _upsert_generic(
        self, df: pd.DataFrame, table_name: str, key_columns: List[str], **kwargs
    ) -> bool:
        """
        Generic UPSERT implementation: UPDATE existing, INSERT new.

        This works for any database but is less efficient than native UPSERT.
        """
        try:
            # 1. First, update existing records
            update_success = self._load_update(df, table_name, key_columns, **kwargs)

            if not update_success:
                return False

            # 2. Find which records weren't updated (new records)
            with self.engine.connect() as conn:
                metadata = MetaData()
                table = Table(table_name, metadata, autoload_with=self.engine)

                # Get existing keys
                existing_keys = set()
                stmt = select(*[table.c[key] for key in key_columns if key in table.c])
                result = conn.execute(stmt)
                for row in result:
                    existing_keys.add(tuple(row))

            # 3. Filter DataFrame to only new records
            new_records = []
            for _, row in df.iterrows():
                key_tuple = tuple(row[key] for key in key_columns if key in row)
                if key_tuple not in existing_keys:
                    new_records.append(row)

            # 4. Append new records
            if new_records:
                new_df = pd.DataFrame(new_records)
                return self._load_append(new_df, table_name, **kwargs)

            return True

        except Exception as e:
            print(f"[Generic UPSERT Error] {e}")
            return False
