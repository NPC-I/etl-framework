"""
Data validation utilities.
"""
from typing import List, Optional

import pandas as pd


def validate_columns(df: pd.DataFrame, required_columns: List[str]) -> bool:
    """
    Check if DataFrame contains all required columns.

    Args:
        df: DataFrame to validate.
        required_columns: List of column names that must be present.

    Returns:
        True if all required columns exist, False otherwise.
    """
    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        print(f"[VALIDATION] Missing required columns: {missing}")
        return False
    return True


def validate_no_empty(
    df: pd.DataFrame, critical_columns: Optional[List[str]] = None
) -> bool:
    """
    Check that critical columns have no empty/null values.

    Args:
        df: DataFrame to validate.
        critical_columns: Columns to check. If None, check all columns.

    Returns:
        True if no empty values in critical columns, False otherwise.
    """
    if critical_columns is None:
        critical_columns = df.columns.tolist()
    else:
        critical_columns = [col for col in critical_columns if col in df.columns]

    for col in critical_columns:
        if df[col].isnull().all():
            print(f"[VALIDATION] Column '{col}' is completely empty.")
            return False
    return True
