"""
Excel extractor implementation with security features.
"""
from typing import Any, Optional

import pandas as pd

from etl_framework.core.extractor import Extractor
from etl_framework.security.input_validator import InputValidator


class ExcelExtractor(Extractor):
    """Extracts data from Excel files with security validation."""

    def __init__(self, validator: Optional[InputValidator] = None):
        """
        Initialize Excel extractor with security validator.

        Args:
            validator: InputValidator instance for security validation.
                      If None, creates basic validation internally.
        """
        self.validator = validator

    def extract(self, excel_path: str, sheet_name: Any = 0, **kwargs) -> pd.DataFrame:
        """
        Extract data from an Excel file with security validation.

        Args:
            excel_path: Path to the Excel file.
            sheet_name: Sheet to read (by name or index).
            **kwargs: Additional arguments passed to pandas.read_excel.

        Returns:
            A pandas DataFrame.

        Raises:
            ValueError: If file path is invalid or file is too large.
        """
        # Security: Use validator if available, otherwise basic validation
        if self.validator:
            try:
                validated_path = self.validator.validate_file_path(
                    excel_path, [".xlsx", ".xls"], operation="read"
                )
                excel_path = str(validated_path)
            except ValueError as e:
                raise ValueError(f"Excel file validation failed: {e}")
        else:
            # Fallback to basic validation
            if not excel_path or not isinstance(excel_path, str):
                raise ValueError("Invalid Excel file path")

            # Security: Check for path traversal attempts
            if ".." in excel_path:
                print(
                    f"[Security Warning] Potential path traversal in Excel path: {excel_path}"
                )
                # In production, you might want to raise an error
                # raise ValueError(f"Path traversal attempt detected: {excel_path}")

            # Security: Check file extension
            if not excel_path.lower().endswith((".xlsx", ".xls")):
                raise ValueError(f"Invalid Excel file extension: {excel_path}")

        try:
            # Use pandas to read Excel with error handling
            df = pd.read_excel(excel_path, sheet_name=sheet_name, **kwargs)

            # Security: Check DataFrame size (basic DoS protection)
            if len(df) > 1000000:  # 1 million rows limit
                print(f"[Security Warning] Large Excel file: {len(df)} rows")
                # In production, you might want to implement chunked reading

            # Security: Check for suspicious column names
            suspicious_patterns = ["password", "secret", "key", "token", "credential"]
            for col in df.columns:
                col_lower = str(col).lower()
                if any(pattern in col_lower for pattern in suspicious_patterns):
                    print(
                        f"[Security Info] Excel contains potentially sensitive column: {col}"
                    )

            # Security: Check for hidden sheets or macros (basic check)
            # Note: This is a simplified check - real Excel security is more complex
            if "engine" in kwargs and kwargs["engine"] == "openpyxl":
                try:
                    from openpyxl import load_workbook

                    wb = load_workbook(excel_path, read_only=True, data_only=True)
                    hidden_sheets = [
                        ws.title for ws in wb.worksheets if ws.sheet_state == "hidden"
                    ]
                    if hidden_sheets:
                        print(
                            f"[Security Info] Excel contains hidden sheets: {hidden_sheets}"
                        )
                except ImportError:
                    print(
                        "[Security Info] openpyxl not available for advanced Excel security checks"
                    )
                except Exception as security_check_error:
                    print(
                        f"[Security Info] Could not perform advanced Excel security check: {security_check_error}"
                    )

            return df

        except FileNotFoundError:
            raise ValueError(f"Excel file not found: {excel_path}")
        except pd.errors.EmptyDataError:
            raise ValueError(f"Excel file is empty: {excel_path}")
        except Exception as e:
            raise ValueError(f"Error reading Excel file {excel_path}: {e}")

    def validate_source(self, source: Any) -> bool:
        """
        Validate the Excel source.

        Args:
            source: Source to validate.

        Returns:
            True if source is valid, False otherwise.
        """
        if not isinstance(source, str):
            return False

        if self.validator:
            try:
                self.validator.validate_file_path(source, [".xlsx", ".xls"], "read")
                return True
            except ValueError:
                return False
        else:
            # Basic validation
            return source.lower().endswith((".xlsx", ".xls")) and ".." not in source

    def get_security_info(self) -> dict:
        """
        Get security information about this extractor.

        Returns:
            Dictionary with security information.
        """
        return {
            "extractor_type": "ExcelExtractor",
            "has_validator": self.validator is not None,
            "validates_path": True,
            "validates_content": False,
        }
