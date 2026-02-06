"""
PDF extractor implementation using pdfplumber with security features.
"""
import os
from typing import Any, Optional

import pandas as pd

from etl_framework.core.extractor import Extractor
from etl_framework.security.input_validator import InputValidator

try:
    import pdfplumber

    PDFPLUMBER_AVAILABLE = True
except ImportError:
    PDFPLUMBER_AVAILABLE = False


class PDFExtractor(Extractor):
    """Extracts tabular data from PDF files with security validation."""

    def __init__(self, validator: Optional[InputValidator] = None):
        """
        Initialize PDF extractor with security validator.

        Args:
            validator: InputValidator instance for security validation.
                      If None, creates basic validation internally.
        """
        if not PDFPLUMBER_AVAILABLE:
            raise ImportError(
                "pdfplumber is required for PDF extraction. "
                "Install with 'pip install etl-framework[pdf]' or 'pip install etl-framework[default]'. "
                "For more details, see: https://pypi.org/project/etl-framework/"
            )

        self.validator = validator

    def extract(
        self, pdf_path: str, max_pages: int = 100, max_tables_per_page: int = 10
    ) -> pd.DataFrame:
        """
        Extract tables from a PDF file with security limits.

        Args:
            pdf_path: Path to the PDF file.
            max_pages: Maximum number of pages to process (security limit).
            max_tables_per_page: Maximum tables per page to extract (security limit).

        Returns:
            A pandas DataFrame containing all extracted table rows.

        Raises:
            ValueError: If file path is invalid or security limits exceeded.
        """
        # Security: Use validator if available, otherwise basic validation
        if self.validator:
            try:
                validated_path = self.validator.validate_file_path(
                    pdf_path, [".pdf"], operation="read"
                )
                pdf_path = str(validated_path)
            except ValueError as e:
                raise ValueError(f"PDF file validation failed: {e}")
        else:
            # Fallback to basic validation
            if not pdf_path or not isinstance(pdf_path, str):
                raise ValueError("Invalid PDF file path")

            # Security: Check for path traversal attempts
            if ".." in pdf_path:
                raise ValueError(f"Path traversal attempt detected: {pdf_path}")

            # Security: Check file extension
            if not pdf_path.lower().endswith(".pdf"):
                raise ValueError(f"Invalid PDF file extension: {pdf_path}")

            # Security: Check file size (basic DoS protection)
            try:
                file_size = os.path.getsize(pdf_path)
                max_file_size = 100 * 1024 * 1024  # 100MB limit
                if file_size > max_file_size:
                    raise ValueError(
                        f"PDF file too large: {file_size} bytes > {max_file_size} limit"
                    )
            except OSError:
                raise ValueError(f"Cannot access PDF file: {pdf_path}")

        data = []
        pages_processed = 0
        total_tables_processed = 0

        try:
            with pdfplumber.open(pdf_path) as pdf:
                total_pages = len(pdf.pages)

                # Security: Check total page count
                if total_pages > max_pages * 2:  # Allow some buffer
                    print(f"[Security Warning] Large PDF: {total_pages} pages")

                for page_num, page in enumerate(pdf.pages):
                    # Security: Limit number of pages processed
                    if pages_processed >= max_pages:
                        print(
                            f"[Security] Stopped processing after {max_pages} pages (security limit)"
                        )
                        break

                    # Extract tables from the page
                    tables = page.extract_tables()

                    # Security: Limit tables per page
                    tables_to_process = tables[:max_tables_per_page]
                    tables_skipped = len(tables) - len(tables_to_process)
                    if tables_skipped > 0:
                        print(
                            f"[Security] Skipped {tables_skipped} tables on page {page_num + 1} (security limit)"
                        )

                    for table_num, table in enumerate(tables_to_process):
                        for row in table:
                            # Add metadata columns for traceability
                            row_with_meta = list(row) + [page_num + 1, table_num + 1]
                            data.append(row_with_meta)

                        total_tables_processed += 1

                        # Security: Limit total tables processed
                        if total_tables_processed >= max_pages * max_tables_per_page:
                            print(
                                f"[Security] Stopped processing after {total_tables_processed} tables (security limit)"
                            )
                            break

                    pages_processed += 1

                    if total_tables_processed >= max_pages * max_tables_per_page:
                        break
        except pdfplumber.exceptions.PDFSyntaxError as e:
            raise ValueError(f"Invalid PDF file {pdf_path}: {e}")
        except Exception as e:
            raise ValueError(f"Error reading PDF file {pdf_path}: {e}")

        # Create DataFrame
        if not data:
            return pd.DataFrame()

        # Security: Check total data size
        if len(data) > 100000:  # 100,000 rows limit
            print(f"[Security Warning] Large data extracted from PDF: {len(data)} rows")
            # In production, you might want to truncate or process in chunks

        # Determine column count
        max_cols = max(len(row) for row in data)

        # Security: Limit number of columns
        max_allowed_cols = 100
        if max_cols > max_allowed_cols:
            print(f"[Security Warning] PDF contains many columns: {max_cols}")
            # Truncate to allowed columns
            data = [row[:max_allowed_cols] for row in data]
            max_cols = max_allowed_cols

        # Create column names: data columns + metadata columns
        col_names = [f"col_{i+1}" for i in range(max_cols - 2)] + ["page", "table"]
        df = pd.DataFrame(data, columns=col_names)

        # Security: Log extraction summary
        print(
            f"[Security] PDF extraction completed: {pages_processed} pages, {total_tables_processed} tables, {len(df)} rows"
        )

        return df

    def validate_source(self, source: Any) -> bool:
        """
        Validate the PDF source.

        Args:
            source: Source to validate.

        Returns:
            True if source is valid, False otherwise.
        """
        if not isinstance(source, str):
            return False

        if self.validator:
            try:
                self.validator.validate_file_path(source, [".pdf"], "read")
                return True
            except ValueError:
                return False
        else:
            # Basic validation
            return source.lower().endswith(".pdf") and ".." not in source

    def get_security_info(self) -> dict:
        """
        Get security information about this extractor.

        Returns:
            Dictionary with security information.
        """
        return {
            "extractor_type": "PDFExtractor",
            "has_validator": self.validator is not None,
            "validates_path": True,
            "validates_content": False,
            "pdfplumber_available": PDFPLUMBER_AVAILABLE,
        }
