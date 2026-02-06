"""
Test Helpers - Utility functions for testing.
"""
import json
import os
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import numpy as np
import pandas as pd


class TestHelpers:
    """Collection of helper functions for testing."""

    @staticmethod
    def assert_dataframes_equal(
        df1: pd.DataFrame,
        df2: pd.DataFrame,
        check_dtypes: bool = False,
        check_index: bool = False,
        rtol: float = 1e-5,
        atol: float = 1e-8,
    ) -> bool:
        """
        Assert that two DataFrames are equal with detailed error reporting.

        Args:
            df1: First DataFrame
            df2: Second DataFrame
            check_dtypes: Whether to check data types
            check_index: Whether to check index equality
            rtol: Relative tolerance for numeric comparisons
            atol: Absolute tolerance for numeric comparisons

        Returns:
            True if DataFrames are equal

        Raises:
            AssertionError: If DataFrames are not equal
        """
        # Check shape
        if df1.shape != df2.shape:
            raise AssertionError(f"DataFrame shapes differ: {df1.shape} != {df2.shape}")

        # Check column names
        if list(df1.columns) != list(df2.columns):
            raise AssertionError(
                f"Column names differ:\n{list(df1.columns)}\n!=\n{list(df2.columns)}"
            )

        # Check index if requested
        if check_index and not df1.index.equals(df2.index):
            raise AssertionError("DataFrame indices differ")

        # Check each column
        for col in df1.columns:
            col1 = df1[col]
            col2 = df2[col]

            # Check for NaN equality
            if col1.isna().any() or col2.isna().any():
                # Compare NaN positions
                nan_mask1 = col1.isna()
                nan_mask2 = col2.isna()

                if not nan_mask1.equals(nan_mask2):
                    raise AssertionError(f"NaN positions differ in column '{col}'")

                # Compare non-NaN values
                non_nan_mask = ~nan_mask1
                if not col1[non_nan_mask].equals(col2[non_nan_mask]):
                    # Try numeric comparison for float columns
                    if pd.api.types.is_numeric_dtype(
                        col1
                    ) and pd.api.types.is_numeric_dtype(col2):
                        if not np.allclose(
                            col1[non_nan_mask].values,
                            col2[non_nan_mask].values,
                            rtol=rtol,
                            atol=atol,
                        ):
                            raise AssertionError(
                                f"Numeric values differ in column '{col}'"
                            )
                    else:
                        raise AssertionError(f"Values differ in column '{col}'")
            else:
                # No NaN values, direct comparison
                if not col1.equals(col2):
                    # Try numeric comparison for float columns
                    if pd.api.types.is_numeric_dtype(
                        col1
                    ) and pd.api.types.is_numeric_dtype(col2):
                        if not np.allclose(
                            col1.values, col2.values, rtol=rtol, atol=atol
                        ):
                            raise AssertionError(
                                f"Numeric values differ in column '{col}'"
                            )
                    else:
                        raise AssertionError(f"Values differ in column '{col}'")

            # Check dtypes if requested
            if check_dtypes and col1.dtype != col2.dtype:
                raise AssertionError(
                    f"Data types differ in column '{col}': {col1.dtype} != {col2.dtype}"
                )

        return True

    @staticmethod
    def capture_output(func: Callable, *args, **kwargs) -> str:
        """
        Capture stdout/stderr output from a function.

        Args:
            func: Function to execute
            *args: Function arguments
            **kwargs: Function keyword arguments

        Returns:
            Captured output as string
        """
        import io
        import sys

        # Capture stdout and stderr
        old_stdout = sys.stdout
        old_stderr = sys.stderr

        sys.stdout = io.StringIO()
        sys.stderr = io.StringIO()

        try:
            func(*args, **kwargs)
            stdout_output = sys.stdout.getvalue()
            stderr_output = sys.stderr.getvalue()
            return stdout_output + stderr_output
        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr

    @staticmethod
    def time_execution(func: Callable, *args, **kwargs) -> Dict[str, Any]:
        """
        Time the execution of a function.

        Args:
            func: Function to time
            *args: Function arguments
            **kwargs: Function keyword arguments

        Returns:
            Dictionary with timing results
        """
        start_time = time.perf_counter()
        start_process_time = time.process_time()

        result = func(*args, **kwargs)

        end_time = time.perf_counter()
        end_process_time = time.process_time()

        return {
            "result": result,
            "wall_time": end_time - start_time,
            "cpu_time": end_process_time - start_process_time,
            "start_time": start_time,
            "end_time": end_time,
        }

    @staticmethod
    def create_temp_file(
        content: Optional[str] = None, suffix: str = ".txt", binary: bool = False
    ) -> Path:
        """
        Create a temporary file with optional content.

        Args:
            content: File content
            suffix: File suffix
            binary: Whether to write binary content

        Returns:
            Path to temporary file
        """
        mode = "wb" if binary else "w"
        encoding = None if binary else "utf-8"

        with tempfile.NamedTemporaryFile(
            mode=mode, suffix=suffix, delete=False, encoding=encoding
        ) as f:
            if content is not None:
                if binary and isinstance(content, str):
                    f.write(content.encode("utf-8"))
                else:
                    f.write(content)

            return Path(f.name)

    @staticmethod
    def cleanup_temp_files(*file_paths):
        """
        Clean up temporary files.

        Args:
            *file_paths: Paths to files to delete
        """
        for file_path in file_paths:
            if isinstance(file_path, (str, Path)):
                path = Path(file_path)
                if path.exists():
                    try:
                        path.unlink()
                    except:
                        pass  # Ignore cleanup errors

    @staticmethod
    def validate_json_schema(
        data: Dict[str, Any], schema: Dict[str, Any], path: str = ""
    ) -> List[str]:
        """
        Validate data against a JSON schema.

        Args:
            data: Data to validate
            schema: Schema definition
            path: Current path for error messages

        Returns:
            List of validation errors
        """
        errors = []

        # Check required fields
        required_fields = schema.get("required", [])
        for field in required_fields:
            if field not in data:
                errors.append(f"Missing required field: {path}.{field}")

        # Check field types
        properties = schema.get("properties", {})
        for field, value in data.items():
            field_path = f"{path}.{field}" if path else field

            if field in properties:
                field_schema = properties[field]
                expected_type = field_schema.get("type")

                if expected_type:
                    type_check = TestHelpers._check_type(value, expected_type)
                    if not type_check["valid"]:
                        errors.append(
                            f"Field {field_path} has wrong type: "
                            f"expected {expected_type}, got {type_check['actual']}"
                        )

                # Recursively check nested objects
                if expected_type == "object" and isinstance(value, dict):
                    nested_schema = field_schema.get("properties", {})
                    if nested_schema:
                        nested_errors = TestHelpers.validate_json_schema(
                            value, {"properties": nested_schema}, field_path
                        )
                        errors.extend(nested_errors)

                # Check array items
                elif expected_type == "array" and isinstance(value, list):
                    items_schema = field_schema.get("items", {})
                    if items_schema:
                        for i, item in enumerate(value):
                            item_path = f"{field_path}[{i}]"
                            if isinstance(item, dict):
                                item_errors = TestHelpers.validate_json_schema(
                                    item, items_schema, item_path
                                )
                                errors.extend(item_errors)

        return errors

    @staticmethod
    def _check_type(value: Any, expected_type: str) -> Dict[str, Any]:
        """Check if value matches expected type."""
        type_map = {
            "string": str,
            "number": (int, float),
            "integer": int,
            "boolean": bool,
            "object": dict,
            "array": list,
            "null": type(None),
        }

        expected = type_map.get(expected_type)
        if expected is None:
            return {
                "valid": False,
                "actual": type(value).__name__,
                "error": f"Unknown type: {expected_type}",
            }

        if expected_type == "null":
            valid = value is None
        elif isinstance(expected, tuple):
            valid = isinstance(value, expected)
        else:
            valid = isinstance(value, expected)

        return {
            "valid": valid,
            "actual": type(value).__name__,
            "expected": expected_type,
        }

    @staticmethod
    def generate_test_report(
        test_results: List[Dict[str, Any]], output_file: Optional[Path] = None
    ) -> Dict[str, Any]:
        """
        Generate a test report from test results.

        Args:
            test_results: List of test result dictionaries
            output_file: Optional file to write report to

        Returns:
            Test report dictionary
        """
        if not test_results:
            return {"error": "No test results provided"}

        # Calculate statistics
        total_tests = len(test_results)
        passed_tests = sum(1 for r in test_results if r.get("passed", False))
        failed_tests = total_tests - passed_tests

        # Calculate average times
        execution_times = [r.get("execution_time", 0) for r in test_results]
        avg_time = sum(execution_times) / len(execution_times) if execution_times else 0

        # Group by category
        categories = {}
        for result in test_results:
            category = result.get("category", "uncategorized")
            if category not in categories:
                categories[category] = {"passed": 0, "failed": 0, "total": 0}

            categories[category]["total"] += 1
            if result.get("passed", False):
                categories[category]["passed"] += 1
            else:
                categories[category]["failed"] += 1

        # Generate report
        report = {
            "summary": {
                "total_tests": total_tests,
                "passed_tests": passed_tests,
                "failed_tests": failed_tests,
                "pass_rate": (passed_tests / total_tests * 100)
                if total_tests > 0
                else 0,
                "avg_execution_time": avg_time,
                "total_execution_time": sum(execution_times),
            },
            "categories": categories,
            "test_results": test_results,
            "timestamp": time.time(),
            "timestamp_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

        # Write to file if requested
        if output_file:
            with open(output_file, "w") as f:
                json.dump(report, f, indent=2)

        return report

    @staticmethod
    @contextmanager
    def temp_working_directory():
        """
        Context manager for temporary working directory.

        Yields:
            Path to temporary directory
        """
        original_cwd = os.getcwd()
        temp_dir = tempfile.mkdtemp()

        try:
            os.chdir(temp_dir)
            yield Path(temp_dir)
        finally:
            os.chdir(original_cwd)
            import shutil

            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
            except:
                pass


# Convenience functions
assert_dataframes_equal = TestHelpers.assert_dataframes_equal
capture_output = TestHelpers.capture_output
time_execution = TestHelpers.time_execution
create_temp_file = TestHelpers.create_temp_file
cleanup_temp_files = TestHelpers.cleanup_temp_files
validate_json_schema = TestHelpers.validate_json_schema
generate_test_report = TestHelpers.generate_test_report
