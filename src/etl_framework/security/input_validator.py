"""
Input validation and sanitization for security.
"""
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional


class InputValidator:
    """Validates and sanitizes inputs for security."""

    def __init__(self, security_level: str = "development"):
        """
        Args:
            security_level: Security level (development, testing, staging, production)
        """
        self.security_level = security_level.lower()

        # SQL identifier pattern
        self.sql_identifier_pattern = r"^[a-zA-Z_][a-zA-Z0-9_]*$"

        # Dangerous patterns for SQL injection
        self.sql_injection_patterns = [
            r";",
            r"--",
            r"/\*",
            r"\*/",
            r"union",
            r"select",
            r"insert",
            r"delete",
            r"drop",
            r"update",
            r"exec",
            r"execute",
            r"xp_",
        ]

        # Dangerous patterns for code injection
        self.code_injection_patterns = [
            r"__import__",
            r"eval\(",
            r"exec\(",
            r"compile\(",
            r"getattr\(",
            r"setattr\(",
            r"__getattribute__",
            r"os\.",
            r"sys\.",
            r"subprocess\.",
        ]

    def validate_sql_identifier(self, identifier: str) -> bool:
        """
        Validate SQL identifier (table or column name).

        Args:
            identifier: Identifier to validate.

        Returns:
            True if valid, False otherwise.
        """
        if not isinstance(identifier, str):
            return False

        # Check length
        if len(identifier) > 100:
            return False

        # Check SQL identifier pattern
        if not re.match(self.sql_identifier_pattern, identifier):
            return False

        # Check for SQL injection patterns
        identifier_lower = identifier.lower()
        for pattern in self.sql_injection_patterns:
            if re.search(pattern, identifier_lower):
                return False

        return True

    def validate_formula(
        self, formula: str, max_length: int = 1000, trusted_source: bool = False
    ) -> str:
        """
        Validate and sanitize a formula expression.

        Args:
            formula: Formula to validate.
            max_length: Maximum formula length.
            trusted_source: Whether formula comes from a trusted source (e.g., config file).
                           If True, allows certain safe patterns that would normally be blocked.

        Returns:
            Sanitized formula.

        Raises:
            ValueError: If formula is invalid.
        """
        if not isinstance(formula, str):
            raise ValueError("Formula must be a string")

        # Check length
        if len(formula) > max_length:
            raise ValueError(
                f"Formula too long: {len(formula)} > {max_length} characters"
            )

        # Check for dangerous patterns
        formula_lower = formula.lower()

        # Always check for code injection patterns (these are never safe)
        for pattern in self.code_injection_patterns:
            if re.search(pattern, formula_lower):
                raise ValueError(f"Formula contains dangerous pattern: {pattern}")

        # Check for SQL injection patterns
        # If trusted_source=True, allow certain safe patterns that contain SQL keywords
        # but are actually numpy/pandas functions
        for pattern in self.sql_injection_patterns:
            if re.search(pattern, formula_lower):
                # Check if this is a safe pattern in a trusted source
                if trusted_source:
                    # Allow certain safe numpy/pandas functions
                    safe_patterns = [
                        r"np\.select",
                        r"pd\.select",
                        r"numpy\.select",
                        r"pandas\.select",
                        r"np\.where",
                        r"pd\.where",
                        r"numpy\.where",
                        r"pandas\.where",
                        r"select\s*\(",  # Function call, not SQL
                    ]

                    # Check if it's a safe pattern
                    is_safe = False
                    for safe_pattern in safe_patterns:
                        if re.search(safe_pattern, formula):
                            is_safe = True
                            break

                    if not is_safe:
                        raise ValueError(
                            f"Formula contains SQL injection pattern: {pattern}"
                        )
                else:
                    # Not a trusted source, reject all SQL patterns
                    raise ValueError(
                        f"Formula contains SQL injection pattern: {pattern}"
                    )

        # Additional checks for production security
        if self.security_level == "production":
            # Disallow certain functions in production
            dangerous_functions = ["eval", "exec", "compile", "getattr", "setattr"]
            for func in dangerous_functions:
                if func in formula_lower:
                    raise ValueError(f"Formula contains dangerous function: {func}")

        return formula

    def validate_file_path(
        self,
        filepath: str,
        allowed_extensions: Optional[List[str]] = None,
        operation: str = "read",
    ) -> Path:
        """
        Validate file path for security.

        Args:
            filepath: File path to validate.
            allowed_extensions: List of allowed file extensions.
            operation: Operation type ("read" or "write").

        Returns:
            Validated Path object.

        Raises:
            ValueError: If file path is invalid.
        """
        if not isinstance(filepath, str):
            raise ValueError("File path must be a string")

        # Check for path traversal
        if ".." in filepath:
            raise ValueError(f"Path traversal attempt detected: {filepath}")

        # Convert to Path object
        path = Path(filepath).resolve()

        # Check file extension
        if allowed_extensions:
            file_ext = path.suffix.lower()
            if file_ext not in allowed_extensions:
                raise ValueError(
                    f"Invalid file extension '{file_ext}'. "
                    f"Allowed: {', '.join(allowed_extensions)}"
                )

        # Operation-specific validation
        if operation == "read":
            # For read operations, file must exist
            if not path.exists():
                raise ValueError(f"File does not exist: {filepath}")

            # Check if it's a file
            if not path.is_file():
                raise ValueError(f"Path is not a file: {filepath}")

            # Check file size (basic DoS protection)
            max_size_mb = 100  # 100MB limit
            file_size_mb = path.stat().st_size / (1024 * 1024)
            if file_size_mb > max_size_mb:
                raise ValueError(
                    f"File too large: {file_size_mb:.1f}MB > {max_size_mb}MB limit"
                )

        elif operation == "write":
            # For write operations, parent directory must exist
            parent_dir = path.parent
            if not parent_dir.exists():
                raise ValueError(f"Parent directory does not exist: {parent_dir}")

            # Check if parent directory is writable
            if not os.access(parent_dir, os.W_OK):
                raise ValueError(f"Parent directory not writable: {parent_dir}")

            # Check if file already exists (for security, we might want to know)
            if path.exists():
                print(f"[Security Info] Output file already exists: {path}")
                # In production, we might want stricter checks
                if self.security_level == "production":
                    # Check file permissions on existing file
                    if not os.access(path, os.W_OK):
                        raise ValueError(f"Existing file not writable: {path}")
        else:
            raise ValueError(
                f"Invalid operation: {operation}. Must be 'read' or 'write'."
            )

        return path

    def validate_json_file(
        self, filepath: str, max_size_mb: int = 10
    ) -> Dict[str, Any]:
        """
        Validate and load JSON file.

        Args:
            filepath: Path to JSON file.
            max_size_mb: Maximum file size in MB.

        Returns:
            Parsed JSON data.

        Raises:
            ValueError: If JSON file is invalid.
        """
        # Validate file path
        path = self.validate_file_path(filepath, [".json"], "read")

        # Check file size
        file_size_mb = path.stat().st_size / (1024 * 1024)
        if file_size_mb > max_size_mb:
            raise ValueError(
                f"JSON file too large: {file_size_mb:.1f}MB > {max_size_mb}MB limit"
            )

        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()

                # Basic JSON validation
                data = json.loads(content)

                # Additional security checks
                if self.security_level == "production":
                    # Check for deep nesting (potential DoS)
                    json_str = json.dumps(data)
                    if json_str.count("[") > 1000 or json_str.count("{") > 1000:
                        raise ValueError("JSON structure too complex (potential DoS)")

                return data

        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in '{filepath}': {e}")
        except UnicodeDecodeError as e:
            raise ValueError(f"Invalid encoding in '{filepath}': {e}")

    def validate_json_string(
        self, json_string: str, max_length: int = 10000
    ) -> Dict[str, Any]:
        """
        Validate JSON string content.

        Args:
            json_string: JSON string to validate.
            max_length: Maximum string length.

        Returns:
            Parsed JSON data.

        Raises:
            ValueError: If JSON string is invalid.
        """
        if not isinstance(json_string, str):
            raise ValueError("JSON string must be a string")

        # Check length
        if len(json_string) > max_length:
            raise ValueError(
                f"JSON string too long: {len(json_string)} > {max_length} characters"
            )

        # Check if empty
        if not json_string.strip():
            raise ValueError("JSON string is empty")

        try:
            # Parse JSON
            data = json.loads(json_string)

            # Security checks (same as validate_json_file)
            if self.security_level == "production":
                # Check for deep nesting (potential DoS)
                json_str = json.dumps(data)
                if json_str.count("[") > 1000 or json_str.count("{") > 1000:
                    raise ValueError("JSON structure too complex (potential DoS)")

            return data

        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {e}")

    def sanitize_string(self, text: str, max_length: int = 1000) -> str:
        """
        Sanitize string input.

        Args:
            text: Text to sanitize.
            max_length: Maximum length.

        Returns:
            Sanitized text.
        """
        if not isinstance(text, str):
            return ""

        # Truncate if too long
        if len(text) > max_length:
            text = text[:max_length]

        # Remove control characters (except newline and tab)
        text = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "", text)

        # Remove dangerous HTML/JavaScript
        dangerous_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"onload=",
            r"onerror=",
            r"onclick=",
            r"vbscript:",
        ]

        for pattern in dangerous_patterns:
            text = re.sub(pattern, "", text, flags=re.IGNORECASE)

        return text

    def validate_email(self, email: str) -> bool:
        """
        Validate email address format.

        Args:
            email: Email address to validate.

        Returns:
            True if valid, False otherwise.
        """
        if not isinstance(email, str):
            return False

        # Basic email pattern
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return bool(re.match(pattern, email))

    def get_validation_summary(self) -> Dict[str, Any]:
        """
        Get validation configuration summary.

        Returns:
            Dictionary with validation settings.
        """
        return {
            "security_level": self.security_level,
            "sql_identifier_validation": True,
            "formula_validation": True,
            "file_path_validation": True,
            "json_validation": True,
            "string_sanitization": True,
            "email_validation": True,
        }
