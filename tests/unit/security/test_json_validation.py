"""
Tests for JSON validation in InputValidator.
"""
import json
import os

import pytest

from etl_framework.security.input_validator import InputValidator


class TestJSONValidation:
    """Test JSON validation functionality."""

    def setup_method(self):
        """Set up test environment."""
        self.validator_testing = InputValidator(security_level="testing")
        self.validator_production = InputValidator(security_level="production")

    def test_validate_json_string_valid(self):
        """Test validating valid JSON strings."""
        test_cases = [
            ('{"name": "test", "value": 123}', {"name": "test", "value": 123}),
            ("[1, 2, 3, 4, 5]", [1, 2, 3, 4, 5]),
            ('"simple string"', "simple string"),
            ("123.45", 123.45),
            ("true", True),
            ("null", None),
            ("{}", {}),
            ("[]", []),
        ]

        for json_string, expected in test_cases:
            result = self.validator_testing.validate_json_string(json_string)
            assert result == expected

    def test_validate_json_string_invalid(self):
        """Test validating invalid JSON strings."""
        invalid_cases = [
            '{"name": "test", "value": 123',  # Missing closing brace
            "[1, 2, 3,",  # Incomplete array
            '{"key": value}',  # Unquoted value
            "not json at all",
            "{invalid: json}",  # Invalid syntax
        ]

        for invalid_json in invalid_cases:
            with pytest.raises(ValueError, match="Invalid JSON"):
                self.validator_testing.validate_json_string(invalid_json)

    def test_validate_json_string_empty(self):
        """Test validating empty JSON string."""
        with pytest.raises(ValueError, match="JSON string is empty"):
            self.validator_testing.validate_json_string("")

        with pytest.raises(ValueError, match="JSON string is empty"):
            self.validator_testing.validate_json_string("   ")

    def test_validate_json_string_not_string(self):
        """Test validating non-string input."""
        with pytest.raises(ValueError, match="JSON string must be a string"):
            self.validator_testing.validate_json_string(123)

        with pytest.raises(ValueError, match="JSON string must be a string"):
            self.validator_testing.validate_json_string({"test": "data"})

        with pytest.raises(ValueError, match="JSON string must be a string"):
            self.validator_testing.validate_json_string(None)

    def test_validate_json_string_too_long(self):
        """Test validating JSON string that exceeds length limit."""
        # Create a very long JSON string
        long_string = '{"data": "' + "x" * 20000 + '"}'

        with pytest.raises(ValueError, match="JSON string too long"):
            self.validator_testing.validate_json_string(long_string)

        # Test with custom length limit
        medium_string = '{"data": "' + "x" * 5000 + '"}'
        result = self.validator_testing.validate_json_string(
            medium_string, max_length=10000
        )
        assert result["data"] == "x" * 5000

    def test_validate_json_string_complexity_production(self):
        """Test complexity checks in production mode."""
        # Create JSON with many brackets by creating many arrays
        # Each inner array adds 2 brackets: [ and ]
        many_arrays = [[1] for _ in range(600)]  # 600 arrays = 1200 brackets
        complex_json = json.dumps(many_arrays)

        # Debug: Check bracket count
        bracket_count = complex_json.count("[") + complex_json.count("{")
        print(f"Debug: Bracket count = {bracket_count}")

        # Should work in testing mode
        result_testing = self.validator_testing.validate_json_string(
            complex_json, max_length=50000
        )
        assert isinstance(result_testing, list)

        # Should fail in production mode due to complexity
        # Actually, 600 arrays gives us 601 '[' characters (outer + 600 inner)
        # We need more... let's use 1200 arrays
        many_more_arrays = [[1] for _ in range(1200)]
        more_complex_json = json.dumps(many_more_arrays)

        with pytest.raises(ValueError, match="JSON structure too complex"):
            self.validator_production.validate_json_string(
                more_complex_json, max_length=50000
            )

    def test_validate_json_string_large_array_production(self):
        """Test large array checks in production mode."""
        # Create JSON with large nested structure
        # Create array of objects, each with nested array
        complex_data = {"data": [{"items": list(range(10))} for _ in range(120)]}
        complex_json = json.dumps(complex_data)

        # Should work in testing mode
        result_testing = self.validator_testing.validate_json_string(
            complex_json, max_length=50000
        )
        assert "data" in result_testing
        assert len(result_testing["data"]) == 120

        # Should fail in production mode due to complexity
        # Count brackets: outer {} (2) + data: [] (2) + 120 * ({} (2) + items: [] (2)) = 2 + 2 + 120*4 = 484
        # Actually need more... let's create more complex structure
        more_complex = {
            "levels": [
                {"nested": [{"deeper": [1, 2, 3]} for _ in range(100)]}
                for _ in range(10)
            ]
        }
        more_complex_json = json.dumps(more_complex)

        with pytest.raises(ValueError, match="JSON structure too complex"):
            self.validator_production.validate_json_string(
                more_complex_json, max_length=50000
            )

    def test_validate_json_string_special_characters(self):
        """Test JSON with special characters."""
        # Use properly escaped JSON
        special_json = """{
            "name": "Test & Special Characters < > & '",
            "multiline": "Line 1\\nLine 2\\tTab",
            "unicode": "🎉 Emoji 📊 Test",
            "escape": "Backslash: \\\\\\\\",
            "control": "Line\\rReturn"
        }"""

        result = self.validator_testing.validate_json_string(special_json)

        assert result["name"] == "Test & Special Characters < > & '"
        assert result["multiline"] == "Line 1\nLine 2\tTab"
        assert result["unicode"] == "🎉 Emoji 📊 Test"
        assert "🎉" in result["unicode"]

    def test_validate_json_string_comparison_with_file(self):
        """Test that validate_json_string matches validate_json_file behavior."""
        import tempfile

        test_json = '{"test": "data", "number": 123, "array": [1, 2, 3]}'

        # Validate as string
        string_result = self.validator_testing.validate_json_string(test_json)

        # Validate as file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(test_json)
            temp_file = f.name

        try:
            file_result = self.validator_testing.validate_json_file(temp_file)

            # Results should be identical
            assert string_result == file_result

        finally:
            os.unlink(temp_file)

    def test_validate_json_string_security_levels(self):
        """Test JSON validation across different security levels."""
        security_levels = ["development", "testing", "staging", "production"]

        # Test JSON that's valid in all levels
        simple_json = '{"test": "data"}'

        for level in security_levels:
            validator = InputValidator(security_level=level)
            result = validator.validate_json_string(simple_json)
            assert result == {"test": "data"}

        # Test JSON that should fail in production only
        # Create JSON with many brackets using many VERY SMALL objects
        # Each object: {"i":N} is only 8-10 characters
        # Need >1000 opening brackets, so need >1000 objects
        many_objects = [{"i": i} for i in range(1200)]  # 1200 objects = 1200 { brackets
        complex_data = {"data": many_objects}
        complex_json = json.dumps(complex_data)

        # Debug: Check counts
        print(f"Debug: JSON length = {len(complex_json)}")
        print(f"Debug: [ count = {complex_json.count('[')}")
        print(f"Debug: {{ count = {complex_json.count('{')}")

        # Should pass in non-production modes
        for level in ["development", "testing", "staging"]:
            validator = InputValidator(security_level=level)
            result = validator.validate_json_string(complex_json, max_length=50000)
            assert "data" in result

        # Should fail in production
        validator_prod = InputValidator(security_level="production")
        with pytest.raises(ValueError, match="JSON structure too complex"):
            validator_prod.validate_json_string(complex_json, max_length=50000)

    def test_validate_json_string_whitespace(self):
        """Test JSON with various whitespace."""
        # JSON with extra whitespace
        json_with_whitespace = """

        {
            "name" : "test" ,
            "value" : 123
        }

        """

        result = self.validator_testing.validate_json_string(json_with_whitespace)
        assert result == {"name": "test", "value": 123}

        # Minified JSON
        minified_json = '{"name":"test","value":123}'
        result = self.validator_testing.validate_json_string(minified_json)
        assert result == {"name": "test", "value": 123}

    def test_validate_json_string_error_messages(self):
        """Test error messages for different validation failures."""
        # Empty string
        with pytest.raises(ValueError) as exc_info:
            self.validator_testing.validate_json_string("")
        assert "JSON string is empty" in str(exc_info.value)

        # Too long
        long_json = '{"data": "' + "x" * 20000 + '"}'
        with pytest.raises(ValueError) as exc_info:
            self.validator_testing.validate_json_string(long_json)
        assert "JSON string too long" in str(exc_info.value)

        # Invalid JSON
        with pytest.raises(ValueError) as exc_info:
            self.validator_testing.validate_json_string("{invalid}")
        assert "Invalid JSON" in str(exc_info.value)

        # Not a string
        with pytest.raises(ValueError) as exc_info:
            self.validator_testing.validate_json_string(123)
        assert "JSON string must be a string" in str(exc_info.value)

    def test_validate_json_string_max_length_parameter(self):
        """Test custom max_length parameter."""
        # Default max_length (10000)
        default_length_json = '{"data": "' + "x" * 9000 + '"}'
        result_default = self.validator_testing.validate_json_string(
            default_length_json
        )
        assert result_default["data"] == "x" * 9000

        # Custom smaller max_length
        with pytest.raises(ValueError, match="JSON string too long"):
            self.validator_testing.validate_json_string(
                default_length_json, max_length=5000
            )

        # Custom larger max_length
        larger_json = '{"data": "' + "x" * 15000 + '"}'
        result_large = self.validator_testing.validate_json_string(
            larger_json, max_length=20000
        )
        assert result_large["data"] == "x" * 15000


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
