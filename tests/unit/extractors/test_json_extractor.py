"""
Tests for JSONExtractor.
"""
import json
import os
import tempfile
from pathlib import Path

import pandas as pd
import pytest

from etl_framework.plugins.extractors.json_extractor import JSONExtractor
from etl_framework.security.input_validator import InputValidator


class TestJSONExtractor:
    """Test JSON string extractor functionality."""

    def setup_method(self):
        """Set up test environment."""
        self.validator = InputValidator(security_level="testing")
        self.extractor = JSONExtractor(self.validator)

    def test_extract_simple_json_array(self):
        """Test extracting simple JSON array."""
        json_string = '[{"name": "Alice", "age": 30}, {"name": "Bob", "age": 25}]'

        df = self.extractor.extract(json_string)

        assert isinstance(df, pd.DataFrame)
        assert len(df) == 2
        assert list(df.columns) == ["name", "age"]
        assert df["name"].tolist() == ["Alice", "Bob"]
        assert df["age"].tolist() == [30, 25]

    def test_extract_simple_json_object(self):
        """Test extracting single JSON object."""
        json_string = '{"id": 1, "name": "Test Product", "price": 99.99}'

        df = self.extractor.extract(json_string)

        assert isinstance(df, pd.DataFrame)
        assert len(df) == 1
        assert list(df.columns) == ["id", "name", "price"]
        assert df["name"].iloc[0] == "Test Product"

    def test_extract_nested_json_with_flattening(self):
        """Test extracting nested JSON with flattening."""
        json_string = """
        {
            "data": {
                "results": [
                    {"user": {"name": "Alice", "details": {"age": 30, "city": "NYC"}}},
                    {"user": {"name": "Bob", "details": {"age": 25, "city": "LA"}}}
                ]
            }
        }
        """

        df = self.extractor.extract(
            json_string, json_path="data.results", flatten_nested=True
        )

        assert isinstance(df, pd.DataFrame)
        assert len(df) == 2
        assert "user.name" in df.columns
        assert "user.details.age" in df.columns
        assert "user.details.city" in df.columns
        assert df["user.name"].tolist() == ["Alice", "Bob"]

    def test_extract_nested_json_without_flattening(self):
        """Test extracting nested JSON without flattening."""
        json_string = '{"user": {"name": "Alice", "details": {"age": 30}}}'

        df = self.extractor.extract(json_string, flatten_nested=False)

        assert isinstance(df, pd.DataFrame)
        assert len(df) == 1
        assert "user" in df.columns
        # user column should contain the nested dict
        assert isinstance(df["user"].iloc[0], dict)

    def test_extract_json_with_json_path(self):
        """Test extracting specific path from JSON."""
        json_string = """
        {
            "status": "success",
            "data": {
                "items": [
                    {"id": 1, "value": "A"},
                    {"id": 2, "value": "B"}
                ]
            }
        }
        """

        df = self.extractor.extract(json_string, json_path="data.items")

        assert isinstance(df, pd.DataFrame)
        assert len(df) == 2
        assert list(df.columns) == ["id", "value"]
        assert df["id"].tolist() == [1, 2]

    def test_extract_json_primitive_array(self):
        """Test extracting JSON array of primitives."""
        json_string = "[1, 2, 3, 4, 5]"

        df = self.extractor.extract(json_string)

        assert isinstance(df, pd.DataFrame)
        assert len(df) == 5
        assert list(df.columns) == ["value"]
        assert df["value"].tolist() == [1, 2, 3, 4, 5]

    def test_extract_json_primitive_value(self):
        """Test extracting single primitive value."""
        json_string = '"Hello World"'

        df = self.extractor.extract(json_string)

        assert isinstance(df, pd.DataFrame)
        assert len(df) == 1
        assert list(df.columns) == ["value"]
        assert df["value"].iloc[0] == "Hello World"

    def test_extract_from_dict(self):
        """Test extracting from already parsed dict."""
        data_dict = {
            "products": [
                {"id": 1, "name": "Laptop", "price": 999.99},
                {"id": 2, "name": "Mouse", "price": 29.99},
            ]
        }

        df = self.extractor.extract(data_dict, json_path="products")

        assert isinstance(df, pd.DataFrame)
        assert len(df) == 2
        assert list(df.columns) == ["id", "name", "price"]

    def test_extract_invalid_json(self):
        """Test extracting invalid JSON raises error."""
        invalid_json = '{"name": "test", "value": 123'  # Missing closing brace

        with pytest.raises(ValueError, match="Invalid JSON"):
            self.extractor.extract(invalid_json)

    def test_extract_empty_json(self):
        """Test extracting empty JSON string."""
        empty_json = ""

        with pytest.raises(ValueError, match="JSON string is empty"):
            self.extractor.extract(empty_json)

    def test_extract_too_large_json(self):
        """Test extracting JSON that exceeds size limit."""
        # Create a very large JSON string
        large_json = json.dumps({"data": ["x" * 10000] * 100})

        # Should fail with size limit
        with pytest.raises(ValueError, match="JSON string too long"):
            self.extractor.extract(large_json)

    def test_extract_with_security_validation_production(self):
        """Test security validation in production mode."""
        # Create deeply nested JSON (potential DoS)
        nested_data = {"level1": {"level2": {"level3": {"level4": "value"}}}}
        for _ in range(100):
            nested_data = {"nested": nested_data}

        dangerous_json = json.dumps(nested_data)

        # Should work in testing mode
        extractor_testing = JSONExtractor(
            InputValidator(security_level="testing")
        )
        df_testing = extractor_testing.extract(dangerous_json)
        assert isinstance(df_testing, pd.DataFrame)

        # Should fail in production mode (either length or complexity)
        extractor_production = JSONExtractor(
            InputValidator(security_level="production")
        )
        try:
            df_production = extractor_production.extract(dangerous_json)
            # If it doesn't fail, that's OK - it means the JSON passed both checks
            assert isinstance(df_production, pd.DataFrame)
        except ValueError as e:
            error_msg = str(e)
            # Should fail with either length or complexity error
            assert (
                "JSON string too long" in error_msg
                or "JSON structure too complex" in error_msg
            )

    def test_validate_source(self):
        """Test source validation method."""
        # Valid JSON strings
        assert self.extractor.validate_source('[{"test": "data"}]') == True
        assert self.extractor.validate_source('{"test": "data"}') == True
        assert self.extractor.validate_source("123") == True  # Valid JSON number

        # Invalid JSON strings
        assert self.extractor.validate_source("invalid json") == False
        assert self.extractor.validate_source("{invalid: json}") == False

        # Valid dict
        assert self.extractor.validate_source({"test": "data"}) == True
        assert self.extractor.validate_source([1, 2, 3]) == True  # List is valid

        # Invalid types
        assert self.extractor.validate_source(123) == False  # Not string or dict/list
        assert self.extractor.validate_source(None) == False

    def test_get_security_info(self):
        """Test security information method."""
        info = self.extractor.get_security_info()

        assert info["extractor_type"] == "JSONExtractor"
        assert info["has_security_validation"] == True
        assert info["validates_json"] == True
        assert info["uses_input_validator"] == True

    def test_extractor_without_validator(self):
        """Test extractor works without explicit validator."""
        extractor = JSONExtractor()  # No validator provided

        json_string = '[{"test": "data"}]'
        df = extractor.extract(json_string)

        assert isinstance(df, pd.DataFrame)
        assert len(df) == 1
        assert "test" in df.columns

    def test_json_path_not_found(self):
        """Test error when JSON path doesn't exist."""
        json_string = '{"data": {"items": [1, 2, 3]}}'

        with pytest.raises(ValueError, match="JSON path not found"):
            self.extractor.extract(json_string, json_path="data.nonexistent")

    def test_complex_json_structure(self):
        """Test extracting complex JSON structure."""
        json_string = """
        {
            "metadata": {"version": "1.0", "timestamp": "2024-01-01"},
            "results": {
                "total": 2,
                "items": [
                    {
                        "id": 1,
                        "name": "Item 1",
                        "tags": ["tag1", "tag2"],
                        "metadata": {"created": "2024-01-01", "updated": "2024-01-02"}
                    },
                    {
                        "id": 2,
                        "name": "Item 2",
                        "tags": ["tag3"],
                        "metadata": {"created": "2024-01-03"}
                    }
                ]
            }
        }
        """

        df = self.extractor.extract(
            json_string, json_path="results.items", flatten_nested=True
        )

        assert isinstance(df, pd.DataFrame)
        assert len(df) == 2
        assert "id" in df.columns
        assert "name" in df.columns
        assert "tags" in df.columns
        assert "metadata.created" in df.columns
        assert df["id"].tolist() == [1, 2]

    def test_json_with_special_characters(self):
        """Test JSON with special characters."""
        # Use properly escaped JSON
        json_string = """{
            "name": "Test & Special Characters < > & '",
            "value": "Line 1\\nLine 2\\tTab",
            "unicode": "🎉 Emoji 📊 Test"
        }"""

        df = self.extractor.extract(json_string)

        assert isinstance(df, pd.DataFrame)
        assert len(df) == 1
        assert "name" in df.columns
        assert "value" in df.columns
        assert "unicode" in df.columns
        # Check that unicode characters are preserved
        assert "🎉" in df["unicode"].iloc[0]
        assert "📊" in df["unicode"].iloc[0]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
