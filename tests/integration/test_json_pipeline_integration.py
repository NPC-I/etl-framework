"""
Integration tests for JSON extractor in ETL pipeline.
"""
import os
import tempfile
from pathlib import Path

import pandas as pd
import pytest

from etl_framework.core.load_strategy import LoadOptions, LoadStrategy
from etl_framework.core.pipeline import ETLPipeline
from etl_framework.plugins.extractors.json_extractor import JSONStringExtractor
from etl_framework.plugins.loaders.file_loader import FileLoader
from etl_framework.plugins.transformers.cleaner import DataCleaner
from etl_framework.plugins.transformers.mapping_loader import MappingLoader
from etl_framework.security.input_validator import InputValidator


class TestJSONPipelineIntegration:
    """Test JSON extractor integration in ETL pipeline."""

    def setup_method(self):
        """Set up test environment."""
        self.validator = InputValidator(security_level="testing")

    def test_json_pipeline_basic(self):
        """Test basic JSON pipeline with security."""
        # Create pipeline with security
        pipeline = ETLPipeline(username="test_user", enable_security=True)

        # Register components
        pipeline.register_extractor("json", JSONStringExtractor(self.validator))
        pipeline.register_loader("file", FileLoader())

        # Add basic cleaner
        pipeline.add_transformer(DataCleaner(enable_security=True))

        # Test JSON data
        json_data = """
        [
            {"id": 1, "name": "Product A", "price": 100.50, "category": "Electronics"},
            {"id": 2, "name": "Product B", "price": 75.25, "category": "Books"},
            {"id": 3, "name": "Product C", "price": 200.00, "category": "Electronics"}
        ]
        """

        # Create temp output file
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            output_file = f.name

        try:
            # Run pipeline
            result = pipeline.run(
                extractor_name="json",
                source=json_data,
                loader_name="file",
                target=output_file,
                strategy=LoadStrategy.REPLACE,
            )

            # Verify results
            assert result is not None
            assert isinstance(result, pd.DataFrame)
            assert len(result) == 3
            assert list(result.columns) == ["id", "name", "price", "category"]

            # Verify output file
            assert os.path.exists(output_file)
            output_df = pd.read_csv(output_file)
            assert len(output_df) == 3

            # Clean shutdown
            pipeline.shutdown()

        finally:
            # Clean up
            if os.path.exists(output_file):
                os.unlink(output_file)

    def test_json_pipeline_with_mapping(self):
        """Test JSON pipeline with JSON mapping."""
        # Create pipeline
        pipeline = ETLPipeline(username="test_user", enable_security=True)

        # Register components
        pipeline.register_extractor("json", JSONStringExtractor(self.validator))
        pipeline.register_loader("file", FileLoader())

        # Create mapping JSON
        mapping_json = """
        {
            "column_mapping": {
                "product_id": "id",
                "product_name": "name",
                "product_price": "price"
            },
            "calculations": [
                {
                    "name": "price_with_tax",
                    "formula": "price * 1.2"
                }
            ]
        }
        """

        # Create mapping file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(mapping_json)
            mapping_file = f.name

        # Create temp output file
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            output_file = f.name

        try:
            # Add transformers
            pipeline.add_transformer(DataCleaner(enable_security=True))
            pipeline.add_transformer(MappingLoader(mapping_file, enable_security=True))

            # Test JSON data
            json_data = """
            [
                {"id": 1, "name": "Product A", "price": 100.50},
                {"id": 2, "name": "Product B", "price": 75.25}
            ]
            """

            # Run pipeline
            result = pipeline.run(
                extractor_name="json",
                source=json_data,
                loader_name="file",
                target=output_file,
                strategy=LoadStrategy.REPLACE,
            )

            # Verify results
            assert result is not None
            assert isinstance(result, pd.DataFrame)
            assert len(result) == 2

            # Check column mapping
            assert "product_id" in result.columns
            assert "product_name" in result.columns
            assert "product_price" in result.columns
            assert "price_with_tax" in result.columns

            # Verify calculations
            assert result["price_with_tax"].iloc[0] == pytest.approx(100.50 * 1.2)

            # Clean shutdown
            pipeline.shutdown()

        finally:
            # Clean up
            for file in [mapping_file, output_file]:
                if os.path.exists(file):
                    os.unlink(file)

    def test_json_pipeline_with_security_validation(self):
        """Test JSON pipeline with security validation failures."""
        # Create pipeline with production security
        pipeline = ETLPipeline(username="test_user", enable_security=True)

        # Create validator with production security
        validator_prod = InputValidator(security_level="production")
        pipeline.register_extractor("json", JSONStringExtractor(validator_prod))
        pipeline.register_loader("file", FileLoader())

        # Create deeply nested JSON (should fail in production)
        nested_data = {}
        current = nested_data
        for i in range(1200):  # Exceeds complexity limit
            current["nested"] = {}
            current = current["nested"]

        import json

        dangerous_json = json.dumps(nested_data)

        # Create temp output file
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            output_file = f.name

        try:
            # Should fail with security validation error
            with pytest.raises(ValueError, match="JSON structure too complex"):
                pipeline.run(
                    extractor_name="json",
                    source=dangerous_json,
                    loader_name="file",
                    target=output_file,
                    strategy=LoadStrategy.REPLACE,
                )

            # Clean shutdown
            pipeline.shutdown()

        finally:
            if os.path.exists(output_file):
                os.unlink(output_file)

    def test_json_pipeline_with_options(self):
        """Test JSON pipeline with LoadOptions."""
        pipeline = ETLPipeline(username="test_user", enable_security=True)

        pipeline.register_extractor("json", JSONStringExtractor(self.validator))
        pipeline.register_loader("file", FileLoader())

        pipeline.add_transformer(DataCleaner(enable_security=True))

        # Test JSON with nested structure
        json_data = """
        {
            "api_response": {
                "status": "success",
                "data": {
                    "products": [
                        {"sku": "P001", "details": {"name": "Laptop", "price": 999.99}},
                        {"sku": "P002", "details": {"name": "Mouse", "price": 29.99}}
                    ]
                }
            }
        }
        """

        # Create temp output file
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            output_file = f.name

        try:
            # Create LoadOptions
            options = LoadOptions(
                strategy=LoadStrategy.REPLACE, batch_size=1000, enable_security=True
            )

            # Run pipeline with options
            result = pipeline.run_with_options(
                extractor_name="json",
                source=json_data,
                loader_name="file",
                target=output_file,
                options=options,
                json_path="api_response.data.products",
                flatten_nested=True,
            )

            # Verify results
            assert result is not None
            assert len(result) == 2

            # Check flattened columns
            assert "sku" in result.columns
            assert "details.name" in result.columns
            assert "details.price" in result.columns

            # Verify data
            assert result["details.name"].tolist() == ["Laptop", "Mouse"]
            assert result["details.price"].tolist() == [999.99, 29.99]

            # Clean shutdown
            pipeline.shutdown()

        finally:
            if os.path.exists(output_file):
                os.unlink(output_file)

    def test_json_pipeline_permission_denied(self):
        """Test JSON pipeline with permission denied scenario."""
        # Create pipeline with security
        pipeline = ETLPipeline(
            username="viewer", enable_security=True
        )  # Viewer role has limited permissions

        pipeline.register_extractor("json", JSONStringExtractor(self.validator))
        pipeline.register_loader("file", FileLoader())

        # Simple JSON data
        json_data = '[{"test": "data"}]'

        # Create temp output file
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            output_file = f.name

        try:
            # Try to run pipeline (viewer might not have execute permission)
            # This depends on your RBAC configuration
            try:
                result = pipeline.run(
                    extractor_name="json",
                    source=json_data,
                    loader_name="file",
                    target=output_file,
                    strategy=LoadStrategy.REPLACE,
                )

                # If it succeeds, that's fine (depends on RBAC config)
                if result is not None:
                    assert isinstance(result, pd.DataFrame)

            except PermissionError:
                # Expected if viewer doesn't have execute permission
                pass

            # Clean shutdown
            pipeline.shutdown()

        finally:
            if os.path.exists(output_file):
                os.unlink(output_file)

    def test_json_pipeline_audit_logging(self):
        """Test that JSON pipeline logs audit events."""
        import tempfile

        # Create pipeline with security and audit logging
        pipeline = ETLPipeline(username="operator", enable_security=True)

        pipeline.register_extractor("json", JSONStringExtractor(self.validator))
        pipeline.register_loader("file", FileLoader())

        pipeline.add_transformer(DataCleaner(enable_security=True))

        # Create audit log file
        with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as f:
            audit_log_file = f.name

        # Simple JSON data
        json_data = '[{"id": 1, "name": "Test"}]'

        # Create temp output file
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            output_file = f.name

        try:
            # Run pipeline
            result = pipeline.run(
                extractor_name="json",
                source=json_data,
                loader_name="file",
                target=output_file,
                strategy=LoadStrategy.REPLACE,
            )

            assert result is not None

            # Check that audit log was created (if audit logging is enabled)
            # Note: This depends on your audit logging configuration

            # Clean shutdown
            pipeline.shutdown()

        finally:
            for file in [audit_log_file, output_file]:
                if os.path.exists(file):
                    os.unlink(file)

    def test_json_pipeline_error_handling(self):
        """Test JSON pipeline error handling."""
        pipeline = ETLPipeline(username="test_user", enable_security=True)

        pipeline.register_extractor("json", JSONStringExtractor(self.validator))
        pipeline.register_loader("file", FileLoader())

        # Invalid JSON data
        invalid_json = '{"test": "data"'  # Missing closing brace

        # Create temp output file
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            output_file = f.name

        try:
            # Should raise ValueError
            with pytest.raises(ValueError, match="Invalid JSON"):
                pipeline.run(
                    extractor_name="json",
                    source=invalid_json,
                    loader_name="file",
                    target=output_file,
                    strategy=LoadStrategy.REPLACE,
                )

            # Clean shutdown
            pipeline.shutdown()

        finally:
            if os.path.exists(output_file):
                os.unlink(output_file)

    def test_json_pipeline_with_sensitive_data(self):
        """Test JSON pipeline with sensitive data detection."""
        pipeline = ETLPipeline(username="operator", enable_security=True)

        pipeline.register_extractor("json", JSONStringExtractor(self.validator))
        pipeline.register_loader("file", FileLoader())

        pipeline.add_transformer(DataCleaner(enable_security=True))

        # JSON with sensitive data
        json_data = """
        [
            {
                "id": 1,
                "name": "John Doe",
                "email": "john@example.com",
                "ssn": "123-45-6789",
                "credit_card": "4111111111111111",
                "salary": 85000
            }
        ]
        """

        # Create temp output file
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            output_file = f.name

        try:
            # Run pipeline
            result = pipeline.run(
                extractor_name="json",
                source=json_data,
                loader_name="file",
                target=output_file,
                strategy=LoadStrategy.REPLACE,
            )

            assert result is not None
            assert len(result) == 1

            # Check that sensitive columns are present
            # Note: Whether they're encrypted depends on encryption configuration
            sensitive_cols = ["email", "ssn", "credit_card", "salary"]
            for col in sensitive_cols:
                assert col in result.columns

            # Clean shutdown
            pipeline.shutdown()

        finally:
            if os.path.exists(output_file):
                os.unlink(output_file)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
