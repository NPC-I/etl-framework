"""
Integration tests for ETL pipeline with real components.
"""
import tempfile
from pathlib import Path

import pandas as pd
import pytest

from etl_framework.core.load_strategy import LoadStrategy
from etl_framework.core.pipeline import ETLPipeline
from etl_framework.plugins.extractors.csv_extractor import CSVExtractor
from etl_framework.plugins.loaders.file_loader import FileLoader
from etl_framework.plugins.transformers.cleaner import DataCleaner


class TestPipelineIntegration:
    """Integration tests for complete pipeline with real components."""

    @pytest.mark.integration
    def test_pipeline_csv_to_csv(
        self, temp_csv_file, directory_context, security_context
    ):
        """Test complete pipeline: CSV extract -> transform -> CSV load."""
        # Use security context to set up environment variables
        with security_context(level="testing"):
            with directory_context() as temp_dir:
                # Create output file path
                output_file = temp_dir / "output.csv"

                # Create pipeline
                pipeline = ETLPipeline(username="operator")

                # Register real components
                pipeline.register_extractor("csv", CSVExtractor())
                pipeline.register_loader("file", FileLoader())

                # Add transformer
                pipeline.add_transformer(DataCleaner(column_mapping={}))

                # Run pipeline
                result = pipeline.run(
                    extractor_name="csv",
                    source=str(temp_csv_file),
                    loader_name="file",
                    target=str(output_file),
                    strategy=LoadStrategy.REPLACE,
                )

                # Verify results
                assert result is not None
                assert len(result) == 3  # Should have 3 rows from test CSV

                # Verify output file was created
                assert output_file.exists()

                # Verify output file can be read
                output_df = pd.read_csv(output_file)
                assert len(output_df) == 3

                # Clean shutdown
                pipeline.shutdown()

    @pytest.mark.integration
    @pytest.mark.security
    def test_pipeline_with_security(
        self, temp_csv_file, directory_context, security_context
    ):
        """Test pipeline with security features enabled."""
        with security_context(level="testing"):
            with directory_context() as temp_dir:
                output_file = temp_dir / "secure_output.csv"

                # Create secure pipeline
                pipeline = ETLPipeline(username="admin", enable_security=True)

                # Register components
                pipeline.register_extractor("csv", CSVExtractor())
                pipeline.register_loader("file", FileLoader())

                # Run pipeline with security
                result = pipeline.run(
                    extractor_name="csv",
                    source=str(temp_csv_file),
                    loader_name="file",
                    target=str(output_file),
                    strategy=LoadStrategy.REPLACE,
                )

                # Verify results
                assert result is not None
                assert output_file.exists()

                pipeline.shutdown()

    @pytest.mark.integration
    def test_pipeline_with_data_cleaning(
        self, temp_csv_file, directory_context, security_context
    ):
        """Test pipeline with data cleaning transformation."""
        # Use security context to set up environment variables
        with security_context(level="testing"):
            with directory_context() as temp_dir:
                output_file = temp_dir / "cleaned_output.csv"

                # Create pipeline
                pipeline = ETLPipeline(username="operator")

                # Register components
                pipeline.register_extractor("csv", CSVExtractor())
                pipeline.register_loader("file", FileLoader())

                # Add data cleaner with column mapping
                # Note: temp_csv_file has columns: id, name, value
                column_mapping = {
                    "name": "description",  # Rename 'name' to 'description'
                    "value": "amount",  # Rename 'value' to 'amount'
                }
                pipeline.add_transformer(DataCleaner(column_mapping=column_mapping))

                # Run pipeline
                result = pipeline.run(
                    extractor_name="csv",
                    source=str(temp_csv_file),
                    loader_name="file",
                    target=str(output_file),
                    strategy=LoadStrategy.REPLACE,
                )

                # Verify column renaming worked
                assert "id" in result.columns  # Should remain unchanged
                assert "description" in result.columns  # Renamed from 'name'
                assert "amount" in result.columns  # Renamed from 'value'

                # Verify original column names are gone
                assert "name" not in result.columns
                assert "value" not in result.columns

                pipeline.shutdown()

    @pytest.mark.integration
    @pytest.mark.parametrize(
        "strategy", [LoadStrategy.REPLACE, LoadStrategy.APPEND, LoadStrategy.FAIL]
    )
    def test_pipeline_different_strategies(
        self, temp_csv_file, directory_context, security_context, strategy
    ):
        """Test pipeline with different loading strategies."""
        # Use security context to set up environment variables
        with security_context(level="testing"):
            with directory_context() as temp_dir:
                output_file = temp_dir / "strategy_test.csv"

                # Create pipeline
                pipeline = ETLPipeline(username="operator")
                pipeline.register_extractor("csv", CSVExtractor())
                pipeline.register_loader("file", FileLoader())

                # First run to create file
                result1 = pipeline.run(
                    extractor_name="csv",
                    source=str(temp_csv_file),
                    loader_name="file",
                    target=str(output_file),
                    strategy=LoadStrategy.REPLACE,
                )

                # Second run with specified strategy
                if strategy == LoadStrategy.FAIL:
                    # FAIL strategy should either raise error or return None when file exists
                    result2 = pipeline.run(
                        extractor_name="csv",
                        source=str(temp_csv_file),
                        loader_name="file",
                        target=str(output_file),
                        strategy=strategy,
                    )
                    # FAIL strategy should not succeed when file exists
                    # Either result is None or an exception was raised (caught by pipeline)
                    assert (
                        result2 is None
                    ), f"FAIL strategy should return None when file exists, got: {result2}"
                else:
                    # Other strategies should work
                    result2 = pipeline.run(
                        extractor_name="csv",
                        source=str(temp_csv_file),
                        loader_name="file",
                        target=str(output_file),
                        strategy=strategy,
                    )

                    assert result2 is not None

                    if strategy == LoadStrategy.APPEND:
                        # APPEND should double the rows
                        output_df = pd.read_csv(output_file)
                        assert len(output_df) == 6  # 3 original + 3 appended

                pipeline.shutdown()

    @pytest.mark.integration
    @pytest.mark.slow
    def test_pipeline_large_dataset(
        self, directory_context, large_dataframe, security_context
    ):
        """Test pipeline with large dataset."""
        # Use security context to set up environment variables
        with security_context(level="testing"):
            with directory_context() as temp_dir:
                # Create input CSV with large dataset
                input_file = temp_dir / "large_input.csv"
                large_dataframe.to_csv(input_file, index=False)

                output_file = temp_dir / "large_output.csv"

                # Create pipeline
                pipeline = ETLPipeline(username="operator")
                pipeline.register_extractor("csv", CSVExtractor())
                pipeline.register_loader("file", FileLoader())

                import time

                start_time = time.time()

                # Run pipeline
                result = pipeline.run(
                    extractor_name="csv",
                    source=str(input_file),
                    loader_name="file",
                    target=str(output_file),
                    strategy=LoadStrategy.REPLACE,
                )

                end_time = time.time()
                execution_time = end_time - start_time

                # Verify results
                assert result is not None
                assert len(result) == len(large_dataframe)
                assert output_file.exists()

                # Performance check
                print(
                    f"Processed {len(large_dataframe)} rows in {execution_time:.2f} seconds"
                )
                print(f"Rate: {len(large_dataframe) / execution_time:.0f} rows/second")

                # Should complete in reasonable time
                assert (
                    execution_time < 10.0
                ), f"Pipeline took {execution_time:.2f} seconds"

                pipeline.shutdown()

    @pytest.mark.integration
    def test_pipeline_error_handling(self, directory_context, security_context):
        """Test pipeline error handling with invalid inputs."""
        # Use security context to set up environment variables
        with security_context(level="testing"):
            with directory_context() as temp_dir:
                # Create pipeline
                pipeline = ETLPipeline(username="operator")
                pipeline.register_extractor("csv", CSVExtractor())
                pipeline.register_loader("file", FileLoader())

                # Test with non-existent file
                non_existent_file = temp_dir / "does_not_exist.csv"

                with pytest.raises(Exception):
                    pipeline.run(
                        extractor_name="csv",
                        source=str(non_existent_file),
                        loader_name="file",
                        target=temp_dir / "output.csv",
                        strategy=LoadStrategy.REPLACE,
                    )

                # Test with invalid file extension
                invalid_file = temp_dir / "invalid.txt"
                invalid_file.write_text("not a csv")

                with pytest.raises(ValueError, match="Invalid file extension"):
                    pipeline.run(
                        extractor_name="csv",
                        source=str(invalid_file),
                        loader_name="file",
                        target=temp_dir / "output.csv",
                        strategy=LoadStrategy.REPLACE,
                    )

                pipeline.shutdown()
