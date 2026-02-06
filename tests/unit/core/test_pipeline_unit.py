"""
Unit tests for ETLPipeline (isolated, fast tests).
"""
from unittest.mock import Mock

import pytest

from etl_framework.core.load_strategy import LoadStrategy
from etl_framework.core.pipeline import ETLPipeline


class TestETLPipelineUnit:
    """Unit tests for ETLPipeline using mocks and fixtures."""

    @pytest.mark.unit
    def test_pipeline_initialization(self, mock_extractor, mock_loader):
        """Test pipeline initialization with mock components."""
        # Disable security for unit tests to avoid file validation
        pipeline = ETLPipeline(username="admin", enable_security=False)

        # Register mock components
        pipeline.register_extractor("mock_extractor", mock_extractor)
        pipeline.register_loader("mock_loader", mock_loader)

        assert "mock_extractor" in pipeline.extractors
        assert "mock_loader" in pipeline.loaders
        assert len(pipeline.transformers) == 0

    @pytest.mark.unit
    def test_add_transformer(self, mock_transformer):
        """Test adding transformers to pipeline."""
        pipeline = ETLPipeline(username="operator")

        # Add transformer
        pipeline.add_transformer(mock_transformer)

        assert len(pipeline.transformers) == 1
        assert pipeline.transformers[0] == mock_transformer

    @pytest.mark.unit
    def test_pipeline_run_with_mocks(
        self, mock_extractor, mock_loader, mock_transformer
    ):
        """Test pipeline execution with mock components."""
        # Disable security for unit tests to avoid file validation
        pipeline = ETLPipeline(username="admin", enable_security=False)

        # Register all components
        pipeline.register_extractor("mock", mock_extractor)
        pipeline.add_transformer(mock_transformer)
        pipeline.register_loader("mock", mock_loader)

        # Run pipeline
        result = pipeline.run(
            extractor_name="mock",
            source="test.csv",
            loader_name="mock",
            target="output.csv",
            strategy=LoadStrategy.REPLACE,
        )

        # Verify mocks were called
        mock_extractor.extract.assert_called_once_with("test.csv")
        mock_transformer.transform.assert_called_once()
        mock_loader.load.assert_called_once()

        # Verify result
        assert result is not None

    @pytest.mark.unit
    def test_pipeline_security_disabled(self):
        """Test pipeline with security disabled."""
        pipeline = ETLPipeline(username="test_user", enable_security=False)

        assert pipeline.username == "test_user"
        assert pipeline.enable_security == False
        assert pipeline.audit_logger is None
        assert pipeline.access_controller is None

    @pytest.mark.unit
    @pytest.mark.parametrize("username", ["admin", "operator", "viewer"])
    def test_pipeline_with_different_users(self, username):
        """Test pipeline initialization with different users."""
        pipeline = ETLPipeline(username=username, enable_security=True)

        assert pipeline.username == username
        assert pipeline.enable_security == True

    @pytest.mark.unit
    def test_pipeline_missing_extractor_error(self, mock_loader):
        """Test error when extractor is not registered."""
        # Disable security for unit tests to avoid file validation
        pipeline = ETLPipeline(username="admin", enable_security=False)
        pipeline.register_loader("mock", mock_loader)

        # Should raise error when extractor not found
        with pytest.raises(ValueError, match="Extractor 'missing' not registered"):
            pipeline.run("missing", "source.csv", "mock", "output.csv")

    @pytest.mark.unit
    def test_pipeline_missing_loader_error(self, mock_extractor):
        """Test error when loader is not registered."""
        # Disable security for unit tests to avoid file validation
        pipeline = ETLPipeline(username="admin", enable_security=False)
        pipeline.register_extractor("mock", mock_extractor)

        # Should raise error when loader not found
        with pytest.raises(ValueError, match="Loader 'missing' not registered"):
            pipeline.run("mock", "source.csv", "missing", "output.csv")

    @pytest.mark.unit
    def test_pipeline_shutdown(self, mock_extractor, mock_loader):
        """Test pipeline shutdown method."""
        pipeline = ETLPipeline(username="admin", enable_security=True)
        pipeline.register_extractor("mock", mock_extractor)
        pipeline.register_loader("mock", mock_loader)

        # Shutdown should not raise errors
        pipeline.shutdown()

        # Verify pipeline can still be used after shutdown
        assert "mock" in pipeline.extractors
        assert "mock" in pipeline.loaders

    @pytest.mark.unit
    def test_pipeline_with_multiple_transformers(self, mock_transformer):
        """Test pipeline with multiple transformers."""
        pipeline = ETLPipeline(username="operator")

        # Create multiple mock transformers
        transformer1 = Mock()
        transformer1.transform.return_value = "transformed1"

        transformer2 = Mock()
        transformer2.transform.return_value = "transformed2"

        # Add transformers
        pipeline.add_transformer(transformer1)
        pipeline.add_transformer(transformer2)

        assert len(pipeline.transformers) == 2
        assert pipeline.transformers[0] == transformer1
        assert pipeline.transformers[1] == transformer2

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "strategy",
        [
            LoadStrategy.REPLACE,
            LoadStrategy.APPEND,
            LoadStrategy.UPDATE,
            LoadStrategy.UPSERT,
            LoadStrategy.FAIL,
        ],
    )
    def test_pipeline_with_different_strategies(
        self, mock_extractor, mock_loader, strategy
    ):
        """Test pipeline with different loading strategies."""
        # Disable security for unit tests to avoid file validation
        pipeline = ETLPipeline(username="admin", enable_security=False)
        pipeline.register_extractor("mock", mock_extractor)
        pipeline.register_loader("mock", mock_loader)

        # Mock loader to accept strategy parameter
        mock_loader.load.return_value = True

        result = pipeline.run(
            extractor_name="mock",
            source="test.csv",
            loader_name="mock",
            target="output.csv",
            strategy=strategy,
        )

        # Verify loader was called with correct strategy
        mock_loader.load.assert_called_once()
        call_kwargs = mock_loader.load.call_args[1]
        assert call_kwargs.get("strategy") == strategy

        assert result is not None
