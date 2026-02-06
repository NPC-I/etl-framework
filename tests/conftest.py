"""
Root test configuration with all fixtures.
"""
pytest_plugins = [
    "tests.fixtures.data.test_data_factory",
    "tests.fixtures.mocks.mock_factory",
    "tests.fixtures.config.environment",
    "tests.fixtures.helpers.test_helpers",
]

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, Generator

import pandas as pd
import pytest

from tests.fixtures.config.environment import TestEnvironment

# Import our fixture modules
from tests.fixtures.data.test_data_factory import TestDataFactory
from tests.fixtures.helpers.test_helpers import TestHelpers
from tests.fixtures.mocks.mock_factory import MockFactory

# ===== Data Fixtures =====


@pytest.fixture
def sample_dataframe() -> pd.DataFrame:
    """Create a sample DataFrame for testing."""
    return TestDataFactory.create_sample_dataframe(rows=5)


@pytest.fixture
def sensitive_dataframe() -> pd.DataFrame:
    """Create a DataFrame with sensitive data for testing."""
    return TestDataFactory.create_sample_dataframe(rows=5, include_sensitive=True)


@pytest.fixture
def roller_door_dataframe() -> pd.DataFrame:
    """Create a roller door specific DataFrame."""
    return TestDataFactory.create_roller_door_dataframe(rows=10)


@pytest.fixture
def large_dataframe() -> pd.DataFrame:
    """Create a large DataFrame for performance testing."""
    return TestDataFactory.create_large_dataset(rows=1000)


@pytest.fixture
def mapping_config() -> Dict[str, Any]:
    """Create a mapping configuration for testing."""
    return TestDataFactory.create_mapping_config()


@pytest.fixture
def temp_mapping_file(mapping_config) -> Generator[Path, None, None]:
    """Create a temporary mapping file."""
    temp_file = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    json.dump(mapping_config, temp_file)
    temp_file.close()

    yield Path(temp_file.name)

    # Cleanup
    if os.path.exists(temp_file.name):
        os.unlink(temp_file.name)


@pytest.fixture
def temp_csv_file() -> Generator[Path, None, None]:
    """Create a temporary CSV file."""
    temp_file = tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False)
    temp_file.write("id,name,value\n1,Test,100.5\n2,Example,200.3\n3,Sample,300.7")
    temp_file.close()

    yield Path(temp_file.name)

    # Cleanup
    if os.path.exists(temp_file.name):
        os.unlink(temp_file.name)


# ===== Mock Fixtures =====


@pytest.fixture
def mock_extractor():
    """Create a mock extractor."""
    return MockFactory.create_mock_extractor()


@pytest.fixture
def mock_transformer():
    """Create a mock transformer."""
    return MockFactory.create_mock_transformer()


@pytest.fixture
def mock_loader():
    """Create a mock loader."""
    return MockFactory.create_mock_loader()


@pytest.fixture
def mock_pipeline():
    """Create a mock pipeline."""
    return MockFactory.create_mock_pipeline()


@pytest.fixture
def mock_security_config():
    """Create a mock security configuration."""
    return MockFactory.create_mock_security_config()


@pytest.fixture
def mock_access_controller():
    """Create a mock access controller."""
    return MockFactory.create_mock_access_controller()


# ===== Environment Fixtures =====


@pytest.fixture
def test_environment():
    """Provide access to test environment utilities."""
    return TestEnvironment


@pytest.fixture
def security_context():
    """Context manager for security testing environment."""
    return TestEnvironment.security_context


@pytest.fixture
def database_context():
    """Context manager for database testing environment."""
    return TestEnvironment.database_context


@pytest.fixture
def file_context():
    """Context manager for temporary file creation."""
    return TestEnvironment.file_context


@pytest.fixture
def directory_context():
    """Context manager for temporary directory creation."""
    return TestEnvironment.directory_context


@pytest.fixture(params=["development", "testing", "staging", "production"])
def security_level(request):
    """Parameterized fixture for security levels."""
    return request.param


@pytest.fixture(params=[10, 100, 1000])
def dataset_size(request):
    """Parameterized fixture for dataset sizes."""
    return request.param


# ===== Helper Fixtures =====


@pytest.fixture
def test_helpers():
    """Provide access to test helper utilities."""
    return TestHelpers


@pytest.fixture
def assert_dataframes_equal():
    """Fixture for DataFrame equality assertion."""
    return TestHelpers.assert_dataframes_equal


@pytest.fixture
def capture_output():
    """Fixture for capturing output."""
    return TestHelpers.capture_output


@pytest.fixture
def time_execution():
    """Fixture for timing execution."""
    return TestHelpers.time_execution


# ===== Integration Test Fixtures =====


@pytest.fixture
def csv_extractor():
    """Create a real CSV extractor for integration tests."""
    from etl_framework.plugins.extractors.csv_extractor import CSVExtractor

    return CSVExtractor()


@pytest.fixture
def file_loader():
    """Create a real file loader for integration tests."""
    from etl_framework.plugins.loaders.file_loader import FileLoader

    return FileLoader()


@pytest.fixture
def data_cleaner():
    """Create a real data cleaner for integration tests."""
    from etl_framework.plugins.transformers.cleaner import DataCleaner

    return DataCleaner(column_mapping={})


@pytest.fixture
def secure_pipeline():
    """Create a secure pipeline for integration tests."""
    from etl_framework.core.pipeline import ETLPipeline

    return ETLPipeline(username="admin", enable_security=True)


# ===== Security Test Fixtures =====


@pytest.fixture
def encryptor_fixture():
    """Create an encryptor for security tests."""
    from etl_framework.security.encryption import DataEncryptor

    # Set encryption key in environment
    os.environ["ETL_ENCRYPTION_KEY"] = "test-encryption-key-12345"
    return DataEncryptor()


@pytest.fixture
def input_validator_fixture():
    """Create an input validator for security tests."""
    from etl_framework.security.input_validator import InputValidator

    return InputValidator()


@pytest.fixture
def audit_logger_fixture():
    """Create an audit logger for security tests."""
    from etl_framework.security.audit_logger import AuditLogger

    with tempfile.NamedTemporaryFile(suffix=".log") as f:
        return AuditLogger(f.name)


# ===== Test Configuration =====


def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line("markers", "unit: Unit tests (fast, isolated)")
    config.addinivalue_line("markers", "integration: Integration tests")
    config.addinivalue_line("markers", "functional: Functional/end-to-end tests")
    config.addinivalue_line("markers", "security: Security-related tests")
    config.addinivalue_line("markers", "performance: Performance tests")
    config.addinivalue_line("markers", "slow: Slow-running tests")
    config.addinivalue_line("markers", "database: Database tests")


def pytest_collection_modifyitems(config, items):
    """Modify test items based on markers."""
    # Skip slow tests unless explicitly requested
    if not config.getoption("--run-slow"):
        skip_slow = pytest.mark.skip(reason="need --run-slow option to run")
        for item in items:
            if "slow" in item.keywords:
                item.add_marker(skip_slow)

    # Skip performance tests unless explicitly requested
    if not config.getoption("--run-performance"):
        skip_perf = pytest.mark.skip(reason="need --run-performance option to run")
        for item in items:
            if "performance" in item.keywords:
                item.add_marker(skip_perf)


def pytest_addoption(parser):
    """Add custom command line options."""
    parser.addoption(
        "--run-slow", action="store_true", default=False, help="Run slow tests"
    )
    parser.addoption(
        "--run-performance",
        action="store_true",
        default=False,
        help="Run performance tests",
    )
    parser.addoption(
        "--test-scenario",
        action="store",
        default=None,
        help="Run specific test scenario",
    )
