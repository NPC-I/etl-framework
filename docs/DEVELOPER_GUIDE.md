# ETL Framework Developer Guide

## 🏗️ Architecture Overview

### Core Architecture

```
ETL Framework Architecture:
┌─────────────────────────────────────────────────────┐
│                    ETLPipeline                       │
│  (Orchestrator with Security Integration)           │
├─────────────┬──────────────┬────────────────────────┤
│  Extractors │ Transformers │        Loaders         │
│  (Read)     │ (Process)    │       (Write)          │
├─────────────┼──────────────┼────────────────────────┤
│  CSV        │ DataCleaner  │       FileLoader       │
│  PDF        │ DataEnricher │       SQLLoader        │
│  Excel      │ MappingLoader│                        │
│  JSON       │ SecureJSON   │                        │
│             │ Calculator   │                        │
└─────────────┴──────────────┴────────────────────────┘
         │              │                  │
         ▼              ▼                  ▼
┌──────────────┬────────────────┬─────────────────────┐
│   Security   │  Configuration │      Utilities       │
│   Layer      │    Management  │                      │
├──────────────┼────────────────┼─────────────────────┤
│ • RBAC       │ • Environment  │ • Logging           │
│ • Encryption │   Variables    │ • Validation        │
│ • Audit      │ • JSON Mapping │ • Error Handling    │
│ • Validation │ • Settings     │                     │
└──────────────┴────────────────┴─────────────────────┘
```

### Design Principles

1. **Modularity**: Each component (extractor, transformer, loader) is independent
2. **Security First**: Security integrated at every layer
3. **JSON-Driven**: Business logic defined in configuration, not code
4. **Extensibility**: Easy to add new components via plugin architecture
5. **Performance**: Optimized for large datasets with batch processing
6. **Auditability**: Comprehensive logging and audit trails

## 🔧 Extending the Framework

### Creating a New Extractor

1. **Create the extractor class**:

```python
# plugins/extractors/custom_extractor.py
from etl_framework.core.extractor import Extractor
import pandas as pd
from typing import Any
from etl_framework.security.input_validator import InputValidator

class CustomExtractor(Extractor):
    """Custom extractor for specialized data sources."""

    def __init__(self, validator: InputValidator = None):
        self.validator = validator

    def extract(self, source: Any, **kwargs) -> pd.DataFrame:
        """
        Extract data from custom source.

        Args:
            source: Source data (file path, URL, etc.)
            **kwargs: Additional extraction parameters

        Returns:
            pandas DataFrame with extracted data
        """
        # Security: Validate source if validator provided
        if self.validator:
            validated_source = self.validator.validate_file_path(
                source, ['.custom'], "read"
            )
            source = str(validated_source)

        # Custom extraction logic
        data = self._parse_custom_format(source)

        # Security: Log extraction
        print(f"[Security] Extracted {len(data)} rows from {source}")

        return pd.DataFrame(data)

    def validate_source(self, source: Any) -> bool:
        """
        Validate if source can be processed by this extractor.

        Args:
            source: Source to validate

        Returns:
            True if source is valid, False otherwise
        """
        if self.validator:
            try:
                self.validator.validate_file_path(source, ['.custom'], "read")
                return True
            except ValueError:
                return False
        return str(source).endswith('.custom')

    def _parse_custom_format(self, source: str) -> list:
        """Parse custom file format."""
        # Implementation
        data = []
        with open(source, 'r') as f:
            for line in f:
                # Parse custom format
                parts = line.strip().split('|')
                data.append({
                    'id': parts[0],
                    'name': parts[1],
                    'value': float(parts[2])
                })
        return data

    def get_security_info(self) -> dict:
        """
        Get security information about this extractor.

        Returns:
            Dictionary with security information
        """
        return {
            'extractor_type': 'CustomExtractor',
            'has_validator': self.validator is not None,
            'validates_path': True,
            'validates_content': False,
            'supports_encryption': True
        }
```

2. **Register the extractor**:

```python
# __init__.py in plugins/extractors
from .custom_extractor import CustomExtractor

__all__ = ['CustomExtractor', ...]

# Package __init__.py
from etl_framework.plugins.extractors.custom_extractor import CustomExtractor
```

3. **Use the extractor**:

```python
from etl_framework.plugins.extractors.custom_extractor import CustomExtractor
from etl_framework.core.pipeline import ETLPipeline

pipeline = ETLPipeline(username="operator", enable_security=True)
pipeline.register_extractor("custom", CustomExtractor())

result = pipeline.run(
    extractor_name="custom",
    source="data/file.custom",
    loader_name="file",
    target="output.csv"
)
```

### Creating a New Transformer

```python
# plugins/transformers/custom_transformer.py
from etl_framework.core.transformer import Transformer
import pandas as pd
from typing import Dict, Any

class CustomTransformer(Transformer):
    """Custom transformer for specialized data processing."""

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Transform the DataFrame.

        Args:
            df: Input DataFrame

        Returns:
            Transformed DataFrame
        """
        df = df.copy()

        # Security: Log transformation
        print(f"[Security] Transforming {len(df)} rows")

        # Apply custom transformation
        if 'multiplier' in self.config:
            df['adjusted_value'] = df['value'] * self.config['multiplier']

        # Add metadata
        df['processed_by'] = 'CustomTransformer'
        df['processing_timestamp'] = pd.Timestamp.now()

        return df

    def get_configuration(self) -> Dict[str, Any]:
        """
        Get transformer configuration.

        Returns:
            Configuration dictionary
        """
        return self.config.copy()
```

### Creating a New Loader

```python
# plugins/loaders/custom_loader.py
from etl_framework.core.loader import Loader
from etl_framework.core.load_strategy import LoadStrategy, LoadOptions
import pandas as pd
from typing import List, Optional, Any

class CustomLoader(Loader):
    """Custom loader for specialized data destinations."""

    def __init__(self, connection_string: str = None, **kwargs):
        self.connection_string = connection_string
        self.kwargs = kwargs

    def load(self, df: pd.DataFrame, target: Any,
             strategy: LoadStrategy = LoadStrategy.REPLACE,
             key_columns: Optional[List[str]] = None,
             **loader_kwargs) -> bool:
        """
        Load DataFrame to custom destination.

        Args:
            df: DataFrame to load
            target: Target destination
            strategy: Loading strategy
            key_columns: Key columns for update/upsert
            **loader_kwargs: Additional loader arguments

        Returns:
            True if successful, False otherwise
        """
        # Security: Validate target
        print(f"[Security] Loading {len(df)} rows to {target}")

        try:
            # Implement loading logic based on strategy
            if strategy == LoadStrategy.REPLACE:
                success = self._load_replace(df, target)
            elif strategy == LoadStrategy.APPEND:
                success = self._load_append(df, target)
            elif strategy == LoadStrategy.UPDATE:
                success = self._load_update(df, target, key_columns)
            elif strategy == LoadStrategy.UPSERT:
                success = self._load_upsert(df, target, key_columns)
            elif strategy == LoadStrategy.FAIL:
                success = self._load_fail(df, target)
            else:
                raise ValueError(f"Unsupported strategy: {strategy}")

            # Security: Log result
            if success:
                print(f"[Security] Successfully loaded to {target}")
            else:
                print(f"[Security] Failed to load to {target}")

            return success

        except Exception as e:
            print(f"[Security Error] Load failed: {e}")
            return False

    def load_legacy(self, df: pd.DataFrame, target: Any) -> bool:
        """Legacy load method for backward compatibility."""
        return self.load(df, target, strategy=LoadStrategy.REPLACE)

    def _load_replace(self, df: pd.DataFrame, target: Any) -> bool:
        """Replace existing data."""
        # Implementation
        return True

    def _load_append(self, df: pd.DataFrame, target: Any) -> bool:
        """Append to existing data."""
        # Implementation
        return True

    def _load_update(self, df: pd.DataFrame, target: Any,
                    key_columns: List[str]) -> bool:
        """Update existing records."""
        # Implementation
        return True

    def _load_upsert(self, df: pd.DataFrame, target: Any,
                    key_columns: List[str]) -> bool:
        """Update existing + insert new records."""
        # Implementation
        return True

    def _load_fail(self, df: pd.DataFrame, target: Any) -> bool:
        """Fail if target exists."""
        # Implementation
        return True
```

## 🧪 Testing Framework

### Test Structure

```
tests/
├── unit/                    # Unit tests
│   ├── core/               # Core framework tests
│   ├── plugins/            # Plugin tests
│   ├── security/           # Security tests
│   └── utils/              # Utility tests
├── integration/            # Integration tests
│   ├── pipeline/           # Pipeline integration
│   ├── security/           # Security integration
│   └── database/           # Database integration
├── functional/             # Functional tests
│   ├── workflows/          # Business workflows
│   ├── security/           # Security workflows
│   └── performance/        # Performance tests
├── fixtures/               # Test fixtures
│   ├── data/              # Test data
│   ├── mocks/             # Mock objects
│   ├── config/            # Test configuration
│   └── helpers/           # Test helpers
├── conftest.py            # Pytest configuration
└── pytest.ini             # Pytest settings
```

### Writing Unit Tests

```python
# tests/unit/plugins/test_custom_extractor.py
import pytest
import pandas as pd
from pathlib import Path
import tempfile
from etl_framework.plugins.extractors.custom_extractor import CustomExtractor
from etl_framework.security.input_validator import InputValidator

class TestCustomExtractor:
    """Test suite for CustomExtractor."""

    @pytest.fixture
    def extractor(self):
        """Create extractor instance."""
        return CustomExtractor(validator=InputValidator())

    @pytest.fixture
    def sample_custom_file(self):
        """Create sample custom format file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.custom', delete=False) as f:
            f.write("1|Alice|100.0\n")
            f.write("2|Bob|200.0\n")
            f.write("3|Charlie|300.0\n")
            return Path(f.name)

    def test_extract_valid_file(self, extractor, sample_custom_file):
        """Test extraction from valid custom file."""
        df = extractor.extract(str(sample_custom_file))

        assert isinstance(df, pd.DataFrame)
        assert len(df) == 3
        assert list(df.columns) == ['id', 'name', 'value']
        assert df['value'].sum() == 600.0

    def test_validate_source_valid(self, extractor, sample_custom_file):
        """Test source validation with valid file."""
        assert extractor.validate_source(str(sample_custom_file)) is True

    def test_validate_source_invalid(self, extractor):
        """Test source validation with invalid file."""
        assert extractor.validate_source("invalid.txt") is False

    def test_security_info(self, extractor):
        """Test security information."""
        info = extractor.get_security_info()

        assert info['extractor_type'] == 'CustomExtractor'
        assert info['has_validator'] is True
        assert info['validates_path'] is True

    def test_extract_with_path_traversal(self, extractor):
        """Test extraction with path traversal attempt."""
        with pytest.raises(ValueError):
            extractor.extract("../../etc/passwd.custom")

    def teardown_method(self, method):
        """Clean up temporary files."""
        import os
        for file in Path('.').glob('*.custom'):
            try:
                os.unlink(file)
            except:
                pass
```

### Writing Integration Tests

```python
# tests/integration/pipeline/test_custom_pipeline.py
import pytest
import pandas as pd
from pathlib import Path
import tempfile
from etl_framework.core.pipeline import ETLPipeline
from etl_framework.plugins.extractors.custom_extractor import CustomExtractor
from etl_framework.plugins.loaders.file_loader import FileLoader

class TestCustomPipelineIntegration:
    """Integration tests for custom pipeline."""

    @pytest.fixture
    def pipeline(self):
        """Create pipeline with custom components."""
        pipeline = ETLPipeline(username="operator", enable_security=True)
        pipeline.register_extractor("custom", CustomExtractor())
        pipeline.register_loader("file", FileLoader())
        return pipeline

    @pytest.fixture
    def sample_data(self):
        """Create sample data file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.custom', delete=False) as f:
            f.write("1|Product A|50.0\n")
            f.write("2|Product B|75.0\n")
            f.write("3|Product C|100.0\n")
            return Path(f.name)

    def test_custom_pipeline_execution(self, pipeline, sample_data):
        """Test complete pipeline with custom components."""
        with tempfile.NamedTemporaryFile(suffix='.csv', delete=False) as output:
            output_path = Path(output.name)

        try:
            # Run pipeline
            result = pipeline.run(
                extractor_name="custom",
                source=str(sample_data),
                loader_name="file",
                target=str(output_path),
                strategy="replace"
            )

            # Verify results
            assert result is not None
            assert len(result) == 3
            assert output_path.exists()

            # Verify output file
            output_df = pd.read_csv(output_path)
            assert len(output_df) == 3
            assert 'id' in output_df.columns
            assert 'name' in output_df.columns
            assert 'value' in output_df.columns

        finally:
            # Cleanup
            import os
            if output_path.exists():
                os.unlink(output_path)
            if sample_data.exists():
                os.unlink(sample_data)

    def test_pipeline_with_security(self, pipeline, sample_data):
        """Test pipeline with security features enabled."""
        # Verify security components are initialized
        assert pipeline.enable_security is True
        assert pipeline.username == "operator"
        assert pipeline.security_config is not None
        assert pipeline.audit_logger is not None
        assert pipeline.access_controller is not None
```

### Writing Security Tests

```python
# tests/unit/security/test_custom_security.py
import pytest
import os
from etl_framework.security.encryption import DataEncryptor
from etl_framework.security.access_control import AccessController, Role, Operation

class TestCustomSecurity:
    """Security tests for custom components."""

    def test_encryption_with_custom_data(self):
        """Test encryption with custom data formats."""
        os.environ['ETL_ENCRYPTION_KEY'] = 'test-key-12345'

        encryptor = DataEncryptor()

        # Test custom data encryption
        custom_data = {
            'customer_code': 'CUST-001',
            'internal_id': 'INT-2024-001',
            'secret_token': 'tok_sec_abc123'
        }

        # Encrypt sensitive fields
        encrypted_token = encryptor.encrypt_value(custom_data['secret_token'])
        decrypted_token = encryptor.decrypt_value(encrypted_token)

        assert decrypted_token == custom_data['secret_token']
        assert encrypted_token != custom_data['secret_token']

    def test_access_control_custom_roles(self):
        """Test access control with custom roles."""
        controller = AccessController()

        # Add custom user with specific roles
        controller.add_user("custom_user", [Role.OPERATOR, Role.DATA_STEWARD])

        # Test permissions
        assert controller.check_permission("custom_user", Operation.EXECUTE_PIPELINE)
        assert controller.check_permission("custom_user", Operation.VIEW_SENSITIVE_DATA)
        assert not controller.check_permission("custom_user", Operation.MANAGE_USERS)

    def test_input_validation_custom_patterns(self):
        """Test input validation with custom patterns."""
        from etl_framework.security.input_validator import InputValidator

        validator = InputValidator(security_level="production")

        # Test custom identifier validation
        custom_identifiers = [
            ('custom_table_2024', True, 'Valid custom table name'),
            ('custom-table', False, 'Hyphen not allowed'),
            ('2024_table', False, 'Starts with number'),
            ('table; DROP', False, 'SQL injection attempt'),
        ]

        for identifier, expected_valid, description in custom_identifiers:
            is_valid = validator.validate_sql_identifier(identifier)
            assert is_valid == expected_valid, f"{description}: {identifier}"
```

## 🏭 Development Environment Setup

### Local Development

```bash
# Clone repository
git clone <repository-url>
cd etl-framework

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install development dependencies
pip install -e .[test,dev,security,all]

# Install pre-commit hooks
pre-commit install

# Run tests
pytest tests/ -v

# Run security checks
bandit -r src/
safety check
pip-audit
```

### Development Dependencies

The project uses several development tools:

```toml
# In pyproject.toml (optional dependencies)
[project.optional-dependencies]
test = [
    "pytest>=7.0.0",
    "pytest-cov>=4.0.0",
    "pytest-xdist>=3.0.0",
    "pytest-html>=3.0.0",
]

dev = [
    "black>=23.0.0",
    "isort>=5.12.0",
    "flake8>=6.0.0",
    "mypy>=1.0.0",
    "pre-commit>=3.0.0",
]

security = [
    "bandit>=1.7.0",
    "safety>=2.0.0",
    "pip-audit>=2.10.0",
]
```

### Pre-commit Configuration

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.4.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-added-large-files
      - id: check-merge-conflict

  - repo: https://github.com/psf/black
    rev: 23.9.1
    hooks:
      - id: black
        language_version: python3

  - repo: https://github.com/PyCQA/isort
    rev: 5.12.0
    hooks:
      - id: isort
        args: ["--profile", "black"]

  - repo: https://github.com/PyCQA/flake8
    rev: 6.1.0
    hooks:
      - id: flake8
        args: ["--max-line-length=88", "--extend-ignore=E203,W503"]

  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.5.1
    hooks:
      - id: mypy
        args: [--ignore-missing-imports]
        additional_dependencies: [types-all]

  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.5
    hooks:
      - id: bandit
        args: ["-r", "src/", "-ll"]
```

## 📦 Packaging and Distribution

### Building the Package

```bash
# Build distribution packages
python -m build

# Build wheel only
python -m build --wheel

# Build source distribution only
python -m build --sdist

# Check package metadata
twine check dist/*
```

### PyPI Publication

```bash
# Test upload to TestPyPI
twine upload --repository testpypi dist/*

# Upload to PyPI
twine upload dist/*
```

### Version Management

The project uses semantic versioning:

- **Major version (1.x.x)**: Breaking changes, major features
- **Minor version (x.1.x)**: New features, backward compatible
- **Patch version (x.x.1)**: Bug fixes, security patches

Update version in `pyproject.toml`:

```toml
[project]
version = "1.0.0"  # Update for releases
```

## 🔍 Code Quality

### Code Style

The project follows Black code style with 88 character line length:

```bash
# Format code
black src/ tests/ examples/

# Check formatting
black --check src/ tests/ examples/

# Sort imports
isort src/ tests/ examples/
```

### Type Checking

```bash
# Run mypy type checking
mypy src/

# Check specific module
mypy src/etl_framework/core/

# Generate type coverage report
mypy --cobertura-xml-report . src/
```

### Linting

```bash
# Run flake8
flake8 src/ tests/ examples/

# Run bandit for security
bandit -r src/ -f json -o bandit-report.json

# Run safety for dependency checks
safety check --json > safety-report.json
```

## 🧪 Testing Strategy

### Test Categories

1. **Unit Tests**: Test individual components in isolation
2. **Integration Tests**: Test component interactions
3. **Functional Tests**: Test complete business workflows
4. **Security Tests**: Test security features
5. **Performance Tests**: Test performance and scalability

### Running Tests

```bash
# Run all tests
pytest tests/

# Run specific test category
pytest tests/unit/ -v
pytest tests/integration/ -v
pytest tests/functional/ -v
pytest tests/unit/security/ -v

# Run with coverage
pytest --cov=src --cov-report=html --cov-report=term-missing

# Run specific test file
pytest tests/unit/core/test_pipeline.py -v

# Run specific test method
pytest tests/unit/core/test_pipeline.py::TestETLPipeline::test_initialization -v
```

### Test Configuration

```ini
# pytest.ini
[pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts = -v --strict-markers
markers =
    unit: Unit tests
    integration: Integration tests
    functional: Functional tests
    security: Security tests
    performance: Performance tests
    slow: Slow-running tests
    database: Database tests
```

## 🔒 Security Development

### Security Review Process

1. **Code Review**: All code changes require security review
2. **Dependency Scanning**: Regular scanning with `pip-audit` and `safety`
3. **Security Testing**: Comprehensive security test suite
4. **Audit Logging**: All security-relevant events logged
5. **Input Validation**: Validate all inputs before processing

### Security Best Practices for Developers

1. **Never trust user input**: Always validate and sanitize
2. **Use prepared statements**: For database operations
3. **Encrypt sensitive data**: At rest and in transit
4. **Follow principle of least privilege**: Minimum necessary permissions
5. **Log security events**: Comprehensive audit trail
6. **Keep dependencies updated**: Regular security updates

### Security Testing

```bash
# Run security tests
pytest tests/unit/security/ -v

# Run security demonstration
python examples/security_demo.py

# Run security scans
bandit -r src/ -f json
safety check
pip-audit

# Generate security report
python scripts/generate_security_report.py
```

## 📚 Documentation

### Documentation Structure

```
docs/
├── INDEX.md              # Main documentation index
├── GETTING_STARTED.md    # Installation and setup
├── USER_GUIDE.md         # User guide and examples
├── SECURITY_GUIDE.md     # Security features and configuration
├── API_REFERENCE.md      # API documentation
├── EXAMPLES.md           # Code examples
├── DEVELOPER_GUIDE.md    # Developer guide (this file)
└── CHANGELOG.md          # Release notes
```

### Writing Documentation

1. **Use Markdown**: All documentation in Markdown format
2. **Include examples**: Code examples for all features
3. **Document security**: Security considerations for each feature
4. **Keep updated**: Update documentation with code changes
5. **Test examples**: Ensure code examples work

### Generating Documentation

```bash
# Check documentation links
python scripts/check_docs.py

# Generate API documentation
python scripts/generate_api_docs.py

# Validate examples
python scripts/validate_examples.py
```

## 🔄 Continuous Integration

### GitHub Actions Workflow

```yaml
# .github/workflows/test.yml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.8", "3.9", "3.10", "3.11", "3.12"]

    steps:
    - uses: actions/checkout@v3

    - name: Set up Python ${{ matrix.python-version }}
      uses: actions/setup-python@v4
      with:
        python-version: ${{ matrix.python-version }}

    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -e .[test,dev,security]

    - name: Run pre-commit
      run: pre-commit run --all-files

    - name: Run tests
      run: pytest tests/ --cov=src --cov-report=xml

    - name: Run security checks
      run: |
        bandit -r src/ -f json
        safety check
        pip-audit

    - name: Upload coverage
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage.xml
```

### Release Workflow

```yaml
# .github/workflows/release.yml
name: Release

on:
  release:
    types: [published]

jobs:
  build-and-publish:
    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v3

    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: "3.11"

    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install build twine

    - name: Build package
      run: python -m build

    - name: Check package
      run: twine check dist/*

    - name: Publish to PyPI
      env:
        TWINE_USERNAME: __token__
        TWINE_PASSWORD: ${{ secrets.PYPI_API_TOKEN }}
      run: twine upload dist/*
```

## 🐛 Debugging

### Common Issues

1. **Import errors**: Check PYTHONPATH and virtual environment
2. **Security errors**: Check environment variables and configuration
3. **Database errors**: Check connection strings and permissions
4. **Performance issues**: Check batch sizes and indexing

### Debugging Tools

```python
# Enable debug logging
import logging
logging.basicConfig(level=logging.DEBUG)

# Debug pipeline execution
pipeline = ETLPipeline(username="debug", enable_security=True)
pipeline.audit_logger.logger.setLevel(logging.DEBUG)

# Debug security components
from etl_framework.security.config import SecurityConfig
config = SecurityConfig.from_environment()
print(config.to_dict())
```

### Profiling

```python
# Profile pipeline execution
import cProfile
import pstats
from etl_framework.core.pipeline import ETLPipeline

def run_pipeline():
    pipeline = ETLPipeline(username="operator", enable_security=True)
    # ... setup pipeline ...
    return pipeline.run(...)

# Run profiler
profiler = cProfile.Profile()
profiler.enable()
result = run_pipeline()
profiler.disable()

# Print stats
stats = pstats.Stats(profiler)
stats.sort_stats('cumulative')
stats.print_stats(20)
```

## 🤝 Contributing

### Contribution Guidelines

1. **Fork the repository**: Create your own fork
2. **Create a branch**: Use descriptive branch names
3. **Write tests**: Include tests for new features
4. **Follow code style**: Use Black and isort
5. **Update documentation**: Update relevant documentation
6. **Submit pull request**: With clear description

### Pull Request Template

```markdown
## Description
Brief description of the changes

## Related Issues
Fixes # (issue number)

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update
- [ ] Security fix

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Security tests added/updated
- [ ] All tests pass

## Security Considerations
- [ ] Input validation updated
- [ ] Security tests updated
- [ ] Audit logging updated
- [ ] Documentation updated

## Checklist
- [ ] Code follows style guidelines
- [ ] Documentation updated
- [ ] Tests added/updated
- [ ] Security considerations addressed
```

### Code Review Process

1. **Automated checks**: CI/CD pipeline runs tests and checks
2. **Security review**: Security team reviews security implications
3. **Code review**: At least one maintainer reviews code
4. **Documentation review**: Documentation updated appropriately
5. **Merge approval**: Approved by maintainer

## 📈 Performance Optimization

### Performance Tips

1. **Use appropriate batch sizes**: Adjust based on data size and database
2. **Disable unnecessary features**: For performance-critical operations
3. **Use efficient file formats**: Parquet for analytics, Feather for speed
4. **Optimize database operations**: Use indexes, appropriate data types
5. **Monitor memory usage**: Process large datasets in chunks

### Performance Testing

```python
# performance_test.py
import time
import pandas as pd
from etl_framework.core.pipeline import ETLPipeline

def benchmark_pipeline(data_size, enable_security=True):
    """Benchmark pipeline performance."""
    # Create test data
    data = pd.DataFrame({
        'id': range(data_size),
        'value': [f'value_{i}' for i in range(data_size)]
    })

    # Setup pipeline
    pipeline = ETLPipeline(
        username="operator",
        enable_security=enable_security
    )

    # Run benchmark
    start = time.time()
    # ... run pipeline ...
    end = time.time()

    return end - start

# Run benchmarks
for size in [1000, 10000, 100000]:
    time_with = benchmark_pipeline(size, enable_security=True)
    time_without = benchmark_pipeline(size, enable_security=False)
    print(f"Size: {size:,}, With security: {time_with:.2f}s, "
          f"Without: {time_without:.2f}s, "
          f"Overhead: {(time_with/time_without - 1)*100:.1f}%")
```

## 🔮 Future Development

### Planned Features

1. **Streaming support**: Real-time data processing
2. **Cloud integration**: AWS, Azure, GCP services
3. **Advanced monitoring**: Prometheus metrics, Grafana dashboards
4. **Workflow orchestration**: DAG-based pipeline scheduling
5. **Machine learning integration**: ML model deployment and scoring

### Roadmap

- **Q1 2024**: Streaming support beta
- **Q2 2024**: Cloud integration v1
- **Q3 2024**: Advanced monitoring
- **Q4 2024**: Workflow orchestration

## 📞 Support

### Getting Help

1. **Documentation**: Check the documentation first
2. **GitHub Issues**: Report bugs and request features
3. **Security Issues**: Contact security@npc-it.co.uk
4. **Community**: Join the community forum (if available)

### Reporting Issues

When reporting issues, include:

1. **Version information**: Framework version, Python version
2. **Error messages**: Complete error traceback
3. **Configuration**: Relevant configuration files
4. **Steps to reproduce**: Clear reproduction steps
5. **Expected behavior**: What you expected to happen

### Security Reporting

For security vulnerabilities:

1. **Do not disclose publicly**: Use private channels
2. **Contact security team**: security@npc-it.co.uk
3. **Provide details**: Vulnerability description, impact, reproduction steps
4. **Follow responsible disclosure**: Allow time for fix before disclosure

---

This developer guide provides comprehensive information for extending and contributing to the ETL Framework. For additional help, refer to the [API Reference](API_REFERENCE.md) and [Examples](EXAMPLES.md).
