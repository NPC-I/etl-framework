# ETL Framework API Reference

## 📚 Core API

### ETLPipeline Class

The main pipeline orchestrator with security integration.

```python
from etl_framework.core.pipeline import ETLPipeline
from etl_framework.core.load_strategy import LoadStrategy, LoadOptions

# Initialize pipeline with security
pipeline = ETLPipeline(username="operator", enable_security=True)

# Register components
pipeline.register_extractor("csv", CSVExtractor())
pipeline.register_loader("file", FileLoader())

# Add transformers (executed in order)
pipeline.add_transformer(DataCleaner())
pipeline.add_transformer(MappingLoader("mapping.json"))

# Run pipeline
result = pipeline.run(
    extractor_name="csv",
    source="input.csv",
    loader_name="file",
    target="output.csv",
    strategy=LoadStrategy.UPSERT,
    key_columns=["id", "date"]
)

# Run with LoadOptions
options = LoadOptions(
    strategy=LoadStrategy.UPSERT,
    key_columns=["id", "date"],
    batch_size=1000,
    create_index=True
)
result = pipeline.run_with_options(
    extractor_name="csv",
    source="input.csv",
    loader_name="file",
    target="output.csv",
    options=options
)
```

#### Constructor Parameters
- `username` (str): User executing the pipeline (for audit logging)
- `enable_security` (bool): Whether to enable security features (default: True)

#### Methods
- `register_extractor(name, extractor)`: Register an extractor
- `add_transformer(transformer)`: Add a transformer to the pipeline
- `register_loader(name, loader)`: Register a loader
- `run(...)`: Execute the complete ETL pipeline
- `run_with_options(...)`: Execute pipeline with LoadOptions
- `run_legacy(...)`: Legacy run method for backward compatibility
- `shutdown()`: Shutdown pipeline and security components

### LoadStrategy Enum

```python
from etl_framework.core.load_strategy import LoadStrategy

# Available strategies
LoadStrategy.FAIL        # Fail if target exists
LoadStrategy.REPLACE     # Replace existing data (default)
LoadStrategy.APPEND      # Append to existing data
LoadStrategy.UPDATE      # Update existing records only
LoadStrategy.UPSERT      # Update existing + insert new

# Convert from string
strategy = LoadStrategy.from_string("upsert")  # Returns LoadStrategy.UPSERT
```

### LoadOptions Class

```python
from etl_framework.core.load_strategy import LoadOptions, LoadStrategy

options = LoadOptions(
    strategy=LoadStrategy.UPSERT,
    key_columns=["id", "date"],
    batch_size=1000,
    chunk_size=500,
    create_index=True,
    drop_duplicates=True,
    extra_options={"if_exists": "append"}
)
```

## 🔌 Plugin API

### Extractor Base Class

```python
from etl_framework.core.extractor import Extractor
import pandas as pd

class CustomExtractor(Extractor):
    def extract(self, source, **kwargs) -> pd.DataFrame:
        """Extract data from source."""
        # Implementation
        return pd.DataFrame()

    def validate_source(self, source) -> bool:
        """Validate if source can be processed by this extractor."""
        return True
```

### Transformer Base Class

```python
from etl_framework.core.transformer import Transformer
import pandas as pd

class CustomTransformer(Transformer):
    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Transform the DataFrame."""
        # Implementation
        return df
```

### Loader Base Class

```python
from etl_framework.core.loader import Loader
import pandas as pd

class CustomLoader(Loader):
    def load(self, df: pd.DataFrame, target, **kwargs) -> bool:
        """Load DataFrame to target."""
        # Implementation
        return True
```

## 🛡️ Security API

### AccessController

```python
from etl_framework.security.access_control import AccessController, Role, Operation

# Initialize
controller = AccessController()

# Check permissions
has_permission = controller.check_permission(
    username="operator",
    operation=Operation.EXECUTE_PIPELINE,
    resource="sales_data"
)

# Add/remove users
controller.add_user("new_user", [Role.OPERATOR])
controller.remove_user("old_user")

# List users
users = controller.list_users()

# Decorator for permission checking
@controller.require_permission("operator", Operation.EXECUTE_PIPELINE)
def run_pipeline():
    pass
```

### DataEncryptor

```python
from etl_framework.security.encryption import DataEncryptor
import pandas as pd

# Initialize (uses ETL_ENCRYPTION_KEY from environment)
encryptor = DataEncryptor()

# Encrypt/decrypt DataFrames
encrypted_df = encryptor.encrypt_dataframe(df)
decrypted_df = encryptor.decrypt_column(encrypted_df, "ssn")

# Encrypt/decrypt single values
encrypted = encryptor.encrypt_value("sensitive-data")
decrypted = encryptor.decrypt_value(encrypted)

# Identify sensitive columns
sensitive_cols = encryptor._identify_sensitive_columns(df)
```

### InputValidator

```python
from etl_framework.security.input_validator import InputValidator

# Initialize with security level
validator = InputValidator(security_level="production")

# Validate SQL identifiers
is_valid = validator.validate_sql_identifier("users_table")

# Validate formulas
validated_formula = validator.validate_formula("price * quantity", trusted_source=True)

# Validate file paths
path = validator.validate_file_path(
    "data/orders.csv",
    allowed_extensions=['.csv', '.xlsx'],
    operation="read"
)

# Validate JSON files
data = validator.validate_json_file("config/mapping.json", max_size_mb=10)

# Validate JSON strings
data = validator.validate_json_string('{"key": "value"}', max_length=10000)

# Sanitize strings
sanitized = validator.sanitize_string("<script>alert('xss')</script>")

# Validate emails
is_valid_email = validator.validate_email("user@example.com")

# Get validation summary
summary = validator.get_validation_summary()
```

### AuditLogger

```python
from etl_framework.security.audit_logger import AuditLogger, AuditEventType

# Initialize logger
logger = AuditLogger(log_file="./logs/audit.log")

# Log various events
logger.log_event(
    AuditEventType.USER_LOGIN,
    "admin",
    {"method": "password", "ip": "192.168.1.100"},
    True
)

logger.log_pipeline_execution(
    user="operator",
    pipeline_name="sales_etl",
    source="sales.csv",
    target="database.sales",
    rows_processed=1500,
    success=True,
    error_message=None
)

logger.log_data_access(
    user="viewer",
    resource="customer_data",
    operation="read",
    filters={"status": "active"}
)

logger.log_permission_denied(
    user="viewer",
    operation="write_config",
    resource="production_config.json"
)

logger.log_security_event(
    user="operator",
    event="Multiple failed login attempts",
    severity="high",
    details={"attempts": 5, "ip_address": "192.168.1.100"}
)

# Retrieve logs
logs = logger.get_recent_logs(limit=100)
search_results = logger.search_logs({"user": "operator", "success": True})
```

### SecurityConfig

```python
from etl_framework.security.config import SecurityConfig, SecurityLevel

# Create from environment
config = SecurityConfig.from_environment()

# Or create manually
config = SecurityConfig(
    security_level=SecurityLevel.PRODUCTION,
    encryption_enabled=True,
    rbac_enabled=True,
    audit_logging_enabled=True,
    max_file_size_mb=100,
    allowed_ip_ranges=["192.168.1.0/24"]
)

# Validate configuration
errors = config.validate()

# Check properties
is_production = config.is_production()
should_encrypt = config.should_encrypt()
should_log_audit = config.should_log_audit()
validation_level = config.get_validation_level()
access_control_level = config.get_access_control_level()
show_error_details = config.should_show_error_details()

# Get restrictions based on security level
restrictions = config.get_restrictions()

# Convert to dictionary
config_dict = config.to_dict()
```

## 📁 Plugin Implementations

### Extractors

#### CSVExtractor

```python
from etl_framework.plugins.extractors.csv_extractor import CSVExtractor
from etl_framework.security.input_validator import InputValidator

# Initialize with validator (recommended)
validator = InputValidator()
extractor = CSVExtractor(validator=validator)

# Extract data
df = extractor.extract("data/orders.csv")

# Validate source
is_valid = extractor.validate_source("data/orders.csv")

# Get security info
security_info = extractor.get_security_info()
```

#### PDFExtractor

```python
from etl_framework.plugins.extractors.pdf_extractor import PDFExtractor

extractor = PDFExtractor(validator=validator)
df = extractor.extract("data/document.pdf")
```

#### ExcelExtractor

```python
from etl_framework.plugins.extractors.excel_extractor import ExcelExtractor

extractor = ExcelExtractor(validator=validator)
df = extractor.extract("data/spreadsheet.xlsx")
```

#### JSONStringExtractor

```python
from etl_framework.plugins.extractors.json_extractor import JSONStringExtractor

extractor = JSONStringExtractor(validator=validator)
df = extractor.extract('{"data": [{"id": 1, "name": "Test"}]}', json_path="data")
```

### Transformers

#### DataCleaner

```python
from etl_framework.plugins.transformers.cleaner import DataCleaner

# Initialize with column mapping
cleaner = DataCleaner(column_mapping={
    "col_1": "order_id",
    "col_2": "customer_name"
})

# Transform data
cleaned_df = cleaner.transform(df)
```

#### DataEnricher

```python
from etl_framework.plugins.transformers.enricher import DataEnricher

enricher = DataEnricher(lookup_tables={
    "material_descriptions": {
        "AL": "Aluminum",
        "ST": "Steel"
    }
})

enriched_df = enricher.transform(df)
```

#### MappingLoader

```python
from etl_framework.plugins.transformers.mapping_loader import MappingLoader

# Load from JSON file
mapping_loader = MappingLoader("config/mapping.json")

# Or from dictionary
mapping_loader = MappingLoader.from_dict(mapping_config)

# Transform with mapping
transformed_df = mapping_loader.transform(df)

# Get loading strategy options
options = mapping_loader.get_loading_strategy_options()
```

#### SecureJSONBusinessCalculator

```python
from etl_framework.plugins.transformers.secure_json_calculator import SecureJSONBusinessCalculator

calculator = SecureJSONBusinessCalculator(mapping_config)
calculated_df = calculator.transform(df)
```

### Loaders

#### FileLoader

```python
from etl_framework.plugins.loaders.file_loader import FileLoader

loader = FileLoader()

# Load with strategy
success = loader.load(
    df=df,
    target="output.csv",
    strategy=LoadStrategy.UPSERT,
    key_columns=["id"]
)

# Legacy method (backward compatibility)
success = loader.load_legacy(df, "output.csv")
```

#### SQLLoader

```python
from etl_framework.plugins.loaders.sql_loader import SQLLoader

# Initialize with connection string
loader = SQLLoader("sqlite:///database.db")
# or
loader = SQLLoader("postgresql://user:pass@localhost:5432/db")

# Load to database
success = loader.load(
    df=df,
    target="table_name",
    strategy=LoadStrategy.UPSERT,
    key_columns=["id", "date"],
    batch_size=1000
)

# Get database type
db_type = loader.get_database_type()

# Check if native UPSERT supported
supports_native_upsert = loader.supports_native_upsert()
```

## ⚙️ Configuration API

### Settings Configuration

```python
from etl_framework.config.settings import config

# Access configuration values
default_extractor = config.DEFAULT_EXTRACTOR
default_loader = config.DEFAULT_LOADER
batch_size = config.BATCH_SIZE

# Get database connection string
connection_string = config.get_database_connection_string()

# Get column mapping
column_mapping = config.get_column_mapping("roller_door")

# Parse key columns
key_columns = config.parse_key_columns("id,date")

# Ensure directories exist
config.ensure_directories()
```

## 🎯 Utility Functions

### Logger

```python
from etl_framework.utils.logger import setup_logger

# Setup logging
logger = setup_logger(
    name="etl_pipeline",
    log_file="etl.log",
    level="INFO"
)

# Use logger
logger.info("Starting pipeline")
logger.warning("Large file detected")
logger.error("Pipeline failed")
```

### Validators

```python
from etl_framework.utils.validators import validate_email, validate_phone

# Validate common formats
is_valid = validate_email("user@example.com")
is_valid = validate_phone("+1-555-123-4567")
```

## 🔧 CLI API

### Main CLI Function

```python
from etl_framework.cli.main import main

# Run CLI programmatically
import sys
sys.argv = [
    "etl-framework",
    "--source", "data.csv",
    "--extractor", "csv",
    "--loader", "file",
    "--target", "output.csv",
    "--username", "operator"
]
main()
```

### Argument Parsing

```python
from etl_framework.cli.main import parse_key_columns

# Parse key columns string
key_columns = parse_key_columns("id,date,customer_id")
# Returns: ["id", "date", "customer_id"]
```

## 🧪 Testing Utilities

### Test Fixtures

```python
# In conftest.py or test files
import pytest
from etl_framework.core.pipeline import ETLPipeline

@pytest.fixture
def secure_pipeline():
    """Fixture for secure pipeline."""
    return ETLPipeline(username="operator", enable_security=True)

@pytest.fixture
def sample_dataframe():
    """Fixture for sample DataFrame."""
    import pandas as pd
    return pd.DataFrame({
        'id': [1, 2, 3],
        'name': ['Alice', 'Bob', 'Charlie'],
        'value': [100, 200, 300]
    })
```

## 📊 Error Handling

### Custom Exceptions

```python
from etl_framework.security.encryption import SecurityError

try:
    encryptor = DataEncryptor()
except SecurityError as e:
    print(f"Security error: {e}")
    # Handle missing encryption key, etc.
```

### Pipeline Error Handling

```python
try:
    result = pipeline.run(...)
except PermissionError as e:
    print(f"Permission denied: {e}")
    # Handle permission errors
except ValueError as e:
    print(f"Validation error: {e}")
    # Handle validation errors
except Exception as e:
    print(f"Unexpected error: {e}")
    # Handle other errors
finally:
    pipeline.shutdown()
```

## 🔄 Integration Patterns

### Custom Plugin Registration

```python
# Register custom components
pipeline = ETLPipeline(username="admin", enable_security=True)

# Register custom extractor
pipeline.register_extractor("custom", CustomExtractor())

# Register custom transformer
pipeline.add_transformer(CustomTransformer())

# Register custom loader
pipeline.register_loader("custom", CustomLoader())

# Use custom components
result = pipeline.run(
    extractor_name="custom",
    source="custom_source",
    loader_name="custom",
    target="custom_target"
)
```

### Batch Processing

```python
import pandas as pd
from etl_framework.core.pipeline import ETLPipeline

pipeline = ETLPipeline(username="operator", enable_security=True)
pipeline.register_extractor("csv", CSVExtractor())
pipeline.register_loader("sql", SQLLoader("sqlite:///database.db"))

# Process in batches
chunk_size = 10000
for chunk_number, chunk in enumerate(pd.read_csv("large_file.csv", chunksize=chunk_size)):
    print(f"Processing chunk {chunk_number + 1}")

    result = pipeline.run(
        extractor_name="csv",
        source=chunk,  # Pass DataFrame directly
        loader_name="sql",
        target="large_table",
        strategy="append"
    )

    if result is None:
        print(f"Failed to process chunk {chunk_number + 1}")
        break
```

## 📈 Monitoring and Metrics

### Pipeline Metrics

```python
import time
from etl_framework.core.pipeline import ETLPipeline

def run_pipeline_with_metrics():
    """Run pipeline and collect performance metrics."""
    start_time = time.time()

    pipeline = ETLPipeline(username="operator", enable_security=True)
    # ... setup pipeline ...

    try:
        result = pipeline.run(...)
        end_time = time.time()

        metrics = {
            'execution_time': end_time - start_time,
            'rows_processed': len(result) if result else 0,
            'success': result is not None,
            'user': pipeline.username,
            'security_enabled': pipeline.enable_security
        }

        return result, metrics

    finally:
        pipeline.shutdown()

# Run and collect metrics
result, metrics = run_pipeline_with_metrics()
print(f"Execution time: {metrics['execution_time']:.2f}s")
print(f"Rows processed: {metrics['rows_processed']}")
```

## 🔗 Related Modules

### pandas Integration

```python
import pandas as pd
from etl_framework.core.pipeline import ETLPipeline

# Use pandas DataFrames directly
df = pd.DataFrame({'col1': [1, 2, 3], 'col2': ['a', 'b', 'c']})

pipeline = ETLPipeline(username="operator", enable_security=True)
pipeline.register_loader("file", FileLoader())

# Pass DataFrame as source
result = pipeline.run(
    extractor_name="csv",
    source=df,  # DataFrame instead of file path
    loader_name="file",
    target="output.csv"
)
```

### SQLAlchemy Integration

```python
from sqlalchemy import create_engine, MetaData
from etl_framework.plugins.loaders.sql_loader import SQLLoader

# Use SQLAlchemy engine directly
engine = create_engine("postgresql://user:pass@localhost:5432/db")
metadata = MetaData()

# Pass engine to loader
loader = SQLLoader(engine=engine)

# Use SQLAlchemy for advanced operations
with engine.connect() as conn:
    # Execute custom SQL
    result = conn.execute("SELECT COUNT(*) FROM processed_data")
    count = result.scalar()
    print(f"Total records: {count}")
```

## 🎯 Best Practices

### Security Best Practices

```python
# Always enable security in production
pipeline = ETLPipeline(
    username="operator",  # Never use 'system' in production
    enable_security=True  # Always True for production
)

# Use appropriate user roles
# - operator for routine ETL jobs
# - admin for configuration changes
# - viewer for read-only access
# - auditor for security monitoring

# Validate all inputs
validator = InputValidator(security_level="production")
validated_path = validator.validate_file_path(user_input, ['.csv'], "read")

# Enable audit logging
logger = AuditLogger("/var/log/etl/audit.log")
logger.log_pipeline_execution(...)
```

### Performance Best Practices

```python
# Use appropriate batch sizes
options = LoadOptions(
    batch_size=5000,  # Adjust based on database and data size
    chunk_size=1000   # For file operations
)

# Disable unnecessary features for performance
os.environ['ETL_CREATE_INDEX'] = 'false'
os.environ['ETL_DROP_DUPLICATES'] = 'false'

# Use appropriate file formats
# - Parquet for analytics (columnar, compressed)
# - Feather for speed (fast read/write)
# - CSV for compatibility (universal)
```

## 📚 Additional Resources

### Type Hints

```python
from typing import List, Dict, Optional, Any
import pandas as pd
from etl_framework.core.pipeline import ETLPipeline

def process_data(
    source: str,
    mapping_file: Optional[str] = None,
    username: str = "operator"
) -> Optional[pd.DataFrame]:
    """Process data with type hints."""
    pipeline = ETLPipeline(username=username, enable_security=True)
    # ... implementation ...
    return result
```

### Documentation Strings

```python
class SecureETLPipeline(ETLPipeline):
    """
    Secure ETL pipeline with enhanced security features.

    Args:
        username: User executing the pipeline
        enable_security: Whether to enable security features
        security_level: Security level (development, testing, staging, production)

    Example:
        >>> pipeline = SecureETLPipeline(username="operator")
        >>> pipeline.register_extractor("csv", CSVExtractor())
        >>> result = pipeline.run(...)
    """

    def __init__(self, username: str = "system",
                 enable_security: bool = True,
                 security_level: str = "production"):
        super().__init__(username, enable_security)
        self.security_level = security_level
```

---

This API reference covers the main components of the ETL Framework. For more detailed information, see the [User Guide](USER_GUIDE.md) and [Examples](EXAMPLES.md).
```

