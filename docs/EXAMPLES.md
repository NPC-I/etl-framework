# ETL Framework Examples

## 📚 Examples Overview

This documentation provides practical examples of using the ETL Framework with its security features. All examples demonstrate real-world scenarios with security best practices.

## 🚀 Quick Start Examples

### Example 1: Basic CSV Processing with Security

```python
from etl_framework.core.pipeline import ETLPipeline
from etl_framework.plugins.extractors.csv_extractor import CSVExtractor
from etl_framework.plugins.transformers.cleaner import DataCleaner
from etl_framework.plugins.loaders.file_loader import FileLoader

# Build pipeline with security
pipeline = ETLPipeline(username="operator", enable_security=True)
pipeline.register_extractor("csv", CSVExtractor())
pipeline.add_transformer(DataCleaner(column_mapping={"col_1": "id"}))
pipeline.register_loader("file", FileLoader())

# Run pipeline with security features
result = pipeline.run("csv", "input.csv", "file", "output.csv")
```

### Example 2: Secure JSON Calculator for Business Logic

```python
import json
from etl_framework.plugins.transformers.secure_json_calculator import SecureJSONBusinessCalculator

# Create secure mapping configuration
mapping_config = {
    "column_mapping": {
        "col_1": "order_id",
        "col_2": "customer_name"
    },
    "business_rules": {
        "tax_rate": 0.1
    },
    "calculations": [
        {"name": "tax", "formula": "price * tax_rate"},
        {"name": "total", "formula": "price + tax"}
    ]
}

# Save to file
with open("mapping.json", "w") as f:
    json.dump(mapping_config, f, indent=2)

# Use secure calculator
calculator = SecureJSONBusinessCalculator(mapping_config)
```

## 🔒 Security Examples

### Security Configuration Example

```python
import os

# Set security environment variables
os.environ.update({
    'ETL_SECURITY_ENABLED': 'true',
    'ETL_SECURITY_LEVEL': 'testing',
    'ETL_ENCRYPTION_ENABLED': 'true',
    'ETL_ENCRYPTION_KEY': 'demo-key-12345',
    'ETL_RBAC_ENABLED': 'true',
    'ETL_USERS': 'admin:admin;operator:operator',
    'ETL_AUDIT_LOGGING_ENABLED': 'true'
})

# Now all pipelines will use security features
```

### Testing Security Features

```python
# Test access control
from etl_framework.security.access_control import AccessController, Operation
controller = AccessController()
print(f"Admin can execute: {controller.check_permission('admin', Operation.EXECUTE_PIPELINE)}")
print(f"Operator can execute: {controller.check_permission('operator', Operation.EXECUTE_PIPELINE)}")

# Test encryption
from etl_framework.security.encryption import DataEncryptor
encryptor = DataEncryptor()
encrypted = encryptor.encrypt_value("sensitive-data")
decrypted = encryptor.decrypt_value(encrypted)
print(f"Encryption test passed: {decrypted == 'sensitive-data'}")

# Test audit logging
from etl_framework.security.audit_logger import AuditLogger, AuditEventType
logger = AuditLogger("./logs/audit.log")
logger.log_event(AuditEventType.USER_LOGIN, "admin", {"method": "password"}, True)
```

## 📊 Business Logic Examples

### Roller Door Business Example

```json
{
  "column_mapping": {
    "col_1": "order_id",
    "col_2": "customer_name",
    "col_3": "door_width",
    "col_4": "door_height",
    "col_5": "material",
    "col_6": "quantity",
    "col_7": "unit_price"
  },
  "business_rules": {
    "material_prices": {
      "AL": 120.0,
      "ST": 180.0,
      "WO": 250.0
    },
    "material_descriptions": {
      "AL": "Aluminum",
      "ST": "Steel",
      "WO": "Wood"
    },
    "profit_margin": 1.3,
    "base_installation_days": 2,
    "min_lead_time_days": 3
  },
  "calculations": [
    {
      "name": "area_sq_units",
      "formula": "door_width * door_height",
      "description": "Door area"
    },
    {
      "name": "material_price",
      "lookup": "material_prices[material]",
      "condition": "has:material"
    },
    {
      "name": "material_description",
      "lookup": "material_descriptions[material]",
      "condition": "has:material"
    },
    {
      "name": "calculated_price",
      "formula": "area_sq_units * material_price * quantity",
      "condition": "has:material_price"
    },
    {
      "name": "sale_price",
      "formula": "calculated_price * profit_margin",
      "condition": "has:calculated_price"
    }
  ]
}
```

### Financial Data Processing Example

```json
{
  "column_mapping": {
    "transaction_id": "id",
    "transaction_date": "date",
    "amount": "amount",
    "currency": "currency"
  },
  "business_rules": {
    "exchange_rates": {
      "USD": 1.0,
      "EUR": 0.85,
      "GBP": 0.75
    },
    "tax_rates": {
      "standard": 0.2,
      "reduced": 0.1,
      "zero": 0.0
    }
  },
  "calculations": [
    {
      "name": "amount_usd",
      "formula": "amount * exchange_rates[currency]",
      "description": "Convert to USD"
    },
    {
      "name": "tax_amount",
      "formula": "amount_usd * tax_rates[tax_category]",
      "condition": "has:tax_category"
    },
    {
      "name": "total_amount",
      "formula": "amount_usd + tax_amount"
    }
  ]
}
```

## 🗄️ Database Examples

### SQLite Example

```bash
# Process CSV and load to SQLite with security
etl-framework \
  --source data/orders.csv \
  --extractor csv \
  --mapping config/mappings/business.json \
  --table processed_orders \
  --db sqlite:///etl_database.db \
  --username operator \
  --security-audit
```

### PostgreSQL Example

```bash
# Process PDF and load to PostgreSQL with security
etl-framework \
  --source data/invoices.pdf \
  --extractor pdf \
  --mapping config/mappings/invoice_mapping.json \
  --table invoices \
  --db postgresql://user:password@localhost:5432/accounting \
  --username admin \
  --strategy upsert \
  --key-columns invoice_number \
  --security-audit
```

### MySQL Example

```bash
# Process Excel and load to MySQL with security
etl-framework \
  --source data/products.xlsx \
  --extractor excel \
  --mapping config/mappings/product_mapping.json \
  --table products \
  --db mysql://user:password@localhost:3306/inventory \
  --username operator \
  --strategy replace \
  --security-audit
```

## ⚡ Performance Examples

### Large Dataset Processing

```bash
# Process large CSV with optimized settings
etl-framework \
  --source large_data.csv \
  --extractor csv \
  --mapping config/mappings/processing.json \
  --table large_table \
  --db postgresql://user:password@localhost:5432/warehouse \
  --batch-size 5000 \
  --username operator \
  --strategy append
```

### Chunked Processing

```python
from etl_framework.core.pipeline import ETLPipeline
from etl_framework.plugins.extractors.csv_extractor import CSVExtractor
from etl_framework.plugins.loaders.sql_loader import SQLLoader
import pandas as pd

# Process in chunks for memory efficiency
pipeline = ETLPipeline(username="operator", enable_security=True)
pipeline.register_extractor("csv", CSVExtractor())
pipeline.register_loader("sql", SQLLoader("sqlite:///database.db"))

chunk_size = 10000
for chunk in pd.read_csv("large_data.csv", chunksize=chunk_size):
    # Process each chunk
    result = pipeline.run("csv", chunk, "sql", "target_table", strategy="append")
    print(f"Processed {len(chunk)} rows")
```

## 🔐 Advanced Security Examples

### Custom Security Configuration

```python
from etl_framework.security.config import SecurityConfig, SecurityLevel
from etl_framework.security.input_validator import InputValidator

# Create custom security configuration
config = SecurityConfig(
    security_level=SecurityLevel.PRODUCTION,
    encryption_enabled=True,
    rbac_enabled=True,
    audit_logging_enabled=True,
    max_file_size_mb=500,
    allowed_ip_ranges=["192.168.1.0/24", "10.0.0.0/8"]
)

# Create validator with custom security level
validator = InputValidator(security_level="production")

# Use in pipeline
from etl_framework.core.pipeline import ETLPipeline
pipeline = ETLPipeline(username="admin", enable_security=True)
```

### Resource-Level Access Control

```python
from etl_framework.security.access_control import AccessController, Operation

controller = AccessController()

# Check access to sensitive resources
sensitive_databases = ["customer_data", "financial_records", "employee_salaries"]

for db in sensitive_databases:
    admin_access = controller.check_permission("admin", Operation.VIEW_SENSITIVE_DATA, db)
    operator_access = controller.check_permission("operator", Operation.VIEW_SENSITIVE_DATA, db)

    print(f"Database: {db}")
    print(f"  Admin access: {admin_access}")
    print(f"  Operator access: {operator_access}")
```

## 🎯 Real-World Scenarios

### Scenario 1: Daily Sales Processing

```bash
#!/bin/bash
# daily_sales_etl.sh

# Set security environment
export ETL_SECURITY_ENABLED=true
export ETL_SECURITY_LEVEL=production
export ETL_ENCRYPTION_ENABLED=true
export ETL_ENCRYPTION_KEY="$ENCRYPTION_KEY"
export ETL_USERS="operator:operator"

# Process daily sales data
etl-framework \
  --source /data/daily_sales_$(date +%Y%m%d).csv \
  --extractor csv \
  --mapping /config/sales_mapping.json \
  --table daily_sales \
  --db postgresql://$DB_USER:$DB_PASSWORD@$DB_HOST:$DB_PORT/$DB_NAME \
  --username operator \
  --strategy upsert \
  --key-columns sale_id,date \
  --batch-size 10000 \
  --security-audit \
  >> /var/log/etl/sales_$(date +%Y%m%d).log 2>&1

# Check exit code
if [ $? -eq 0 ]; then
    echo "Daily sales ETL completed successfully"
else
    echo "Daily sales ETL failed"
    # Send alert
    echo "ETL failed for $(date +%Y-%m-%d)" | mail -s "ETL Alert" admin@example.com
fi
```

### Scenario 2: Customer Data Migration with Encryption

```python
#!/usr/bin/env python3
# migrate_customer_data.py

import os
from etl_framework.core.pipeline import ETLPipeline
from etl_framework.plugins.extractors.csv_extractor import CSVExtractor
from etl_framework.plugins.transformers.cleaner import DataCleaner
from etl_framework.plugins.transformers.mapping_loader import MappingLoader
from etl_framework.plugins.loaders.sql_loader import SQLLoader

# Security configuration
os.environ['ETL_SECURITY_ENABLED'] = 'true'
os.environ['ETL_SECURITY_LEVEL'] = 'production'
os.environ['ETL_ENCRYPTION_ENABLED'] = 'true'
os.environ['ETL_ENCRYPTION_KEY'] = os.getenv('PRODUCTION_ENCRYPTION_KEY')
os.environ['ETL_USERS'] = 'data_steward:data_steward'

# Build secure pipeline
pipeline = ETLPipeline(username="data_steward", enable_security=True)
pipeline.register_extractor("csv", CSVExtractor())
pipeline.add_transformer(DataCleaner(column_mapping={
    "customer_id": "id",
    "customer_name": "name",
    "customer_email": "email",
    "customer_phone": "phone"
}))
pipeline.add_transformer(MappingLoader("config/mappings/customer_mapping.json"))
pipeline.register_loader("sql", SQLLoader(os.getenv('PRODUCTION_DB_URL')))

# Process customer data
print("Starting customer data migration with encryption...")
result = pipeline.run(
    extractor_name="csv",
    source="data/customers.csv",
    loader_name="sql",
    target="customers",
    strategy="replace"
)

if result is not None:
    print(f"Migration successful: {len(result)} customers processed")
    print("Sensitive columns (email, phone) were automatically encrypted")
else:
    print("Migration failed")
```

### Scenario 3: Audit Log Analysis

```python
#!/usr/bin/env python3
# analyze_audit_logs.py

from etl_framework.security.audit_logger import AuditLogger
from datetime import datetime, timedelta
import json

def analyze_security_events():
    """Analyze audit logs for security insights."""
    logger = AuditLogger("/var/log/etl/audit.log")

    # Get logs from last 24 hours
    logs = logger.get_recent_logs(limit=1000)

    # Filter for last 24 hours
    cutoff_time = datetime.utcnow() - timedelta(hours=24)
    recent_logs = [
        log for log in logs
        if datetime.fromisoformat(log['timestamp'].replace('Z', '')) > cutoff_time
    ]

    # Analyze by event type
    event_counts = {}
    for log in recent_logs:
        event_type = log['event_type']
        event_counts[event_type] = event_counts.get(event_type, 0) + 1

    print("Security Event Analysis (Last 24 Hours)")
    print("=" * 50)
    print(f"Total events: {len(recent_logs)}")
    print("\nEvent breakdown:")
    for event_type, count in sorted(event_counts.items()):
        print(f"  {event_type}: {count}")

    # Check for security events
    security_events = logger.search_logs({'event_type': 'security_event'})
    if security_events:
        print(f"\n⚠️  Security Events Found: {len(security_events)}")
        for event in security_events:
            print(f"  - {event['timestamp']}: {event['details']['event']} "
                  f"(severity: {event['details']['severity']})")

    # Check for permission denied events
    permission_denied = logger.search_logs({'event_type': 'permission_denied'})
    if permission_denied:
        print(f"\n🚫 Permission Denied Events: {len(permission_denied)}")
        for event in permission_denied:
            print(f"  - {event['user']} denied {event['details']['operation']} "
                  f"on {event['details']['resource']}")

if __name__ == "__main__":
    analyze_security_events()
```

## 🧪 Testing Examples

### Unit Test Example

```python
# test_secure_pipeline.py
import pytest
from etl_framework.core.pipeline import ETLPipeline
from etl_framework.security.access_control import AccessController, Operation

def test_pipeline_security():
    """Test pipeline security features."""
    # Create pipeline with security
    pipeline = ETLPipeline(username="operator", enable_security=True)

    # Test that security components are initialized
    assert pipeline.enable_security == True
    assert pipeline.username == "operator"
    assert pipeline.security_config is not None
    assert pipeline.audit_logger is not None
    assert pipeline.access_controller is not None

    # Test access control
    controller = AccessController()
    assert controller.check_permission("operator", Operation.EXECUTE_PIPELINE)
    assert not controller.check_permission("viewer", Operation.EXECUTE_PIPELINE)

def test_encryption():
    """Test data encryption features."""
    from etl_framework.security.encryption import DataEncryptor
    import pandas as pd

    # Create encryptor
    encryptor = DataEncryptor()

    # Test single value encryption
    plaintext = "sensitive-data"
    encrypted = encryptor.encrypt_value(plaintext)
    decrypted = encryptor.decrypt_value(encrypted)
    assert decrypted == plaintext

    # Test DataFrame encryption
    df = pd.DataFrame({
        'name': ['Test'],
        'email': ['test@example.com'],
        'ssn': ['123-45-6789']
    })

    encrypted_df = encryptor.encrypt_dataframe(df)
    assert encrypted_df['email'][0] != 'test@example.com'  # Should be encrypted
    assert encrypted_df['ssn'][0] != '123-45-6789'  # Should be encrypted
```

### Integration Test Example

```python
# test_integration_security.py (continued)
import pytest
import tempfile
import pandas as pd
from pathlib import Path
from etl_framework.core.pipeline import ETLPipeline
from etl_framework.plugins.extractors.csv_extractor import CSVExtractor
from etl_framework.plugins.loaders.file_loader import FileLoader

def test_pipeline_with_security_integration():
    """Test complete pipeline with security integration."""
    # Create test data
    test_data = pd.DataFrame({
        'order_id': [1, 2, 3],
        'customer_name': ['Alice', 'Bob', 'Charlie'],
        'amount': [100.0, 200.0, 300.0]
    })

    with tempfile.TemporaryDirectory() as temp_dir:
        # Create test CSV
        input_csv = Path(temp_dir) / "input.csv"
        test_data.to_csv(input_csv, index=False)

        # Create output file path
        output_csv = Path(temp_dir) / "output.csv"

        # Create pipeline with security
        pipeline = ETLPipeline(username="operator", enable_security=True)
        pipeline.register_extractor("csv", CSVExtractor())
        pipeline.register_loader("file", FileLoader())

        # Run pipeline
        result = pipeline.run(
            extractor_name="csv",
            source=str(input_csv),
            loader_name="file",
            target=str(output_csv),
            strategy="replace"
        )

        # Verify results
        assert result is not None
        assert len(result) == 3
        assert output_csv.exists()

        # Verify output
        output_data = pd.read_csv(output_csv)
        assert len(output_data) == 3
        assert list(output_data.columns) == list(test_data.columns)
```

## 📋 CLI Usage Examples

### Basic CLI Examples

```bash
# Process CSV with JSON mapping
etl-framework \
  --source data/orders.csv \
  --extractor csv \
  --mapping config/mappings/my_business.json \
  --loader file \
  --target output.csv \
  --username operator

# Process PDF with security audit
etl-framework \
  --source data/invoice.pdf \
  --extractor pdf \
  --mapping config/mappings/invoice.json \
  --table invoices \
  --username admin \
  --security-audit \
  --verbose

# Process Excel with custom database
etl-framework \
  --source data/products.xlsx \
  --extractor excel \
  --mapping config/mappings/products.json \
  --table products \
  --db mysql://user:pass@localhost:3306/inventory \
  --username operator \
  --strategy upsert \
  --key-columns product_id
```

### Advanced CLI Examples

```bash
# Large dataset with optimized settings
etl-framework \
  --source large_data.csv \
  --extractor csv \
  --mapping config/processing.json \
  --table large_table \
  --batch-size 5000 \
  --username operator \
  --strategy append

# Multiple key columns for UPSERT
etl-framework \
  --source daily_metrics.csv \
  --extractor csv \
  --mapping config/metrics.json \
  --table daily_metrics \
  --strategy upsert \
  --key-columns date,metric_name,location \
  --username operator

# JSON string input
etl-framework \
  --json-string '[{\"id\": 1, \"name\": \"Test\"}]' \
  --extractor json \
  --mapping config/mapping.json \
  --loader file \
  --target output.csv \
  --username operator
```

## 🎯 Demo Suite Examples

The framework includes a comprehensive demo suite. Run the demos to see all features in action:

```bash
# Run the security demonstration
python examples/security_demo.py

# Run basic usage example
python examples/basic_usage.py

# Run specific demos from the demo directory
python demo/01_basic_csv_etl.py
python demo/02_secure_csv_etl.py
python demo/03_pdf_extraction.py
python demo/04_database_operations.py
python demo/05_comprehensive_security.py
```

## 🔧 Custom Component Examples

### Custom Extractor with Security

```python
from etl_framework.core.extractor import Extractor
import pandas as pd
from etl_framework.security.input_validator import InputValidator

class CustomExtractor(Extractor):
    def __init__(self, validator: InputValidator = None):
        self.validator = validator

    def extract(self, source, **kwargs):
        # Security: Validate source if validator provided
        if self.validator:
            validated_source = self.validator.validate_file_path(
                source, ['.txt', '.dat'], "read"
            )
            source = str(validated_source)

        # Custom extraction logic
        data = []
        with open(source, 'r') as f:
            for line in f:
                # Parse custom format
                parts = line.strip().split('|')
                data.append(parts)

        return pd.DataFrame(data, columns=['col1', 'col2', 'col3'])

    def validate_source(self, source):
        if self.validator:
            try:
                self.validator.validate_file_path(source, ['.txt', '.dat'], "read")
                return True
            except ValueError:
                return False
        return source.endswith(('.txt', '.dat'))
```

### Custom Transformer with Security Logging

```python
from etl_framework.core.transformer import Transformer
import pandas as pd

class SecureCustomTransformer(Transformer):
    def __init__(self, transformation_name: str):
        self.transformation_name = transformation_name

    def transform(self, df):
        df = df.copy()

        # Log transformation start
        print(f"[Security] Starting transformation: {self.transformation_name}")
        print(f"[Security] Processing {len(df)} rows")

        # Apply custom transformation
        df['processed_date'] = pd.Timestamp.now().date()
        df['transformation_applied'] = self.transformation_name

        # Log transformation completion
        print(f"[Security] Completed transformation: {self.transformation_name}")

        return df
```

## 📊 Performance Benchmark Examples

```python
# benchmark_performance.py
import time
import pandas as pd
from etl_framework.core.pipeline import ETLPipeline
from etl_framework.plugins.extractors.csv_extractor import CSVExtractor
from etl_framework.plugins.loaders.file_loader import FileLoader

def benchmark_pipeline(data_size: int, enable_security: bool = True):
    """Benchmark pipeline performance with different data sizes."""
    # Create test data
    data = pd.DataFrame({
        'id': range(data_size),
        'value': [f'value_{i}' for i in range(data_size)],
        'amount': [i * 10.0 for i in range(data_size)]
    })

    with tempfile.NamedTemporaryFile(suffix='.csv', delete=False) as f:
        data.to_csv(f.name, index=False)

        # Create pipeline
        pipeline = ETLPipeline(
            username="operator",
            enable_security=enable_security
        )
        pipeline.register_extractor("csv", CSVExtractor())
        pipeline.register_loader("file", FileLoader())

        # Benchmark
        start_time = time.time()
        result = pipeline.run(
            extractor_name="csv",
            source=f.name,
            loader_name="file",
            target=f.name.replace('.csv', '_output.csv'),
            strategy="replace"
        )
        end_time = time.time()

        # Clean up
        import os
        os.unlink(f.name)
        if result is not None:
            os.unlink(f.name.replace('.csv', '_output.csv'))

        return end_time - start_time

# Run benchmarks
sizes = [1000, 10000, 100000]
for size in sizes:
    time_with_security = benchmark_pipeline(size, enable_security=True)
    time_without_security = benchmark_pipeline(size, enable_security=False)

    print(f"Data size: {size:,}")
    print(f"  With security: {time_with_security:.2f}s")
    print(f"  Without security: {time_without_security:.2f}s")
    print(f"  Security overhead: {(time_with_security/time_without_security - 1)*100:.1f}%")
    print()
```

## 🚀 Production Deployment Examples

### Docker Deployment

```dockerfile
# Dockerfile
FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create directories
RUN mkdir -p /app/data /app/logs /app/config

# Set environment variables
ENV ETL_SECURITY_ENABLED=true
ENV ETL_SECURITY_LEVEL=production
ENV ETL_AUDIT_LOG_FILE=/app/logs/audit.log

# Run as non-root user
RUN useradd -m -u 1000 etluser
USER etluser

# Entry point
ENTRYPOINT ["python", "-m", "etl_framework.cli.main"]
```

### Kubernetes Deployment

```yaml
# etl-job.yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: daily-etl
spec:
  schedule: "0 2 * * *"  # Run daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: etl-runner
            image: your-registry/etl-framework:latest
            env:
            - name: ETL_SECURITY_ENABLED
              value: "true"
            - name: ETL_SECURITY_LEVEL
              value: "production"
            - name: ETL_ENCRYPTION_KEY
              valueFrom:
                secretKeyRef:
                  name: etl-secrets
                  key: encryption-key
            - name: DB_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: database-secrets
                  key: password
            command: ["etl-framework"]
            args:
            - "--source"
            - "/data/daily_orders.csv"
            - "--mapping"
            - "/config/mapping.json"
            - "--table"
            - "daily_orders"
            - "--db"
            - "postgresql://user:$(DB_PASSWORD)@database:5432/production"
            - "--username"
            - "operator"
            - "--strategy"
            - "upsert"
            - "--key-columns"
            - "order_id,date"
            - "--security-audit"
            volumeMounts:
            - name: data-volume
              mountPath: /data
            - name: config-volume
              mountPath: /config
          restartPolicy: OnFailure
          volumes:
          - name: data-volume
            persistentVolumeClaim:
              claimName: etl-data-pvc
          - name: config-volume
            configMap:
              name: etl-config
```

## 📚 Additional Resources

### Example Mapping Files

The framework includes several example mapping files in `config/mappings/`:

1. **`roller_door_mapping.json`** - Complete roller door business example
2. **`financial_mapping.json`** - Financial data processing example
3. **`customer_mapping.json`** - Customer data management example
4. **`simple_mapping.json`** - Basic example for getting started

### Sample Data Files

Sample data files are available in the `data/` directory:

- `orders.csv` - Sample order data
- `customers.csv` - Sample customer data
- `financial.pdf` - Sample financial PDF
- `sensitive_data.csv` - Sensitive data for encryption demo

### Running Examples

```bash
# Install with all features
pip install -e .[all]

# Run security demo
python examples/security_demo.py

# Run all demos
for demo in demo/*.py; do
    echo "Running $demo"
    python "$demo"
    echo ""
done

# Test examples
pytest tests/ -v
```

## 🆘 Getting Help with Examples

If you encounter issues with the examples:

1. **Check the documentation**: Review [Getting Started](GETTING_STARTED.md) and [User Guide](USER_GUIDE.md)
2. **Run security tests**: `pytest tests/unit/security/ -v`
3. **Check example files**: Review the example files in `examples/` and `demo/`
4. **Contact support**: <nathan@npc-it.co.uk> for security-related issues

---

**Remember**: These examples demonstrate the framework's capabilities with security best practices. Always test with your own data and security requirements before deploying to production.
```
