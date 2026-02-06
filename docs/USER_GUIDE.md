# ETL Framework User Guide

## 📖 Table of Contents

1. [Introduction](#introduction)
2. [Command-Line Interface](#command-line-interface)
3. [JSON Mapping Configuration](#json-mapping-configuration)
4. [Loading Strategies](#loading-strategies)
5. [Database Support](#database-support)
6. [Performance Optimization](#performance-optimization)
7. [Advanced Usage](#advanced-usage)
8. [Troubleshooting](#troubleshooting)

## Introduction

The ETL Framework is a modular, JSON-driven ETL framework. It allows you to extract data from various sources, transform it with configurable business logic, and load it to databases or files with intelligent strategies.

### Key Concepts

- **Extractors**: Read data from sources (CSV, Excel, PDF, JSON)
- **Transformers**: Modify and enrich data (cleaning, calculations, lookups)
- **Loaders**: Write data to destinations (files, databases)
- **Mapping Files**: JSON configuration defining business logic
- **Security Features**: RBAC, encryption, audit logging, input validation

## Command-Line Interface

### Basic Usage

```bash
# Process a CSV file with JSON mapping
etl-framework \
  --source data/orders.csv \
  --extractor csv \
  --mapping config/mappings/my_business.json \
  --loader file \
  --target output.csv \
  --username operator
```

### Complete Command Reference

```bash
usage: etl-framework [-h] --source SOURCE [--extractor {pdf,csv,excel}]
              [--loader {sql,file}] [--table TABLE] [--target TARGET]
              [--db DB] [--strategy {fail,replace,append,update,upsert}]
              [--key-columns KEY_COLUMNS] [--batch-size BATCH_SIZE]
              [--mapping MAPPING] [--column-mapping {roller_door,generic}]
              [--username USERNAME] [--disable-security] [--security-audit]
              [--verbose]

required:
  --source SOURCE       Source file path (PDF, CSV, Excel)

optional:
  --extractor {pdf,csv,excel}  Extractor to use (default: csv)
  --loader {sql,file}          Loader to use (default: file)
  --table TABLE                Target SQL table (required for sql loader)
  --target TARGET              Target file path (required for file loader)
  --db DB                      Database connection string
  --strategy {fail,replace,append,update,upsert}  Loading strategy (default: replace)
  --key-columns KEY_COLUMNS    Key columns for update/upsert (comma-separated)
  --batch-size BATCH_SIZE      Batch size for database operations (default: 1000)
  --mapping MAPPING            JSON mapping file (recommended)
  --username USERNAME          Username for audit logging and access control (default: system)
  --disable-security           Disable all security features (not recommended)
  --security-audit             Show security audit information
  --verbose, -v               Show verbose output
```

### Environment Variables

The framework supports configuration via environment variables. Create a `.env` file:

```bash
# Database configuration
ETL_DB_TYPE=sqlite
ETL_DB_FILE=data/etl_database.db

# OR for PostgreSQL
ETL_DB_TYPE=postgresql
ETL_DB_HOST=localhost
ETL_DB_PORT=5432
ETL_DB_NAME=your_database
ETL_DB_USER=your_user
ETL_DB_PASSWORD=your_password

# Default behaviors
ETL_DEFAULT_EXTRACTOR=csv
ETL_DEFAULT_LOADER=file
ETL_DEFAULT_STRATEGY=replace
ETL_KEY_COLUMNS=id,order_date
ETL_BATCH_SIZE=1000

# Logging
ETL_LOG_LEVEL=INFO
ETL_LOG_FILE=etl.log

# Column mapping
ETL_COLUMN_MAPPING=roller_door
```

## JSON Mapping Configuration

### Basic Structure

```json
{
  "column_mapping": {
    "source_col_1": "target_col_1",
    "source_col_2": "target_col_2"
  },
  "business_rules": {
    "tax_rate": 0.1,
    "discount_rate": 0.05
  },
  "calculations": [
    {"name": "tax_amount", "formula": "price * tax_rate"},
    {"name": "final_price", "formula": "price + tax_amount - (price * discount_rate)"}
  ],
  "loading_strategy": {
    "strategy": "upsert",
    "key_columns": ["order_id", "customer_email"],
    "batch_size": 1000
  }
}
```

### Column Mapping

Map source columns to target columns:

```json
"column_mapping": {
  "pdf_col_1": "order_id",
  "pdf_col_2": "customer_name",
  "pdf_col_3": "width",
  "pdf_col_4": "height"
}
```

### Business Rules

Define constants and lookup tables:

```json
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
  "default_price_per_sq_unit": 150.0,
  "base_installation_days": 2,
  "profit_margin": 1.3,
  "lead_time_per_1000_sq_units": 1.0,
  "min_lead_time_days": 3
}
```

### Calculations

Define calculations using formulas, lookups, or constants:

```json
"calculations": [
  {
    "name": "area_sq_units",
    "formula": "width * height",
    "description": "Product area"
  },
  {
    "name": "material_price",
    "lookup": "material_prices[material]",
    "condition": "has:material"
  },
  {
    "name": "lead_time_days",
    "formula": "max(3, area_sq_units / 1000 * lead_time_per_1000_units)",
    "description": "Lead time with 3-day minimum"
  }
]
```

#### Calculation Types

1. **Formulas**: `"formula": "width * height * unit_price"`
2. **Lookups**: `"lookup": "material_prices[material]"`
3. **Conditions**: `"condition": "has:material"` or `"condition": "not:has:unit_price"`
4. **Constants**: `"value": 150.0`

### Loading Strategy Configuration

Define loading strategy in the mapping file:

```json
"loading_strategy": {
  "strategy": "upsert",
  "key_columns": ["order_id", "customer_email"],
  "batch_size": 1000,
  "chunk_size": 500,
  "create_index": true,
  "drop_duplicates": true,
  "options": {
    "if_exists": "append",
    "index": false
  }
}
```

**Priority Order**:
1. CLI arguments (highest priority)
2. Mapping file configuration
3. Environment variables
4. Default values (lowest priority)

## Loading Strategies

### 1. REPLACE (Default)
Overwrites existing data. Use for fresh imports.

```bash
etl-framework --source data.csv --target output.csv --strategy replace --username operator
```

### 2. APPEND
Adds new data to existing. Use for incremental loads.

```bash
etl-framework --source new_data.csv --target output.csv --strategy append --username operator
```

### 3. UPDATE
Updates existing records only. Requires `--key-columns`.

```bash
etl-framework --source updates.csv --table orders --strategy update --key-columns order_id --username operator
```

### 4. UPSERT (Most Powerful!)
Updates existing records AND inserts new ones. Requires `--key-columns`.

```bash
etl-framework --source daily_data.csv --table metrics --strategy upsert --key-columns date,metric_name --username operator
```

### 5. FAIL
Fails if target already exists. Use for safety.

```bash
etl-framework --source data.csv --target output.csv --strategy fail --username operator
```

### Key Columns for UPDATE/UPSERT

Key columns identify which records to update. For databases, these should match table primary/unique keys.

```bash
# Multiple key columns
etl-framework --strategy upsert --key-columns customer_id,order_date --username operator

# Environment variable
ETL_KEY_COLUMNS="id,date"
```

## Database Support

### Supported Databases

- **PostgreSQL** - Full support with native UPSERT
- **MySQL** - Full support with native UPSERT
- **SQLite** - Full support with generic UPSERT
- **Any SQLAlchemy-supported database** - Basic support

### Connection Strings

```bash
# SQLite
--db sqlite:///etl_database.db

# PostgreSQL
--db postgresql://user:password@localhost:5432/database

# MySQL
--db mysql://user:password@localhost:3306/database
```

### UPSERT Implementation

- **PostgreSQL**: Uses `INSERT ... ON CONFLICT UPDATE` (most efficient)
- **MySQL**: Uses `INSERT ... ON DUPLICATE KEY UPDATE`
- **SQLite**: Uses generic UPDATE-then-INSERT (works on all versions)
- **Other databases**: Falls back to generic implementation

## Performance Optimization

### For Large Datasets

```bash
# Increase batch size for database operations
etl-framework --batch-size 5000 --username operator

# Use appropriate file formats
# Parquet for analytics, Feather for speed, CSV for compatibility

# Disable unnecessary features
export ETL_CREATE_INDEX=false
export ETL_DROP_DUPLICATES=false
```

### Security Performance Considerations

```bash
# Encryption adds overhead - disable for non-sensitive data
ETL_ENCRYPTION_ENABLED=false

# Audit logging adds I/O - adjust log level
ETL_LOG_LEVEL=WARNING

# Input validation adds CPU - adjust security level
ETL_SECURITY_LEVEL=testing  # Less strict validation
```

## Advanced Usage

### Multiple Mapping Files

```bash
# Different mappings for different PDF formats
etl-framework --source supplier_a.pdf --mapping config/mappings/supplier_a.json --username operator
etl-framework --source supplier_b.pdf --mapping config/mappings/supplier_b.json --username operator
```

### Verbose Output with Security Audit

```bash
etl-framework --source data.pdf --mapping config.json --username operator --verbose --security-audit
```

### Custom Database Connection with Security

```bash
# Override environment configuration with explicit connection string
etl-framework \
  --source data/orders.pdf \
  --mapping config/mappings/my_business.json \
  --table orders \
  --db postgresql://user:password@localhost:5432/production_db \
  --username admin \
  --security-audit
```

### Scheduling with Cron and Security

```bash
# Add to crontab -e
# Run daily at 2 AM with security audit
0 2 * * * cd /path/to/etl_project && /path/to/venv/bin/etl-framework \
  --source /data/daily_orders.pdf \
  --mapping /config/roller_door.json \
  --table daily_orders \
  --username operator \
  --security-audit \
  >> /var/log/etl_security.log 2>&1
```

## Troubleshooting

### Check Security Configuration

```bash
# Test security configuration
python -c "from etl_framework.security.config import SecurityConfig; config = SecurityConfig.from_environment(); print(f'Security Level: {config.security_level.value}'); print(f'Encryption: {config.should_encrypt()}'); print(f'Access Control: {config.rbac_enabled}')"

# Test user permissions
python -c "from etl_framework.security.access_control import AccessController; controller = AccessController(); print('Admin permissions:', controller.check_permission('admin', 'execute_pipeline')); print('Operator permissions:', controller.check_permission('operator', 'execute_pipeline'))"
```

### Debug Security Issues

```bash
# Test with verbose output to see security validation
etl-framework --source data.csv --username operator --verbose

# Check audit logs for security events
tail -f ./logs/audit.log | grep -E '(security_event|permission_denied|data_access)'

# Test encryption/decryption
python -c "from etl_framework.security.encryption import DataEncryptor; encryptor = DataEncryptor(); encrypted = encryptor.encrypt_value('test'); decrypted = encryptor.decrypt_value(encrypted); print(f'Encryption test: {decrypted == \"test\"}')"
```

### View Results with Security Context

```bash
# Check SQLite database
sqlite3 data/etl_database.db "SELECT * FROM processed_orders LIMIT 5;"

# Check audit logs
cat ./logs/audit.log | python -m json.tool | head -20

# Check security events
grep -i security ./logs/etl.log
```

## 🎯 Example: Roller Door Business

See `config/mappings/roller_door_mapping.json` for a complete example:

- Column mapping for PDF extraction
- Material pricing rules
- Area calculations with secure formula evaluation
- Lead time estimation
- Installation time formulas
- Material description enrichment
- Loading strategy configuration

## 📚 Next Steps

- Read the [Security Guide](SECURITY_GUIDE.md) for comprehensive security configuration
- Explore [Examples](EXAMPLES.md) for practical use cases
- Check the [API Reference](API_REFERENCE.md) for programmatic usage
- Review the [Developer Guide](DEVELOPER_GUIDE.md) for extending the framework

---

For additional help, check the [main documentation](INDEX.md) or contact <nathan@npc-it.co.uk> for security issues.
