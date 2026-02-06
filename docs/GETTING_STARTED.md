# Getting Started with ETL Framework

## 🚀 1-Minute Setup

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Installation

#### From PyPI (Recommended for Users)
```bash
# Install minimal version (works with CSV/JSON out of the box)
pip install etl-framework

# Install with security features (recommended for production)
pip install etl-framework[security]

# Install with specific features
pip install etl-framework[pdf]          # PDF support
pip install etl-framework[excel]        # Excel support
pip install etl-framework[postgresql]   # PostgreSQL support
pip install etl-framework[mysql]        # MySQL support
pip install etl-framework[sql]          # SQLAlchemy for any database
pip install etl-framework[dotenv]       # Environment variable support
pip install etl-framework[all]          # All optional dependencies
```

#### From Source (Recommended for Developers)
```bash
# Clone the repository
git clone <repository-url>
cd etl-framework

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install with security features (recommended)
pip install -e .[security]

# Or install with specific features
pip install -e .[pdf]          # PDF support
pip install -e .[postgresql]   # PostgreSQL support
pip install -e .[mysql]        # MySQL support
pip install -e .[excel]        # Excel support
pip install -e .[sql]          # SQLAlchemy support
pip install -e .[dotenv]       # Environment variable support
pip install -e .[all]          # All optional dependencies
pip install -e .[test,dev]     # Development dependencies
```

## 🔧 2. Configure Your Environment

### Security Configuration (Recommended)
Create a `.env.security` file:

```bash
# Security Configuration
ETL_SECURITY_ENABLED=true
ETL_SECURITY_LEVEL=production
ETL_ENCRYPTION_ENABLED=true
ETL_ENCRYPTION_KEY=your-secure-encryption-key-here
ETL_RBAC_ENABLED=true
ETL_USERS=admin:admin;operator:operator;viewer:viewer;auditor:auditor
ETL_AUDIT_LOGGING_ENABLED=true
ETL_AUDIT_LOG_FILE=./logs/audit.log
ETL_MAX_FILE_SIZE_MB=10
ETL_ALLOWED_IP_RANGES=127.0.0.1,localhost
```

### Database Configuration (Optional)
Create a `.env` file:

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

# OR for MySQL
ETL_DB_TYPE=mysql
ETL_DB_HOST=localhost
ETL_DB_PORT=3306
ETL_DB_NAME=your_database
ETL_DB_USER=your_user
ETL_DB_PASSWORD=your_password

# Default behaviors
ETL_DEFAULT_EXTRACTOR=csv
ETL_DEFAULT_LOADER=file
ETL_DEFAULT_STRATEGY=replace  # or: fail, append, update, upsert
ETL_KEY_COLUMNS=id,order_date  # for update/upsert strategies
ETL_BATCH_SIZE=1000

# Logging
ETL_LOG_LEVEL=INFO
ETL_LOG_FILE=etl.log

# Column mapping
ETL_COLUMN_MAPPING=roller_door
```

## 📄 3. Create Your First Mapping File

Create `config/mappings/my_business.json`:

```json
{
  "column_mapping": {
    "col_1": "order_id",
    "col_2": "customer_name",
    "col_3": "width",
    "col_4": "height",
    "col_5": "material",
    "col_6": "quantity",
    "col_7": "unit_price"
  },
  "business_rules": {
    "material_prices": {"AL": 120.0, "ST": 180.0},
    "profit_margin": 1.3
  },
  "calculations": [
    {"name": "area", "formula": "width * height"},
    {"name": "total_price", "formula": "area * material_prices[material] * quantity * profit_margin"}
  ]
}
```

## 🚀 4. Run Your First Pipeline

### Process CSV to CSV with Security
```bash
etl-framework \
  --source data/orders.csv \
  --extractor csv \
  --mapping config/mappings/my_business.json \
  --loader file \
  --target output.csv \
  --username operator \
  --security-audit \
  --verbose
```

### Process CSV to Database with Security
```bash
etl-framework \
  --source data/orders.csv \
  --extractor csv \
  --mapping config/mappings/my_business.json \
  --table processed_orders \
  --db sqlite:///etl_database.db \
  --username admin \
  --security-audit
```

### Process PDF with Security (requires PDF support)
```bash
etl-framework \
  --source data/orders.pdf \
  --extractor pdf \
  --mapping config/mappings/my_business.json \
  --table processed_orders \
  --username operator \
  --security-audit
```

## ✅ 5. Verify Results

### Check CSV Output
```bash
head -n 5 output.csv
```

### Check Database (SQLite)
```bash
sqlite3 data/etl_database.db "SELECT * FROM processed_orders LIMIT 5;"
```

### Check Audit Logs
```bash
tail -f ./logs/audit.log
```

## 🎯 Loading Strategies Examples

### 1. REPLACE (Default) - Overwrite existing
```bash
etl-framework --source data.csv --target output.csv --strategy replace --username operator
```

### 2. APPEND - Add to existing
```bash
etl-framework --source new_data.csv --target output.csv --strategy append --username operator
```

### 3. UPDATE - Update existing records only
```bash
etl-framework --source updates.csv --table orders --strategy update --key-columns order_id --username operator
```

### 4. UPSERT - Update existing + insert new (Most Useful!)
```bash
etl-framework --source daily_data.csv --table metrics --strategy upsert --key-columns date,metric_name --username operator
```

### 5. FAIL - Fail if target exists
```bash
etl-framework --source data.csv --target output.csv --strategy fail --username operator
```

## 🔐 Security Features Quick Reference

### Enable/Disable Security
```bash
# Enable security (default)
etl-framework --source data.csv --username operator

# Disable security (not recommended)
etl-framework --source data.csv --disable-security
```

### User Roles and Permissions
```bash
# Available roles: admin, operator, viewer, auditor, data_steward, system
# Configure in .env.security: ETL_USERS="admin:admin;operator:operator"

# Run as different users
etl-framework --source data.csv --username admin    # Full access
etl-framework --source data.csv --username operator # Execute pipelines
etl-framework --source data.csv --username viewer   # Read-only access
```

### Encryption for Sensitive Data
```bash
# Enable encryption in .env.security
ETL_ENCRYPTION_ENABLED=true
ETL_ENCRYPTION_KEY="your-secure-key-here"

# Sensitive columns automatically encrypted:
# - email, ssn, credit_card, password, secret, token
# - Any column with sensitive patterns in name
```

### Audit Logging
```bash
# Enable audit logging in .env.security
ETL_AUDIT_LOGGING_ENABLED=true
ETL_AUDIT_LOG_FILE="./logs/audit.log"

# View audit logs
tail -f ./logs/audit.log

# Search audit logs
python -c "from etl_framework.security.audit_logger import AuditLogger; logger = AuditLogger('./logs/audit.log'); print(logger.search_logs({'user': 'operator'}))"
```

## ⚡ Performance Optimization with Security

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

## 🚨 Troubleshooting

### Permission Denied Errors
```bash
# Error: User 'system' lacks permission to execute pipeline
# Solution: Specify a user with appropriate permissions
etl-framework --source data.csv --username operator

# Configure users in .env.security:
ETL_USERS="admin:admin;operator:operator;viewer:viewer"
```

### Encryption Errors
```bash
# Error: Encryption key required
# Solution: Set encryption key in .env.security
ETL_ENCRYPTION_KEY="your-secure-encryption-key-here"

# Or disable encryption for testing
ETL_ENCRYPTION_ENABLED=false
```

### Input Validation Errors
```bash
# Error: Invalid file path or SQL injection attempt
# Solution: Check your inputs for security violations
# Use --verbose flag to see validation details
etl-framework --source data.csv --username operator --verbose
```

## 🎯 Next Steps

1. **Explore the [User Guide](USER_GUIDE.md)** for detailed usage instructions
2. **Read the [Security Guide](SECURITY_GUIDE.md)** for comprehensive security configuration
3. **Check out [Examples](EXAMPLES.md)** for practical use cases
4. **Review the [API Reference](API_REFERENCE.md)** for programmatic usage
5. **Run the security demo**: `python examples/security_demo.py`

## 📞 Need Help?

- Check the main [documentation](INDEX.md)
- Review example mapping files in `config/mappings/`
- Run security tests: `pytest tests/unit/security/ -v`
- Contact: <nathan@npc-it.co.uk> for security issues

---

Your ETL framework is now ready to process data securely! 🎉
