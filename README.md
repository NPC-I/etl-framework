# ETL Framework v1.0.0

A **fully JSON-driven**, modular ETL framework designed for extracting data from PDFs (and other sources), transforming it with configurable business logic, and loading to databases or files with intelligent strategies.

## 🚀 Key Features

- **JSON-Driven Configuration**: All business logic, calculations, and mappings defined in JSON files
- **Zero-Code Business Logic**: Modify calculations, pricing, and rules without touching Python code
- **Plugin Architecture**: Easily add new extractors, transformers, and loaders
- **PDF-First**: Built-in PDF table extraction using `pdfplumber`
- **Pandas-Centric**: All transformations operate on pandas DataFrames
- **Database Agnostic**: SQL loading via SQLAlchemy (PostgreSQL, MySQL, SQLite, etc.)
- **Environment-Aware**: Configuration via environment variables (`.env` file supported)
- **Smart Loading Strategies**: 5 loading strategies including UPSERT (update + insert)
- **Security**: Role-Based Access Control, data encryption, audit logging, input validation

## 🔒 Security Features

### 1. Role-Based Access Control (RBAC)
- **6 Predefined Roles**: Admin, Operator, Viewer, Auditor, Data Steward, System
- **Resource-Level Permissions**: Fine-grained control over data access
- **Environment Configuration**: User roles configured via environment variables

### 2. Data Protection
- **Column-Level Encryption**: Automatic encryption of sensitive data (SSN, email, credit cards)
- **Secure Key Management**: Environment-based encryption keys
- **Data Masking**: Sensitive data protection in test environments

### 3. Input Validation & Sanitization
- **SQL Injection Prevention**: Validated SQL identifiers and parameterized queries
- **Path Traversal Protection**: Secure file path validation
- **Formula Security**: Safe formula evaluation with timeout protection
- **JSON Schema Validation**: Secure JSON configuration validation

### 4. Audit Logging & Monitoring
- **Structured JSON Logs**: Comprehensive audit trail in JSON format
- **Security Event Monitoring**: Real-time security alerts
- **Access Tracking**: Detailed logging of all data access and modifications

### 5. Secure Configuration
- **4 Security Levels**: Development, Testing, Staging, Production
- **Environment-Based Security**: Security configuration via environment variables
- **Secure Defaults**: Production-safe default configurations

## 📦 Installation

### From PyPI (Recommended)

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

### From Source (Development)

```bash
# Clone the repository
git clone https://github.com/NPC-I/etl-framework.git
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

## ⚡ Quick Start

### 1. Create Your Mapping File

Create `config/mappings/my_business.json`:

```json
{
  "column_mapping": {
    "col_1": "order_id",
    "col_2": "customer_name",
    "col_3": "product_width",
    "col_4": "product_height"
  },
  "business_rules": {
    "material_prices": {"AL": 120.0, "ST": 180.0},
    "profit_margin": 1.3,
    "base_installation_days": 2
  },
  "calculations": [
    {
      "name": "area",
      "formula": "product_width * product_height"
    },
    {
      "name": "material_price",
      "lookup": "material_prices[material]"
    },
    {
      "name": "total_price",
      "formula": "area * material_price * quantity * profit_margin"
    }
  ]
}
```

### 2. Run Your First Pipeline

```bash
# Process CSV with security features enabled
etl-framework \
  --source data/orders.csv \
  --extractor csv \
  --mapping config/mappings/my_business.json \
  --loader file \
  --target data/output.csv \
  --username operator \
  --security-audit
```

### 3. Load to Database

```bash
# Load to SQLite database
etl-framework \
  --source data/orders.csv \
  --extractor csv \
  --mapping config/mappings/my_business.json \
  --table processed_orders \
  --db sqlite:///etl_database.db \
  --username admin \
  --security-audit
```

## 🎯 Loading Strategies

The framework supports 5 loading strategies:

| Strategy | Description | Use Case |
|----------|-------------|----------|
| **REPLACE** (Default) | Overwrites existing data | Fresh imports |
| **APPEND** | Adds new data to existing | Incremental loads |
| **UPDATE** | Updates existing records only | Data corrections |
| **UPSERT** | Updates existing + inserts new | Daily updates |
| **FAIL** | Fails if target exists | Safety checks |

```bash
# UPSERT example (updates existing, inserts new)
etl-framework \
  --source daily_data.csv \
  --table metrics \
  --strategy upsert \
  --key-columns date,metric_name \
  --username operator
```

## 🔐 Security Quick Start

### Enable Basic Security

```bash
# Set minimal security environment variables
export ETL_SECURITY_ENABLED=true
export ETL_SECURITY_LEVEL=testing
export ETL_USERS="admin:admin;operator:operator"

# Run pipeline with security
etl-framework --source data.csv --username operator --security-audit
```

### Enable Encryption

```bash
# Enable encryption
export ETL_ENCRYPTION_ENABLED=true
export ETL_ENCRYPTION_KEY="your-secure-key-here"

# Sensitive columns automatically encrypted
etl-framework --source sensitive_data.csv --username admin
```

## 📁 Supported Formats

### Extraction
- **PDF** (.pdf) - Table extraction via pdfplumber
- **CSV** (.csv) - Comma-separated values
- **Excel** (.xlsx, .xls) - Microsoft Excel files
- **JSON** (.json) - JSON files and strings

### Loading
- **CSV** (.csv) - Universal format
- **Excel** (.xlsx, .xls) - Microsoft Excel
- **Parquet** (.parquet) - Columnar format, efficient for analytics
- **Feather** (.feather) - Fast binary format
- **Databases** - PostgreSQL, MySQL, SQLite via SQLAlchemy

## 📖 Documentation

For comprehensive documentation, visit the [GitHub repository](https://github.com/NPC-I/etl-framework):

- [Getting Started Guide](https://github.com/NPC-I/etl-framework/blob/main/docs/GETTING_STARTED.md)
- [User Guide](https://github.com/NPC-I/etl-framework/blob/main/docs/USER_GUIDE.md)
- [Security Guide](https://github.com/NPC-I/etl-framework/blob/main/docs/SECURITY_GUIDE.md)
- [API Reference](https://github.com/NPC-I/etl-framework/blob/main/docs/API_REFERENCE.md)
- [Examples](https://github.com/NPC-I/etl-framework/blob/main/docs/EXAMPLES.md)

## 🧪 Testing

```bash
# Run all tests
pytest tests/

# Run security tests
pytest tests/unit/security/ -v

# Run security demonstration
python examples/security_demo.py
```

## 🤝 Contributing

Contributions are welcome! Please see the [Contributing Guide](https://github.com/NPC-I/etl-framework/blob/main/docs/DEVELOPER_GUIDE.md#contributing) for details.

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.

## 🛡️ Security Reporting

For security vulnerabilities, please contact: <nathan@npc-it.co.uk>

All security issues will be promptly addressed in accordance with our security policy.
