# ETL Framework v1.0.0 - Comprehensive Documentation

## 📚 Documentation Overview

Welcome to the ETL Framework documentation. This modular, JSON-driven ETL framework provides enterprise-grade security features for data extraction, transformation, and loading operations.

### Quick Navigation

- **[Getting Started](GETTING_STARTED.md)** - Installation and basic setup
- **[User Guide](USER_GUIDE.md)** - Complete usage instructions
- **[Security Guide](SECURITY_GUIDE.md)** - Security features and configuration
- **[CI/CD Guide](CI_CD_GUIDE.md)** - Automated security gates and deployment
- **[API Reference](API_REFERENCE.md)** - Detailed API documentation
- **[Examples](EXAMPLES.md)** - Practical usage examples
- **[Developer Guide](DEVELOPER_GUIDE.md)** - Extending and contributing

## 🚀 Key Features

### Core Features
- **JSON-Driven Configuration**: Define business logic, calculations, and mappings in JSON files
- **Zero-Code Business Logic**: Modify calculations and rules without touching Python code
- **Plugin Architecture**: Easily add new extractors, transformers, and loaders
- **PDF-First Design**: Built-in PDF table extraction using `pdfplumber`
- **Pandas-Centric**: All transformations operate on pandas DataFrames
- **Database Agnostic**: SQL loading via SQLAlchemy (PostgreSQL, MySQL, SQLite, etc.)
- **Smart Loading Strategies**: 5 loading strategies including UPSERT (update + insert)

### Enterprise Security Features
- **Role-Based Access Control (RBAC)**: 6 predefined roles with fine-grained permissions
- **Data Encryption**: Column-level encryption for sensitive data
- **Input Validation**: Comprehensive validation for SQL, formulas, and file paths
- **Audit Logging**: Structured JSON audit trails for security monitoring
- **Secure Configuration**: Environment-based security with 4 security levels
- **CI/CD Security Gates**: Automated security scanning and compliance checks"

## 📦 Installation

### From PyPI (Recommended)
```bash
# Install minimal version
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
git clone <repository-url>
cd etl-framework
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -e .[security,test,dev]
```

## ⚡ Quick Start

### 1. Create a Mapping File
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
    "profit_margin": 1.3
  },
  "calculations": [
    {"name": "area", "formula": "product_width * product_height"},
    {"name": "total_price", "formula": "area * material_prices[material] * quantity * profit_margin"}
  ]
}
```

### 2. Run Your First Pipeline
```bash
etl-framework \
  --source data/orders.csv \
  --extractor csv \
  --mapping config/mappings/my_business.json \
  --loader file \
  --target output.csv \
  --username operator \
  --security-audit
```

## 🔒 Security Quick Start

### Enable Basic Security
```bash
export ETL_SECURITY_ENABLED=true
export ETL_SECURITY_LEVEL=testing
export ETL_USERS="admin:admin;operator:operator"

etl-framework --source data.csv --username operator --security-audit
```

### Enable Encryption
```bash
export ETL_ENCRYPTION_ENABLED=true
export ETL_ENCRYPTION_KEY="your-secure-key-here"

etl-framework --source sensitive_data.csv --username admin
```

## 📁 Project Structure

```
ETL_Framework/
├── src/etl_framework/          # Package source code
│   ├── core/                   # Abstract interfaces & pipeline orchestrator
│   ├── plugins/                # Concrete implementations
│   ├── security/               # Security components (RBAC, encryption, audit logging)
│   ├── config/                 # Configuration management
│   └── cli/                    # Command-line interface
├── .github/workflows/          # CI/CD workflows with security gates
│   ├── security-audit.yml      # Comprehensive security scanning
│   ├── test-suite.yml          # Multi-python testing
│   ├── build-release.yml       # Automated packaging and publishing
│   └── demo-validation.yml     # Demo script validation
├── config/                     # Configuration files
│   └── mappings/   
├── data/                       # Sample data files
├── tests/                      # Test suite
├── examples/                   # Usage examples
├── docs/                       # Documentation
├── pyproject.toml             # Modern package configuration
└── LICENSE                    # MIT License
```

## 🎯 Loading Strategies

The framework supports 5 loading strategies:

1. **REPLACE** (Default) - Overwrites existing data
2. **APPEND** - Adds new data to existing
3. **UPDATE** - Updates existing records only (requires key columns)
4. **UPSERT** - Updates existing AND inserts new (requires key columns)
5. **FAIL** - Fails if target already exists

## 🛡️ Security Features

### Role-Based Access Control (RBAC)
- **6 Predefined Roles**: Admin, Operator, Viewer, Auditor, Data Steward, System
- **Fine-Grained Permissions**: Resource-level access control
- **Environment Configuration**: User roles configured via environment variables

### Data Protection
- **Column-Level Encryption**: Automatic encryption of sensitive data
- **Secure Key Management**: Environment-based encryption keys
- **Data Masking**: Sensitive data protection in test environments

### Input Validation & Sanitization
- **SQL Injection Prevention**: Validated SQL identifiers and parameterized queries
- **Path Traversal Protection**: Secure file path validation
- **Formula Security**: Safe formula evaluation with timeout protection
- **JSON Schema Validation**: Secure JSON configuration validation

### Audit Logging & Monitoring
- **Structured JSON Logs**: Comprehensive audit trail in JSON format
- **Security Event Monitoring**: Real-time security alerts
- **Access Tracking**: Detailed logging of all data access and modifications

## 📞 Support

- **Documentation**: [GitHub Repository](https://github.com/NPC-I/etl-framework)
- **Issues**: [GitHub Issues](https://github.com/NPC-I/etl-framework/issues)
- **Security Issues**: Contact <nathan@npc-it.co.uk>

## 📄 License

MIT License - See [LICENSE](../LICENSE) for details.

---

**Note**: This framework provides security features for data processing pipelines. While these security features can support compliance efforts, the framework focuses on **security** (protecting data and systems) rather than **compliance** (meeting regulatory requirements). Compliance responsibility lies with the application implementing this framework.
