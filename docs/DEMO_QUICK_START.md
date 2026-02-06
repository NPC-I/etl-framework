# ETL Framework v1.0.0 - Comprehensive Demo Suite

This demo suite provides real-world examples of the ETL Framework's capabilities, with a focus on enterprise-grade security and compliance.

## 🚀 Quick Start

### 1. Setup Environment
```bash
# Run the setup script
python demo/setup_demo.py

# Or manually:
cp demo/.env.example .env
cp demo/.env.security.example .env.security

# Install the framework with security features
pip install -e .[security,all]

# Create necessary directories
mkdir -p demo/data demo/output demo/config logs
```

### 2. Run Demos in Order
```bash
# Start with basic functionality
python demo/01_basic_csv_etl.py

# Then explore security features
python demo/02_secure_csv_etl.py

# Continue through all demos
python demo/03_pdf_extraction.py
python demo/04_database_operations.py
python demo/06_json_business_logic.py
python demo/07_audit_logging_demo.py
python demo/08_rbac_demo.py
python demo/09_encryption_demo.py
python demo/10_end_to_end_scenario.py
```

### 3. Test All Demos
```bash
# Run the test suite
python demo/test_demos.py
```

## 📁 Demo Structure

```
demo/
├── README.md                    # This file
├── setup_demo.py               # Environment setup script
├── test_demos.py               # Demo test suite
├── .env.example                # Environment configuration template
├── .env.security.example       # Security configuration template
├── 01_basic_csv_etl.py        # Basic CSV ETL without security
├── 02_secure_csv_etl.py       # CSV ETL with security features
├── 03_pdf_extraction.py       # PDF table extraction demo
├── 04_database_operations.py  # Database loading strategies
├── 06_json_business_logic.py  # JSON-driven business logic
├── 07_audit_logging_demo.py   # Audit logging and compliance
├── 08_rbac_demo.py           # Role-Based Access Control demo
├── 09_encryption_demo.py     # Data encryption demo
├── 10_end_to_end_scenario.py # Complete real-world scenario
├── config/                    # Configuration files
│   ├── roller_door_mapping.json
│   ├── financial_mapping.json
│   ├── customer_mapping.json
│   ├── production_customer_mapping.json
│   ├── production_order_mapping.json
│   └── production_analytics_mapping.json
├── data/                      # Sample data files
│   ├── orders.csv
│   ├── customers.csv
│   ├── sensitive_customer_data.csv
│   ├── production_customers.csv
│   ├── production_orders.csv
│   └── production_products.csv
└── output/                    # Generated output files
    ├── processed_orders.csv
    ├── etl_database.db
    ├── audit.log
    └── security_report.json
