# ETL Framework Security Guide

## 🛡️ Security Architecture Overview

The ETL Framework v1.0.0 provides security features designed to protect data and systems throughout the ETL pipeline lifecycle.

### Security Principles

1. **Defense in Depth**: Multiple layers of security controls
2. **Principle of Least Privilege**: Users have minimum necessary permissions
3. **Secure Defaults**: Production-safe default configurations
4. **Comprehensive Audit Trail**: Detailed logging of all security-relevant events
5. **Input Validation**: Validate all inputs before processing

## 🔐 Role-Based Access Control (RBAC)

### Predefined Roles

The framework includes 6 predefined roles with specific permissions:

| Role | Description | Key Permissions |
|------|-------------|-----------------|
| **Admin** | Full system access | All operations including security configuration |
| **Operator** | Execute pipelines | Extract, transform, load, execute pipelines |
| **Viewer** | Read-only access | View configurations and results |
| **Auditor** | Security monitoring | View audit logs and sensitive data (audit only) |
| **Data Steward** | Manage sensitive data | Handle sensitive data with encryption/decryption |
| **System** | Automated processes | Internal system operations |

### Permission Matrix

```python
from etl_framework.security.access_control import Operation

# Available operations
operations = [
    Operation.EXTRACT,          # Extract data from sources
    Operation.TRANSFORM,        # Transform data
    Operation.LOAD,             # Load data to destinations
    Operation.READ_CONFIG,      # Read configuration
    Operation.WRITE_CONFIG,     # Write configuration
    Operation.EXECUTE_PIPELINE, # Execute complete pipelines
    Operation.VIEW_SENSITIVE_DATA,    # View sensitive data
    Operation.MODIFY_SENSITIVE_DATA,  # Modify sensitive data
    Operation.MANAGE_USERS,     # Manage user accounts
    Operation.VIEW_AUDIT_LOGS,  # View audit logs
]
```

### User Configuration

Configure users via environment variable:

```bash
# Format: 'username:role1,role2;username2:role1'
ETL_USERS="admin:admin;operator:operator;viewer:viewer;auditor:auditor"
```

Or programmatically:

```python
from etl_framework.security.access_control import AccessController, Role

controller = AccessController()
controller.add_user('operator', [Role.OPERATOR])
controller.add_user('admin', [Role.ADMIN, Role.OPERATOR])

# Check permissions
has_permission = controller.check_permission('operator', Operation.EXECUTE_PIPELINE)
```

## 🔒 Data Encryption

### Column-Level Encryption

Sensitive columns are automatically encrypted based on naming patterns:

```python
from etl_framework.security.encryption import DataEncryptor

# Initialize encryptor (uses ETL_ENCRYPTION_KEY from environment)
encryptor = DataEncryptor()

# Encrypt sensitive columns in DataFrame
df = pd.DataFrame({
    'name': ['Alice', 'Bob'],
    'email': ['alice@example.com', 'bob@example.com'],
    'ssn': ['123-45-6789', '987-65-4321']
})

encrypted_df = encryptor.encrypt_dataframe(df)
# email and ssn columns are automatically encrypted
```

### Sensitive Data Patterns

The framework automatically detects sensitive columns based on naming patterns:

- **Personal Information**: `email`, `phone`, `address`, `ssn`, `dob`
- **Financial Information**: `credit_card`, `bank_account`, `salary`, `income`
- **Security Credentials**: `password`, `secret`, `key`, `token`, `credential`
- **Medical Information**: `medical`, `health`, `patient`, `diagnosis`

### Encryption Configuration

```bash
# Enable encryption
ETL_ENCRYPTION_ENABLED=true

# Set encryption key (required if encryption enabled)
ETL_ENCRYPTION_KEY="your-secure-encryption-key-here"

# Key rotation period (days)
ETL_KEY_ROTATION_DAYS=90
```

### Manual Encryption/Decryption

```python
# Encrypt single value
encrypted = encryptor.encrypt_value("sensitive-data")

# Decrypt single value
decrypted = encryptor.decrypt_value(encrypted)

# Encrypt specific column
df = encryptor.encrypt_column(df, 'credit_card')

# Decrypt specific column
df = encryptor.decrypt_column(df, 'credit_card')
```

## 🛡️ Input Validation & Sanitization

### SQL Injection Prevention

```python
from etl_framework.security.input_validator import InputValidator

validator = InputValidator()

# Validate SQL identifiers (table/column names)
is_valid = validator.validate_sql_identifier('users_table')  # True
is_valid = validator.validate_sql_identifier('users; DROP TABLE users; --')  # False
```

### Formula Security

```python
# Validate formulas with timeout protection
valid_formula = validator.validate_formula('price * quantity')  # OK

# Dangerous formulas are rejected
try:
    validator.validate_formula('__import__("os").system("rm -rf /")')
except ValueError as e:
    print(f"Security violation: {e}")  # Rejected
```

### File Path Validation

```python
# Validate file paths for security
path = validator.validate_file_path(
    'data/orders.csv',
    allowed_extensions=['.csv', '.xlsx'],
    operation='read'
)

# Path traversal attempts are blocked
try:
    validator.validate_file_path('../../etc/passwd', ['.txt'])
except ValueError as e:
    print(f"Security violation: {e}")  # Rejected
```

### JSON Validation

```python
# Validate JSON files with size limits
data = validator.validate_json_file('config/mapping.json', max_size_mb=10)

# Validate JSON strings
data = validator.validate_json_string('{"key": "value"}', max_length=10000)
```

## 📊 Audit Logging

### Structured Audit Logs

```python
from etl_framework.security.audit_logger import AuditLogger, AuditEventType

# Initialize logger
logger = AuditLogger('./logs/audit.log')

# Log various events
logger.log_event(
    AuditEventType.USER_LOGIN,
    'admin',
    {'method': 'password', 'ip': '192.168.1.100'},
    True
)

logger.log_pipeline_execution(
    'operator',
    'sales_etl',
    'sales.csv',
    'database.sales',
    1500,
    True
)

logger.log_permission_denied(
    'viewer',
    'write_config',
    'production_config.json'
)
```

### Audit Log Format

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "event_type": "pipeline_execution",
  "user": "operator",
  "success": true,
  "details": {
    "pipeline": "sales_etl",
    "source": "sales.csv",
    "target": "database.sales",
    "rows_processed": 1500
  },
  "source_ip": "192.168.1.100",
  "session_id": "session-12345"
}
```

### Log Search and Analysis

```python
# Get recent logs
logs = logger.get_recent_logs(limit=100)

# Search logs by criteria
results = logger.search_logs({
    'user': 'operator',
    'event_type': 'pipeline_execution',
    'success': True
})

for log in results:
    print(f"{log['timestamp']}: {log['user']} executed {log['details']['pipeline']}")
```

## ⚙️ Security Configuration

### Security Levels

The framework supports 4 security levels with different restrictions:

```python
from etl_framework.security.config import SecurityConfig, SecurityLevel

# Development (least restrictive)
config = SecurityConfig(security_level=SecurityLevel.DEVELOPMENT)

# Testing
config = SecurityConfig(security_level=SecurityLevel.TESTING)

# Staging
config = SecurityConfig(security_level=SecurityLevel.STAGING)

# Production (most restrictive)
config = SecurityConfig(security_level=SecurityLevel.PRODUCTION)
```

### Environment Configuration

```bash
# Security Configuration
ETL_SECURITY_ENABLED=true
ETL_SECURITY_LEVEL=production

# Encryption
ETL_ENCRYPTION_ENABLED=true
ETL_ENCRYPTION_KEY=your-secure-encryption-key-here

# Access Control
ETL_RBAC_ENABLED=true
ETL_USERS=admin:admin;operator:operator;viewer:viewer;auditor:auditor

# Audit Logging
ETL_AUDIT_LOGGING_ENABLED=true
ETL_AUDIT_LOG_FILE=./logs/audit.log
ETL_AUDIT_RETENTION_DAYS=365

# Input Validation
ETL_MAX_FILE_SIZE_MB=100
ETL_MAX_JSON_DEPTH=10
ETL_MAX_CALCULATIONS_PER_MAPPING=50

# Network Security
ETL_ALLOW_INSECURE_CONNECTIONS=false
ETL_REQUIRE_TLS=true
ETL_ALLOWED_IP_RANGES=127.0.0.1,localhost
```

### Configuration Validation

```python
config = SecurityConfig.from_environment()
errors = config.validate()

if errors:
    print("Security configuration errors:")
    for error in errors:
        print(f"  - {error}")
else:
    print("Security configuration is valid")

# Check if production
if config.is_production():
    print("Running in production mode with strict security")

# Check security restrictions
restrictions = config.get_restrictions()
print(f"Encryption required: {restrictions['encryption_required']}")
print(f"Input validation: {restrictions['input_validation']}")
print(f"Access control: {restrictions['access_control']}")
```

## 🚨 Security Monitoring

### Security Event Alerts

```python
# Log security events with severity levels
logger.log_security_event(
    'operator',
    'Multiple failed login attempts',
    severity='high',
    details={
        'attempts': 5,
        'ip_address': '192.168.1.100',
        'timeframe': '5 minutes'
    }
)
```

### Real-time Monitoring

```bash
# Monitor audit logs in real-time
tail -f ./logs/audit.log | grep -E '(SECURITY_EVENT|PERMISSION_DENIED)'

# Check for security events
python -c "
from etl_framework.security.audit_logger import AuditLogger
logger = AuditLogger('./logs/audit.log')
events = logger.search_logs({'event_type': 'security_event'})
for event in events:
    print(f"{event['timestamp']}: {event['details']['event']} (severity: {event['details']['severity']})")
"
```

## 🔧 Security Testing

### Run Security Tests

```bash
# Run all security tests
pytest tests/unit/security/ -v

# Run security demonstration
python examples/security_demo.py
```

### Security Test Examples

```python
# Test encryption/decryption
def test_encryption():
    encryptor = DataEncryptor()
    plaintext = "sensitive-data"
    encrypted = encryptor.encrypt_value(plaintext)
    decrypted = encryptor.decrypt_value(encrypted)
    assert decrypted == plaintext

# Test access control
def test_access_control():
    controller = AccessController()
    assert controller.check_permission('admin', Operation.EXECUTE_PIPELINE)
    assert not controller.check_permission('viewer', Operation.EXECUTE_PIPELINE)

# Test input validation
def test_input_validation():
    validator = InputValidator()
    assert validator.validate_sql_identifier('users_table')
    assert not validator.validate_sql_identifier('users; DROP TABLE users; --')
```

## 🎯 Security Best Practices

### 1. Always Enable Security in Production
```bash
ETL_SECURITY_ENABLED=true
ETL_SECURITY_LEVEL=production
```

### 2. Use Strong Encryption Keys
```bash
# Generate strong key
openssl rand -base64 32

# Use in configuration
ETL_ENCRYPTION_KEY="generated-strong-key-here"
```

### 3. Follow Principle of Least Privilege
```bash
# Don't use admin for routine operations
ETL_USERS="operator:operator;viewer:viewer;admin:admin"

# Use appropriate roles
etl-framework --source data.csv --username operator  # Not admin
```

### 4. Enable Comprehensive Audit Logging
```bash
ETL_AUDIT_LOGGING_ENABLED=true
ETL_AUDIT_LOG_FILE="/var/log/etl/audit.log"
ETL_LOG_SENSITIVE_OPERATIONS=true
```

### 5. Regular Security Updates
```bash
# Update dependencies regularly
pip-audit
bandit -r src/
safety check
```

### 6. Monitor Security Events
```bash
# Set up alerts for security events
tail -f /var/log/etl/audit.log | grep -E '(security_event|permission_denied)'

# Regular security reviews
python -c "
from etl_framework.security.audit_logger import AuditLogger
logger = AuditLogger('/var/log/etl/audit.log')
security_events = logger.search_logs({'event_type': 'security_event'})
print(f'Found {len(security_events)} security events in last 24 hours')
"
```

### 7. Secure Configuration Management
- Never commit `.env.security` to version control
- Use environment variables in production
- Rotate encryption keys regularly (every 90 days)
- Store database passwords securely
- Use TLS for database connections

## 📋 Security Compliance

### Security Features Supporting Compliance

While the framework focuses on **security** rather than implementing complete regulatory compliance solutions, its security features can support compliance efforts:

- **Data Protection**: Encryption and access controls support data privacy requirements
- **Audit Trail**: Comprehensive logging supports audit and accountability requirements
- **Access Control**: RBAC supports least privilege and separation of duties
- **Input Validation**: Security validation supports secure processing requirements

### Compliance Responsibility

**Important**: The framework provides security features that can help you build secure applications, but does not implement complete regulatory compliance solutions. Compliance responsibility lies with the application implementing this framework.

## 🚨 Security Incident Response

### 1. Immediate Actions
- Check audit logs: `tail -f ./logs/audit.log`
- Identify affected users and resources
- Temporarily disable affected accounts if necessary
- Preserve evidence (log files, configuration)

### 2. Investigation
```bash
# Search for security events
python -c "
from etl_framework.security.audit_logger import AuditLogger
logger = AuditLogger('./logs/audit.log')
events = logger.search_logs({'event_type': 'security_event'})
for event in events:
    print(f"{event['timestamp']}: {event['user']} - {event['details']['event']}")
"

# Check permission denied events
grep -i 'permission_denied' ./logs/audit.log
```

### 3. Remediation
- Rotate encryption keys if compromised
- Review and update user permissions
- Update security configuration
- Patch vulnerabilities

### 4. Reporting
- Document incident details
- Report to appropriate stakeholders
- Update security procedures

## 📞 Security Support

For security vulnerabilities or issues:

1. **Check Documentation**: Review this security guide
2. **Run Security Tests**: `pytest tests/unit/security/ -v`
3. **Review Audit Logs**: Check `./logs/audit.log`
4. **Contact Security Team**: <nathan@npc-it.co.uk>

---

**Remember**: Security is a continuous process. Regularly review and update your security configuration, monitor audit logs, and stay informed about security best practices.
