#!/usr/bin/env python3
"""
Security Features Demonstration

This script demonstrates the security features added in v0.3.0.
"""
import os
import tempfile
from pathlib import Path

import pandas as pd

# Set up environment for demo
os.environ["ETL_ENCRYPTION_KEY"] = "demo-encryption-key-12345"
os.environ["ETL_USERS"] = "admin:admin;operator:operator;viewer:viewer"

from etl_framework.security.access_control import AccessController, Operation, Role
from etl_framework.security.audit_logger import AuditEventType, AuditLogger
from etl_framework.security.config import SecurityConfig

# Import security modules
from etl_framework.security.encryption import DataEncryptor
from etl_framework.security.input_validator import InputValidator


def demo_encryption():
    """Demonstrate data encryption features."""
    print("\n=== Data Encryption Demo ===")

    # Create encryptor
    encryptor = DataEncryptor()

    # Create sample data with sensitive information
    df = pd.DataFrame(
        {
            "name": ["Alice Smith", "Bob Johnson", "Charlie Brown"],
            "email": ["alice@example.com", "bob@example.com", "charlie@example.com"],
            "ssn": ["123-45-6789", "987-65-4321", "456-78-9012"],
            "credit_card": ["4111111111111111", "4222222222222222", "4333333333333333"],
            "salary": [50000, 60000, 70000],
        }
    )

    print("Original DataFrame:")
    print(df)

    # Encrypt sensitive columns
    encrypted_df = encryptor.encrypt_dataframe(df)
    print("\nEncrypted DataFrame (sensitive columns encrypted):")
    print(encrypted_df)

    # Decrypt to verify
    decrypted_df = encryptor.decrypt_column(encrypted_df, "ssn")
    print("\nDecrypted SSN column:")
    print(decrypted_df[["name", "ssn"]])

    # Test single value encryption
    plaintext = "secret-password-123"
    encrypted = encryptor.encrypt_value(plaintext)
    decrypted = encryptor.decrypt_value(encrypted)
    print(f"\nSingle value encryption test:")
    print(f"  Plaintext: {plaintext}")
    print(f"  Encrypted: {encrypted[:20]}...")
    print(f"  Decrypted: {decrypted}")
    print(f"  Match: {plaintext == decrypted}")


def demo_access_control():
    """Demonstrate role-based access control."""
    print("\n=== Access Control Demo ===")

    # Create access controller
    controller = AccessController()

    # List users
    print("Configured users:")
    for user in controller.list_users():
        print(f"  - {user['username']}: {user['roles']}")

    # Test permissions
    test_cases = [
        ("admin", Operation.EXECUTE_PIPELINE, "Should have permission"),
        ("admin", Operation.MANAGE_USERS, "Should have permission"),
        ("operator", Operation.EXECUTE_PIPELINE, "Should have permission"),
        ("operator", Operation.MANAGE_USERS, "Should NOT have permission"),
        ("viewer", Operation.READ_CONFIG, "Should have permission"),
        ("viewer", Operation.WRITE_CONFIG, "Should NOT have permission"),
    ]

    print("\nPermission tests:")
    for username, operation, expected in test_cases:
        has_permission = controller.check_permission(username, operation)
        status = "✓" if has_permission == ("NOT" not in expected) else "✗"
        print(f"  {status} {username}.{operation.value}: {expected}")

    # Test resource-level permissions
    print("\nResource-level permissions:")
    sensitive_resource = "sensitive_customer_data"
    admin_has_access = controller.check_permission(
        "admin", Operation.VIEW_SENSITIVE_DATA, sensitive_resource
    )
    operator_has_access = controller.check_permission(
        "operator", Operation.VIEW_SENSITIVE_DATA, sensitive_resource
    )

    print(f"  Admin access to '{sensitive_resource}': {admin_has_access}")
    print(f"  Operator access to '{sensitive_resource}': {operator_has_access}")


def demo_input_validation():
    """Demonstrate input validation features."""
    print("\n=== Input Validation Demo ===")

    validator = InputValidator()

    # Test SQL identifier validation
    print("SQL Identifier Validation:")
    identifiers = [
        ("users", True, "Valid table name"),
        ("user_table", True, "Valid table name"),
        ("users; DROP TABLE users; --", False, "SQL injection attempt"),
        ("table' OR '1'='1", False, "SQL injection attempt"),
        ("123table", False, "Starts with number"),
    ]

    for identifier, expected_valid, description in identifiers:
        is_valid = validator.validate_sql_identifier(identifier)
        status = "✓" if is_valid == expected_valid else "✗"
        print(f"  {status} '{identifier}': {description} (valid: {is_valid})")

    # Test formula validation
    print("\nFormula Validation:")
    formulas = [
        ("price * quantity", True, "Valid formula"),
        ("total / count", True, "Valid formula"),
        ('__import__("os").system("rm -rf /")', False, "Dangerous code"),
        ('open("/etc/passwd")', False, "File access attempt"),
    ]

    for formula, expected_valid, description in formulas:
        try:
            validated = validator.validate_formula(formula)
            is_valid = True
        except ValueError:
            is_valid = False

        status = "✓" if is_valid == expected_valid else "✗"
        print(f"  {status} '{formula[:30]}...': {description} (valid: {is_valid})")

    # Test file path validation
    print("\nFile Path Validation:")
    with tempfile.NamedTemporaryFile(suffix=".csv") as f:
        try:
            path = validator.validate_file_path(f.name, [".csv"])
            print(f"  ✓ Valid CSV file: {path}")
        except ValueError as e:
            print(f"  ✗ Invalid file: {e}")

        try:
            validator.validate_file_path(f.name, [".json"])
            print(f"  ✗ Should reject wrong extension")
        except ValueError:
            print(f"  ✓ Correctly rejected wrong extension")


def demo_audit_logging():
    """Demonstrate audit logging features."""
    print("\n=== Audit Logging Demo ===")

    # Create temporary log file
    with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as f:
        log_file = f.name

    try:
        # Create audit logger
        logger = AuditLogger(log_file)

        # Log various events
        logger.log_event(
            AuditEventType.USER_LOGIN,
            "admin",
            {"method": "password", "ip": "192.168.1.100"},
            True,
        )

        logger.log_pipeline_execution(
            "operator", "sales_etl", "sales.csv", "database.sales", 1500, True
        )

        logger.log_data_access(
            "viewer", "customer_data", "read", {"filter": "status=active"}
        )

        logger.log_permission_denied("viewer", "write_config", "production_config.json")

        # Get recent logs
        logs = logger.get_recent_logs()
        print(f"Logged {len(logs)} audit events:")
        for log in logs:
            print(f"  - {log['event_type']} by {log['user']} ({log['timestamp']})")

        # Search logs
        search_results = logger.search_logs({"user": "operator"})
        print(f"\nFound {len(search_results)} events by 'operator':")
        for result in search_results:
            print(
                f"  - {result['event_type']}: {result['details'].get('pipeline', 'N/A')}"
            )

    finally:
        # Clean up
        Path(log_file).unlink(missing_ok=True)


def demo_security_config():
    """Demonstrate security configuration."""
    print("\n=== Security Configuration Demo ===")

    # Test different security levels
    security_levels = ["development", "testing", "staging", "production"]

    for level in security_levels:
        os.environ["ETL_SECURITY_LEVEL"] = level
        config = SecurityConfig.from_environment()
        restrictions = config.get_restrictions()

        print(f"\nSecurity Level: {level.upper()}")
        print(f"  Encryption required: {restrictions['encryption_required']}")
        print(f"  Input validation: {restrictions['input_validation']}")
        print(f"  Access control: {restrictions['access_control']}")
        print(f"  Show error details: {restrictions['error_details']}")

    # Reset environment
    os.environ.pop("ETL_SECURITY_LEVEL", None)


def main():
    """Run all security demos."""
    print("ETL Framework v0.3.0 - Security Features Demonstration")
    print("=" * 60)

    try:
        demo_encryption()
        demo_access_control()
        demo_input_validation()
        demo_audit_logging()
        demo_security_config()

        print("\n" + "=" * 60)
        print("All security demos completed successfully!")
        print("\nSummary of security features:")
        print("1. Data encryption for sensitive columns")
        print("2. Role-Based Access Control (RBAC)")
        print("3. Input validation and sanitization")
        print("4. Comprehensive audit logging")
        print("5. Environment-based security configuration")
        print("6. SQL injection prevention")
        print("7. Secure formula evaluation")

    except Exception as e:
        print(f"\nError during demo: {e}")
        import traceback

        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
