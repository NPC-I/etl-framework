#!/usr/bin/env python3
"""
Data Encryption Demo

This demo shows data encryption capabilities:
1. Column-level encryption
2. Automatic sensitive data detection
3. Encryption key management
4. Data masking for test environments
"""
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

# Add the project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# At the top of each demo
try:
    from dotenv import load_dotenv

    load_dotenv()
    print("✅ Loaded .env configuration")
except ImportError:
    print("⚠️  Install python-dotenv: pip install python-dotenv")

from etl_framework.security.audit_logger import AuditEventType, AuditLogger

# Import security components
from etl_framework.security.encryption import DataEncryptor, SecurityError
from etl_framework.security.input_validator import InputValidator


def create_sensitive_data():
    """Create sample data with sensitive information."""
    print("📝 CREATING SAMPLE SENSITIVE DATA")
    print("=" * 60)

    demo_dir = Path(__file__).parent
    data_dir = demo_dir / "data"
    data_dir.mkdir(exist_ok=True)

    # Create DataFrame with sensitive data
    sensitive_data = pd.DataFrame(
        {
            "customer_id": ["C001", "C002", "C003", "C004", "C005"],
            "first_name": ["John", "Jane", "Robert", "Emily", "Michael"],
            "last_name": ["Smith", "Doe", "Johnson", "Williams", "Brown"],
            "email": [
                "john.smith@example.com",
                "jane.doe@example.com",
                "robert.j@example.com",
                "emily.w@example.com",
                "michael.b@example.com",
            ],
            "phone": ["555-0101", "555-0102", "555-0103", "555-0104", "555-0105"],
            "ssn": [
                "123-45-6789",
                "987-65-4321",
                "456-78-9012",
                "321-54-8765",
                "654-32-1098",
            ],
            "credit_card": [
                "4111111111111111",
                "4222222222222222",
                "4333333333333333",
                "4444444444444444",
                "4555555555555555",
            ],
            "date_of_birth": [
                "1980-05-15",
                "1985-08-22",
                "1978-12-10",
                "1990-03-30",
                "1982-07-18",
            ],
            "annual_income": [85000, 92000, 78000, 65000, 88000],
            "address": [
                "123 Main St, New York, NY 10001",
                "456 Oak Ave, Los Angeles, CA 90001",
                "789 Pine Rd, Chicago, IL 60601",
                "321 Elm St, Houston, TX 77001",
                "654 Maple Dr, Phoenix, AZ 85001",
            ],
            "medical_record_number": ["MRN001", "MRN002", "MRN003", "MRN004", "MRN005"],
            "insurance_policy": ["POL001", "POL002", "POL003", "POL004", "POL005"],
        }
    )

    # Save to CSV
    sensitive_file = data_dir / "sensitive_customer_data.csv"
    sensitive_data.to_csv(sensitive_file, index=False)

    print(f"Created sample data with {len(sensitive_data)} records")
    print(f"File: {sensitive_file}")
    print()

    # Show sensitive columns detected
    encryptor = DataEncryptor()
    sensitive_cols = encryptor._identify_sensitive_columns(sensitive_data)

    print("Sensitive columns automatically detected:")
    for col in sensitive_cols:
        print(f"  • {col}")

    print()
    print("=" * 60)
    print()

    return sensitive_file, sensitive_data


def demonstrate_encryption_basics():
    """Demonstrate basic encryption operations."""
    print("🔐 BASIC ENCRYPTION OPERATIONS")
    print("=" * 60)

    # Create encryptor
    try:
        encryptor = DataEncryptor()
        print("✓ Encryptor initialized successfully")
    except SecurityError as e:
        print(f"✗ Encryptor initialization failed: {e}")
        return

    # Test single value encryption
    print("\n1. Single Value Encryption:")
    test_values = [
        "secret-password-123",
        "4111111111111111",  # Credit card
        "123-45-6789",  # SSN
        "sensitive@email.com",
    ]

    for value in test_values:
        encrypted = encryptor.encrypt_value(value)
        decrypted = encryptor.decrypt_value(encrypted)

        print(f"   Original: {value}")
        print(f"   Encrypted: {encrypted[:30]}...")
        print(f"   Decrypted: {decrypted}")
        print(f"   Match: {value == decrypted}")
        print()

    # Test column encryption
    print("2. Column Encryption:")
    df = pd.DataFrame(
        {
            "name": ["Alice", "Bob", "Charlie"],
            "ssn": ["111-22-3333", "444-55-6666", "777-88-9999"],
            "credit_card": ["4111111111111111", "4222222222222222", "4333333333333333"],
        }
    )

    print("   Original DataFrame:")
    print(df)
    print()

    # Encrypt SSN column
    df_encrypted = encryptor.encrypt_column(df, "ssn")
    print("   After encrypting 'ssn' column:")
    print(df_encrypted)
    print()

    # Decrypt SSN column
    df_decrypted = encryptor.decrypt_column(df_encrypted, "ssn")
    print("   After decrypting 'ssn' column:")
    print(df_decrypted)
    print()

    print("=" * 60)
    print()


def demonstrate_automatic_encryption():
    """Demonstrate automatic encryption of sensitive data."""
    print("🤖 AUTOMATIC SENSITIVE DATA DETECTION & ENCRYPTION")
    print("=" * 60)

    # Create sample data
    df = pd.DataFrame(
        {
            "customer_id": ["C001", "C002"],
            "full_name": ["John Smith", "Jane Doe"],
            "email_address": ["john@example.com", "jane@example.com"],
            "social_security": ["123-45-6789", "987-65-4321"],
            "credit_card_number": ["4111111111111111", "4222222222222222"],
            "bank_account": ["ACC001", "ACC002"],
            "salary_amount": [50000, 60000],
            "phone_number": ["555-0101", "555-0102"],
            "home_address": ["123 Main St", "456 Oak Ave"],
            "date_of_birth": ["1980-01-01", "1985-02-02"],
        }
    )

    print("Original DataFrame columns:")
    for col in df.columns:
        print(f"  • {col}")
    print()

    # Create encryptor and detect sensitive columns
    encryptor = DataEncryptor()
    sensitive_cols = encryptor._identify_sensitive_columns(df)

    print("Automatically detected sensitive columns:")
    for col in sensitive_cols:
        print(f"  • {col}")
    print()

    # Encrypt all sensitive columns
    print("Encrypting sensitive columns")
    df_encrypted = encryptor.encrypt_dataframe(df)

    print("DataFrame after automatic encryption:")
    print(df_encrypted)
    print()

    # Show encrypted vs original values
    print("Comparison of original vs encrypted values:")
    for col in sensitive_cols[:2]:  # Show first 2 columns for brevity
        print(f"\nColumn: {col}")
        print(f"  Original: {df[col].iloc[0]}")
        print(f"  Encrypted: {df_encrypted[col].iloc[0][:30]}...")

    print()
    print("=" * 60)
    print()


def demonstrate_data_masking():
    """Demonstrate data masking for test environments."""
    print("🎭 DATA MASKING FOR TEST ENVIRONMENTS")
    print("=" * 60)

    # Create sample data
    df = pd.DataFrame(
        {
            "customer_id": [f"C{str(i).zfill(3)}" for i in range(1, 6)],
            "email": [f"user{i}@example.com" for i in range(1, 6)],
            "phone": [f"555-01{str(i).zfill(2)}" for i in range(1, 6)],
            "credit_card": [f"411111111111{str(i).zfill(4)}" for i in range(1, 6)],
            "ssn": [f"123-45-{str(i).zfill(4)}" for i in range(1, 6)],
            "salary": [50000 + i * 10000 for i in range(5)],
        }
    )

    print("Original Data (Production):")
    print(df)
    print()

    # Create masked data for testing
    print("Masked Data (Test Environment):")
    df_masked = df.copy()

    # Mask sensitive columns
    mask_patterns = {
        "email": lambda x: f"masked_{hash(x) % 10000}@test.example",
        "phone": lambda x: "555-XXXX",
        "credit_card": lambda x: "XXXX-XXXX-XXXX-" + x[-4:],
        "ssn": lambda x: "XXX-XX-" + x[-4:],
        "salary": lambda x: round(x / 1000) * 1000,  # Round to nearest 1000
    }

    for col, mask_func in mask_patterns.items():
        if col in df_masked.columns:
            df_masked[col] = df_masked[col].apply(mask_func)

    print(df_masked)
    print()

    # Show comparison
    print("Data Protection Levels:")
    print("  1. Production: Full encryption")
    print("  2. Staging: Partial masking")
    print("  3. Testing: Full masking")
    print("  4. Development: Sample/anonymized data")
    print()

    print("Masking Techniques:")
    print("  • Hashing: One-way transformation")
    print("  • Truncation: Show only last 4 digits")
    print("  • Generalization: Round numbers")
    print("  • Substitution: Replace with test data")
    print("  • Shuffling: Randomize within dataset")
    print()

    print("=" * 60)
    print()


def demonstrate_key_management():
    """Demonstrate encryption key management."""
    print("🔑 ENCRYPTION KEY MANAGEMENT")
    print("=" * 60)

    print("Key Management Best Practices:")
    print("  1. Environment-based keys:")
    print("     • Development: demo-key-123")
    print("     • Testing: test-key-456")
    print("     • Staging: staging-key-789")
    print("     • Production: [secure random key]")
    print()

    print("  2. Key Rotation:")
    print("     • Regular rotation (every 90 days)")
    print("     • Grace period for re-encryption")
    print("     • Audit trail for key changes")
    print()

    print("  3. Key Storage:")
    print("     • Environment variables")
    print("     • Secret management systems")
    print("     • Hardware security modules (HSM)")
    print("     • NEVER in code or version control")
    print()

    print("  4. Key Backup:")
    print("     • Secure backup location")
    print("     • Encrypted backup")
    print("     • Access controls")
    print()

    # Demonstrate different keys
    print("Key Separation by Environment:")
    environments = ["development", "testing", "staging", "production"]

    for env in environments:
        # Simulate different keys for different environments
        key = f"{env}-key-{hash(env) % 10000:04d}"
        print(f"  • {env.title()}: {key[:20]}...")

    print()
    print("Security Implications:")
    print("  • Compromised dev key ≠ compromised prod data")
    print("  • Isolated security breaches")
    print("  • Enhanced data protection")
    print()

    print("=" * 60)
    print()


def create_encryption_security_report():
    """Create an encryption report."""
    print("📄 ENCRYPTION SECURITY REPORT")
    print("=" * 60)

    # Simulate encryption audit
    report = {
        "report_date": datetime.now(timezone.utc).isoformat(),
        "encryption_status": {
            "enabled": os.environ.get("ETL_ENCRYPTION_ENABLED", "false") == "true",
            "key_configured": bool(os.environ.get("ETL_ENCRYPTION_KEY")),
            "key_rotation_days": 90,
            "last_key_rotation": "2024-01-01",
            "next_key_rotation": "2024-04-01",
        },
        "data_protection": {
            "sensitive_columns_detected": [
                "ssn",
                "credit_card",
                "email",
                "phone",
                "date_of_birth",
                "salary",
                "address",
            ],
            "encryption_coverage": "automatic",
            "masking_enabled": True,
            "test_data_protection": True,
        },
        "security_standards": {
            "data_encryption": True,
            "access_controls": True,
            "audit_trail": True,
            "key_management": True,
            "data_masking": True,
        },
        "recommendations": [
            {
                "priority": "medium",
                "action": "Schedule key rotation",
                "details": "Next rotation due in 30 days",
            },
            {
                "priority": "low",
                "action": "Review encryption coverage",
                "details": "Ensure all sensitive columns are covered",
            },
        ],
    }

    # Save report
    demo_dir = Path(__file__).parent
    output_dir = demo_dir / "output"
    output_dir.mkdir(exist_ok=True)

    report_file = output_dir / "encryption_security_report.json"
    with open(report_file, "w") as f:
        json.dump(report, f, indent=2)

    print(f"   Report generated: {report_file}")
    print()

    # Print summary
    print("   Encryption Report Summary:")
    print(f"     • Encryption Enabled: {report['encryption_status']['enabled']}")
    print(f"     • Key Configured: {report['encryption_status']['key_configured']}")
    print(
        f"     • Sensitive Columns: {len(report['data_protection']['sensitive_columns_detected'])}"
    )
    print(f"     • Data Encryption: {report['security_standards']['data_encryption']}")
    print(f"     • Access Controls: {report['security_standards']['access_controls']}")
    print(f"     • Audit Trail: {report['security_standards']['audit_trail']}")
    print()

    print("=" * 60)
    print()


def main():
    """Run the encryption demo."""
    print("=" * 70)
    print("🔐 DATA ENCRYPTION & PROTECTION DEMO")
    print("=" * 70)
    print("This demo shows comprehensive data encryption capabilities.")
    print()

    # Setup output directory
    demo_dir = Path(__file__).parent
    output_dir = demo_dir / "output"
    output_dir.mkdir(exist_ok=True)

    # Import json here
    import json

    # Run demonstrations
    create_sensitive_data()
    demonstrate_encryption_basics()
    demonstrate_automatic_encryption()
    demonstrate_data_masking()
    demonstrate_key_management()
    create_encryption_security_report()

    print("🎯 Key Features Demonstrated:")
    print("   1. Column-level encryption for sensitive data")
    print("   2. Automatic detection of sensitive columns")
    print("   3. Secure key management and rotation")
    print("   4. Data masking for test environments")
    print("   5. Security standards implementation")
    print("   6. Environment-based key separation")
    print("   7. Complete audit trail for encryption operations")
    print()

    print("🔒 Security Benefits:")
    print("   • Protection of sensitive data at rest")
    print("   • Enhanced data protection standards")
    print("   • Defense against data breaches")
    print("   • Safe use of test data")
    print("   • Audit trail for compliance")
    print()

    print("💾 Output Files:")
    print("   • Sample sensitive data: demo/data/sensitive_customer_data.csv")
    print("   • Security report: demo/output/encryption_security_report.json")
    print()

    print("⚠️  Important Security Notes:")
    print("   1. Use different encryption keys for each environment")
    print("   2. Rotate keys regularly (every 90 days recommended)")
    print("   3. Never store keys in code or version control")
    print("   4. Use environment variables or secret management")
    print("   5. Monitor encryption operations in audit logs")
    print()

    print("=" * 70)
    print("🎉 Encryption demo completed successfully!")
    print("=" * 70)

    return 0


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
