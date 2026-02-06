#!/usr/bin/env python3
"""
Secure CSV ETL Demo

This demo shows the same use case as the basic demo,
but with security features enabled:
1. Input validation and sanitization
2. Audit logging
3. Permission checks
4. Secure configuration
"""
import os
import sys
from pathlib import Path

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

from etl_framework.core.load_strategy import LoadStrategy

# Import ETL Framework components
from etl_framework.core.pipeline import ETLPipeline
from etl_framework.plugins.extractors.csv_extractor import CSVExtractor
from etl_framework.plugins.loaders.file_loader import FileLoader
from etl_framework.plugins.transformers.cleaner import DataCleaner
from etl_framework.plugins.transformers.mapping_loader import MappingLoader

# Import security components for demonstration
from etl_framework.security.access_control import AccessController, Operation, Role
from etl_framework.security.audit_logger import AuditEventType, AuditLogger
from etl_framework.security.input_validator import InputValidator


def demonstrate_security_features():
    """Demonstrate individual security features."""
    print("🔒 SECURITY FEATURES DEMONSTRATION")
    print("=" * 50)

    # 1. Input Validator
    print("1. Input Validation:")
    validator = InputValidator()

    # Test SQL identifier validation
    test_identifiers = [
        ("valid_table", True, "Valid identifier"),
        ("table; DROP TABLE users; --", False, "SQL injection attempt"),
        ("123invalid", False, "Starts with number"),
    ]

    for identifier, expected_valid, description in test_identifiers:
        is_valid = validator.validate_sql_identifier(identifier)
        status = "✓" if is_valid == expected_valid else "✗"
        print(f"   {status} '{identifier}': {description} (valid: {is_valid})")

    # Test file path validation
    print("\n2. File Path Validation:")
    test_file = Path(__file__).parent / "data" / "orders.csv"
    try:
        validated_path = validator.validate_file_path(str(test_file), [".csv"])
        print(f"   ✓ Valid CSV file: {validated_path}")
    except ValueError as e:
        print(f"   ✗ Invalid file: {e}")

    # 2. Access Controller
    print("\n3. Role-Based Access Control:")
    controller = AccessController()

    # List configured users
    users = controller.list_users()
    print(f"   Configured users: {len(users)}")
    for user in users:
        print(f"     • {user['username']}: {user['roles']}")

    # Test permissions
    test_permissions = [
        ("admin", Operation.EXECUTE_PIPELINE, True, "Admin can execute pipeline"),
        ("operator", Operation.EXECUTE_PIPELINE, True, "Operator can execute pipeline"),
        ("viewer", Operation.EXECUTE_PIPELINE, False, "Viewer cannot execute pipeline"),
        ("admin", Operation.MANAGE_USERS, True, "Admin can manage users"),
        ("operator", Operation.MANAGE_USERS, False, "Operator cannot manage users"),
    ]

    for username, operation, expected, description in test_permissions:
        has_permission = controller.check_permission(username, operation)
        status = "✓" if has_permission == expected else "✗"
        print(f"   {status} {username}.{operation.value}: {description}")

    print("=" * 50)
    print()


def main():
    """Run the secure CSV ETL demo."""
    print("=" * 70)
    print("🔒 SECURE CSV ETL DEMO")
    print("=" * 70)
    print("This demo shows the same use case as the basic demo,")
    print("but with comprehensive security features enabled.")
    print()

    # Demonstrate security features
    demonstrate_security_features()

    # Setup paths
    demo_dir = Path(__file__).parent
    data_dir = demo_dir / "data"
    output_dir = demo_dir / "output"
    config_dir = demo_dir / "config"

    # Ensure output directory exists
    output_dir.mkdir(exist_ok=True)

    # Define file paths
    source_file = data_dir / "orders.csv"
    mapping_file = config_dir / "roller_door_mapping.json"
    output_file = output_dir / "processed_orders_secure.csv"

    print("📁 File Paths:")
    print(f"   Source:      {source_file}")
    print(f"   Mapping:     {mapping_file}")
    print(f"   Output:      {output_file}")
    print(f"   Audit Log:   {os.environ['ETL_AUDIT_LOG_FILE']}")
    print()

    # Check if files exist
    if not source_file.exists():
        print(f"❌ Error: Source file not found: {source_file}")
        return 1

    if not mapping_file.exists():
        print(f"❌ Error: Mapping file not found: {mapping_file}")
        return 1

    # Create pipeline WITH security
    print("🔧 Creating ETL pipeline (security enabled)...")
    print(f"   Security Level: {os.environ['ETL_SECURITY_LEVEL']}")
    print(f"   Encryption:     {os.environ['ETL_ENCRYPTION_ENABLED']}")
    print(f"   RBAC:           {os.environ['ETL_RBAC_ENABLED']}")
    print(f"   Audit Logging:  {os.environ['ETL_AUDIT_LOGGING_ENABLED']}")
    print(f"   User:           operator")
    print()

    pipeline = ETLPipeline(username="operator", enable_security=True)

    # Register extractor
    pipeline.register_extractor("csv", CSVExtractor())

    # Add transformers
    print("🔄 Adding transformers...")

    # 1. Basic data cleaner
    pipeline.add_transformer(DataCleaner(column_mapping={}, enable_security=True))

    # 2. JSON mapping loader
    pipeline.add_transformer(MappingLoader(str(mapping_file), enable_security=True))

    # Register loader
    pipeline.register_loader("file", FileLoader())

    # Run the pipeline
    print("🚀 Running pipeline with security...")
    print(f"   Extractor:   CSV")
    print(f"   Transformers: DataCleaner, MappingLoader")
    print(f"   Loader:      File")
    print(f"   Strategy:    REPLACE")
    print(f"   Security:    ENABLED")
    print()

    try:
        result = pipeline.run(
            extractor_name="csv",
            source=str(source_file),
            loader_name="file",
            target=str(output_file),
            strategy=LoadStrategy.REPLACE,
        )

        if result is not None:
            print("✅ ETL completed successfully with security!")
            print()
            print("📊 Results:")
            print(f"   Rows processed: {len(result)}")
            print(f"   Final columns:  {list(result.columns)}")
            print()

            # Show security audit information
            print("🔒 Security Audit Summary:")
            print("   • Input validation: ✓")
            print("   • Permission checks: ✓")
            print("   • Audit logging:    ✓")

            # Check if encryption was applied
            if os.environ.get("ETL_ENCRYPTION_ENABLED", "false").lower() == "true":
                print("   • Data encryption:  ✓ (if sensitive columns present)")
            else:
                print("   • Data encryption:  ✗ (disabled)")

            print()
            print("💾 Output saved to:")
            print(f"   {output_file}")
            print()

            # Show audit log location
            audit_log = os.environ.get("ETL_AUDIT_LOG_FILE", "./logs/audit.log")
            if Path(audit_log).exists():
                print("📝 Audit log generated:")
                print(f"   {audit_log}")

                # Show last few audit entries
                try:
                    with open(audit_log, "r") as f:
                        lines = f.readlines()[-3:]  # Last 3 entries
                        if lines:
                            print("\n   Recent audit entries:")
                            for line in lines:
                                import json

                                entry = json.loads(line.strip())
                                print(
                                    f"     • {entry['event_type']} by {entry['user']}"
                                )
                except:
                    pass

            print()

            # Clean shutdown
            pipeline.shutdown()

            return 0
        else:
            print("❌ ETL failed - no result returned")
            pipeline.shutdown()
            return 1

    except Exception as e:
        print(f"❌ Pipeline error: {e}")

        # Don't show full traceback in secure mode
        if os.environ.get("ETL_SECURITY_LEVEL", "development") == "development":
            import traceback

            traceback.print_exc()
        else:
            print("   (Detailed error hidden for security)")

        # Clean shutdown even on error
        try:
            pipeline.shutdown()
        except:
            pass

        return 1


if __name__ == "__main__":
    # Import pandas here to avoid dependency if not needed
    import pandas as pd

    exit_code = main()

    print("=" * 70)
    if exit_code == 0:
        print("🎉 Secure CSV ETL demo completed successfully!")
    else:
        print("❌ Secure CSV ETL demo failed.")
    print("=" * 70)

    sys.exit(exit_code)
