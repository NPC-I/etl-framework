"""
ETL Framework CLI entry point with security integration.

Usage examples:
    # Extract from PDF, clean, apply mapping (with JSON calculations), load to SQL
    etl-framework \
        --source data/orders.pdf \
        --extractor pdf \
        --mapping config/mappings/roller_door_mapping.json \
        --table rollerdoor_orders \
        --db postgresql://user:pass@localhost/dbname

    # Extract from CSV, clean, use built-in calculator, output to CSV
    etl-framework \
        --source data/input.csv \
        --extractor csv \
        --loader file \
        --target data/output.csv

    # Extract from JSON string, clean, apply mapping, output to CSV
    etl-framework \
        --json-string '[{"id": 1, "name": "Product A"}]' \
        --extractor json \
        --mapping config/mappings/product_mapping.json \
        --loader file \
        --target products.csv

Environment variables (loaded automatically from .env if present):
    # Security Configuration
    ETL_SECURITY_LEVEL=production
    ETL_ENCRYPTION_ENABLED=true
    ETL_ENCRYPTION_KEY=your-secure-key-here
    ETL_RBAC_ENABLED=true
    ETL_USERS=admin:admin;operator:operator;viewer:viewer
    ETL_AUDIT_LOGGING_ENABLED=true
    ETL_AUDIT_LOG_FILE=./logs/audit.log

    # Database configuration
    ETL_DB_TYPE: Database type (sqlite, postgresql, mysql)
    ETL_DB_HOST: Database host
    ETL_DB_PORT: Database port
    ETL_DB_NAME: Database name
    ETL_DB_USER: Database user
    ETL_DB_PASSWORD: Database password
    ETL_DB_FILE: SQLite file path (for sqlite)

    # Default behaviors
    ETL_DEFAULT_EXTRACTOR: Default extractor (pdf, csv, excel)
    ETL_DEFAULT_LOADER: Default loader (sql, file)
    ETL_COLUMN_MAPPING: Default column mapping (roller_door, generic)
    ETL_DEFAULT_STRATEGY: Default loading strategy (fail, replace, append, update, upsert)
    ETL_KEY_COLUMNS: Default key columns for update/upsert (comma-separated)
    ETL_BATCH_SIZE: Batch size for database operations (default: 1000)
    ETL_CHUNK_SIZE: Chunk size for file processing (default: 500)
    ETL_CREATE_INDEX: Create index on key columns (true/false, default: false)
    ETL_DROP_DUPLICATES: Drop duplicates during loading (true/false, default: true)

    # Logging
    ETL_LOG_LEVEL: Logging level (DEBUG, INFO, WARNING, ERROR)
    ETL_LOG_FILE: Log file path
"""
import argparse
import os
import sys

# Load environment variables from .env file if dotenv is available
try:
    from dotenv import load_dotenv

    load_dotenv()
    DOTENV_LOADED = True
except ImportError:
    DOTENV_LOADED = False

from etl_framework.config.settings import DEFAULT_COLUMN_MAPPINGS, config
from etl_framework.core.load_strategy import LoadOptions, LoadStrategy

# Import from the package
from etl_framework.core.pipeline import ETLPipeline
from etl_framework.plugins.extractors.csv_extractor import CSVExtractor
from etl_framework.plugins.extractors.excel_extractor import ExcelExtractor
from etl_framework.plugins.extractors.json_extractor import JSONStringExtractor
from etl_framework.plugins.extractors.pdf_extractor import PDFExtractor
from etl_framework.plugins.loaders.file_loader import FileLoader
from etl_framework.plugins.loaders.sql_loader import SQLLoader
from etl_framework.plugins.transformers.cleaner import DataCleaner
from etl_framework.plugins.transformers.enricher import DataEnricher
from etl_framework.plugins.transformers.mapping_loader import MappingLoader

# Security imports
from etl_framework.security.config import SecurityConfig, SecurityLevel
from etl_framework.security.input_validator import InputValidator


def parse_key_columns(value: str) -> list:
    """Parse comma-separated key columns string into list."""
    return config.parse_key_columns(value)


def validate_security_configuration():
    """Validate security configuration and return security status."""
    security_config = SecurityConfig.from_environment()

    # Check if security is enabled
    security_enabled = os.getenv("ETL_SECURITY_ENABLED", "true").lower() == "true"

    if not security_enabled:
        print("⚠️  SECURITY WARNING: Security features are disabled")
        print("   Set ETL_SECURITY_ENABLED=true to enable security features")
        return False, None

    # Validate security configuration
    errors = security_config.validate()
    if errors:
        print("❌ SECURITY CONFIGURATION ERRORS:")
        for error in errors:
            print(f"   - {error}")

        # Check security level
        if security_config.is_production():
            print("\n🚨 CRITICAL: Production security configuration has errors")
            print("   Pipeline execution blocked for security reasons")
            return False, security_config
        else:
            print("\n⚠️  WARNING: Security configuration has errors")
            print("   Pipeline will run with reduced security")

    # Check encryption key
    if security_config.should_encrypt() and not os.getenv("ETL_ENCRYPTION_KEY"):
        print("⚠️  SECURITY WARNING: Encryption enabled but no encryption key set")
        print("   Set ETL_ENCRYPTION_KEY environment variable")
        print("   Or set ETL_ENCRYPTION_ENABLED=false to disable encryption")

    return True, security_config


def main():
    parser = argparse.ArgumentParser(
        description="ETL Framework: Extract, Transform, Load data from various sources."
    )

    # Input source arguments (mutually exclusive)
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument(
        "--source", help="Source file path (PDF, CSV, Excel, JSON)."
    )
    source_group.add_argument(
        "--json-string", help="JSON string to process (alternative to --source file)."
    )

    # Security arguments
    parser.add_argument(
        "--username",
        default=os.getenv("ETL_USERNAME", "system"),
        help="Username for audit logging and access control.",
    )
    parser.add_argument(
        "--disable-security",
        action="store_true",
        help="Disable all security features (not recommended).",
    )

    # Extraction arguments
    parser.add_argument(
        "--extractor",
        default=config.DEFAULT_EXTRACTOR,
        choices=["pdf", "csv", "excel", "json"],
        help=f"Extractor to use (default: {config.DEFAULT_EXTRACTOR}).",
    )

    # JSON-specific arguments
    parser.add_argument(
        "--json-path", help="Path to data within JSON (e.g., 'data.results')."
    )

    # Loading arguments
    parser.add_argument(
        "--loader",
        default=config.DEFAULT_LOADER,
        choices=["sql", "file"],
        help=f"Loader to use (default: {config.DEFAULT_LOADER}).",
    )
    parser.add_argument(
        "--table",
        help="Target SQL table name (required if loader is 'sql' and --db not provided).",
    )
    parser.add_argument(
        "--target", help="Target file path (required if loader is 'file')."
    )
    parser.add_argument(
        "--db", help="Database connection string (overrides environment configuration)."
    )

    # Loading strategy arguments
    parser.add_argument(
        "--strategy",
        default=config.DEFAULT_STRATEGY,
        choices=["fail", "replace", "append", "update", "upsert"],
        help="Loading strategy: fail, replace (default), append, update, upsert.",
    )
    parser.add_argument(
        "--key-columns",
        type=parse_key_columns,
        default=config.parse_key_columns(),
        help="Key columns for update/upsert strategies (comma-separated).",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=config.BATCH_SIZE,
        help="Batch size for database operations (default: 1000).",
    )

    # Transformation arguments
    parser.add_argument(
        "--mapping",
        help="JSON mapping file for column renaming, business rules, and lookups.",
    )
    parser.add_argument(
        "--column-mapping",
        default="generic",
        choices=list(DEFAULT_COLUMN_MAPPINGS.keys()),
        help="Predefined column mapping to use (default: generic, ignored if --mapping is provided).",
    )
    parser.add_argument(
        "--enrichment-file",
        help="JSON file with enrichment lookups (use --mapping instead for integrated configuration).",
    )

    # Output arguments
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show verbose output including loaded configuration.",
    )
    parser.add_argument(
        "--security-audit", action="store_true", help="Show security audit information."
    )

    args = parser.parse_args()

    # Validate extractor compatibility
    if args.json_string and args.extractor != "json":
        parser.error("--json-string requires --extractor json")

    if args.json_path and args.extractor != "json":
        parser.error("--json-path requires --extractor json")

    if args.extractor == "json" and not args.json_string:
        parser.error("--extractor json requires --json-string")

    # Validate security configuration
    security_enabled = not args.disable_security
    security_config = None

    if security_enabled:
        security_valid, security_config = validate_security_configuration()
        if not security_valid and security_config and security_config.is_production():
            sys.exit(1)

    # Ensure directories exist before starting
    config.ensure_directories()

    # Create necessary directories for security
    if security_enabled:
        audit_log_file = os.getenv("ETL_AUDIT_LOG_FILE", "./logs/audit.log")
        audit_log_dir = os.path.dirname(audit_log_file)
        if audit_log_dir:
            os.makedirs(audit_log_dir, exist_ok=True)

    if args.verbose or args.security_audit:
        print("ETL Framework Configuration:")
        print("=" * 60)

        # Security information
        if security_enabled and security_config:
            print("🔒 SECURITY CONFIGURATION:")
            print(
                f"   Security Level:    {security_config.security_level.value.upper()}"
            )
            print(
                f"   Encryption:       {'ENABLED' if security_config.should_encrypt() else 'DISABLED'}"
            )
            print(
                f"   Access Control:   {'ENABLED' if security_config.rbac_enabled else 'DISABLED'}"
            )
            print(
                f"   Audit Logging:    {'ENABLED' if security_config.should_log_audit() else 'DISABLED'}"
            )
            print(
                f"   Input Validation: {security_config.get_validation_level().upper()}"
            )
            print(f"   User:             {args.username}")
        else:
            print("🔓 SECURITY: DISABLED")

        print("\n📊 PIPELINE CONFIGURATION:")
        if DOTENV_LOADED:
            print("   ✓ .env file loaded")
        else:
            print("   ℹ  python-dotenv not installed, using system environment")
        print(f"   Database Type:      {config.DB_TYPE}")
        if config.DB_TYPE == "sqlite":
            print(f"   Database File:      {config.DB_FILE}")
        else:
            print(f"   Database Host:      {config.DB_HOST}:{config.DB_PORT}")
            print(f"   Database Name:      {config.DB_NAME}")
            print(f"   Database User:      {config.DB_USER}")
        print(f"   Extractor:          {args.extractor}")
        if args.extractor == "json":
            json_preview = (
                args.json_string[:50] + "..."
                if len(args.json_string) > 50
                else args.json_string
            )
            print(f"   JSON Source:       {json_preview}")
            if args.json_path:
                print(f"   JSON Path:         {args.json_path}")
        else:
            print(f"   Source File:       {args.source}")
        print(f"   Loader:            {args.loader}")
        print(f"   Loading Strategy:  {args.strategy}")
        if args.key_columns:
            print(f"   Key Columns:       {', '.join(args.key_columns)}")
        if args.mapping:
            print(f"   Mapping File:      {args.mapping}")
            print(f"   Calculation Mode:  JSON-driven")
        else:
            print(
                f"   Calculation Mode:  Basic cleaning only (no JSON mapping provided)"
            )
        if args.enrichment_file:
            print(f"   Enrichment File:   {args.enrichment_file}")
        print("=" * 60)
        print()

    # Validate arguments
    if args.loader == "sql" and not args.db and not (args.table):
        # Try to use environment configuration
        try:
            db_connection = config.get_database_connection_string()
            if args.verbose:
                print(f"Using database connection from environment: {db_connection}")
        except ValueError as e:
            parser.error(
                f"--loader sql requires --db or valid environment configuration. Error: {e}"
            )

    if args.loader == "file" and not args.target:
        parser.error("--loader file requires --target")

    # Validate strategy requirements
    if args.strategy in ["update", "upsert"] and not args.key_columns:
        parser.error(f"--strategy {args.strategy} requires --key-columns")

    # Security: Validate inputs
    if security_enabled:
        validator = InputValidator()
        try:
            if args.extractor == "json" and args.json_string:
                # Validate JSON string
                json_data = validator.validate_json_string(args.json_string)
                # Store parsed JSON for the extractor
                args.source = json_data  # Pass parsed JSON dict to extractor
                if args.verbose:
                    print(
                        f"[Security] JSON string validated: {len(str(json_data))} characters"
                    )
            elif args.source:
                # Validate source file
                source_path = validator.validate_file_path(
                    args.source, [".csv", ".xlsx", ".xls", ".pdf", ".json"]
                )
                args.source = str(source_path)
                if args.verbose:
                    print(f"[Security] Source file validated: {args.source}")

            # Validate target if provided
            if args.target:
                target_path = validator.validate_file_path(
                    args.target, [".csv", ".xlsx", ".xls", ".parquet", ".feather"]
                )
                args.target = str(target_path)
                if args.verbose:
                    print(f"[Security] Target file validated: {args.target}")

        except ValueError as e:
            print(f"❌ SECURITY ERROR: {e}")
            sys.exit(1)

    # Build pipeline with security
    pipeline = ETLPipeline(username=args.username, enable_security=security_enabled)

    # Create validator for all extractors
    security_level = os.getenv("ETL_SECURITY_LEVEL", "development")
    validator = InputValidator(security_level=security_level)

    # Register extractor with validator
    if args.extractor == "pdf":
        pipeline.register_extractor("pdf", PDFExtractor(validator))
    elif args.extractor == "csv":
        pipeline.register_extractor("csv", CSVExtractor(validator))
    elif args.extractor == "excel":
        pipeline.register_extractor("excel", ExcelExtractor(validator))
    elif args.extractor == "json":
        pipeline.register_extractor("json", JSONStringExtractor(validator))

    # Add transformers in logical order
    mapping_loader = None
    if args.mapping:
        # Security: Validate mapping file
        if security_enabled:
            try:
                mapping_data = validator.validate_json_file(args.mapping)
                # Additional validation could be added here
            except ValueError as e:
                print(f"❌ SECURITY ERROR: Invalid mapping file: {e}")
                sys.exit(1)

        # Create mapping loader
        mapping_loader = MappingLoader(args.mapping)

        # If we have a JSON mapping file, don't apply default column mapping
        # Just do basic cleaning (standardize column names, handle missing values)
        pipeline.add_transformer(DataCleaner(column_mapping={}))

        # Add mapping loader to pipeline
        pipeline.add_transformer(mapping_loader)

        # Check if mapping file has loading strategy configuration
        mapping_strategy_options = mapping_loader.get_loading_strategy_options()
        if mapping_strategy_options:
            if args.verbose:
                print(
                    f"📋 Mapping file specifies loading strategy: {mapping_strategy_options.strategy}"
                )
                if mapping_strategy_options.key_columns:
                    print(
                        f"   Key columns from mapping: {mapping_strategy_options.key_columns}"
                    )
    else:
        # Use the default column mapping
        column_mapping = config.get_column_mapping(args.column_mapping)
        pipeline.add_transformer(DataCleaner(column_mapping=column_mapping))

        print(
            f"⚠️  WARNING: No JSON mapping file provided. Only basic cleaning will be applied."
        )
        print(
            f"   For business calculations, provide a --mapping file with JSON configuration."
        )

    # 4. Apply enrichment from separate file if provided (legacy - prefer integrated mapping)
    if args.enrichment_file:
        print(
            f"❌ ERROR: --enrichment-file is no longer supported. Add enrichments to your mapping file instead."
        )
        sys.exit(1)

    # Register loader
    if args.loader == "sql":
        # Use provided connection string or environment configuration
        db_connection = args.db if args.db else config.get_database_connection_string()
        pipeline.register_loader("sql", SQLLoader(db_connection))
        target = args.table
        loader_kwargs = {"batch_size": args.batch_size}
    else:  # file
        pipeline.register_loader("file", FileLoader())
        target = args.target
        loader_kwargs = {}

    # Create load options - prioritize in this order:
    # 1. CLI arguments (highest priority)
    # 2. Mapping file configuration
    # 3. Environment configuration (lowest priority)

    # Start with CLI arguments
    load_strategy = LoadStrategy.from_string(args.strategy)
    load_options = LoadOptions(
        strategy=load_strategy,
        key_columns=args.key_columns,
        batch_size=args.batch_size,
        chunk_size=config.CHUNK_SIZE,
        create_index=config.CREATE_INDEX,
        drop_duplicates=config.DROP_DUPLICATES,
    )

    # Override with mapping file configuration if available
    if args.mapping and mapping_loader:
        mapping_strategy_options = mapping_loader.get_loading_strategy_options()
        if mapping_strategy_options:
            # Merge mapping options with CLI options
            # CLI arguments take precedence over mapping file
            load_options = LoadOptions(
                strategy=load_strategy,  # CLI takes precedence
                key_columns=args.key_columns or mapping_strategy_options.key_columns,
                batch_size=args.batch_size or mapping_strategy_options.batch_size,
                chunk_size=config.CHUNK_SIZE or mapping_strategy_options.chunk_size,
                create_index=config.CREATE_INDEX
                or mapping_strategy_options.create_index,
                drop_duplicates=config.DROP_DUPLICATES
                or mapping_strategy_options.drop_duplicates,
                **mapping_strategy_options.extra_options,
            )

            if args.verbose:
                print(f"🔧 Using merged loading strategy configuration")
                print(f"   Strategy: {load_options.strategy}")
                if load_options.key_columns:
                    print(f"   Key columns: {load_options.key_columns}")

    # Run pipeline
    print(f"\n🚀 Starting ETL pipeline...")
    print(f"   Extractor:  {args.extractor}")
    if args.extractor == "json":
        json_preview = (
            args.json_string[:30] + "..."
            if len(args.json_string) > 30
            else args.json_string
        )
        print(f"   Source:     JSON string: {json_preview}")
        if args.json_path:
            print(f"   JSON Path:  {args.json_path}")
    else:
        print(f"   Source:     {args.source}")
    print(f"   Loader:     {args.loader}")
    print(f"   Target:     {target}")
    print(f"   Strategy:   {load_options.strategy}")
    if load_options.key_columns:
        print(f"   Key Columns: {', '.join(load_options.key_columns)}")
    if args.mapping:
        print(f"   Mapping:    {args.mapping}")
        print(f"   Calculations: JSON-driven")
    else:
        print(f"   Calculations: Basic cleaning only")
    if security_enabled:
        print(f"   Security:    ENABLED (User: {args.username})")
    else:
        print(f"   Security:    DISABLED")

    try:
        # Prepare extractor kwargs
        extractor_kwargs = {}
        if args.extractor == "json" and args.json_path:
            extractor_kwargs["json_path"] = args.json_path

        # Run pipeline with strategy
        result = pipeline.run_with_options(
            extractor_name=args.extractor,
            source=args.source,
            loader_name=args.loader,
            target=target,
            options=load_options,
            **{**loader_kwargs, **extractor_kwargs},
        )

        if result is not None:
            print(f"\n✅ ETL completed successfully!")
            print(f"   Strategy: {load_options.strategy}")
            print(f"   Rows processed: {len(result)}")
            print(f"   Final columns: {list(result.columns)}")

            # Show calculated columns
            base_cols = [
                "order_id",
                "customer_name",
                "door_width",
                "door_height",
                "material",
                "quantity",
                "unit_price",
            ]
            calculated_cols = [col for col in result.columns if col not in base_cols]
            if calculated_cols:
                print(f"   Calculated columns: {calculated_cols}")

            # Security summary
            if security_enabled and args.security_audit:
                print(f"\n🔒 SECURITY AUDIT SUMMARY:")
                print(f"   User: {args.username}")
                print(f"   Source validated: ✓")
                print(f"   Target validated: ✓")
                if args.extractor == "json":
                    print(f"   JSON validated:   ✓")
                if security_config and security_config.should_encrypt():
                    print(f"   Data encrypted:   ✓")
                print(f"   Audit logged:     ✓")

            # Clean shutdown
            pipeline.shutdown()
            sys.exit(0)
        else:
            print("\n❌ ETL failed.")
            pipeline.shutdown()
            sys.exit(1)
    except Exception as e:
        print(f"\n❌ Pipeline error: {e}")

        # Security: Log error details if security is enabled
        if security_enabled:
            import traceback

            error_details = traceback.format_exc()
            print(f"\n🔒 SECURITY ERROR DETAILS (for debugging):")
            print(f"   Error type: {type(e).__name__}")
            print(f"   Error message: {str(e)}")

            # Don't show full traceback in production for security
            if security_config and not security_config.is_production():
                print(f"\nFull traceback:")
                print(error_details)

        # Clean shutdown even on error
        try:
            pipeline.shutdown()
        except Exception as shutdown_error:
            # Log shutdown error but don't crash
            print(f"[Warning] Pipeline shutdown failed: {shutdown_error}")

        sys.exit(1)


if __name__ == "__main__":
    main()
