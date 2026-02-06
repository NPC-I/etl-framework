#!/usr/bin/env python3
"""
JSON Business Logic Demo

This demo shows JSON-driven business logic capabilities:
1. Define business rules in JSON
2. Complex calculations and lookups
3. Conditional transformations
4. Loading strategy configuration
"""
import json
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
from etl_framework.plugins.transformers.secure_json_calculator import (
    SecureJSONBusinessCalculator,
)


def demonstrate_json_configurations():
    """Demonstrate different JSON configuration examples."""
    print("📋 JSON CONFIGURATION EXAMPLES")
    print("=" * 60)

    # Example 1: Simple column mapping
    simple_mapping = {
        "column_mapping": {
            "col_1": "order_id",
            "col_2": "customer_name",
            "col_3": "amount",
        }
    }

    print("1. Simple Column Mapping:")
    print(json.dumps(simple_mapping, indent=2))
    print()

    # Example 2: Business rules with calculations
    business_rules = {
        "business_rules": {
            "tax_rate": 0.2,
            "discount_rate": 0.1,
            "shipping_rates": {"standard": 5.99, "express": 12.99, "overnight": 24.99},
        },
        "calculations": [
            {"name": "subtotal", "formula": "quantity * unit_price"},
            {
                "name": "discount_amount",
                "formula": "subtotal * discount_rate",
                "condition": "has:subtotal",
            },
            {
                "name": "tax_amount",
                "formula": "(subtotal - discount_amount) * tax_rate",
            },
            {
                "name": "total_amount",
                "formula": "subtotal - discount_amount + tax_amount + shipping_cost",
            },
        ],
    }

    print("2. Business Rules with Calculations:")
    print(json.dumps(business_rules, indent=2))
    print()

    # Example 3: Complex conditional logic
    complex_logic = {
        "calculations": [
            {
                "name": "customer_tier",
                "lookup": "customer_tiers[customer_id]",
                "condition": "has:customer_id",
            },
            {
                "name": "customer_tier",
                "value": "standard",
                "condition": "not:has:customer_id",
            },
            {
                "name": "discount_rate",
                "formula": "tier_discounts[customer_tier]",
                "condition": "has:customer_tier",
            },
            {
                "name": "final_price",
                "formula": "base_price * (1 - discount_rate)",
                "condition": "has:discount_rate",
            },
            {
                "name": "final_price",
                "formula": "base_price",
                "condition": "not:has:discount_rate",
            },
        ]
    }

    print("3. Complex Conditional Logic:")
    print(json.dumps(complex_logic, indent=2))
    print()

    print("=" * 60)
    print()


def create_custom_mapping():
    """Create a custom JSON mapping for the demo."""
    demo_dir = Path(__file__).parent
    config_dir = demo_dir / "config"

    custom_mapping = {
        "column_mapping": {
            "order_id": "order_id",
            "customer_name": "customer_name",
            "door_width": "door_width",
            "door_height": "door_height",
            "material": "material",
            "quantity": "quantity",
            "unit_price": "unit_price",
            "order_date": "order_date",
        },
        "business_rules": {
            "material_prices": {"AL": 120.0, "ST": 180.0, "WO": 250.0},
            "installation_rates": {"small": 100.0, "medium": 150.0, "large": 200.0},
            "tax_rate": 0.2,
            "profit_margin": 1.3,
            "warranty_years": 5,
        },
        "calculations": [
            {
                "name": "area_sq_units",
                "formula": "door_width * door_height",
                "description": "Calculate door area",
            },
            {
                "name": "size_category",
                "formula": "pd.cut(area_sq_units, bins=[0, 5000000, 10000000, float('inf')], labels=['small', 'medium', 'large'])",
                "description": "Categorize by size",
            },
            {
                "name": "material_cost",
                "lookup": "material_prices[material]",
                "description": "Get material price",
                "condition": "has:material",
            },
            {
                "name": "installation_cost",
                "lookup": "installation_rates[size_category]",
                "description": "Get installation cost",
                "condition": "has:size_category",
            },
            {
                "name": "material_total",
                "formula": "area_sq_units * material_cost",
                "description": "Total material cost",
                "condition": "has:material_cost",
            },
            {
                "name": "production_cost",
                "formula": "material_total + installation_cost",
                "description": "Total production cost",
                "condition": "has:material_total",
            },
            {
                "name": "sale_price_before_tax",
                "formula": "production_cost * profit_margin",
                "description": "Sale price before tax",
                "condition": "has:production_cost",
            },
            {
                "name": "tax_amount",
                "formula": "sale_price_before_tax * tax_rate",
                "description": "Tax amount",
                "condition": "has:sale_price_before_tax",
            },
            {
                "name": "total_price",
                "formula": "sale_price_before_tax + tax_amount",
                "description": "Total price including tax",
                "condition": "has:sale_price_before_tax",
            },
            {
                "name": "warranty_end_date",
                "formula": "order_date + pd.DateOffset(years=warranty_years)",
                "description": "Warranty end date",
                "condition": "has:order_date",
            },
            {
                "name": "profit_margin_percentage",
                "formula": "(profit_margin - 1) * 100",
                "description": "Profit margin as percentage",
            },
        ],
        "loading_strategy": {
            "strategy": "upsert",
            "key_columns": ["order_id"],
            "batch_size": 1000,
            "create_index": True,
            "drop_duplicates": True,
        },
    }

    custom_file = config_dir / "custom_business_logic.json"
    with open(custom_file, "w") as f:
        json.dump(custom_mapping, f, indent=2)

    print(f"📝 Created custom JSON mapping: {custom_file}")
    print()

    return custom_file


def main():
    """Run the JSON business logic demo."""
    print("=" * 70)
    print("📋 JSON BUSINESS LOGIC DEMO")
    print("=" * 70)
    print("This demo shows JSON-driven business logic capabilities.")
    print()

    # Demonstrate JSON configurations
    demonstrate_json_configurations()

    # Setup paths
    demo_dir = Path(__file__).parent
    data_dir = demo_dir / "data"
    output_dir = demo_dir / "output"
    config_dir = demo_dir / "config"

    # Ensure directories exist
    output_dir.mkdir(exist_ok=True)

    # Create custom JSON mapping
    print("📝 Creating custom JSON mapping for demo...")
    custom_mapping_file = create_custom_mapping()

    # Define file paths
    source_file = data_dir / "orders.csv"
    output_file = output_dir / "orders_with_business_logic.csv"

    print("📁 File Paths:")
    print(f"   Source:  {source_file}")
    print(f"   Mapping: {custom_mapping_file}")
    print(f"   Output:  {output_file}")
    print()

    # Check if source file exists
    if not source_file.exists():
        print(f"❌ Error: Source file not found: {source_file}")
        return 1

    # Create pipeline
    print("🔧 Creating ETL pipeline...")
    pipeline = ETLPipeline(username="operator", enable_security=True)

    # Register extractor
    pipeline.register_extractor("csv", CSVExtractor())

    # Add transformers
    print("🔄 Adding transformers...")

    # 1. Basic data cleaner
    pipeline.add_transformer(DataCleaner(column_mapping={}, enable_security=True))

    # 2. JSON mapping loader
    pipeline.add_transformer(
        MappingLoader(str(custom_mapping_file), enable_security=True)
    )

    # 3. Secure JSON business calculator
    # Load the mapping to create calculator
    with open(custom_mapping_file, "r") as f:
        mapping_config = json.load(f)

    calculator = SecureJSONBusinessCalculator(mapping_config)
    pipeline.add_transformer(calculator)

    # Register loader
    pipeline.register_loader("file", FileLoader())

    # Run the pipeline
    print("🚀 Running pipeline with JSON business logic...")
    print(f"   Extractor:   CSV")
    print(f"   Transformers: DataCleaner, MappingLoader, SecureJSONBusinessCalculator")
    print(f"   Loader:      File")
    print(f"   Strategy:    REPLACE")
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
            print("✅ JSON business logic processing completed successfully!")
            print()
            print("📊 Results:")
            print(f"   Rows processed: {len(result)}")
            print(f"   Total columns:  {len(result.columns)}")
            print()

            # Show original vs calculated columns
            original_cols = [
                "order_id",
                "customer_name",
                "door_width",
                "door_height",
                "material",
                "quantity",
                "unit_price",
                "order_date",
            ]
            calculated_cols = [
                col for col in result.columns if col not in original_cols
            ]

            print("📈 Business Logic Calculations Applied:")
            for col in calculated_cols:
                # Get calculation description from mapping
                description = ""
                for calc in mapping_config.get("calculations", []):
                    if calc.get("name") == col:
                        description = calc.get("description", "")
                        break

                if description:
                    print(f"   • {col}: {description}")
                else:
                    print(f"   • {col}")

            print()
            print("🔍 Sample of calculated data:")

            # Select a subset of columns to display
            display_cols = [
                "order_id",
                "customer_name",
                "area_sq_units",
                "size_category",
                "production_cost",
                "total_price",
                "warranty_end_date",
                "profit_margin_percentage",
            ]

            # Filter to columns that exist in result
            display_cols = [col for col in display_cols if col in result.columns]

            if display_cols:
                print(result[display_cols].head(3).to_string())
            else:
                print(result.head(3).to_string())

            print()

            # Show loading strategy from JSON
            loading_strategy = mapping_config.get("loading_strategy", {})
            if loading_strategy:
                print("⚙️  Loading Strategy from JSON:")
                print(
                    f"   Strategy:      {loading_strategy.get('strategy', 'replace')}"
                )
                print(
                    f"   Key Columns:   {', '.join(loading_strategy.get('key_columns', []))}"
                )
                print(f"   Batch Size:    {loading_strategy.get('batch_size', 1000)}")
                print(
                    f"   Create Index:  {loading_strategy.get('create_index', False)}"
                )

            print()
            print("💾 Output saved to:")
            print(f"   {output_file}")
            print()

            # Show JSON configuration benefits
            print("🎯 Benefits of JSON-Driven Business Logic:")
            print("   1. No code changes needed for business rule updates")
            print("   2. Business users can modify rules without developers")
            print("   3. Version control for business logic")
            print("   4. Easy testing of different rule sets")
            print("   5. Secure formula evaluation with validation")

            # Clean shutdown
            pipeline.shutdown()

            return 0
        else:
            print("❌ Processing failed - no result returned")
            pipeline.shutdown()
            return 1

    except Exception as e:
        print(f"❌ Pipeline error: {e}")
        import traceback

        traceback.print_exc()

        # Clean shutdown even on error
        try:
            pipeline.shutdown()
        except:
            pass

        return 1


if __name__ == "__main__":
    # Import pandas here to avoid dependency if not needed
    import numpy as np
    import pandas as pd

    exit_code = main()

    print("=" * 70)
    if exit_code == 0:
        print("🎉 JSON business logic demo completed successfully!")
    else:
        print("❌ JSON business logic demo failed.")
    print("=" * 70)

    sys.exit(exit_code)
