#!/usr/bin/env python3
"""
Basic CSV ETL Demo

This demo shows the simplest use case of the ETL Framework:
1. Extract data from a CSV file
2. Apply basic cleaning and transformation
3. Load to an output CSV file
4. No security features enabled
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


def main():
    """Run the basic CSV ETL demo."""
    print("=" * 70)
    print("📊 BASIC CSV ETL DEMO")
    print("=" * 70)
    print("This demo shows the simplest use case of the ETL Framework.")
    print("No security features are enabled in this demo.")
    print()

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
    output_file = output_dir / "processed_orders_basic.csv"

    print("📁 File Paths:")
    print(f"   Source:      {source_file}")
    print(f"   Mapping:     {mapping_file}")
    print(f"   Output:      {output_file}")
    print()

    # Check if files exist
    if not source_file.exists():
        print(f"❌ Error: Source file not found: {source_file}")
        return 1

    if not mapping_file.exists():
        print(f"❌ Error: Mapping file not found: {mapping_file}")
        return 1

    # Create pipeline WITHOUT security
    print("🔧 Creating ETL pipeline (security disabled)...")
    pipeline = ETLPipeline(username="demo_user", enable_security=False)

    # Register extractor
    pipeline.register_extractor("csv", CSVExtractor())

    # Add transformers
    print("🔄 Adding transformers...")

    # 1. Basic data cleaner
    pipeline.add_transformer(DataCleaner(column_mapping={}))

    # 2. JSON mapping loader
    pipeline.add_transformer(MappingLoader(str(mapping_file)))

    # Register loader
    pipeline.register_loader("file", FileLoader())

    # Run the pipeline
    print("🚀 Running pipeline...")
    print(f"   Extractor:   CSV")
    print(f"   Transformers: DataCleaner, MappingLoader")
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
            print("✅ ETL completed successfully!")
            print()
            print("📊 Results:")
            print(f"   Rows processed: {len(result)}")
            print(f"   Original columns: {list(pd.read_csv(source_file).columns)}")
            print(f"   Final columns:    {list(result.columns)}")
            print()

            # Show calculated columns
            base_cols = [
                "order_id",
                "customer_name",
                "door_width",
                "door_height",
                "material",
                "quantity",
                "unit_price",
                "order_date",
            ]
            calculated_cols = [col for col in result.columns if col not in base_cols]

            if calculated_cols:
                print("📈 Calculated columns:")
                for col in calculated_cols:
                    print(f"   • {col}")

            print()
            print("💾 Output saved to:")
            print(f"   {output_file}")
            print()

            # Show sample of output
            print("🔍 Sample of processed data:")
            print(result.head(3).to_string())
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
    import pandas as pd

    exit_code = main()

    print("=" * 70)
    if exit_code == 0:
        print("🎉 Basic CSV ETL demo completed successfully!")
    else:
        print("❌ Basic CSV ETL demo failed.")
    print("=" * 70)

    sys.exit(exit_code)
