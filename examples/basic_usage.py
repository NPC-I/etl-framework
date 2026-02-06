"""
Basic usage example for the ETL Framework.

This example shows how to:
1. Create a simple mapping configuration
2. Process a CSV file
3. Apply business calculations
4. Save results to a database
"""
import json
import os
import tempfile
from pathlib import Path

from etl_framework.config.settings import config

# Import the ETL Framework
from etl_framework.core.pipeline import ETLPipeline
from etl_framework.plugins.extractors.csv_extractor import CSVExtractor
from etl_framework.plugins.loaders.file_loader import FileLoader
from etl_framework.plugins.loaders.sql_loader import SQLLoader
from etl_framework.plugins.transformers.cleaner import DataCleaner
from etl_framework.plugins.transformers.mapping_loader import MappingLoader


def example_csv_to_csv():
    """
    Example 1: Process CSV file and output to CSV with business calculations.
    """
    print("=" * 60)
    print("Example 1: CSV to CSV with Business Calculations")
    print("=" * 60)

    # Create a temporary CSV file for testing
    csv_content = """order_id,customer_name,product_width,product_height,material,quantity,unit_price
1,John Doe,10,8,AL,2,100
2,Jane Smith,12,10,ST,1,150
3,Bob Johnson,8,6,WO,3,200
"""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
        f.write(csv_content)
        source_file = f.name

    try:
        # Create a mapping configuration
        mapping_config = {
            "column_mapping": {
                "order_id": "order_id",
                "customer_name": "customer_name",
                "product_width": "door_width",
                "product_height": "door_height",
                "material": "material",
                "quantity": "quantity",
                "unit_price": "unit_price",
            },
            "business_rules": {
                "material_prices": {"AL": 120.0, "ST": 180.0, "WO": 250.0},
                "profit_margin": 1.3,
            },
            "calculations": [
                {
                    "name": "area_sq_units",
                    "formula": "door_width * door_height",
                    "description": "Door area in square units",
                },
                {
                    "name": "material_price_per_sq_unit",
                    "lookup": "material_prices[material]",
                    "description": "Price per square unit based on material",
                },
                {
                    "name": "calculated_price",
                    "formula": "area_sq_units * material_price_per_sq_unit * quantity",
                    "description": "Calculated price before margin",
                },
                {
                    "name": "final_price",
                    "formula": "calculated_price * profit_margin",
                    "description": "Final price with profit margin",
                },
            ],
        }

        # Save mapping to temporary file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(mapping_config, f, indent=2)
            mapping_file = f.name

        # Create output file path
        output_file = "output_example.csv"

        # Build the pipeline
        pipeline = ETLPipeline()

        # Register extractor
        pipeline.register_extractor("csv", CSVExtractor())

        # Add transformers
        # Basic cleaning (no column mapping since JSON mapping will handle it)
        pipeline.add_transformer(DataCleaner(column_mapping={}))

        # JSON mapping with calculations
        pipeline.add_transformer(MappingLoader(mapping_file))

        # Register loader
        pipeline.register_loader("file", FileLoader())

        # Run the pipeline
        print(f"Processing CSV file: {source_file}")
        print(f"Using mapping file: {mapping_file}")
        print(f"Output file: {output_file}")

        result = pipeline.run("csv", source_file, "file", output_file)

        if result is not None:
            print(f"\nSuccess! Processed {len(result)} rows.")
            print(f"Final columns: {list(result.columns)}")
            print(f"\nFirst row of results:")
            print(result.iloc[0].to_dict())
            print(f"\nOutput saved to: {output_file}")
        else:
            print("\nPipeline failed!")

    finally:
        # Cleanup temporary files
        if os.path.exists(source_file):
            os.unlink(source_file)
        if "mapping_file" in locals() and os.path.exists(mapping_file):
            os.unlink(mapping_file)

    print()


def example_csv_to_database():
    """
    Example 2: Process CSV file and load to SQLite database.
    """
    print("=" * 60)
    print("Example 2: CSV to SQLite Database")
    print("=" * 60)

    # Create a temporary CSV file for testing
    csv_content = """product_id,product_name,width_cm,height_cm,quantity,price_per_unit
P001,Standard Door,100,200,5,150.50
P002,Large Door,150,250,3,225.75
P003,Small Door,80,180,10,120.25
"""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
        f.write(csv_content)
        source_file = f.name

    try:
        # Create a simple mapping configuration
        mapping_config = {
            "column_mapping": {
                "product_id": "product_id",
                "product_name": "product_name",
                "width_cm": "width",
                "height_cm": "height",
                "quantity": "quantity",
                "price_per_unit": "unit_price",
            },
            "business_rules": {"tax_rate": 0.1},
            "calculations": [
                {
                    "name": "area_cm2",
                    "formula": "width * height",
                    "description": "Area in square centimeters",
                },
                {
                    "name": "subtotal",
                    "formula": "unit_price * quantity",
                    "description": "Subtotal before tax",
                },
                {
                    "name": "tax_amount",
                    "formula": "subtotal * tax_rate",
                    "description": "Tax amount",
                },
                {
                    "name": "total_price",
                    "formula": "subtotal + tax_amount",
                    "description": "Total price with tax",
                },
            ],
        }

        # Save mapping to temporary file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(mapping_config, f, indent=2)
            mapping_file = f.name

        # Create a temporary SQLite database
        db_file = "example_database.db"
        table_name = "processed_products"

        # Build the pipeline
        pipeline = ETLPipeline()

        # Register extractor
        pipeline.register_extractor("csv", CSVExtractor())

        # Add transformers
        pipeline.add_transformer(DataCleaner(column_mapping={}))
        pipeline.add_transformer(MappingLoader(mapping_file))

        # Register loader with SQLite connection
        db_connection = f"sqlite:///{db_file}"
        pipeline.register_loader("sql", SQLLoader(db_connection))

        # Run the pipeline
        print(f"Processing CSV file: {source_file}")
        print(f"Using mapping file: {mapping_file}")
        print(f"Database: {db_file}")
        print(f"Table: {table_name}")

        result = pipeline.run("csv", source_file, "sql", table_name)

        if result is not None:
            print(f"\nSuccess! Processed {len(result)} rows.")
            print(f"Final columns: {list(result.columns)}")
            print(f"\nSample of results:")
            for _, row in result.head(2).iterrows():
                print(
                    f"  {row['product_id']}: {row['product_name']} - Total: ${row['total_price']:.2f}"
                )
            print(f"\nData loaded to table '{table_name}' in database '{db_file}'")
        else:
            print("\nPipeline failed!")

    finally:
        # Cleanup temporary files
        if os.path.exists(source_file):
            os.unlink(source_file)
        if "mapping_file" in locals() and os.path.exists(mapping_file):
            os.unlink(mapping_file)
        # Note: Database file is kept for demonstration

    print()


def example_programmatic_usage():
    """
    Example 3: Programmatic usage without JSON mapping files.
    """
    print("=" * 60)
    print("Example 3: Programmatic Usage (No JSON Files)")
    print("=" * 60)

    import pandas as pd

    # Create a DataFrame directly
    data = {
        "customer_id": [1, 2, 3, 4],
        "customer_name": ["Alice", "Bob", "Charlie", "Diana"],
        "order_amount": [100.50, 200.75, 150.25, 300.00],
        "discount_rate": [0.1, 0.15, 0.05, 0.2],
    }
    df = pd.DataFrame(data)

    print("Original DataFrame:")
    print(df)
    print()

    # Create a custom transformer
    from etl_framework.core.transformer import Transformer

    class DiscountCalculator(Transformer):
        """Custom transformer to calculate discounted price."""

        def transform(self, df):
            df = df.copy()
            df["discounted_amount"] = df["order_amount"] * (1 - df["discount_rate"])
            df["savings"] = df["order_amount"] - df["discounted_amount"]
            return df

    # Build pipeline programmatically
    pipeline = ETLPipeline()

    # Create a custom extractor that returns our DataFrame
    from etl_framework.core.extractor import Extractor

    class DataFrameExtractor(Extractor):
        """Extractor that returns a pre-existing DataFrame."""

        def __init__(self, df):
            self.df = df

        def extract(self, source):
            # Ignore source parameter, return our DataFrame
            return self.df

    # Register extractor with our DataFrame
    pipeline.register_extractor("dataframe", DataFrameExtractor(df))

    # Add custom transformer
    pipeline.add_transformer(DiscountCalculator())

    # Create a custom loader that prints results
    from etl_framework.core.loader import Loader

    class PrintLoader(Loader):
        """Loader that prints the DataFrame."""

        def load(self, df, target):
            print(f"\nLoading to: {target}")
            print(df)
            return True

    pipeline.register_loader("print", PrintLoader())

    # Run the pipeline
    print("Running pipeline with custom components...")
    result = pipeline.run("dataframe", "dummy_source", "print", "console_output")

    if result is not None:
        print(f"\nPipeline completed successfully!")
        print(f"Total savings across all orders: ${result['savings'].sum():.2f}")

    print()


def main():
    """Run all examples."""
    print("ETL Framework - Usage Examples")
    print("=" * 60)
    print()

    # Run examples
    example_csv_to_csv()
    example_csv_to_database()
    example_programmatic_usage()

    print("=" * 60)
    print("All examples completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()
