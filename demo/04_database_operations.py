#!/usr/bin/env python3
"""
Database Operations Demo

This demo shows database loading capabilities:
1. Load data to SQLite/PostgreSQL/MySQL
2. Demonstrate different loading strategies
3. Show database-specific optimizations
4. Transaction management
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


from etl_framework.config.settings import config
from etl_framework.core.load_strategy import LoadOptions, LoadStrategy

# Import ETL Framework components
from etl_framework.core.pipeline import ETLPipeline
from etl_framework.plugins.extractors.csv_extractor import CSVExtractor
from etl_framework.plugins.loaders.sql_loader import SQLLoader
from etl_framework.plugins.transformers.cleaner import DataCleaner
from etl_framework.plugins.transformers.mapping_loader import MappingLoader


def demonstrate_loading_strategies():
    """Demonstrate different loading strategies."""
    print("📊 LOADING STRATEGIES DEMONSTRATION")
    print("=" * 50)

    strategies = [
        (LoadStrategy.REPLACE, "Overwrites existing data", "Fresh imports"),
        (LoadStrategy.APPEND, "Adds new data to existing", "Incremental loads"),
        (LoadStrategy.UPDATE, "Updates existing records only", "Data corrections"),
        (LoadStrategy.UPSERT, "Updates existing AND inserts new", "Daily updates"),
        (LoadStrategy.FAIL, "Fails if target exists", "Safety checks"),
    ]

    for strategy, description, use_case in strategies:
        print(f"\n{strategy.value.upper()}:")
        print(f"   Description: {description}")
        print(f"   Use Case:    {use_case}")

        if strategy in [LoadStrategy.UPDATE, LoadStrategy.UPSERT]:
            print(f"   Requires:    Key columns (--key-columns)")

    print("=" * 50)
    print()


def create_sample_data():
    """Create sample data for database operations."""
    from datetime import datetime, timedelta

    import pandas as pd

    demo_dir = Path(__file__).parent
    data_dir = demo_dir / "data"

    # Create initial orders data
    orders_data = []
    base_date = datetime(2024, 1, 1)

    for i in range(1, 11):
        order_date = base_date + timedelta(days=i - 1)
        orders_data.append(
            {
                "order_id": f"ORD{i:04d}",
                "customer_id": f"CUST{(i % 5) + 1:03d}",
                "product_id": f"PROD{(i % 3) + 1:03d}",
                "quantity": (i % 5) + 1,
                "unit_price": 100.0 + (i * 10),
                "order_date": order_date.strftime("%Y-%m-%d"),
                "status": "completed" if i % 2 == 0 else "pending",
                "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
        )

    df_initial = pd.DataFrame(orders_data)
    initial_file = data_dir / "initial_orders.csv"
    df_initial.to_csv(initial_file, index=False)

    # Create update data (some updates, some new)
    update_data = []

    # Updates to existing orders
    for i in [1, 3, 5, 7, 9]:  # Update odd-numbered orders
        update_data.append(
            {
                "order_id": f"ORD{i:04d}",
                "customer_id": f"CUST{(i % 5) + 1:03d}",
                "product_id": f"PROD{(i % 3) + 1:03d}",
                "quantity": (i % 5) + 2,  # Increased quantity
                "unit_price": 100.0 + (i * 10) + 5,  # Increased price
                "order_date": (base_date + timedelta(days=i - 1)).strftime("%Y-%m-%d"),
                "status": "completed",  # All updated to completed
                "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
        )

    # New orders
    for i in range(11, 16):
        order_date = base_date + timedelta(days=i - 1)
        update_data.append(
            {
                "order_id": f"ORD{i:04d}",
                "customer_id": f"CUST{(i % 5) + 1:03d}",
                "product_id": f"PROD{(i % 3) + 1:03d}",
                "quantity": (i % 5) + 1,
                "unit_price": 100.0 + (i * 10),
                "order_date": order_date.strftime("%Y-%m-%d"),
                "status": "pending",
                "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
        )

    df_updates = pd.DataFrame(update_data)
    update_file = data_dir / "updated_orders.csv"
    df_updates.to_csv(update_file, index=False)

    print(f"📝 Created sample data files:")
    print(f"   • {initial_file} ({len(df_initial)} rows)")
    print(f"   • {update_file} ({len(df_updates)} rows)")
    print()

    return initial_file, update_file


def main():
    """Run the database operations demo."""
    print("=" * 70)
    print("🗄️  DATABASE OPERATIONS DEMO")
    print("=" * 70)
    print("This demo shows database loading capabilities.")
    print(f"Database Type: {os.environ.get('ETL_DB_TYPE', 'sqlite')}")
    print()

    # Demonstrate loading strategies
    demonstrate_loading_strategies()

    # Setup paths
    demo_dir = Path(__file__).parent
    data_dir = demo_dir / "data"
    output_dir = demo_dir / "output"

    # Ensure directories exist
    data_dir.mkdir(exist_ok=True)
    output_dir.mkdir(exist_ok=True)

    # Create sample data
    print("📝 Creating sample data for database operations...")
    initial_file, update_file = create_sample_data()

    # Get database connection string
    db_connection = config.get_database_connection_string()
    print(f"🔗 Database Connection: {db_connection}")
    print()

    # Create pipeline
    print("🔧 Creating ETL pipeline...")
    pipeline = ETLPipeline(username="operator", enable_security=True)

    # Register extractor
    pipeline.register_extractor("csv", CSVExtractor())

    # Register loader
    pipeline.register_loader("sql", SQLLoader(db_connection))

    # Phase 1: Initial load with REPLACE strategy
    print("\n" + "=" * 50)
    print("PHASE 1: Initial Load (REPLACE Strategy)")
    print("=" * 50)

    try:
        result1 = pipeline.run(
            extractor_name="csv",
            source=str(initial_file),
            loader_name="sql",
            target="orders",
            strategy=LoadStrategy.REPLACE,
            batch_size=1000,
        )

        if result1 is not None:
            print(f"✅ Initial load successful: {len(result1)} rows loaded")
        else:
            print("❌ Initial load failed")
            return 1

    except Exception as e:
        print(f"❌ Initial load error: {e}")
        return 1

    # Phase 2: Append more data
    print("\n" + "=" * 50)
    print("PHASE 2: Append Additional Data (APPEND Strategy)")
    print("=" * 50)

    # Create some additional data to append
    import pandas as pd

    additional_data = [
        {
            "order_id": "ORD0011",
            "customer_id": "CUST001",
            "product_id": "PROD001",
            "quantity": 3,
            "unit_price": 150.0,
            "order_date": "2024-01-11",
            "status": "pending",
            "last_updated": pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
    ]

    df_additional = pd.DataFrame(additional_data)
    additional_file = data_dir / "additional_orders.csv"
    df_additional.to_csv(additional_file, index=False)

    try:
        result2 = pipeline.run(
            extractor_name="csv",
            source=str(additional_file),
            loader_name="sql",
            target="orders",
            strategy=LoadStrategy.APPEND,
            batch_size=1000,
        )

        if result2 is not None:
            print(f"✅ Append successful: {len(result2)} rows appended")
        else:
            print("❌ Append failed")

    except Exception as e:
        print(f"❌ Append error: {e}")

    # Phase 3: Update existing records
    print("\n" + "=" * 50)
    print("PHASE 3: Update Existing Records (UPDATE Strategy)")
    print("=" * 50)

    # Create update data
    update_data = [
        {
            "order_id": "ORD0001",  # Existing order
            "customer_id": "CUST001",
            "product_id": "PROD001",
            "quantity": 5,  # Updated quantity
            "unit_price": 120.0,  # Updated price
            "order_date": "2024-01-01",
            "status": "shipped",  # Updated status
            "last_updated": pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
    ]

    df_update = pd.DataFrame(update_data)
    update_single_file = data_dir / "update_single_order.csv"
    df_update.to_csv(update_single_file, index=False)

    try:
        result3 = pipeline.run(
            extractor_name="csv",
            source=str(update_single_file),
            loader_name="sql",
            target="orders",
            strategy=LoadStrategy.UPDATE,
            key_columns=["order_id"],
            batch_size=1000,
        )

        if result3 is not None:
            print(f"✅ Update successful: {len(result3)} rows updated")
            print(f"   Updated order ORD0001: quantity=5, status=shipped")
        else:
            print("❌ Update failed")

    except Exception as e:
        print(f"❌ Update error: {e}")

    # Phase 4: UPSERT (Update existing + Insert new)
    print("\n" + "=" * 50)
    print("PHASE 4: UPSERT Operations (Update + Insert)")
    print("=" * 50)

    try:
        result4 = pipeline.run(
            extractor_name="csv",
            source=str(update_file),
            loader_name="sql",
            target="orders",
            strategy=LoadStrategy.UPSERT,
            key_columns=["order_id"],
            batch_size=1000,
        )

        if result4 is not None:
            print(f"✅ UPSERT successful: {len(result4)} rows processed")
            print(f"   • Updated existing orders: 1-10 (odd numbers)")
            print(f"   • Inserted new orders: 11-15")
        else:
            print("❌ UPSERT failed")

    except Exception as e:
        print(f"❌ UPSERT error: {e}")

    # Phase 5: Query the database to show results
    print("\n" + "=" * 50)
    print("PHASE 5: Verify Database Contents")
    print("=" * 50)

    try:
        import sqlite3

        db_path = output_dir / "etl_database.db"
        if db_path.exists():
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()

            # Get row count
            cursor.execute("SELECT COUNT(*) FROM orders")
            total_rows = cursor.fetchone()[0]

            # Get status distribution
            cursor.execute("SELECT status, COUNT(*) FROM orders GROUP BY status")
            status_counts = cursor.fetchall()

            # Get sample data
            cursor.execute(
                "SELECT order_id, customer_id, quantity, status FROM orders ORDER BY order_id LIMIT 5"
            )
            sample_data = cursor.fetchall()

            conn.close()

            print(f"📊 Database Statistics:")
            print(f"   Total orders: {total_rows}")
            print(f"   Status distribution:")
            for status, count in status_counts:
                print(f"     • {status}: {count}")

            print(f"\n🔍 Sample data (first 5 orders):")
            for row in sample_data:
                print(
                    f"   • {row[0]} | Customer: {row[1]} | Qty: {row[2]} | Status: {row[3]}"
                )

        else:
            print("❌ Database file not found")

    except Exception as e:
        print(f"❌ Database query error: {e}")

    # Clean shutdown
    print("\n🔧 Cleaning up...")
    pipeline.shutdown()

    print("\n" + "=" * 70)
    print("🎉 Database operations demo completed!")
    print("=" * 70)
    print("\nSummary of operations demonstrated:")
    print("1. REPLACE strategy: Initial database load")
    print("2. APPEND strategy: Add new records")
    print("3. UPDATE strategy: Modify existing records")
    print("4. UPSERT strategy: Update existing + Insert new")
    print("5. Database verification: Query and analyze results")
    print("\nDatabase file: demo/output/etl_database.db")

    return 0


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
