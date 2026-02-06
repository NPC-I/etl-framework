#!/usr/bin/env python3
"""
Demo Manager - Unified demo setup and testing.
Combines setup_demo.py and test_demos.py functionality.
"""
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


class DemoManager:
    """Manages demo setup, testing, and cleanup."""

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.demo_dir = project_root / "demo"
        self.output_dir = project_root / "demo" / "output"
        self.config_dir = project_root / "demo" / "config"
        self.data_dir = project_root / "demo" / "data"

    def setup_demos(self) -> Dict[str, any]:
        """Setup demo environment."""
        print("🔧 Setting up demo environment...")

        # Create necessary directories
        directories = [self.output_dir, self.config_dir, self.data_dir]
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
            print(f"  Created: {directory.relative_to(self.project_root)}")

        # Create sample data files if they don't exist
        self._create_sample_data()

        # Create sample config files
        self._create_sample_configs()

        print("✅ Demo environment setup complete!")
        return {
            "success": True,
            "directories_created": [
                str(d.relative_to(self.project_root)) for d in directories
            ],
            "sample_files_created": self._list_sample_files(),
        }

    def _create_sample_data(self):
        """Create sample data files for demos."""
        # Sample orders data
        orders_data = """order_id,customer_name,door_width,door_height,material,quantity,unit_price,order_date
ORD001,John Smith,2000,1000,AL,2,120.0,2024-01-15
ORD002,Jane Doe,1800,900,ST,1,180.0,2024-01-16
ORD003,Bob Johnson,2200,1100,WO,3,250.0,2024-01-17
ORD004,Alice Brown,2400,1200,AL,2,120.0,2024-01-18
ORD005,Charlie Wilson,2000,1000,ST,1,180.0,2024-01-19
"""

        orders_file = self.data_dir / "orders.csv"
        if not orders_file.exists():
            with open(orders_file, "w") as f:
                f.write(orders_data)
            print(
                f"  Created sample data: {orders_file.relative_to(self.project_root)}"
            )

        # Sample customers data
        customers_data = """customer_id,customer_name,email,phone,address,registration_date
CUST001,John Smith,john@example.com,555-0101,123 Main St,2023-12-01
CUST002,Jane Doe,jane@example.com,555-0102,456 Oak Ave,2023-12-05
CUST003,Bob Johnson,bob@example.com,555-0103,789 Pine Rd,2023-12-10
CUST004,Alice Brown,alice@example.com,555-0104,321 Elm St,2023-12-15
CUST005,Charlie Wilson,charlie@example.com,555-0105,654 Maple Dr,2023-12-20
"""

        customers_file = self.data_dir / "customers.csv"
        if not customers_file.exists():
            with open(customers_file, "w") as f:
                f.write(customers_data)
            print(
                f"  Created sample data: {customers_file.relative_to(self.project_root)}"
            )

    def _create_sample_configs(self):
        """Create sample configuration files."""
        # Sample mapping configuration
        mapping_config = {
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
                "tax_rate": 0.2,
                "profit_margin": 1.3,
            },
        }

        mapping_file = self.config_dir / "sample_mapping.json"
        if not mapping_file.exists():
            with open(mapping_file, "w") as f:
                json.dump(mapping_config, f, indent=2)
            print(
                f"  Created sample config: {mapping_file.relative_to(self.project_root)}"
            )

    def _list_sample_files(self) -> List[str]:
        """List sample files created."""
        files = []
        for pattern in ["*.csv", "*.json"]:
            for file in self.data_dir.glob(pattern):
                files.append(str(file.relative_to(self.project_root)))
            for file in self.config_dir.glob(pattern):
                files.append(str(file.relative_to(self.project_root)))
        return files

    def test_demos(self, demo_filter: Optional[str] = None) -> Dict[str, any]:
        """Test all demos or filtered demos."""
        print("🧪 Testing demos...")

        # Find all demo files
        demo_files = list(self.demo_dir.glob("*.py"))
        demo_files = [
            f for f in demo_files if f.name.startswith("0")
        ]  # Only numbered demos

        if demo_filter:
            demo_files = [f for f in demo_files if demo_filter in f.name]
            print(f"  Filter: '{demo_filter}' ({len(demo_files)} demos)")

        if not demo_files:
            print("❌ No demo files found")
            return {"success": False, "error": "No demo files found"}

        print(f"  Found {len(demo_files)} demo files")

        results = []
        passed = 0
        failed = 0

        for demo_file in sorted(demo_files):
            demo_name = demo_file.name
            print(f"\n  Testing: {demo_name}")
            print(f"  {'=' * (len(demo_name) + 10)}")

            try:
                # Run the demo
                result = subprocess.run(
                    [sys.executable, str(demo_file)],
                    capture_output=True,
                    text=True,
                    cwd=self.project_root,
                    timeout=120,  # 2 minute timeout per demo
                )

                success = result.returncode == 0
                if success:
                    print(f"  ✅ PASSED")
                    passed += 1
                else:
                    print(f"  ❌ FAILED (exit code: {result.returncode})")
                    # Show last few lines of error
                    if result.stderr:
                        error_lines = result.stderr.strip().split("\n")[-5:]
                        for line in error_lines:
                            print(f"    {line}")
                    failed += 1

                results.append(
                    {
                        "demo": demo_name,
                        "success": success,
                        "exit_code": result.returncode,
                        "has_output": bool(result.stdout),
                        "has_errors": bool(result.stderr),
                    }
                )

            except subprocess.TimeoutExpired:
                print(f"  ⏰ TIMEOUT (exceeded 2 minutes)")
                failed += 1
                results.append(
                    {
                        "demo": demo_name,
                        "success": False,
                        "error": "Timeout expired",
                        "exit_code": -1,
                    }
                )
            except Exception as e:
                print(f"  💥 ERROR: {str(e)}")
                failed += 1
                results.append(
                    {
                        "demo": demo_name,
                        "success": False,
                        "error": str(e),
                        "exit_code": -1,
                    }
                )

        # Print summary
        print("\n" + "=" * 60)
        print("📊 DEMO TEST SUMMARY")
        print("=" * 60)
        print(f"  Total: {len(demo_files)}")
        print(f"  Passed: {passed}")
        print(f"  Failed: {failed}")
        print("=" * 60)

        if failed == 0:
            print("🎉 All demos passed!")
        else:
            print(f"⚠️  {failed} demo(s) failed")

        # Save results
        results_file = self.output_dir / "demo_test_results.json"
        with open(results_file, "w") as f:
            json.dump(
                {
                    "timestamp": datetime.now().isoformat(),
                    "total_demos": len(demo_files),
                    "passed": passed,
                    "failed": failed,
                    "results": results,
                },
                f,
                indent=2,
            )

        print(f"\n📊 Results saved to: {results_file.relative_to(self.project_root)}")

        return {
            "success": failed == 0,
            "total": len(demo_files),
            "passed": passed,
            "failed": failed,
            "results_file": str(results_file),
            "results": results,
        }

    def clean_demos(self) -> Dict[str, any]:
        """Clean demo output files."""
        print("🧹 Cleaning demo output files...")

        cleaned_files = []
        cleaned_dirs = []

        # Clean output directory
        if self.output_dir.exists():
            for item in self.output_dir.iterdir():
                if item.is_file():
                    item.unlink()
                    cleaned_files.append(str(item.relative_to(self.project_root)))
                elif item.is_dir():
                    import shutil

                    shutil.rmtree(item)
                    cleaned_dirs.append(str(item.relative_to(self.project_root)))
            print(
                f"  Cleaned output directory: {self.output_dir.relative_to(self.project_root)}"
            )

        # Clean sample data files (optional)
        clean_data = input("\nClean sample data files? (y/N): ").lower().strip() == "y"
        if clean_data and self.data_dir.exists():
            for item in self.data_dir.glob("*.csv"):
                if item.name not in [
                    "orders.csv",
                    "customers.csv",
                ]:  # Keep base samples
                    item.unlink()
                    cleaned_files.append(str(item.relative_to(self.project_root)))
            print(f"  Cleaned sample data files")

        print(
            f"✅ Cleaned {len(cleaned_files)} files and {len(cleaned_dirs)} directories"
        )

        return {
            "success": True,
            "cleaned_files": cleaned_files,
            "cleaned_dirs": cleaned_dirs,
        }

    def list_demos(self):
        """List available demos."""
        demo_files = list(self.demo_dir.glob("*.py"))
        demo_files = [f for f in demo_files if f.name.startswith("0")]

        print("📋 Available Demos:")
        print("=" * 40)
        for demo_file in sorted(demo_files):
            # Read first few lines to get description
            with open(demo_file, "r") as f:
                lines = f.readlines()[:5]
                description = ""
                for line in lines:
                    if line.strip().startswith('"""'):
                        continue
                    if '"""' in line:
                        description = line.replace('"""', "").strip()
                        break
                    if line.strip():
                        description = line.strip()
                        break

            print(f"  {demo_file.name:25} - {description[:50]}...")
        print("=" * 40)
        print(f"Total: {len(demo_files)} demos")


def main():
    """Main entry point for standalone demo management."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Demo Manager - Setup, test, and clean demos"
    )
    parser.add_argument("--setup", action="store_true", help="Setup demo environment")
    parser.add_argument("--test", action="store_true", help="Test demos")
    parser.add_argument("--clean", action="store_true", help="Clean demo output files")
    parser.add_argument("--list", action="store_true", help="List available demos")
    parser.add_argument("--filter", help="Filter demos by name pattern")
    parser.add_argument(
        "--project-root", type=Path, default=Path.cwd(), help="Project root directory"
    )

    args = parser.parse_args()

    manager = DemoManager(args.project_root)

    if args.setup:
        result = manager.setup_demos()
        sys.exit(0 if result["success"] else 1)

    elif args.test:
        result = manager.test_demos(args.filter)
        sys.exit(0 if result["success"] else 1)

    elif args.clean:
        result = manager.clean_demos()
        sys.exit(0 if result["success"] else 1)

    elif args.list:
        manager.list_demos()
        sys.exit(0)

    else:
        # Default: run tests
        result = manager.test_demos(args.filter)
        sys.exit(0 if result["success"] else 1)


if __name__ == "__main__":
    main()
