"""
Test Data Factory - Centralized test data generation.
"""
import random
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd


class TestDataFactory:
    """Factory for creating consistent, reusable test data."""

    # Common test data templates
    _USER_NAMES = [
        "Alice Smith",
        "Bob Johnson",
        "Charlie Brown",
        "Diana Prince",
        "Edward Norton",
    ]
    _MATERIALS = ["AL", "ST", "WO", "CU", "BR"]
    _MATERIAL_DESCRIPTIONS = {
        "AL": "Aluminum",
        "ST": "Steel",
        "WO": "Wood",
        "CU": "Copper",
        "BR": "Bronze",
    }
    _EMAIL_DOMAINS = ["example.com", "test.org", "demo.net"]

    @staticmethod
    def create_sample_dataframe(
        rows: int = 5,
        include_sensitive: bool = False,
        include_dates: bool = False,
        seed: Optional[int] = None,
    ) -> pd.DataFrame:
        """
        Create standardized test DataFrame with consistent structure.

        Args:
            rows: Number of rows to generate
            include_sensitive: Whether to include sensitive columns (SSN, credit cards)
            include_dates: Whether to include date columns
            seed: Random seed for reproducibility

        Returns:
            pandas DataFrame with test data
        """
        if seed is not None:
            random.seed(seed)
            np.random.seed(seed)

        # Generate base data
        data = {
            "id": list(range(1, rows + 1)),
            "name": [random.choice(TestDataFactory._USER_NAMES) for _ in range(rows)],
            "email": [
                f"{name.lower().replace(' ', '.')}@{random.choice(TestDataFactory._EMAIL_DOMAINS)}"
                for name in [
                    random.choice(TestDataFactory._USER_NAMES) for _ in range(rows)
                ]
            ],
            "amount": [round(random.uniform(100.0, 1000.0), 2) for _ in range(rows)],
            "material": [
                random.choice(TestDataFactory._MATERIALS) for _ in range(rows)
            ],
            "quantity": [random.randint(1, 10) for _ in range(rows)],
            "unit_price": [round(random.uniform(50.0, 500.0), 2) for _ in range(rows)],
        }

        # Add sensitive columns if requested
        if include_sensitive:
            data.update(
                {
                    "ssn": [
                        f"{random.randint(100, 999)}-{random.randint(10, 99)}-{random.randint(1000, 9999)}"
                        for _ in range(rows)
                    ],
                    "credit_card": [
                        f"{random.randint(4000, 4999)}{random.randint(1000, 9999)}{random.randint(1000, 9999)}{random.randint(1000, 9999)}"
                        for _ in range(rows)
                    ],
                    "phone": [
                        f"({random.randint(200, 999)}) {random.randint(200, 999)}-{random.randint(1000, 9999)}"
                        for _ in range(rows)
                    ],
                }
            )

        # Add date columns if requested
        if include_dates:
            base_date = datetime.now()
            data.update(
                {
                    "order_date": [
                        (base_date - timedelta(days=random.randint(0, 30))).strftime(
                            "%Y-%m-%d"
                        )
                        for _ in range(rows)
                    ],
                    "delivery_date": [
                        (base_date + timedelta(days=random.randint(1, 60))).strftime(
                            "%Y-%m-%d"
                        )
                        for _ in range(rows)
                    ],
                }
            )

        return pd.DataFrame(data)

    @staticmethod
    def create_roller_door_dataframe(rows: int = 10) -> pd.DataFrame:
        """
        Create specialized DataFrame for roller door business testing.

        Args:
            rows: Number of rows to generate

        Returns:
            DataFrame with roller door specific columns
        """
        df = TestDataFactory.create_sample_dataframe(rows)

        # Add roller door specific columns
        df["door_width"] = [round(random.uniform(1.0, 5.0), 2) for _ in range(rows)]
        df["door_height"] = [round(random.uniform(1.0, 3.0), 2) for _ in range(rows)]
        df["installation_type"] = [
            random.choice(["standard", "premium", "custom"]) for _ in range(rows)
        ]
        df["warranty_years"] = [random.choice([1, 2, 5, 10]) for _ in range(rows)]

        return df

    @staticmethod
    def create_large_dataset(rows: int = 10000) -> pd.DataFrame:
        """
        Create large dataset for performance testing.

        Args:
            rows: Number of rows to generate

        Returns:
            Large DataFrame for performance tests
        """
        # Use numpy for efficient large data generation
        ids = np.arange(1, rows + 1)
        values = np.random.randn(rows) * 100 + 500  # Normal distribution around 500
        categories = np.random.choice(["A", "B", "C", "D", "E"], rows)

        return pd.DataFrame(
            {
                "id": ids,
                "value": values,
                "category": categories,
                "score": np.random.randint(1, 100, rows),
                "flag": np.random.choice([True, False], rows),
            }
        )

    @staticmethod
    def create_mapping_config() -> Dict[str, Any]:
        """
        Create standardized mapping configuration for testing.

        Returns:
            Dictionary with mapping configuration
        """
        return {
            "column_mapping": {
                "col_1": "order_id",
                "col_2": "customer_name",
                "col_3": "door_width",
                "col_4": "door_height",
                "col_5": "material",
                "col_6": "quantity",
                "col_7": "unit_price",
            },
            "business_rules": {
                "material_prices": {
                    "AL": 120.0,
                    "ST": 180.0,
                    "WO": 250.0,
                    "CU": 300.0,
                    "BR": 350.0,
                },
                "material_descriptions": TestDataFactory._MATERIAL_DESCRIPTIONS,
                "default_price_per_sq_unit": 150.0,
                "base_installation_days": 2,
                "profit_margin": 1.3,
                "lead_time_per_1000_sq_units": 1.0,
                "min_lead_time_days": 3,
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
                    "condition": "has:material",
                },
                {
                    "name": "total_price",
                    "formula": "area_sq_units * material_price_per_sq_unit * quantity * profit_margin",
                    "description": "Total price with profit margin",
                },
            ],
        }

    @staticmethod
    def create_security_test_data() -> Dict[str, Any]:
        """
        Create test data for security testing.

        Returns:
            Dictionary with security test data
        """
        return {
            "users": [
                {"username": "admin", "roles": ["admin"], "permissions": ["all"]},
                {
                    "username": "operator",
                    "roles": ["operator"],
                    "permissions": ["execute", "read"],
                },
                {"username": "viewer", "roles": ["viewer"], "permissions": ["read"]},
                {
                    "username": "auditor",
                    "roles": ["auditor"],
                    "permissions": ["read", "audit"],
                },
                {
                    "username": "data_steward",
                    "roles": ["data_steward"],
                    "permissions": ["read", "write", "encrypt"],
                },
            ],
            "sensitive_resources": [
                "customer_pii",
                "financial_records",
                "health_data",
                "employee_salaries",
            ],
            "security_levels": ["development", "testing", "staging", "production"],
        }

    @classmethod
    def get_material_description(cls, material_code: str) -> str:
        """
        Get material description for a material code.

        Args:
            material_code: Material code (AL, ST, WO, etc.)

        Returns:
            Material description
        """
        return cls._MATERIAL_DESCRIPTIONS.get(material_code, "Unknown Material")

    @staticmethod
    def generate_test_cases() -> List[Dict[str, Any]]:
        """
        Generate parameterized test cases.

        Returns:
            List of test case dictionaries
        """
        return [
            {
                "name": "small_dataset",
                "rows": 10,
                "include_sensitive": False,
                "description": "Small dataset for fast tests",
            },
            {
                "name": "medium_dataset",
                "rows": 100,
                "include_sensitive": True,
                "description": "Medium dataset with sensitive data",
            },
            {
                "name": "large_dataset",
                "rows": 1000,
                "include_sensitive": True,
                "description": "Large dataset for performance",
            },
        ]
