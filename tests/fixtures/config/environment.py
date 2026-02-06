"""
Test Environment Configuration - Manage test environment setup.
"""
import json
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional


class TestEnvironment:
    """Manage test environment configuration and cleanup."""

    # Default environment configurations
    SECURITY_CONFIGS = {
        "development": {
            "ETL_SECURITY_LEVEL": "development",
            "ETL_ENCRYPTION_ENABLED": "false",
            "ETL_MAX_FILE_SIZE_MB": "100",
            "ETL_ERROR_DETAILS": "true",
        },
        "testing": {
            "ETL_SECURITY_LEVEL": "testing",
            "ETL_ENCRYPTION_ENABLED": "true",
            "ETL_MAX_FILE_SIZE_MB": "50",
            "ETL_ERROR_DETAILS": "true",
        },
        "staging": {
            "ETL_SECURITY_LEVEL": "staging",
            "ETL_ENCRYPTION_ENABLED": "true",
            "ETL_MAX_FILE_SIZE_MB": "10",
            "ETL_ERROR_DETAILS": "false",
        },
        "production": {
            "ETL_SECURITY_LEVEL": "production",
            "ETL_ENCRYPTION_ENABLED": "true",
            "ETL_MAX_FILE_SIZE_MB": "5",
            "ETL_ERROR_DETAILS": "false",
        },
    }

    @staticmethod
    @contextmanager
    def security_context(
        level: str = "testing",
        encryption: bool = True,
        rbac: bool = True,
        audit_logging: bool = True,
        users: Optional[str] = None,
    ):
        """
        Context manager for security testing environment.

        Args:
            level: Security level (development, testing, staging, production)
            encryption: Whether encryption is enabled
            rbac: Whether RBAC is enabled
            audit_logging: Whether audit logging is enabled
            users: User configuration string

        Yields:
            None
        """
        # Save original environment
        original_env = dict(os.environ)

        # Base security configuration
        env_vars = {
            "ETL_SECURITY_ENABLED": "true",
            "ETL_SECURITY_LEVEL": level,
            "ETL_ENCRYPTION_ENABLED": str(encryption).lower(),
            "ETL_ENCRYPTION_KEY": "test-encryption-key-12345" if encryption else "",
            "ETL_RBAC_ENABLED": str(rbac).lower(),
            "ETL_AUDIT_LOGGING_ENABLED": str(audit_logging).lower(),
            "ETL_AUDIT_LOG_FILE": "./logs/test_audit.log",
        }

        # Add user configuration
        if users:
            env_vars["ETL_USERS"] = users
        else:
            # Format: 'username:role1,role2;username2:role1'
            # Role names must match Role enum values (lowercase)
            env_vars[
                "ETL_USERS"
            ] = "admin:admin;operator:operator;viewer:viewer;auditor:auditor;data_steward:data_steward"

        # Add level-specific configuration
        if level in TestEnvironment.SECURITY_CONFIGS:
            env_vars.update(TestEnvironment.SECURITY_CONFIGS[level])

        try:
            # Update environment
            os.environ.update(env_vars)
            yield
        finally:
            # Restore original environment
            os.environ.clear()
            os.environ.update(original_env)

    @staticmethod
    @contextmanager
    def database_context(db_type: str = "sqlite", db_file: Optional[str] = None):
        """
        Context manager for database testing environment.

        Args:
            db_type: Database type (sqlite, postgresql, mysql)
            db_file: SQLite database file path (optional)

        Yields:
            Database connection string
        """
        original_env = dict(os.environ)

        if db_type == "sqlite":
            if db_file is None:
                # Create temporary database file
                temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
                db_file = temp_db.name
                temp_db.close()

            env_vars = {"ETL_DB_TYPE": "sqlite", "ETL_DB_FILE": db_file}
            connection_string = f"sqlite:///{db_file}"
        else:
            # For other databases, use test configurations
            env_vars = {
                "ETL_DB_TYPE": db_type,
                "ETL_DB_HOST": "localhost",
                "ETL_DB_PORT": "5432" if db_type == "postgresql" else "3306",
                "ETL_DB_NAME": "test_db",
                "ETL_DB_USER": "test_user",
                "ETL_DB_PASSWORD": "test_password",
            }

            if db_type == "postgresql":
                connection_string = (
                    f"postgresql://test_user:test_password@localhost:5432/test_db"
                )
            else:  # mysql
                connection_string = (
                    f"mysql+pymysql://test_user:test_password@localhost:3306/test_db"
                )

        try:
            os.environ.update(env_vars)
            yield connection_string
        finally:
            # Clean up temporary database file if we created it
            if db_type == "sqlite" and db_file and "temp_db" in locals():
                try:
                    Path(db_file).unlink(missing_ok=True)
                except:
                    pass

            # Restore environment
            os.environ.clear()
            os.environ.update(original_env)

    @staticmethod
    @contextmanager
    def file_context(
        file_type: str = "csv",
        content: Optional[str] = None,
        json_data: Optional[Dict] = None,
    ):
        """
        Context manager for temporary file creation.

        Args:
            file_type: File type (csv, json, txt)
            content: File content as string
            json_data: JSON data to write (overrides content for json files)

        Yields:
            Path to temporary file
        """
        suffix = f".{file_type}"

        with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False) as f:
            if file_type == "json" and json_data is not None:
                json.dump(json_data, f)
            elif content is not None:
                f.write(content)
            else:
                # Default content based on file type
                if file_type == "csv":
                    f.write("id,name,value\n1,Test,100.5\n2,Example,200.3")
                elif file_type == "json":
                    json.dump({"test": "data", "value": 123}, f)
                else:
                    f.write("Test content")

            temp_file = f.name

        try:
            yield Path(temp_file)
        finally:
            # Clean up
            try:
                Path(temp_file).unlink(missing_ok=True)
            except:
                pass

    @staticmethod
    @contextmanager
    def directory_context():
        """
        Context manager for temporary directory creation.

        Yields:
            Path to temporary directory
        """
        temp_dir = tempfile.mkdtemp()

        try:
            yield Path(temp_dir)
        finally:
            # Clean up
            import shutil

            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
            except:
                pass

    @staticmethod
    def setup_test_environment(
        security_level: str = "testing",
        db_type: str = "sqlite",
        enable_logging: bool = False,
    ) -> Dict[str, Any]:
        """
        Set up complete test environment.

        Args:
            security_level: Security level
            db_type: Database type
            enable_logging: Whether to enable file logging

        Returns:
            Dictionary with environment configuration
        """
        # Security configuration
        with TestEnvironment.security_context(level=security_level) as security_ctx:
            security_config = {
                "level": security_level,
                "encryption_enabled": os.getenv("ETL_ENCRYPTION_ENABLED") == "true",
                "rbac_enabled": os.getenv("ETL_RBAC_ENABLED") == "true",
            }

        # Database configuration
        with TestEnvironment.database_context(db_type=db_type) as db_conn:
            db_config = {"type": db_type, "connection_string": db_conn}

        # Logging configuration
        log_config = {}
        if enable_logging:
            with TestEnvironment.directory_context() as log_dir:
                log_file = log_dir / "test.log"
                os.environ["ETL_LOG_FILE"] = str(log_file)
                os.environ["ETL_LOG_LEVEL"] = "DEBUG"
                log_config = {"log_file": log_file, "log_level": "DEBUG"}

        return {
            "security": security_config,
            "database": db_config,
            "logging": log_config,
            "environment_set": True,
        }

    @staticmethod
    def create_test_scenario(
        name: str,
        description: str,
        security_level: str = "testing",
        data_size: str = "small",
        include_sensitive: bool = False,
    ) -> Dict[str, Any]:
        """
        Create a complete test scenario configuration.

        Args:
            name: Scenario name
            description: Scenario description
            security_level: Security level
            data_size: Data size (small, medium, large)
            include_sensitive: Whether to include sensitive data

        Returns:
            Test scenario configuration
        """
        # Map data size to row count
        size_map = {"small": 10, "medium": 100, "large": 1000}

        rows = size_map.get(data_size, 10)

        return {
            "name": name,
            "description": description,
            "security_level": security_level,
            "data_size": data_size,
            "rows": rows,
            "include_sensitive": include_sensitive,
            "scenario_id": f"{name}_{security_level}_{data_size}".lower().replace(
                " ", "_"
            ),
        }

    @classmethod
    def get_available_scenarios(cls) -> List[Dict[str, Any]]:
        """
        Get list of available test scenarios.

        Returns:
            List of scenario configurations
        """
        return [
            cls.create_test_scenario(
                name="Basic Functionality",
                description="Test basic ETL functionality",
                security_level="development",
                data_size="small",
                include_sensitive=False,
            ),
            cls.create_test_scenario(
                name="Security Compliance",
                description="Test security compliance features",
                security_level="production",
                data_size="medium",
                include_sensitive=True,
            ),
            cls.create_test_scenario(
                name="Performance Test",
                description="Test performance with large datasets",
                security_level="testing",
                data_size="large",
                include_sensitive=False,
            ),
            cls.create_test_scenario(
                name="Security Standards",
                description="Test security standards features",
                security_level="production",
                data_size="medium",
                include_sensitive=True,
            ),
        ]
