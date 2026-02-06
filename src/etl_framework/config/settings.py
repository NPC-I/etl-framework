"""
Framework settings and constants with security integration.
"""
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

# Security imports
from etl_framework.security.config import SecurityConfig, SecurityLevel

# Default column mappings for common PDF extraction scenarios
DEFAULT_COLUMN_MAPPINGS: Dict[str, Dict[str, str]] = {
    "generic": {
        "col_1": "id",
        "col_2": "name",
        "col_3": "value",
    }
}

# Supported file extensions
SUPPORTED_EXTRACTORS = {
    ".pdf": "pdf",
    ".csv": "csv",
    ".xlsx": "excel",
    ".xls": "excel",
}

# Database connection templates
DB_CONNECTION_TEMPLATES = {
    "postgresql": "postgresql://{user}:{password}@{host}:{port}/{database}",
    "mysql": "mysql+pymysql://{user}:{password}@{host}:{port}/{database}",
    "sqlite": "sqlite:///{file_path}",
}


def get_project_root() -> Path:
    """
    Get the project root directory.

    Returns:
        Path to project root (current working directory in most cases).
    """
    # Try to find project root by looking for common markers
    cwd = Path.cwd()

    # Check for common project markers
    markers = ["pyproject.toml", "setup.py", "README.md", ".git"]
    for marker in markers:
        if (cwd / marker).exists():
            return cwd

    # If no markers found, use current working directory
    return cwd


def ensure_directory(path: Path) -> Path:
    """
    Ensure a directory exists, creating it if necessary.

    Args:
        path: Directory path to ensure exists.

    Returns:
        The path (guaranteed to exist as a directory).
    """
    path.mkdir(parents=True, exist_ok=True)
    return path


# Environment variable configuration
class Config:
    """Configuration loaded from environment variables with defaults and security."""

    # Database connection environment variables
    DB_TYPE = os.getenv("ETL_DB_TYPE", "sqlite").lower()
    DB_HOST = os.getenv("ETL_DB_HOST", "localhost")
    DB_PORT = os.getenv("ETL_DB_PORT", "5432")
    DB_NAME = os.getenv("ETL_DB_NAME", "etl_data")
    DB_USER = os.getenv("ETL_DB_USER", "postgres")
    DB_PASSWORD = os.getenv("ETL_DB_PASSWORD", "")
    DB_FILE = os.getenv("ETL_DB_FILE", "etl_database.db")

    # Framework behavior
    LOG_LEVEL = os.getenv("ETL_LOG_LEVEL", "INFO")
    LOG_FILE = os.getenv("ETL_LOG_FILE", "etl.log")
    DEFAULT_EXTRACTOR = os.getenv("ETL_DEFAULT_EXTRACTOR", "csv")
    DEFAULT_LOADER = os.getenv("ETL_DEFAULT_LOADER", "file")

    # Loading strategy environment variables
    DEFAULT_STRATEGY = os.getenv("ETL_DEFAULT_STRATEGY", "replace")
    KEY_COLUMNS = os.getenv("ETL_KEY_COLUMNS", "")
    BATCH_SIZE = int(os.getenv("ETL_BATCH_SIZE", "1000"))
    CHUNK_SIZE = int(os.getenv("ETL_CHUNK_SIZE", "500"))
    CREATE_INDEX = os.getenv("ETL_CREATE_INDEX", "false").lower() == "true"
    DROP_DUPLICATES = os.getenv("ETL_DROP_DUPLICATES", "true").lower() == "true"

    # Security configuration
    SECURITY_ENABLED = os.getenv("ETL_SECURITY_ENABLED", "true").lower() == "true"
    SECURITY_LEVEL = os.getenv("ETL_SECURITY_LEVEL", "development").lower()
    ENCRYPTION_ENABLED = os.getenv("ETL_ENCRYPTION_ENABLED", "true").lower() == "true"
    RBAC_ENABLED = os.getenv("ETL_RBAC_ENABLED", "true").lower() == "true"
    AUDIT_LOGGING_ENABLED = (
        os.getenv("ETL_AUDIT_LOGGING_ENABLED", "true").lower() == "true"
    )
    AUDIT_LOG_FILE = os.getenv("ETL_AUDIT_LOG_FILE", "./logs/audit.log")

    # Path configuration
    PROJECT_ROOT = Path(os.getenv("ETL_PROJECT_ROOT", str(get_project_root())))
    DATA_DIR = Path(os.getenv("ETL_DATA_DIR", str(PROJECT_ROOT / "data")))
    LOG_DIR = Path(os.getenv("ETL_LOG_DIR", str(PROJECT_ROOT / "logs")))

    @classmethod
    def get_security_config(cls) -> SecurityConfig:
        """
        Get security configuration.

        Returns:
            SecurityConfig instance.
        """
        return SecurityConfig.from_environment()

    @classmethod
    def validate_security_configuration(cls) -> List[str]:
        """
        Validate security configuration.

        Returns:
            List of validation errors.
        """
        if not cls.SECURITY_ENABLED:
            return []

        security_config = cls.get_security_config()
        return security_config.validate()

    @classmethod
    def is_security_enabled(cls) -> bool:
        """Check if security features are enabled."""
        return cls.SECURITY_ENABLED

    @classmethod
    def get_security_level(cls) -> SecurityLevel:
        """Get current security level."""
        try:
            return SecurityLevel(cls.SECURITY_LEVEL)
        except ValueError:
            return SecurityLevel.DEVELOPMENT

    @classmethod
    def get_database_connection_string(cls) -> str:
        """
        Build a database connection string from environment variables.

        Returns:
            SQLAlchemy connection string.
        """
        if cls.DB_TYPE == "sqlite":
            # For SQLite, resolve the database file path
            db_file_path = Path(cls.DB_FILE)

            # If it's not an absolute path, make it relative to project root
            if not db_file_path.is_absolute():
                # Check if the path already starts with data/
                # If it does, it's already relative to project root
                if str(db_file_path).startswith("data/") or str(
                    db_file_path
                ).startswith("./data/"):
                    db_file_path = cls.PROJECT_ROOT / db_file_path
                else:
                    # Otherwise, put it in the data directory
                    db_file_path = cls.DATA_DIR / db_file_path

            ensure_directory(db_file_path.parent)
            return DB_CONNECTION_TEMPLATES["sqlite"].format(file_path=str(db_file_path))
        elif cls.DB_TYPE == "postgresql":
            return DB_CONNECTION_TEMPLATES["postgresql"].format(
                user=cls.DB_USER,
                password=cls.DB_PASSWORD,
                host=cls.DB_HOST,
                port=cls.DB_PORT,
                database=cls.DB_NAME,
            )
        elif cls.DB_TYPE == "mysql":
            return DB_CONNECTION_TEMPLATES["mysql"].format(
                user=cls.DB_USER,
                password=cls.DB_PASSWORD,
                host=cls.DB_HOST,
                port=cls.DB_PORT,
                database=cls.DB_NAME,
            )
        else:
            raise ValueError(f"Unsupported database type: {cls.DB_TYPE}")

    @classmethod
    def get_column_mapping(cls, mapping_name: Optional[str] = None) -> Dict[str, str]:
        """
        Get column mapping by name, with fallback to environment variable.

        Args:
            mapping_name: Name of the mapping to use.

        Returns:
            Column mapping dictionary.
        """
        if mapping_name:
            return DEFAULT_COLUMN_MAPPINGS.get(mapping_name, {})

        # Try environment variable
        env_mapping = os.getenv("ETL_COLUMN_MAPPING")
        if env_mapping and env_mapping in DEFAULT_COLUMN_MAPPINGS:
            return DEFAULT_COLUMN_MAPPINGS[env_mapping]

        return {}

    @classmethod
    def parse_key_columns(cls, value: Optional[str] = None) -> List[str]:
        """
        Parse comma-separated key columns string into list.

        Args:
            value: String to parse. If None, uses cls.KEY_COLUMNS.

        Returns:
            List of key column names.
        """
        if value is None:
            value = cls.KEY_COLUMNS

        if not value:
            return []

        return [col.strip() for col in value.split(",") if col.strip()]

    @classmethod
    def ensure_directories(cls) -> None:
        """Ensure all configured directories exist."""
        ensure_directory(cls.DATA_DIR)
        ensure_directory(cls.LOG_DIR)

        # Ensure audit log directory if security is enabled
        if cls.SECURITY_ENABLED and cls.AUDIT_LOGGING_ENABLED:
            audit_log_path = Path(cls.AUDIT_LOG_FILE)
            if not audit_log_path.is_absolute():
                audit_log_path = cls.PROJECT_ROOT / audit_log_path
            ensure_directory(audit_log_path.parent)

    @classmethod
    def get_log_file_path(cls) -> Path:
        """Get full path to log file."""
        log_file = Path(cls.LOG_FILE)
        if not log_file.is_absolute():
            log_file = cls.LOG_DIR / log_file
        ensure_directory(log_file.parent)
        return log_file

    @classmethod
    def get_audit_log_file_path(cls) -> Path:
        """Get full path to audit log file."""
        if not cls.SECURITY_ENABLED or not cls.AUDIT_LOGGING_ENABLED:
            return None

        audit_log_file = Path(cls.AUDIT_LOG_FILE)
        if not audit_log_file.is_absolute():
            audit_log_file = cls.PROJECT_ROOT / audit_log_file
        ensure_directory(audit_log_file.parent)
        return audit_log_file

    @classmethod
    def should_encrypt_data(cls) -> bool:
        """Check if data encryption should be enabled."""
        if not cls.SECURITY_ENABLED or not cls.ENCRYPTION_ENABLED:
            return False

        security_config = cls.get_security_config()
        return security_config.should_encrypt()

    @classmethod
    def should_enforce_access_control(cls) -> bool:
        """Check if access control should be enforced."""
        if not cls.SECURITY_ENABLED or not cls.RBAC_ENABLED:
            return False

        security_config = cls.get_security_config()
        return security_config.rbac_enabled

    @classmethod
    def should_log_audit_events(cls) -> bool:
        """Check if audit events should be logged."""
        if not cls.SECURITY_ENABLED or not cls.AUDIT_LOGGING_ENABLED:
            return False

        security_config = cls.get_security_config()
        return security_config.should_log_audit()

    @classmethod
    def get_security_summary(cls) -> Dict[str, Any]:
        """
        Get security configuration summary.

        Returns:
            Dictionary with security configuration summary.
        """
        if not cls.SECURITY_ENABLED:
            return {"security_enabled": False}

        security_config = cls.get_security_config()
        return {
            "security_enabled": True,
            "security_level": security_config.security_level.value,
            "encryption_enabled": security_config.should_encrypt(),
            "access_control_enabled": security_config.rbac_enabled,
            "audit_logging_enabled": security_config.should_log_audit(),
            "validation_level": security_config.get_validation_level(),
            "access_control_level": security_config.get_access_control_level(),
        }


# Create config instance for easy import
config = Config()
