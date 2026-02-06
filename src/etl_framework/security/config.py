"""
Security configuration for ETL Framework.
"""
import os
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Dict, List, Optional


class SecurityLevel(Enum):
    """Security levels for different environments."""

    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging"
    PRODUCTION = "production"


@dataclass
class SecurityConfig:
    """Security configuration settings."""

    # Environment
    security_level: SecurityLevel = SecurityLevel.DEVELOPMENT

    # Encryption
    encryption_enabled: bool = True
    encryption_algorithm: str = "AES-256-GCM"
    key_rotation_days: int = 90

    # Access Control
    rbac_enabled: bool = True
    require_authentication: bool = False
    session_timeout_minutes: int = 60

    # Audit Logging
    audit_logging_enabled: bool = True
    audit_retention_days: int = 365
    log_sensitive_operations: bool = False

    # Input Validation
    max_file_size_mb: int = 100
    max_json_depth: int = 10
    max_calculations_per_mapping: int = 50

    # Network Security
    allow_insecure_connections: bool = False
    require_tls: bool = True
    allowed_ip_ranges: Optional[List[str]] = None

    # Security Standards
    data_protection_enabled: bool = True
    access_control_enabled: bool = True
    audit_logging_enabled: bool = True

    @classmethod
    def from_environment(cls) -> "SecurityConfig":
        """
        Create configuration from environment variables.

        Returns:
            SecurityConfig instance.
        """
        # Get security level
        security_level_str = os.getenv("ETL_SECURITY_LEVEL", "development").lower()
        try:
            security_level = SecurityLevel(security_level_str)
        except ValueError:
            security_level = SecurityLevel.DEVELOPMENT

        # Parse allowed IP ranges
        allowed_ip_ranges = None
        ip_ranges_str = os.getenv("ETL_ALLOWED_IP_RANGES")
        if ip_ranges_str:
            allowed_ip_ranges = [ip.strip() for ip in ip_ranges_str.split(",")]

        return cls(
            security_level=security_level,
            encryption_enabled=os.getenv("ETL_ENCRYPTION_ENABLED", "true").lower()
            == "true",
            rbac_enabled=os.getenv("ETL_RBAC_ENABLED", "true").lower() == "true",
            audit_logging_enabled=os.getenv("ETL_AUDIT_LOGGING_ENABLED", "true").lower()
            == "true",
            max_file_size_mb=int(os.getenv("ETL_MAX_FILE_SIZE_MB", "100")),
            max_json_depth=int(os.getenv("ETL_MAX_JSON_DEPTH", "10")),
            max_calculations_per_mapping=int(os.getenv("ETL_MAX_CALCULATIONS", "50")),
            allow_insecure_connections=os.getenv(
                "ETL_ALLOW_INSECURE_CONNECTIONS", "false"
            ).lower()
            == "true",
            require_tls=os.getenv("ETL_REQUIRE_TLS", "true").lower() == "true",
            allowed_ip_ranges=allowed_ip_ranges,
            data_protection_enabled=os.getenv(
                "ETL_DATA_PROTECTION_ENABLED", "true"
            ).lower()
            == "true",
            access_control_enabled=os.getenv(
                "ETL_ACCESS_CONTROL_ENABLED", "true"
            ).lower()
            == "true",
        )

    def get_restrictions(self) -> Dict[str, Any]:
        """
        Get security restrictions based on security level.

        Returns:
            Dictionary of restrictions.
        """
        restrictions = {
            "development": {
                "encryption_required": False,
                "audit_logging": False,
                "input_validation": "basic",
                "access_control": "none",
                "error_details": True,
            },
            "testing": {
                "encryption_required": True,
                "audit_logging": True,
                "input_validation": "strict",
                "access_control": "basic",
                "error_details": False,
            },
            "staging": {
                "encryption_required": True,
                "audit_logging": True,
                "input_validation": "strict",
                "access_control": "strict",
                "error_details": False,
            },
            "production": {
                "encryption_required": True,
                "audit_logging": True,
                "input_validation": "paranoid",
                "access_control": "strict",
                "error_details": False,
            },
        }

        return restrictions.get(self.security_level.value, restrictions["development"])

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        config_dict = asdict(self)
        config_dict["security_level"] = self.security_level.value
        return config_dict

    def validate(self) -> List[str]:
        """
        Validate configuration.

        Returns:
            List of validation errors.
        """
        errors = []

        # Validate security level
        if not isinstance(self.security_level, SecurityLevel):
            errors.append("Invalid security level")

        # Validate numeric values
        if self.max_file_size_mb <= 0:
            errors.append("max_file_size_mb must be positive")

        if self.max_json_depth <= 0:
            errors.append("max_json_depth must be positive")

        if self.max_calculations_per_mapping <= 0:
            errors.append("max_calculations_per_mapping must be positive")

        if self.key_rotation_days <= 0:
            errors.append("key_rotation_days must be positive")

        if self.session_timeout_minutes <= 0:
            errors.append("session_timeout_minutes must be positive")

        if self.audit_retention_days <= 0:
            errors.append("audit_retention_days must be positive")

        # Validate IP ranges if provided
        if self.allowed_ip_ranges:
            import ipaddress

            for ip_range in self.allowed_ip_ranges:
                try:
                    ipaddress.ip_network(ip_range)
                except ValueError:
                    errors.append(f"Invalid IP range: {ip_range}")

        return errors

    def is_production(self) -> bool:
        """Check if configuration is for production."""
        return self.security_level == SecurityLevel.PRODUCTION

    def should_encrypt(self) -> bool:
        """Check if encryption should be enabled."""
        return (
            self.encryption_enabled and self.get_restrictions()["encryption_required"]
        )

    def should_log_audit(self) -> bool:
        """Check if audit logging should be enabled."""
        return self.audit_logging_enabled and self.get_restrictions()["audit_logging"]

    def get_validation_level(self) -> str:
        """Get input validation level."""
        return self.get_restrictions()["input_validation"]

    def get_access_control_level(self) -> str:
        """Get access control level."""
        return self.get_restrictions()["access_control"]

    def should_show_error_details(self) -> bool:
        """Check if error details should be shown."""
        return self.get_restrictions()["error_details"]
