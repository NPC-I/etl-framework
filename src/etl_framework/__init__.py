"""
ETL Framework for data extraction, transformation, and loading.
"""

__version__ = "1.0.1"  # Updated to 1.0.1 for patch release

# Configuration
from etl_framework.config.settings import config
from etl_framework.core.load_strategy import LoadOptions, LoadStrategy

# Core components
from etl_framework.core.pipeline import ETLPipeline

# Plugin components
from etl_framework.plugins.extractors.csv_extractor import CSVExtractor
from etl_framework.plugins.extractors.excel_extractor import ExcelExtractor
from etl_framework.plugins.extractors.pdf_extractor import PDFExtractor
from etl_framework.plugins.loaders.file_loader import FileLoader
from etl_framework.plugins.loaders.sql_loader import SQLLoader
from etl_framework.plugins.transformers.cleaner import DataCleaner
from etl_framework.plugins.transformers.enricher import DataEnricher
from etl_framework.plugins.transformers.mapping_loader import MappingLoader
from etl_framework.plugins.transformers.secure_json_calculator import (
    SecureJSONBusinessCalculator,
)
from etl_framework.security.access_control import AccessController, Operation, Role
from etl_framework.security.audit_logger import AuditEventType, AuditLogger

# Security components
from etl_framework.security.config import SecurityConfig
from etl_framework.security.encryption import DataEncryptor
from etl_framework.security.input_validator import InputValidator

__all__ = [
    # Core
    "ETLPipeline",
    "LoadStrategy",
    "LoadOptions",
    # Security
    "SecurityConfig",
    "AccessController",
    "Role",
    "Operation",
    "InputValidator",
    "DataEncryptor",
    "AuditLogger",
    "AuditEventType",
    # Extractors
    "CSVExtractor",
    "ExcelExtractor",
    "PDFExtractor",
    # Transformers
    "DataCleaner",
    "DataEnricher",
    "MappingLoader",
    "SecureJSONBusinessCalculator",
    # Loaders
    "FileLoader",
    "SQLLoader",
    # Configuration
    "config",
]
