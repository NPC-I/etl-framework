"""
Data extractors for the ETL Framework.
"""

from etl_framework.plugins.extractors.csv_extractor import CSVExtractor
from etl_framework.plugins.extractors.excel_extractor import ExcelExtractor
from etl_framework.plugins.extractors.json_extractor import JSONStringExtractor
from etl_framework.plugins.extractors.pdf_extractor import PDFExtractor

# Import loaders
from etl_framework.plugins.loaders.file_loader import FileLoader
from etl_framework.plugins.loaders.sql_loader import SQLLoader

# Import transformers that might be used with extractors
from etl_framework.plugins.transformers.cleaner import DataCleaner
from etl_framework.plugins.transformers.enricher import DataEnricher
from etl_framework.plugins.transformers.mapping_loader import MappingLoader
from etl_framework.plugins.transformers.secure_json_calculator import (
    SecureJSONBusinessCalculator,
)

__all__ = [
    # Extractors
    "CSVExtractor",
    "ExcelExtractor",
    "PDFExtractor",
    "JSONStringExtractor",
    # Transformers
    "DataCleaner",
    "DataEnricher",
    "MappingLoader",
    "SecureJSONBusinessCalculator",
    # Loaders
    "FileLoader",
    "SQLLoader",
]
