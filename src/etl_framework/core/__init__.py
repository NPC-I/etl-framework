"""
Core ETL framework interfaces and pipeline orchestration.
"""

from etl_framework.core.extractor import Extractor
from etl_framework.core.loader import Loader
from etl_framework.core.pipeline import ETLPipeline
from etl_framework.core.transformer import Transformer

__all__ = [
    "Extractor",
    "Transformer",
    "Loader",
    "ETLPipeline",
]
