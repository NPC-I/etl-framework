"""
Main ETL pipeline orchestrator with security integration.
"""
import os
from typing import Any, Dict, List, Optional

import pandas as pd

from etl_framework.core.extractor import Extractor
from etl_framework.core.load_strategy import LoadOptions, LoadStrategy
from etl_framework.core.loader import Loader
from etl_framework.core.transformer import Transformer
from etl_framework.security.access_control import AccessController, Operation

# Security imports
from etl_framework.security.audit_logger import AuditEventType, AuditLogger
from etl_framework.security.config import SecurityConfig
from etl_framework.security.encryption import DataEncryptor
from etl_framework.security.input_validator import InputValidator


class ETLPipeline:
    """
    Orchestrates the execution of an ETL pipeline with registered components.
    Includes comprehensive security features.
    """

    def __init__(self, username: str = "system", enable_security: bool = True):
        """
        Initialize ETL pipeline with security features.

        Args:
            username: User executing the pipeline (for audit logging)
            enable_security: Whether to enable security features
        """
        self.extractors: Dict[str, Extractor] = {}
        self.transformers: List[Transformer] = []
        self.loaders: Dict[str, Loader] = {}

        # Security components
        self.username = username
        self.enable_security = enable_security

        if enable_security:
            # Initialize security components
            self.security_config = SecurityConfig.from_environment()
            self.audit_logger = AuditLogger(
                log_file=os.getenv("ETL_AUDIT_LOG_FILE", "./logs/audit.log")
            )
            self.access_controller = AccessController()
            self.input_validator = InputValidator()
            self.encryptor = None

            # Initialize encryptor if encryption is enabled
            if self.security_config.should_encrypt():
                try:
                    self.encryptor = DataEncryptor()
                except Exception as e:
                    print(f"[Security Warning] Encryption initialization failed: {e}")

            # Log pipeline initialization
            self.audit_logger.log_event(
                AuditEventType.SYSTEM_STARTUP,
                self.username,
                {"pipeline": "ETLPipeline", "security_enabled": enable_security},
                True,
            )
        else:
            self.security_config = None
            self.audit_logger = None
            self.access_controller = None
            self.input_validator = None
            self.encryptor = None

    def register_extractor(self, name: str, extractor: Extractor) -> None:
        """
        Register an extractor under a given name.

        Args:
            name: Unique identifier for the extractor.
            extractor: Extractor instance.
        """
        if self.enable_security and self.input_validator:
            # Validate extractor name
            if not self.input_validator.validate_sql_identifier(name):
                raise ValueError(f"Invalid extractor name: '{name}'")

        self.extractors[name] = extractor

    def add_transformer(self, transformer: Transformer) -> None:
        """
        Add a transformer to the pipeline (executed in order of addition).

        Args:
            transformer: Transformer instance.
        """
        self.transformers.append(transformer)

    def register_loader(self, name: str, loader: Loader) -> None:
        """
        Register a loader under a given name.

        Args:
            name: Unique identifier for the loader.
            loader: Loader instance.
        """
        if self.enable_security and self.input_validator:
            # Validate loader name
            if not self.input_validator.validate_sql_identifier(name):
                raise ValueError(f"Invalid loader name: '{name}'")

        self.loaders[name] = loader

    def _check_permission(
        self, operation: Operation, resource: Optional[str] = None
    ) -> bool:
        """
        Check if user has permission for operation.

        Args:
            operation: Operation to check.
            resource: Optional resource name.

        Returns:
            True if permission granted, False otherwise.
        """
        if not self.enable_security or not self.access_controller:
            return True  # Security disabled, allow all

        has_permission = self.access_controller.check_permission(
            self.username, operation, resource
        )

        if not has_permission and self.audit_logger:
            self.audit_logger.log_permission_denied(
                self.username, operation.value, resource
            )

        return has_permission

    def _validate_input_path(
        self, path: str, operation: str = "read", loader_type: str = None
    ) -> str:
        """
        Validate input path for security.

        Args:
            path: Path to validate.
            operation: Operation type (read/write).
            loader_type: Type of loader (sql, file, etc.) for write operations.

        Returns:
            Validated path.

        Raises:
            ValueError: If path is invalid.
        """
        if not self.enable_security or not self.input_validator:
            return path

        try:
            # For SQL loader write operations, validate as SQL identifier
            if loader_type == "sql" and operation == "write":
                if not self.input_validator.validate_sql_identifier(path):
                    raise ValueError(f"Invalid SQL table name: '{path}'")
                return path

            # For file operations, validate as file path
            allowed_extensions = {
                "read": [".csv", ".xlsx", ".xls", ".pdf", ".json"],
                "write": [".csv", ".xlsx", ".xls", ".parquet", ".feather"],
            }

            validated_path = self.input_validator.validate_file_path(
                path, allowed_extensions.get(operation, []), operation=operation
            )
            return str(validated_path)

        except ValueError as e:
            if self.audit_logger:
                self.audit_logger.log_security_event(
                    self.username,
                    f"Invalid {operation} path: {path}",
                    "high",
                    {"path": path, "error": str(e), "loader_type": loader_type},
                )
            raise

    def _apply_security_transformations(
        self, df: pd.DataFrame, stage: str
    ) -> pd.DataFrame:
        """
        Apply security transformations to DataFrame.

        Args:
            df: Input DataFrame.
            stage: Processing stage (extract/transform/load).

        Returns:
            Secured DataFrame.
        """
        if not self.enable_security or df.empty:
            return df

        df_secured = df.copy()

        # Apply encryption if enabled
        if self.encryptor and self.security_config.should_encrypt():
            try:
                df_secured = self.encryptor.encrypt_dataframe(df_secured)
                if self.audit_logger:
                    self.audit_logger.log_event(
                        AuditEventType.DATA_MODIFICATION,
                        self.username,
                        {
                            "stage": stage,
                            "operation": "encryption",
                            "rows": len(df_secured),
                            "encrypted_columns": self.encryptor._identify_sensitive_columns(
                                df
                            ),
                        },
                        True,
                    )
            except Exception as e:
                if self.audit_logger:
                    self.audit_logger.log_security_event(
                        self.username,
                        f"Encryption failed at {stage} stage",
                        "medium",
                        {"error": str(e), "stage": stage},
                    )
                print(f"[Security Warning] Encryption failed: {e}")

        return df_secured

    def run(
        self,
        extractor_name: str,
        source: Any,
        loader_name: str,
        target: Any,
        strategy: LoadStrategy = LoadStrategy.REPLACE,
        key_columns: Optional[List[str]] = None,
        **loader_kwargs,
    ) -> pd.DataFrame:
        """
        Execute the complete ETL pipeline with security.

        Steps:
            1. Check permissions
            2. Validate inputs
            3. EXTRACT using the named extractor
            4. TRANSFORM using all added transformers in sequence
            5. LOAD using the named loader with specified strategy
            6. Log audit trail

        Args:
            extractor_name: Name of the registered extractor to use.
            source: Source data for the extractor.
            loader_name: Name of the registered loader to use.
            target: Target destination for the loader.
            strategy: How to handle existing data at target.
            key_columns: Columns to use for matching records (for UPDATE/UPSERT).
            **loader_kwargs: Additional arguments passed to the loader.

        Returns:
            The final transformed DataFrame if successful, None otherwise.
        """
        # Security: Check permissions
        if not self._check_permission(Operation.EXECUTE_PIPELINE, str(source)):
            raise PermissionError(
                f"User '{self.username}' lacks permission to execute pipeline"
            )

        # Security: Validate inputs
        source_path = self._validate_input_path(str(source), "read")
        if isinstance(target, str):
            target_path = self._validate_input_path(target, "write", loader_name)
        else:
            target_path = str(target)

        # Security: Validate extractor and loader names
        if self.enable_security and self.input_validator:
            if not self.input_validator.validate_sql_identifier(extractor_name):
                raise ValueError(f"Invalid extractor name: {extractor_name}")
            if not self.input_validator.validate_sql_identifier(loader_name):
                raise ValueError(f"Invalid loader name: {loader_name}")

        # Log pipeline start
        if self.audit_logger:
            self.audit_logger.log_pipeline_execution(
                user=self.username,
                pipeline_name=f"{extractor_name}_to_{loader_name}",
                source=source_path,
                target=target_path,
                rows_processed=0,
                success=False,
                error_message=None,
            )

        try:
            # 1. EXTRACT
            if extractor_name not in self.extractors:
                raise ValueError(f"Extractor '{extractor_name}' not registered.")
            extractor = self.extractors[extractor_name]

            # Security: Log data access
            if self.audit_logger:
                self.audit_logger.log_data_access(
                    self.username, source_path, "extract", {"extractor": extractor_name}
                )

            df = extractor.extract(source_path)
            print(f"[EXTRACT] Extracted {len(df)} rows")

            # Security: Apply encryption to extracted data
            df = self._apply_security_transformations(df, "extract")

            # 2. TRANSFORM
            for transformer in self.transformers:
                # Security: Check transformer permission
                transformer_name = transformer.__class__.__name__
                if not self._check_permission(Operation.TRANSFORM, transformer_name):
                    print(
                        f"[Security] Skipping transformer '{transformer_name}' - permission denied"
                    )
                    continue

                df = transformer.transform(df)
                print(f"[TRANSFORM] Applied {transformer_name}")

                # Security: Apply encryption after each transformation if needed
                df = self._apply_security_transformations(
                    df, f"transform_{transformer_name}"
                )

            # 3. LOAD
            if loader_name not in self.loaders:
                raise ValueError(f"Loader '{loader_name}' not registered.")
            loader = self.loaders[loader_name]

            # Security: Check load permission
            if not self._check_permission(Operation.LOAD, target_path):
                raise PermissionError(f"Permission denied to load to {target_path}")

            # Security: Validate key columns if provided
            if key_columns and self.enable_security and self.input_validator:
                for col in key_columns:
                    if not self.input_validator.validate_sql_identifier(col):
                        raise ValueError(f"Invalid key column name: {col}")

            # Security: Apply final encryption before loading
            df = self._apply_security_transformations(df, "load")

            # Try to use the new load method with strategy
            try:
                success = loader.load(
                    df=df,
                    target=target,
                    strategy=strategy,
                    key_columns=key_columns,
                    **loader_kwargs,
                )
            except TypeError as e:
                # Fallback for loaders that don't support strategy parameter yet
                if "unexpected keyword argument 'strategy'" in str(e):
                    print(
                        f"[WARNING] Loader doesn't support strategy parameter, using REPLACE"
                    )
                    success = loader.load_legacy(df, target)
                else:
                    raise

            if success:
                print(
                    f"[LOAD] Successfully loaded to {target} using {strategy} strategy"
                )

                # Security: Log successful pipeline execution
                if self.audit_logger:
                    self.audit_logger.log_pipeline_execution(
                        user=self.username,
                        pipeline_name=f"{extractor_name}_to_{loader_name}",
                        source=source_path,
                        target=target_path,
                        rows_processed=len(df),
                        success=True,
                        error_message=None,
                    )

                return df
            else:
                print("[LOAD] Failed to load data")

                # Security: Log failed pipeline execution
                if self.audit_logger:
                    self.audit_logger.log_pipeline_execution(
                        user=self.username,
                        pipeline_name=f"{extractor_name}_to_{loader_name}",
                        source=source_path,
                        target=target_path,
                        rows_processed=len(df),
                        success=False,
                        error_message="Loader returned failure",
                    )

                return None

        except Exception as e:
            print(f"[Pipeline Error] {e}")

            # Security: Log pipeline error
            if self.audit_logger:
                self.audit_logger.log_pipeline_execution(
                    user=self.username,
                    pipeline_name=f"{extractor_name}_to_{loader_name}",
                    source=source_path,
                    target=target_path,
                    rows_processed=0,
                    success=False,
                    error_message=str(e),
                )

            # Security: Log security event for certain error types
            if self.audit_logger and "permission" in str(e).lower():
                self.audit_logger.log_security_event(
                    self.username,
                    "Permission violation attempt",
                    "high",
                    {"error": str(e), "source": source_path, "target": target_path},
                )

            raise

    def run_with_options(
        self,
        extractor_name: str,
        source: Any,
        loader_name: str,
        target: Any,
        options: LoadOptions,
        **loader_kwargs,
    ) -> pd.DataFrame:
        """
        Execute pipeline with LoadOptions configuration and security.

        Args:
            extractor_name: Name of the registered extractor to use.
            source: Source data for the extractor.
            loader_name: Name of the registered loader to use.
            target: Target destination for the loader.
            options: LoadOptions configuration object.
            **loader_kwargs: Additional arguments passed to the loader.

        Returns:
            The final transformed DataFrame if successful, None otherwise.
        """
        return self.run(
            extractor_name=extractor_name,
            source=source,
            loader_name=loader_name,
            target=target,
            strategy=options.strategy,
            key_columns=options.key_columns,
            **{**options.extra_options, **loader_kwargs},
        )

    # Backward compatibility method
    def run_legacy(
        self,
        extractor_name: str,
        source: Any,
        loader_name: str,
        target: Any,
    ) -> pd.DataFrame:
        """
        Legacy run method for backward compatibility.
        Uses default REPLACE strategy.
        """
        return self.run(
            extractor_name=extractor_name,
            source=source,
            loader_name=loader_name,
            target=target,
            strategy=LoadStrategy.REPLACE,
        )

    def shutdown(self):
        """
        Shutdown pipeline and security components.
        """
        if self.audit_logger:
            self.audit_logger.log_event(
                AuditEventType.SYSTEM_SHUTDOWN,
                self.username,
                {"pipeline": "ETLPipeline"},
                True,
            )
        print("[Pipeline] Security components shutdown complete")
