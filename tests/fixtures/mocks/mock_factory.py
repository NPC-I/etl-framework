"""
Mock Factory - Centralized mock object creation.
"""
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, Mock, patch

import pandas as pd

from etl_framework.core.extractor import Extractor
from etl_framework.core.load_strategy import LoadOptions, LoadStrategy
from etl_framework.core.loader import Loader
from etl_framework.core.transformer import Transformer
from tests.fixtures.data.test_data_factory import TestDataFactory


class MockFactory:
    """Factory for creating standardized mock objects."""

    @staticmethod
    def create_mock_extractor(
        data: Optional[pd.DataFrame] = None,
        raise_error: bool = False,
        error_type: Exception = ValueError,
        error_message: str = "Test error",
    ) -> Extractor:
        """
        Create a standardized mock extractor.

        Args:
            data: DataFrame to return (uses test data if None)
            raise_error: Whether to raise an error
            error_type: Type of error to raise
            error_message: Error message

        Returns:
            Mock extractor instance
        """
        mock_extractor = Mock(spec=Extractor)

        if raise_error:
            mock_extractor.extract.side_effect = error_type(error_message)
        else:
            return_data = (
                data if data is not None else TestDataFactory.create_sample_dataframe()
            )
            mock_extractor.extract.return_value = return_data

        # Add security info method
        mock_extractor.get_security_info.return_value = {
            "extractor_type": "MockExtractor",
            "has_security_validation": True,
        }

        return mock_extractor

    @staticmethod
    def create_mock_transformer(
        transform_data: Optional[pd.DataFrame] = None,
        raise_error: bool = False,
        add_column: str = "transformed",
        add_value: Any = "test_value",
    ) -> Transformer:
        """
        Create a standardized mock transformer.

        Args:
            transform_data: Specific data to return (transforms input if None)
            raise_error: Whether to raise an error
            add_column: Column to add to transformed data
            add_value: Value to add to new column

        Returns:
            Mock transformer instance
        """
        mock_transformer = Mock(spec=Transformer)

        if raise_error:
            mock_transformer.transform.side_effect = ValueError("Transform error")
        else:

            def transform_impl(df):
                if transform_data is not None:
                    return transform_data

                df = df.copy()
                df[add_column] = add_value
                return df

            mock_transformer.transform.side_effect = transform_impl

        # Add security info method
        mock_transformer.get_security_info.return_value = {
            "transformer_type": "MockTransformer",
            "has_input_validation": True,
            "has_output_validation": True,
        }

        # Add validation methods
        mock_transformer.validate_input.return_value = True
        mock_transformer.validate_output.return_value = True

        return mock_transformer

    @staticmethod
    def create_mock_loader(
        should_succeed: bool = True,
        track_calls: bool = True,
        validate_target: bool = True,
        validate_dataframe: bool = True,
    ) -> Loader:
        """
        Create a standardized mock loader.

        Args:
            should_succeed: Whether load should succeed
            track_calls: Whether to track method calls
            validate_target: Whether target validation should succeed
            validate_dataframe: Whether dataframe validation should succeed

        Returns:
            Mock loader instance
        """
        mock_loader = Mock(spec=Loader)

        # Track calls if requested
        if track_calls:
            mock_loader.calls = []
            mock_loader.load_calls = []

            def load_impl(df, target, strategy=LoadStrategy.REPLACE, **kwargs):
                if track_calls:
                    mock_loader.load_calls.append(
                        {
                            "df": df,
                            "target": target,
                            "strategy": strategy,
                            "kwargs": kwargs,
                        }
                    )
                return should_succeed

            mock_loader.load.side_effect = load_impl
        else:
            mock_loader.load.return_value = should_succeed

        # Add security info method
        mock_loader.get_security_info.return_value = {
            "loader_type": "MockLoader",
            "has_target_validation": True,
            "has_dataframe_validation": True,
        }

        # Add validation methods
        mock_loader.validate_target.return_value = validate_target
        mock_loader.validate_dataframe.return_value = validate_dataframe

        # Add legacy method for compatibility
        mock_loader.load_legacy.return_value = should_succeed

        return mock_loader

    @staticmethod
    def create_mock_pipeline(
        username: str = "test_user",
        enable_security: bool = True,
        extractors: Optional[Dict[str, Extractor]] = None,
        transformers: Optional[List[Transformer]] = None,
        loaders: Optional[Dict[str, Loader]] = None,
    ) -> Mock:
        """
        Create a mock ETL pipeline.

        Args:
            username: Username for the pipeline
            enable_security: Whether security is enabled
            extractors: Dictionary of extractors to register
            transformers: List of transformers to add
            loaders: Dictionary of loaders to register

        Returns:
            Mock pipeline instance
        """
        from etl_framework.core.pipeline import ETLPipeline

        mock_pipeline = Mock(spec=ETLPipeline)

        # Set up pipeline attributes
        mock_pipeline.username = username
        mock_pipeline.enable_security = enable_security
        mock_pipeline.extractors = extractors or {}
        mock_pipeline.transformers = transformers or []
        mock_pipeline.loaders = loaders or {}

        # Mock methods
        mock_pipeline.register_extractor.side_effect = (
            lambda name, extractor: mock_pipeline.extractors.update({name: extractor})
        )

        mock_pipeline.add_transformer.side_effect = (
            lambda transformer: mock_pipeline.transformers.append(transformer)
        )

        mock_pipeline.register_loader.side_effect = (
            lambda name, loader: mock_pipeline.loaders.update({name: loader})
        )

        # Mock run method
        def run_impl(extractor_name, source, loader_name, target, **kwargs):
            if extractor_name not in mock_pipeline.extractors:
                raise ValueError(f"Extractor '{extractor_name}' not registered")
            if loader_name not in mock_pipeline.loaders:
                raise ValueError(f"Loader '{loader_name}' not registered")

            # Simulate extraction
            extractor = mock_pipeline.extractors[extractor_name]
            df = extractor.extract(source)

            # Simulate transformation
            for transformer in mock_pipeline.transformers:
                df = transformer.transform(df)

            # Simulate loading
            loader = mock_pipeline.loaders[loader_name]
            success = loader.load(df, target, **kwargs)

            return df if success else None

        mock_pipeline.run.side_effect = run_impl
        mock_pipeline.run_with_options.side_effect = run_impl
        mock_pipeline.run_legacy.side_effect = run_impl

        # Mock shutdown
        mock_pipeline.shutdown.return_value = None

        return mock_pipeline

    @staticmethod
    def create_mock_security_config(
        security_level: str = "testing",
        encryption_enabled: bool = True,
        rbac_enabled: bool = True,
        audit_logging_enabled: bool = True,
    ) -> Mock:
        """
        Create a mock security configuration.

        Args:
            security_level: Security level
            encryption_enabled: Whether encryption is enabled
            rbac_enabled: Whether RBAC is enabled
            audit_logging_enabled: Whether audit logging is enabled

        Returns:
            Mock security config instance
        """
        from etl_framework.security.config import SecurityConfig

        mock_config = Mock(spec=SecurityConfig)

        # Set attributes
        mock_config.security_level = Mock()
        mock_config.security_level.value = security_level
        mock_config.encryption_enabled = encryption_enabled
        mock_config.rbac_enabled = rbac_enabled
        mock_config.audit_logging_enabled = audit_logging_enabled

        # Mock methods
        mock_config.should_encrypt.return_value = encryption_enabled
        mock_config.should_log_audit.return_value = audit_logging_enabled
        mock_config.validate.return_value = []
        mock_config.get_restrictions.return_value = {
            "encryption_required": encryption_enabled,
            "input_validation": "strict" if security_level == "production" else "basic",
            "access_control": rbac_enabled,
            "error_details": security_level != "production",
        }

        return mock_config

    @staticmethod
    def create_mock_access_controller(
        users: Optional[Dict[str, List[str]]] = None
    ) -> Mock:
        """
        Create a mock access controller.

        Args:
            users: Dictionary of username -> roles

        Returns:
            Mock access controller instance
        """
        from etl_framework.security.access_control import AccessController, Operation

        mock_controller = Mock(spec=AccessController)

        # Default users if none provided
        if users is None:
            users = {"admin": ["admin"], "operator": ["operator"], "viewer": ["viewer"]}

        # Mock check_permission method
        def check_permission_impl(username, operation, resource=None):
            # Admin has all permissions
            if username == "admin":
                return True

            # Operator can execute pipelines but not manage users
            if username == "operator":
                if operation.value in [
                    "execute_pipeline",
                    "extract",
                    "transform",
                    "load",
                    "read_config",
                ]:
                    return True
                return False

            # Viewer can only read config
            if username == "viewer":
                return operation.value == "read_config"

            return False

        mock_controller.check_permission.side_effect = check_permission_impl

        # Mock other methods
        mock_controller.list_users.return_value = [
            {"username": user, "roles": roles} for user, roles in users.items()
        ]

        return mock_controller

    @staticmethod
    def patch_module(module_path: str, **mock_attributes) -> Any:
        """
        Create a patch for a module with specified mock attributes.

        Args:
            module_path: Path to module to patch
            **mock_attributes: Attributes to set on the mock

        Returns:
            Patch context manager
        """
        mock_obj = Mock()
        for attr_name, attr_value in mock_attributes.items():
            setattr(mock_obj, attr_name, attr_value)

        return patch(module_path, mock_obj)
