"""
Role-Based Access Control for ETL operations.
"""
import os
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class Operation(Enum):
    """ETL operations that can be controlled."""

    EXTRACT = "extract"
    TRANSFORM = "transform"
    LOAD = "load"
    READ_CONFIG = "read_config"
    WRITE_CONFIG = "write_config"
    EXECUTE_PIPELINE = "execute_pipeline"
    VIEW_SENSITIVE_DATA = "view_sensitive_data"
    MODIFY_SENSITIVE_DATA = "modify_sensitive_data"
    MANAGE_USERS = "manage_users"
    VIEW_AUDIT_LOGS = "view_audit_logs"


class Role(Enum):
    """Predefined roles for ETL operations."""

    VIEWER = "viewer"  # Can view pipelines and results
    OPERATOR = "operator"  # Can execute predefined pipelines
    DEVELOPER = "developer"  # Can create/modify pipelines
    ADMIN = "admin"  # Full access including security config
    AUDITOR = "auditor"  # Can view audit logs and security events
    DATA_STEWARD = "data_steward"  # Can manage sensitive data


@dataclass
class User:
    """User with assigned roles."""

    username: str
    roles: Set[Role]
    attributes: Dict[str, Any] = None

    def __post_init__(self):
        if self.attributes is None:
            self.attributes = {}

    def has_role(self, role: Role) -> bool:
        """Check if user has specific role."""
        return role in self.roles

    def has_any_role(self, roles: List[Role]) -> bool:
        """Check if user has any of the specified roles."""
        return any(role in self.roles for role in roles)

    def has_all_roles(self, roles: List[Role]) -> bool:
        """Check if user has all of the specified roles."""
        return all(role in self.roles for role in roles)


class AccessController:
    """Controls access to ETL operations based on roles."""

    # Role permissions mapping
    ROLE_PERMISSIONS = {
        Role.VIEWER: {
            Operation.READ_CONFIG,
            # VIEWER cannot execute pipelines - only view results
        },
        Role.OPERATOR: {
            Operation.READ_CONFIG,
            Operation.EXECUTE_PIPELINE,
            Operation.EXTRACT,
            Operation.TRANSFORM,
            Operation.LOAD,
        },
        Role.DEVELOPER: {
            Operation.READ_CONFIG,
            Operation.WRITE_CONFIG,
            Operation.EXECUTE_PIPELINE,
            Operation.EXTRACT,
            Operation.TRANSFORM,
            Operation.LOAD,
        },
        Role.ADMIN: set(Operation),  # All operations
        Role.AUDITOR: {
            Operation.READ_CONFIG,
            Operation.VIEW_AUDIT_LOGS,
            Operation.VIEW_SENSITIVE_DATA,  # For audit purposes only
        },
        Role.DATA_STEWARD: {
            Operation.READ_CONFIG,
            Operation.EXECUTE_PIPELINE,
            Operation.EXTRACT,
            Operation.TRANSFORM,
            Operation.LOAD,
            Operation.VIEW_SENSITIVE_DATA,
            Operation.MODIFY_SENSITIVE_DATA,
        },
    }

    def __init__(self):
        self.users: Dict[str, User] = {}
        self._load_users()

    def _load_users(self):
        """Load users from environment or configuration file."""
        # Load from environment variable
        # Format: 'user1:viewer,operator;user2:admin;user3:auditor'
        users_config = os.getenv("ETL_USERS", "")
        if users_config:
            for user_spec in users_config.split(";"):
                if ":" in user_spec:
                    username, roles_str = user_spec.split(":", 1)
                    roles = {
                        Role(role.strip())
                        for role in roles_str.split(",")
                        if role.strip()
                    }
                    self.users[username] = User(username, roles)

        # Default admin user if no users configured
        if not self.users:
            self.users["admin"] = User("admin", {Role.ADMIN})

    def check_permission(
        self, username: str, operation: Operation, resource: Optional[str] = None
    ) -> bool:
        """
        Check if user has permission for operation.

        Args:
            username: Username to check.
            operation: Operation to check permission for.
            resource: Optional resource name for resource-level checks.

        Returns:
            True if user has permission, False otherwise.
        """
        user = self.users.get(username)
        if not user:
            return False

        # Check each role for permission
        for role in user.roles:
            if operation in self.ROLE_PERMISSIONS.get(role, set()):
                # Additional resource-based checks
                if resource and not self._check_resource_permission(
                    user, operation, resource
                ):
                    continue
                return True

        return False

    def _check_resource_permission(
        self, user: User, operation: Operation, resource: str
    ) -> bool:
        """
        Check resource-specific permissions.

        Args:
            user: User object.
            operation: Operation being performed.
            resource: Resource name.

        Returns:
            True if user has permission for this resource.
        """
        # Implement resource-level access control
        # Example: Restrict access to certain databases or tables

        # Check for sensitive resources
        sensitive_keywords = ["sensitive", "confidential", "secret", "private"]
        resource_lower = resource.lower()

        if any(keyword in resource_lower for keyword in sensitive_keywords):
            # Only admins and data stewards can access sensitive resources
            return user.has_any_role([Role.ADMIN, Role.DATA_STEWARD, Role.AUDITOR])

        return True

    def require_permission(
        self, username: str, operation: Operation, resource: Optional[str] = None
    ):
        """
        Decorator to require permission for function execution.

        Args:
            username: Username to check.
            operation: Required operation.
            resource: Optional resource name.

        Returns:
            Decorator function.
        """

        def decorator(func):
            def wrapper(*args, **kwargs):
                if not self.check_permission(username, operation, resource):
                    raise PermissionError(
                        f"User '{username}' lacks permission for {operation.value} "
                        f"on resource '{resource if resource else 'any'}'"
                    )
                return func(*args, **kwargs)

            return wrapper

        return decorator

    def add_user(
        self,
        username: str,
        roles: List[Role],
        attributes: Optional[Dict[str, Any]] = None,
    ):
        """
        Add a new user.

        Args:
            username: Username.
            roles: List of roles for the user.
            attributes: Optional user attributes.
        """
        self.users[username] = User(username, set(roles), attributes or {})

    def remove_user(self, username: str):
        """
        Remove a user.

        Args:
            username: Username to remove.
        """
        if username in self.users:
            del self.users[username]

    def update_user_roles(self, username: str, roles: List[Role]):
        """
        Update user roles.

        Args:
            username: Username.
            roles: New list of roles.
        """
        if username in self.users:
            self.users[username].roles = set(roles)

    def list_users(self) -> List[Dict[str, Any]]:
        """
        List all users with their roles.

        Returns:
            List of user dictionaries.
        """
        return [
            {
                "username": user.username,
                "roles": [role.value for role in user.roles],
                "attributes": user.attributes,
            }
            for user in self.users.values()
        ]
