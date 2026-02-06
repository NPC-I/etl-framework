"""
Structured audit logging for security and compliance.
"""
import json
import logging
import os
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class AuditEventType(Enum):
    """Types of audit events."""

    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    PIPELINE_EXECUTION = "pipeline_execution"
    DATA_ACCESS = "data_access"
    DATA_MODIFICATION = "data_modification"
    CONFIG_CHANGE = "config_change"
    SECURITY_EVENT = "security_event"
    PERMISSION_DENIED = "permission_denied"
    ERROR = "error"
    SYSTEM_STARTUP = "system_startup"
    SYSTEM_SHUTDOWN = "system_shutdown"


class AuditLogger:
    """Structured audit logging with security events."""

    def __init__(self, log_file: Optional[str] = None):
        """
        Initialize audit logger.

        Args:
            log_file: Optional path to audit log file.
        """
        self.logger = logging.getLogger("etl_audit")
        self.logger.setLevel(logging.INFO)

        # Remove existing handlers
        self.logger.handlers.clear()

        # Console handler for warnings and errors
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.WARNING)
        console_formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)

        # File handler for audit logs
        if log_file:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(log_file), exist_ok=True)

            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.INFO)
            json_formatter = logging.Formatter("%(message)s")  # JSON messages only
            file_handler.setFormatter(json_formatter)
            self.logger.addHandler(file_handler)
            self.log_file = log_file
        else:
            self.log_file = None

    def log_event(
        self,
        event_type: AuditEventType,
        user: str,
        details: Dict[str, Any],
        success: bool = True,
    ):
        """
        Log a structured audit event.

        Args:
            event_type: Type of audit event.
            user: Username performing the action.
            details: Event details dictionary.
            success: Whether the operation was successful.
        """
        audit_record = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": event_type.value,
            "user": user,
            "success": success,
            "details": details,
            "source_ip": self._get_source_ip(),
            "session_id": self._get_session_id(),
        }

        # Add to log
        self.logger.info(json.dumps(audit_record))

        # Alert on security events or failures
        if event_type == AuditEventType.SECURITY_EVENT or not success:
            self._alert_security_team(audit_record)

    def log_pipeline_execution(
        self,
        user: str,
        pipeline_name: str,
        source: str,
        target: str,
        rows_processed: int,
        success: bool,
        error_message: Optional[str] = None,
    ):
        """
        Log pipeline execution for audit trail.

        Args:
            user: Username executing the pipeline.
            pipeline_name: Name of the pipeline.
            source: Source data location.
            target: Target data location.
            rows_processed: Number of rows processed.
            success: Whether execution was successful.
            error_message: Optional error message if failed.
        """
        details = {
            "pipeline": pipeline_name,
            "source": source,
            "target": target,
            "rows_processed": rows_processed,
            "error_message": error_message,
        }

        self.log_event(AuditEventType.PIPELINE_EXECUTION, user, details, success)

    def log_data_access(
        self, user: str, resource: str, operation: str, filters: Optional[Dict] = None
    ):
        """
        Log data access for compliance.

        Args:
            user: Username accessing data.
            resource: Resource being accessed.
            operation: Type of access operation.
            filters: Optional filters applied to the data.
        """
        details = {"resource": resource, "operation": operation, "filters": filters}

        self.log_event(AuditEventType.DATA_ACCESS, user, details, True)

    def log_permission_denied(
        self, user: str, operation: str, resource: Optional[str] = None
    ):
        """
        Log permission denied events.

        Args:
            user: Username denied permission.
            operation: Operation attempted.
            resource: Resource attempted to access.
        """
        details = {"operation": operation, "resource": resource}

        self.log_event(AuditEventType.PERMISSION_DENIED, user, details, False)

    def log_security_event(
        self,
        user: str,
        event: str,
        severity: str = "medium",
        details: Optional[Dict] = None,
    ):
        """
        Log security events.

        Args:
            user: Username involved.
            event: Security event description.
            severity: Event severity (low, medium, high, critical).
            details: Additional event details.
        """
        event_details = {"event": event, "severity": severity, **(details or {})}

        self.log_event(AuditEventType.SECURITY_EVENT, user, event_details, False)

    def _get_source_ip(self) -> Optional[str]:
        """Get source IP address if available."""
        # Implementation depends on deployment environment
        # For CLI: return None or localhost
        # For web: extract from request
        return os.getenv("ETL_SOURCE_IP", "localhost")

    def _get_session_id(self) -> Optional[str]:
        """Get session ID if available."""
        # Implementation depends on authentication system
        return os.getenv("ETL_SESSION_ID")

    def _alert_security_team(self, audit_record: Dict[str, Any]):
        """Alert security team of critical events."""
        # Could send email, Slack message, or trigger SIEM integration
        # For now, log to console with high visibility
        print(f"\n⚠️  SECURITY ALERT: {audit_record['event_type']}")
        print(f"   User: {audit_record['user']}")
        print(f"   Success: {audit_record['success']}")
        print(f"   Details: {json.dumps(audit_record['details'], indent=2)}")
        print()

    def get_recent_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get recent audit logs.

        Args:
            limit: Maximum number of logs to return.

        Returns:
            List of audit log entries.
        """
        if not self.log_file or not os.path.exists(self.log_file):
            return []

        logs = []
        try:
            with open(self.log_file, "r") as f:
                lines = f.readlines()[-limit:]  # Get last N lines
                for line in lines:
                    try:
                        logs.append(json.loads(line.strip()))
                    except json.JSONDecodeError:
                        continue  # Skip invalid JSON lines
        except (FileNotFoundError, PermissionError, OSError) as file_error:
            print(f"[Audit Logger Warning] Could not read log file: {file_error}")
        except Exception as unexpected_error:
            print(
                f"[Audit Logger Error] Unexpected error reading logs: {unexpected_error}"
            )

        return logs

    def search_logs(self, query: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Search audit logs by query.

        Args:
            query: Dictionary with search criteria.

        Returns:
            List of matching audit log entries.
        """
        all_logs = self.get_recent_logs(limit=1000)
        matching_logs = []

        for log in all_logs:
            match = True
            for key, value in query.items():
                if key not in log or log[key] != value:
                    match = False
                    break
            if match:
                matching_logs.append(log)

        return matching_logs

    def search_logs(self, query: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Search audit logs by query.

        Args:
            query: Dictionary with search criteria.

        Returns:
            List of matching audit log entries.
        """
        all_logs = self.get_recent_logs(limit=1000)
        matching_logs = []

        for log in all_logs:
            match = True
            for key, value in query.items():
                if key not in log or log[key] != value:
                    match = False
                    break
            if match:
                matching_logs.append(log)

        return matching_logs
