#!/usr/bin/env python3
"""
Audit Logging Demo

This demo shows comprehensive audit logging capabilities:
1. Structured audit logging
2. Security event monitoring
3. Security reporting
4. Log search and analysis
"""
import json
import os
import sys
from datetime import datetime
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# At the top of each demo
try:
    from dotenv import load_dotenv

    load_dotenv()
    print("✅ Loaded .env configuration")
except ImportError:
    print("⚠️  Install python-dotenv: pip install python-dotenv")


from etl_framework.security.access_control import AccessController, Operation

# Import security components
from etl_framework.security.audit_logger import AuditEventType, AuditLogger
from etl_framework.security.input_validator import InputValidator


def demonstrate_audit_logging():
    """Demonstrate audit logging features."""
    print("📝 AUDIT LOGGING DEMONSTRATION")
    print("=" * 60)

    # Create audit logger
    audit_log_file = os.environ["ETL_AUDIT_LOG_FILE"]
    logger = AuditLogger(audit_log_file)

    # Log different types of events
    print("1. Logging various audit events...")

    # User authentication events
    logger.log_event(
        AuditEventType.USER_LOGIN,
        "admin",
        {"method": "password", "ip": "192.168.1.100", "success": True},
        True,
    )

    logger.log_event(
        AuditEventType.USER_LOGIN,
        "hacker",
        {"method": "password", "ip": "10.0.0.99", "success": False},
        False,
    )

    # Pipeline execution events
    logger.log_pipeline_execution(
        "operator", "sales_etl", "sales.csv", "database.sales", 1500, True
    )

    logger.log_pipeline_execution(
        "operator",
        "failed_etl",
        "corrupt.csv",
        "database.failed",
        0,
        False,
        "File not found",
    )

    # Data access events
    logger.log_data_access(
        "viewer",
        "customer_data",
        "read",
        {"filter": "status=active", "rows_returned": 250},
    )

    # Permission denied events
    logger.log_permission_denied("viewer", "write_config", "production_config.json")

    # Security events
    logger.log_security_event(
        "system",
        "Suspicious file access pattern detected",
        "high",
        {"pattern": "path_traversal", "file": "../../../etc/passwd"},
    )

    # System events
    logger.log_event(
        AuditEventType.SYSTEM_STARTUP,
        "system",
        {"version": "1.0.0", "security_level": "production"},
        True,
    )

    print("   ✓ Logged 8 different audit events")
    print()

    # Read and display audit logs
    print("2. Reading and analyzing audit logs...")
    logs = logger.get_recent_logs(limit=10)

    print(f"   Total logs retrieved: {len(logs)}")
    print()

    # Analyze log distribution
    event_types = {}
    users = {}
    success_count = 0

    for log in logs:
        event_type = log["event_type"]
        user = log["user"]
        success = log["success"]

        event_types[event_type] = event_types.get(event_type, 0) + 1
        users[user] = users.get(user, 0) + 1
        if success:
            success_count += 1

    print("   Event Type Distribution:")
    for event_type, count in sorted(event_types.items()):
        print(f"     • {event_type}: {count}")

    print()
    print("   User Activity:")
    for user, count in sorted(users.items()):
        print(f"     • {user}: {count} events")

    print()
    print(
        f"   Success Rate: {success_count}/{len(logs)} ({success_count/len(logs)*100:.1f}%)"
    )
    print()

    # Search logs
    print("3. Searching audit logs...")

    # Search by user
    admin_logs = logger.search_logs({"user": "admin"})
    print(f"   Admin events: {len(admin_logs)}")

    # Search by event type
    security_logs = logger.search_logs({"event_type": "security_event"})
    print(f"   Security events: {len(security_logs)}")

    # Search by success status
    failed_logs = logger.search_logs({"success": False})
    print(f"   Failed events: {len(failed_logs)}")

    print()

    # Show sample log entries
    print("4. Sample Audit Log Entries:")
    print()

    for i, log in enumerate(logs[:2], 1):
        print(f"   Entry {i}:")
        print(f"     Timestamp: {log['timestamp']}")
        print(f"     Event:     {log['event_type']}")
        print(f"     User:      {log['user']}")
        print(f"     Success:   {log['success']}")

        if "details" in log and log["details"]:
            print(f"     Details:   {json.dumps(log['details'], indent=14)[14:]}")

        print()

    print("=" * 60)
    print()


def demonstrate_security_features():
    """Demonstrate compliance-related audit features."""
    print("📋 SECURITY FEATURES")
    print("=" * 60)

    # Security audit example
    print("Security Audit Trail:")
    print("  1. Data Access Logging:")
    print("     • Who accessed what data")
    print("     • When and why")
    print("     • What filters were applied")
    print()

    print("  2. Data Modification Tracking:")
    print("     • What data was changed")
    print("     • Who changed it")
    print("     • Previous and new values")
    print()

    print("  3. Consent Management:")
    print("     • Consent given/withdrawn")
    print("     • Consent purpose")
    print("     • Timestamp of consent")
    print()

    print("  4. Data Subject Rights:")
    print("     • Access requests")
    print("     • Deletion requests")
    print("     • Portability requests")
    print()

    # Healthcare security example
    print("Healthcare Security (if enabled):")
    print("  • PHI access logging")
    print("  • Minimum necessary principle")
    print("  • Audit controls")
    print("  • Integrity controls")
    print()

    print("=" * 60)
    print()


def create_security_report():
    """Create a security report from audit logs."""
    print("📄 GENERATING SECURITY REPORT")
    print("=" * 60)

    audit_log_file = os.environ["ETL_AUDIT_LOG_FILE"]
    logger = AuditLogger(audit_log_file)
    logs = logger.get_recent_logs(limit=1000)

    # Generate compliance metrics
    report = {
        "report_date": datetime.utcnow().isoformat() + "Z",
        "audit_period": "Last 1000 events",
        "total_events": len(logs),
        "compliance_metrics": {},
        "security_events": {},
        "user_activity": {},
        "recommendations": [],
    }

    # Calculate metrics
    success_events = [log for log in logs if log["success"]]
    failed_events = [log for log in logs if not log["success"]]
    security_events = [log for log in logs if log["event_type"] == "security_event"]
    data_access_events = [log for log in logs if log["event_type"] == "data_access"]

    report["compliance_metrics"] = {
        "success_rate": len(success_events) / len(logs) * 100 if logs else 0,
        "security_event_rate": len(security_events) / len(logs) * 100 if logs else 0,
        "data_access_tracking": len(data_access_events) > 0,
        "audit_trail_completeness": len(logs) > 0,
    }

    report["security_events"] = {
        "total": len(security_events),
        "by_severity": {},
        "top_patterns": [],
    }

    report["user_activity"] = {
        "total_users": len(set(log["user"] for log in logs)),
        "most_active_user": max(
            set(log["user"] for log in logs),
            key=lambda user: sum(1 for log in logs if log["user"] == user),
        )
        if logs
        else "N/A",
    }

    # Generate recommendations
    if len(failed_events) > len(logs) * 0.1:  # More than 10% failures
        report["recommendations"].append(
            {
                "priority": "high",
                "action": "Investigate high failure rate",
                "details": f"{len(failed_events)} failed events ({len(failed_events)/len(logs)*100:.1f}%)",
            }
        )

    if len(security_events) == 0:
        report["recommendations"].append(
            {
                "priority": "medium",
                "action": "Enable security event monitoring",
                "details": "No security events logged in audit period",
            }
        )

    # Save report
    demo_dir = Path(__file__).parent
    output_dir = demo_dir / "output"
    output_dir.mkdir(exist_ok=True)

    report_file = output_dir / "security_report.json"
    with open(report_file, "w") as f:
        json.dump(report, f, indent=2)

    print(f"   Report generated: {report_file}")
    print()

    # Print summary
    print("   Security Report Summary:")
    print(f"     • Total Events: {report['total_events']}")
    print(f"     • Success Rate: {report['compliance_metrics']['success_rate']:.1f}%")
    print(f"     • Security Events: {report['security_events']['total']}")
    print(f"     • Unique Users: {report['user_activity']['total_users']}")
    print(f"     • Recommendations: {len(report['recommendations'])}")
    print()

    print("=" * 60)
    print()


def main():
    """Run the audit logging demo."""
    print("=" * 70)
    print("📝 AUDIT LOGGING & SECURITY DEMO")
    print("=" * 70)
    print("This demo shows comprehensive audit logging capabilities.")
    print()

    # Setup output directory
    demo_dir = Path(__file__).parent
    output_dir = demo_dir / "output"
    output_dir.mkdir(exist_ok=True)

    # Clean up previous audit log
    audit_log_file = output_dir / "audit_demo.log"
    if audit_log_file.exists():
        audit_log_file.unlink()

    # Run demonstrations
    demonstrate_audit_logging()
    demonstrate_security_features()
    create_security_report()

    print("🎯 Key Features Demonstrated:")
    print("   1. Structured JSON audit logging")
    print("   2. Multiple event types (login, pipeline, data access, etc.)")
    print("   3. Log search and analysis capabilities")
    print("   4. Security reporting")
    print("   5. Security event monitoring")
    print("   6. Success/failure tracking")
    print("   7. User activity analysis")
    print()

    print("💾 Output Files:")
    print(f"   • Audit Log: {audit_log_file}")
    print(f"   • Security Report: demo/output/security_report.json")
    print()

    print("🔒 Security Benefits:")
    print("   • Complete audit trail for compliance")
    print("   • Real-time security monitoring")
    print("   • Incident investigation support")
    print("   • Security standards evidence")
    print("   • User behavior analysis")
    print()

    print("=" * 70)
    print("🎉 Audit logging demo completed successfully!")
    print("=" * 70)

    return 0


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
