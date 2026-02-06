#!/usr/bin/env python3
"""
Unified Security Suite - Main Entry Point

Orchestrates all security, testing, and compliance operations.
"""
import argparse
import sys
from pathlib import Path
from typing import List, Optional


class SecuritySuite:
    """Main orchestrator for security suite operations."""

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.results = {}

    def run_security_audit(self, skip_tests: bool = False) -> bool:
        """Run comprehensive security audit."""
        print("🔒 Running comprehensive security audit...")
        try:
            # Import and run security audit
            from security_audit import SecurityAuditor

            auditor = SecurityAuditor(self.project_root)
            result = auditor.run_comprehensive_audit(skip_tests=skip_tests)
            self.results["security_audit"] = result
            return result.get("success", False)
        except ImportError as e:
            print(f"❌ Security audit module not available: {e}")
            print("   Install with: pip install -r scripts/requirements-audit.txt")
            return False

    def generate_sbom(self) -> bool:
        """Generate Software Bill of Materials."""
        print("📄 Generating Software Bill of Materials...")
        try:
            from sbom_generator import SBOMManager

            manager = SBOMManager(self.project_root)
            sbom = manager.generate_sbom()
            self.results["sbom"] = sbom
            return True
        except ImportError as e:
            print(f"❌ SBOM generator not available: {e}")
            return False

    def run_tests(
        self, profile: str = "security", scenario: Optional[str] = None
    ) -> bool:
        """Run tests with specified profile or scenario."""
        print(f"🧪 Running tests with profile: {profile}")
        try:
            from test_runner import TestRunner

            runner = TestRunner(self.project_root)

            if scenario:
                exit_code = runner.run_scenario(scenario)
            else:
                exit_code = runner.run_profile(profile)

            self.results["tests"] = {
                "profile": profile,
                "scenario": scenario,
                "exit_code": exit_code,
                "success": exit_code == 0,
            }
            return exit_code == 0
        except ImportError as e:
            print(f"❌ Test runner not available: {e}")
            return False

    def manage_demos(
        self, action: str = "test", demo_filter: Optional[str] = None
    ) -> bool:
        """Setup or test demos."""
        print(f"🎮 Managing demos: {action}")
        try:
            from demo_manager import DemoManager

            manager = DemoManager(self.project_root)

            if action == "setup":
                result = manager.setup_demos()
            elif action == "test":
                result = manager.test_demos(demo_filter)
            elif action == "clean":
                result = manager.clean_demos()
            else:
                print(f"❌ Unknown demo action: {action}")
                return False

            self.results["demos"] = result
            return result.get("success", False)
        except ImportError as e:
            print(f"❌ Demo manager not available: {e}")
            return False

    def run_all(self, skip_tests: bool = False) -> bool:
        """Run all security suite operations."""
        print("🚀 Running complete security suite...")
        print("=" * 70)

        results = []

        # 1. Generate SBOM
        results.append(("SBOM Generation", self.generate_sbom()))

        # 2. Run security audit
        results.append(("Security Audit", self.run_security_audit(skip_tests)))

        # 3. Run security tests
        if not skip_tests:
            results.append(("Security Tests", self.run_tests("security")))

        # 4. Test demos
        results.append(("Demo Tests", self.manage_demos("test")))

        # Print summary
        print("\n" + "=" * 70)
        print("📊 SECURITY SUITE SUMMARY")
        print("=" * 70)

        all_passed = True
        for name, passed in results:
            status = "✅ PASSED" if passed else "❌ FAILED"
            print(f"{name:20} {status}")
            if not passed:
                all_passed = False

        print("=" * 70)

        if all_passed:
            print("🎉 All security suite checks passed!")
        else:
            print("⚠️  Some checks failed. Review the output above.")

        return all_passed


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Unified Security Suite for ETL Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --all                    # Run all checks
  %(prog)s --audit                  # Run security audit only
  %(prog)s --sbom                   # Generate SBOM only
  %(prog)s --tests --profile unit   # Run unit tests
  %(prog)s --demos --action setup   # Setup demos
        """,
    )

    # Operation selection
    parser.add_argument(
        "--all", action="store_true", help="Run all security suite operations"
    )
    parser.add_argument(
        "--audit", action="store_true", help="Run comprehensive security audit"
    )
    parser.add_argument(
        "--sbom", action="store_true", help="Generate Software Bill of Materials"
    )
    parser.add_argument("--tests", action="store_true", help="Run tests")
    parser.add_argument("--demos", action="store_true", help="Manage demos")

    # Options
    parser.add_argument(
        "--profile",
        default="security",
        choices=[
            "fast",
            "unit",
            "integration",
            "security",
            "functional",
            "all",
            "coverage",
            "smoke",
            "regression",
        ],
        help="Test profile to run (default: security)",
    )
    parser.add_argument(
        "--scenario",
        choices=[
            "basic",
            "security",
            "integration",
            "performance",
            "comprehensive",
            "ci",
        ],
        help="Test scenario to run",
    )
    parser.add_argument(
        "--demo-action",
        default="test",
        choices=["setup", "test", "clean"],
        help="Demo action (default: test)",
    )
    parser.add_argument("--demo-filter", help="Filter demos by name pattern")
    parser.add_argument(
        "--skip-tests", action="store_true", help="Skip test execution in audit"
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path.cwd(),
        help="Project root directory (default: current directory)",
    )

    args = parser.parse_args()

    # Initialize suite
    suite = SecuritySuite(args.project_root)

    # Run selected operations
    if args.all:
        success = suite.run_all(skip_tests=args.skip_tests)
        sys.exit(0 if success else 1)

    results = []

    if args.audit:
        results.append(("Security Audit", suite.run_security_audit(args.skip_tests)))

    if args.sbom:
        results.append(("SBOM Generation", suite.generate_sbom()))

    if args.tests:
        results.append(("Tests", suite.run_tests(args.profile, args.scenario)))

    if args.demos:
        results.append(
            ("Demos", suite.manage_demos(args.demo_action, args.demo_filter))
        )

    # If no operations specified, show help
    if not any([args.all, args.audit, args.sbom, args.tests, args.demos]):
        parser.print_help()
        return 0

    # Print results
    print("\n" + "=" * 70)
    print("📊 OPERATION RESULTS")
    print("=" * 70)

    all_passed = True
    for name, passed in results:
        status = "✅ PASSED" if passed else "❌ FAILED"
        print(f"{name:20} {status}")
        if not passed:
            all_passed = False

    print("=" * 70)

    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
