#!/usr/bin/env python3
"""
Advanced Test Runner - Run tests with different profiles and configurations.
"""
import argparse
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


class TestRunner:
    """Advanced test runner with different profiles and configurations."""

    # Test profiles with different configurations
    TEST_PROFILES: Dict[str, List[str]] = {
        "fast": [
            "-m",
            "unit",
            "--tb=short",
            "-q",  # Quiet mode
            "--disable-warnings",
            "--no-header",
            "-rN",  # Show only failed tests
        ],
        "unit": ["-m", "unit", "-v", "--tb=line", "--durations=5"],
        "integration": ["-m", "integration", "-v", "--tb=short", "--durations=10"],
        "security": ["-m", "security", "-v", "--tb=line", "--strict-markers"],
        "functional": ["-m", "functional", "-v", "--tb=short", "--durations=20"],
        "all": ["-v", "--tb=short", "--durations=20", "--strict-markers"],
        "coverage": [
            "-v",
            "--cov=src",
            "--cov-report=html",
            "--cov-report=term-missing",
            "--tb=short",
        ],
        "smoke": ["-m", "smoke", "-v", "--tb=short", "-q"],
        "regression": ["-m", "regression", "-v", "--tb=short", "--durations=15"],
    }

    # Test scenarios for different use cases
    TEST_SCENARIOS: Dict[str, Dict[str, List[str]]] = {
        "basic": {
            "description": "Basic functionality tests",
            "profiles": ["unit", "smoke"],
        },
        "security": {
            "description": "Security compliance tests",
            "profiles": ["security", "unit"],
        },
        "integration": {
            "description": "Integration and end-to-end tests",
            "profiles": ["integration", "functional"],
        },
        "performance": {
            "description": "Performance and load tests",
            "profiles": ["performance"],
            "options": ["--run-performance"],
        },
        "comprehensive": {
            "description": "Comprehensive test suite",
            "profiles": ["all", "coverage"],
        },
        "ci": {
            "description": "CI/CD pipeline tests",
            "profiles": ["unit", "integration", "security"],
            "options": ["--junitxml=test-results.xml"],
        },
    }

    def __init__(self, project_root: Path):
        """Initialize test runner."""
        self.project_root = project_root
        self.results_dir = project_root / "test_results"
        self.results_dir.mkdir(exist_ok=True)

    def run_profile(self, profile: str, extra_args: Optional[List[str]] = None) -> int:
        """
        Run tests with a specific profile.

        Args:
            profile: Profile name
            extra_args: Extra command line arguments

        Returns:
            Exit code
        """
        if profile not in self.TEST_PROFILES:
            print(f"❌ Unknown profile: {profile}")
            print(f"Available profiles: {', '.join(self.TEST_PROFILES.keys())}")
            return 1

        # Build command
        cmd = ["pytest", "tests/"] + self.TEST_PROFILES[profile]

        if extra_args:
            cmd.extend(extra_args)

        print(f"🚀 Running tests with profile: {profile}")
        print(f"Command: {' '.join(cmd)}")
        print("-" * 60)

        # Run tests
        result = subprocess.run(cmd, cwd=self.project_root)

        print("-" * 60)
        if result.returncode == 0:
            print(f"✅ Tests passed with profile: {profile}")
        else:
            print(f"❌ Tests failed with profile: {profile}")

        return result.returncode

    def run_scenario(
        self, scenario: str, extra_args: Optional[List[str]] = None
    ) -> int:
        """
        Run a test scenario (combination of profiles).

        Args:
            scenario: Scenario name
            extra_args: Extra command line arguments

        Returns:
            Exit code
        """
        if scenario not in self.TEST_SCENARIOS:
            print(f"❌ Unknown scenario: {scenario}")
            print(f"Available scenarios: {', '.join(self.TEST_SCENARIOS.keys())}")
            return 1

        scenario_config = self.TEST_SCENARIOS[scenario]

        print(f"🎯 Running test scenario: {scenario}")
        print(f"Description: {scenario_config['description']}")
        print("-" * 60)

        exit_codes = []

        # Run each profile in the scenario
        for profile in scenario_config["profiles"]:
            profile_args = scenario_config.get("options", []) + (extra_args or [])
            exit_code = self.run_profile(profile, profile_args)
            exit_codes.append(exit_code)

            if exit_code != 0:
                print(f"⚠️  Profile '{profile}' failed, continuing with scenario...")

        # Determine overall result
        overall_exit_code = 0 if all(ec == 0 for ec in exit_codes) else 1

        print("-" * 60)
        if overall_exit_code == 0:
            print(f"✅ Scenario '{scenario}' completed successfully")
        else:
            print(f"❌ Scenario '{scenario}' had failures")

        return overall_exit_code

    def generate_report(self, profile: str, exit_code: int) -> Dict[str, any]:
        """
        Generate a test run report.

        Args:
            profile: Profile name
            exit_code: Exit code from test run

        Returns:
            Report dictionary
        """
        timestamp = datetime.now().isoformat()
        report_file = self.results_dir / f"test_report_{profile}_{timestamp}.json"

        report = {
            "profile": profile,
            "timestamp": timestamp,
            "exit_code": exit_code,
            "success": exit_code == 0,
            "report_file": str(report_file),
            "metadata": {
                "project_root": str(self.project_root),
                "python_version": sys.version,
                "platform": sys.platform,
            },
        }

        # Save report
        with open(report_file, "w") as f:
            json.dump(report, f, indent=2)

        print(f"📊 Report saved to: {report_file}")
        return report

    def list_profiles(self):
        """List available test profiles."""
        print("📋 Available Test Profiles:")
        print("-" * 40)
        for profile, args in self.TEST_PROFILES.items():
            print(f"  {profile:15} -> {' '.join(args[:3])}...")

    def list_scenarios(self):
        """List available test scenarios."""
        print("📋 Available Test Scenarios:")
        print("-" * 40)
        for scenario, config in self.TEST_SCENARIOS.items():
            print(f"  {scenario:15} -> {config['description']}")
            print(f"                 Profiles: {', '.join(config['profiles'])}")
            print()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Advanced Test Runner for ETL Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --profile unit          # Run unit tests
  %(prog)s --scenario security     # Run security tests
  %(prog)s --list-profiles         # List available profiles
  %(prog)s --list-scenarios        # List available scenarios
  %(prog)s --profile coverage --html  # Generate coverage report
        """,
    )

    parser.add_argument(
        "--profile",
        choices=list(TestRunner.TEST_PROFILES.keys()),
        help="Test profile to run",
    )
    parser.add_argument(
        "--scenario",
        choices=list(TestRunner.TEST_SCENARIOS.keys()),
        help="Test scenario to run",
    )
    parser.add_argument(
        "--list-profiles", action="store_true", help="List available test profiles"
    )
    parser.add_argument(
        "--list-scenarios", action="store_true", help="List available test scenarios"
    )
    parser.add_argument(
        "--extra-args", nargs="*", help="Extra arguments to pass to pytest"
    )
    parser.add_argument(
        "--html", action="store_true", help="Generate HTML coverage report"
    )
    parser.add_argument("--xml", action="store_true", help="Generate JUnit XML report")

    args = parser.parse_args()

    # Get project root
    project_root = Path.cwd()
    runner = TestRunner(project_root)

    # Handle list commands
    if args.list_profiles:
        runner.list_profiles()
        return 0

    if args.list_scenarios:
        runner.list_scenarios()
        return 0

    # Build extra arguments
    extra_args = []
    if args.extra_args:
        extra_args.extend(args.extra_args)
    if args.html:
        extra_args.extend(["--cov-report=html"])
    if args.xml:
        extra_args.extend(["--junitxml=test-results.xml"])

    # Run tests
    exit_code = 0

    if args.scenario:
        exit_code = runner.run_scenario(args.scenario, extra_args)
        profile = args.scenario
    elif args.profile:
        exit_code = runner.run_profile(args.profile, extra_args)
        profile = args.profile
    else:
        # Default to fast profile
        exit_code = runner.run_profile("fast", extra_args)
        profile = "fast"

    # Generate report
    runner.generate_report(profile, exit_code)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
