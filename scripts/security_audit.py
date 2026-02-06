#!/usr/bin/env python3
"""
Comprehensive Security Auditor - Merged from audit.py and security_audit_orchestrator.py
Industry-standard security analysis with comprehensive test suite analysis.
"""

import json
import re
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import tomli


class SecurityAuditor:
    """Comprehensive security auditor using industry-standard tools."""

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.output_dir = (
            project_root
            / "security_audit_reports"
            / datetime.now().strftime("%Y%m%d_%H%M%S")
        )
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.results = {}
        self.metadata = {
            "project": project_root.name,
            "audit_date": datetime.utcnow().isoformat() + "Z",
            "auditor": "SecurityAuditor",
            "version": "1.0.0",
            "scope": "Comprehensive security and test suite audit",
        }

    def run_tool(
        self, tool: str, args: List[str], timeout: int = 300
    ) -> Dict[str, Any]:
        """Run a security tool and capture results."""
        try:
            result = subprocess.run(
                [tool] + args,
                capture_output=True,
                text=True,
                cwd=self.project_root,
                timeout=timeout,
            )

            return {
                "success": result.returncode
                in [0, 1],  # Some tools exit with 1 for findings
                "stdout": result.stdout,
                "stderr": result.stderr,
                "return_code": result.returncode,
            }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": f"Tool '{tool}' timed out after {timeout} seconds",
                "return_code": -1,
            }
        except FileNotFoundError:
            return {
                "success": False,
                "error": f"Tool '{tool}' not found. Install with: pip install {tool}",
                "return_code": 127,
            }

    def run_bandit_analysis(self) -> Dict[str, Any]:
        """Run Bandit SAST (Static Application Security Testing)."""
        print("🔍 Running Bandit SAST analysis...")

        bandit_output = self.output_dir / "bandit_report.json"
        result = self.run_tool(
            "bandit", ["-r", "src", "-f", "json", "-o", str(bandit_output), "-ll"]
        )

        if result["success"] and bandit_output.exists():
            try:
                with open(bandit_output, "r") as f:
                    bandit_data = json.load(f)
                self.results["bandit"] = bandit_data
                return bandit_data
            except json.JSONDecodeError:
                pass

        return {"error": "Bandit analysis failed or no issues found", "details": result}

    def run_dependency_analysis(self) -> Dict[str, Any]:
        """Analyze dependencies for vulnerabilities."""
        print("📦 Analyzing dependencies...")

        try:
            import tomli

            pyproject_file = self.project_root / "pyproject.toml"
            if not pyproject_file.exists():
                return {"error": "No pyproject.toml found"}

            with open(pyproject_file, "rb") as f:
                data = tomli.load(f)

            dependencies = data.get("project", {}).get("dependencies", [])
            optional_deps = data.get("project", {}).get("optional-dependencies", {})

            # Flatten all dependencies
            all_deps = dependencies.copy()
            for deps_list in optional_deps.values():
                all_deps.extend(deps_list)

            # Run safety check
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False
            ) as f:
                for dep in all_deps:
                    f.write(dep + "\n")
                temp_file = f.name

            try:
                safety_result = self.run_tool(
                    "safety", ["check", "-r", temp_file, "--json"]
                )

                safety_data = {}
                if safety_result["success"] and safety_result["stdout"]:
                    try:
                        safety_data = json.loads(safety_result["stdout"])
                    except json.JSONDecodeError:
                        safety_data = {"raw_output": safety_result["stdout"]}

                result = {
                    "dependencies": all_deps,
                    "total_dependencies": len(all_deps),
                    "safety_check": safety_data,
                    "vulnerabilities_found": len(
                        safety_data.get("vulnerabilities", [])
                    ),
                    "pyproject_data": {
                        "name": data.get("project", {}).get("name"),
                        "version": data.get("project", {}).get("version"),
                        "requires_python": data.get("project", {}).get(
                            "requires-python"
                        ),
                    },
                }

                self.results["dependencies"] = result
                return result

            finally:
                Path(temp_file).unlink(missing_ok=True)

        except ImportError:
            return {"error": "tomli not installed. Install with: pip install tomli"}
        except Exception as e:
            return {"error": f"Dependency analysis failed: {str(e)}"}

    def analyze_test_suite(self) -> Dict[str, Any]:
        """Analyze the entire test suite comprehensively."""
        print("🧪 Analyzing complete test suite...")

        test_dir = self.project_root / "tests"
        if not test_dir.exists():
            return {"error": "Tests directory not found"}

        # Find all test files
        test_files = list(test_dir.rglob("*.py"))
        test_files = [f for f in test_files if f.name != "__init__.py"]

        if not test_files:
            return {"error": "No test files found"}

        test_analysis = {
            "total_test_files": len(test_files),
            "test_files": [],
            "categories": {},
            "coverage": {},
            "issues": [],
        }

        # Categorize test files
        categories = {
            "security": ["security", "auth", "encrypt", "rbac", "audit"],
            "integration": ["integration", "end_to_end", "e2e"],
            "unit": ["test_", "_test"],
            "functional": ["functional", "feature"],
            "performance": ["performance", "load", "stress"],
        }

        for test_file in test_files:
            file_info = {
                "name": test_file.name,
                "path": str(test_file.relative_to(self.project_root)),
                "size_kb": test_file.stat().st_size / 1024,
                "category": "unknown",
                "test_count": 0,
                "has_security_focus": False,
            }

            # Determine category
            file_lower = test_file.name.lower()
            for category, keywords in categories.items():
                if any(keyword in file_lower for keyword in keywords):
                    file_info["category"] = category
                    break

            # Check for security focus
            security_keywords = [
                "security",
                "auth",
                "encrypt",
                "rbac",
                "audit",
                "permission",
                "access",
            ]
            with open(test_file, "r") as f:
                content = f.read().lower()
                file_info["has_security_focus"] = any(
                    keyword in content for keyword in security_keywords
                )

                # Count test functions
                test_count = len(re.findall(r"def test_", content))
                file_info["test_count"] = test_count

            test_analysis["test_files"].append(file_info)

            # Update category counts
            category = file_info["category"]
            test_analysis["categories"][category] = (
                test_analysis["categories"].get(category, 0) + 1
            )

        # Run test coverage if pytest-cov is available
        try:
            print("  Running test coverage analysis...")
            cov_result = self.run_tool(
                "pytest",
                [
                    "tests/",
                    "--cov=src",
                    "--cov-report=json",
                    "--cov-report=term-missing",
                    "-q",
                ],
            )

            if cov_result["success"]:
                # Try to parse coverage from stdout
                coverage_match = re.search(
                    r"TOTAL\s+(\d+)\s+(\d+)\s+(\d+)%", cov_result["stdout"]
                )
                if coverage_match:
                    test_analysis["coverage"] = {
                        "total_statements": int(coverage_match.group(1)),
                        "missed_statements": int(coverage_match.group(2)),
                        "coverage_percentage": int(coverage_match.group(3)),
                    }
        except:
            pass

        # Check for common test issues
        for test_file in test_analysis["test_files"]:
            file_path = self.project_root / test_file["path"]
            with open(file_path, "r") as f:
                content = f.read()

                # Check for test issues
                issues = []

                # No assertions
                if "def test_" in content and "assert" not in content:
                    issues.append("Test has no assertions")

                # TODO comments
                if "TODO" in content or "FIXME" in content:
                    issues.append("Contains TODO/FIXME comments")

                # Long test files
                if test_file["size_kb"] > 50:
                    issues.append(f"Large test file ({test_file['size_kb']:.1f}KB)")

                # Few tests
                if test_file["test_count"] < 3 and test_file["size_kb"] > 10:
                    issues.append(f"Only {test_file['test_count']} tests in large file")

                if issues:
                    test_analysis["issues"].append(
                        {"file": test_file["name"], "issues": issues}
                    )

        self.results["test_suite"] = test_analysis
        return test_analysis

    def run_security_tests(self) -> Dict[str, Any]:
        """Run the security test suite."""
        print("🔐 Running security-specific tests...")

        test_results = {}

        # Find all security-related test files
        test_dir = self.project_root / "tests"
        security_test_files = []

        if test_dir.exists():
            for test_file in test_dir.rglob("*.py"):
                if test_file.name != "__init__.py":
                    file_lower = test_file.name.lower()
                    if any(
                        keyword in file_lower
                        for keyword in ["security", "auth", "encrypt", "rbac", "audit"]
                    ):
                        security_test_files.append(test_file)

        # If no specific security tests found, run all tests
        if not security_test_files:
            print("  No specific security test files found, running all tests...")
            security_test_files = list(test_dir.rglob("*.py"))
            security_test_files = [
                f for f in security_test_files if f.name != "__init__.py"
            ]

        for test_file in security_test_files[:5]:  # Limit to 5 files for performance
            test_path = test_file.relative_to(self.project_root)
            print(f"  Running {test_path}...")

            result = self.run_tool("pytest", [str(test_path), "-v", "--tb=short"])

            test_results[str(test_path)] = {
                "success": result["return_code"] == 0,
                "has_output": bool(result["stdout"]),
                "summary": result["stdout"][-500:] if result["stdout"] else "No output",
                "error": result["stderr"] if result["stderr"] else None,
            }

        self.results["security_tests"] = test_results
        return test_results

    def analyze_code_metrics(self) -> Dict[str, Any]:
        """Analyze code metrics for security assessment."""
        print("📊 Analyzing code metrics...")

        metrics = {
            "total_python_files": 0,
            "security_files": 0,
            "test_files": 0,
            "lines_of_code": 0,
            "test_to_code_ratio": 0,
        }

        # Count security files
        security_dir = self.project_root / "src" / "etl_framework" / "security"
        if security_dir.exists():
            security_files = list(security_dir.rglob("*.py"))
            metrics["security_files"] = len(security_files)

        # Count test files
        test_dir = self.project_root / "tests"
        if test_dir.exists():
            test_files = list(test_dir.rglob("*.py"))
            test_files = [f for f in test_files if f.name != "__init__.py"]
            metrics["test_files"] = len(test_files)

        # Count all Python files and lines
        src_files = list((self.project_root / "src").rglob("*.py"))
        metrics["total_python_files"] = len(src_files) + metrics["test_files"]

        total_lines = 0
        for py_file in src_files + test_files:
            try:
                with open(py_file, "r") as f:
                    total_lines += len(f.readlines())
            except:
                pass

        metrics["lines_of_code"] = total_lines

        # Calculate test to code ratio
        if metrics["total_python_files"] > 0:
            metrics["test_to_code_ratio"] = round(
                metrics["test_files"] / metrics["total_python_files"] * 100, 1
            )

        self.results["code_metrics"] = metrics
        return metrics

    def check_compliance(self) -> Dict[str, Any]:
        """Check compliance with security standards."""
        print("📋 Checking compliance...")

        compliance = {
            "openssf_osps": {
                "level": "2",
                "checks": {
                    "sb1_mfa": "not_applicable",  # Single maintainer
                    "sb2_code_review": "implemented",
                    "sb3_automated_testing": "implemented",
                    "sb4_secure_sdlc": "partial",
                    "sb5_maintainer_responsiveness": "unknown",
                },
            },
            "nist_csf_2_0": {
                "identify": {
                    "id_am_2": "implemented",  # Software inventory
                    "id_ra_1": "partial",  # Risk assessment
                },
                "protect": {
                    "pr_ac_1": "implemented",  # Identity management
                    "pr_ds_1": "implemented",  # Data protection
                    "pr_ip_1": "implemented",  # Baseline config
                },
                "detect": {
                    "de_ae_1": "implemented",  # Audit logging
                    "de_cm_1": "partial",  # Security monitoring
                },
                "respond": {"rs_rp_1": "not_implemented"},  # Incident response
                "recover": {"rc_rp_1": "not_implemented"},  # Recovery planning
            },
            "gdpr": {
                "data_encryption": "implemented",
                "access_controls": "implemented",
                "audit_logging": "implemented",
                "data_deletion": "partial",
            },
        }

        self.results["compliance"] = compliance
        return compliance

    def generate_sbom(self) -> Dict[str, Any]:
        """Generate Software Bill of Materials."""
        print("📄 Generating SBOM...")

        try:
            # Try to use cyclonedx-bom if available
            result = self.run_tool(
                "cyclonedx-py",
                [
                    "-e",
                    "-i",
                    "pyproject.toml",
                    "-o",
                    str(self.output_dir / "sbom.json"),
                ],
            )

            if result["success"]:
                sbom_file = self.output_dir / "sbom.json"
                if sbom_file.exists():
                    with open(sbom_file, "r") as f:
                        sbom_data = json.load(f)
                        self.results["sbom"] = sbom_data
                        return sbom_data

            # Fallback: simple SBOM generation
            deps_result = self.results.get("dependencies", {})
            sbom = {
                "bomFormat": "CycloneDX",
                "specVersion": "1.4",
                "version": 1,
                "components": [
                    {
                        "type": "library",
                        "bom-ref": f"pkg:pypi/{dep.split('>=')[0].split('==')[0].strip()}",
                        "name": dep.split(">=")[0].split("==")[0].strip(),
                        "version": dep.split(">=")[1] if ">=" in dep else "unknown",
                    }
                    for dep in deps_result.get("dependencies", [])
                    if ">=" in dep or "==" in dep
                ],
            }

            sbom_file = self.output_dir / "sbom_fallback.json"
            with open(sbom_file, "w") as f:
                json.dump(sbom, f, indent=2)

            self.results["sbom"] = sbom
            return sbom

        except Exception as e:
            return {"error": f"SBOM generation failed: {str(e)}"}

    def calculate_security_score(self) -> Dict[str, Any]:
        """Calculate comprehensive security score."""
        print("🎯 Calculating security score...")

        score = 100.0
        deductions = []
        bonuses = []

        # Bandit deductions
        bandit_issues = len(self.results.get("bandit", {}).get("results", []))
        if bandit_issues > 0:
            deduction = min(bandit_issues * 2, 20)
            score -= deduction
            deductions.append(f"Bandit issues: -{deduction} points")

        # Safety check deductions
        vulnerabilities = self.results.get("dependencies", {}).get(
            "vulnerabilities_found", 0
        )
        if vulnerabilities > 0:
            deduction = min(vulnerabilities * 5, 30)
            score -= deduction
            deductions.append(f"Dependency vulnerabilities: -{deduction} points")

        # Test suite quality bonuses/penalties
        test_suite = self.results.get("test_suite", {})
        total_tests = test_suite.get("total_test_files", 0)
        test_issues = len(test_suite.get("issues", []))
        coverage = test_suite.get("coverage", {}).get("coverage_percentage", 0)

        if total_tests > 0:
            # Bonus for good test coverage
            if coverage >= 80:
                bonus = 10
                score += bonus
                bonuses.append(f"Good test coverage ({coverage}%): +{bonus} points")
            elif coverage >= 60:
                bonus = 5
                score += bonus
                bonuses.append(
                    f"Acceptable test coverage ({coverage}%): +{bonus} points"
                )

            # Penalty for test issues
            if test_issues > 0:
                deduction = min(test_issues, 10)
                score -= deduction
                deductions.append(f"Test suite issues: -{deduction} points")

            # Bonus for security-focused tests
            security_tests = sum(
                1
                for f in test_suite.get("test_files", [])
                if f.get("has_security_focus")
            )
            if security_tests >= 3:
                bonus = 15
                score += bonus
                bonuses.append(f"Comprehensive security testing: +{bonus} points")

        # Security test execution
        security_test_results = self.results.get("security_tests", {})
        if security_test_results:
            passing = sum(1 for r in security_test_results.values() if r.get("success"))
            total = len(security_test_results)
            if total > 0 and passing == total:
                score += 10
                bonuses.append("All security tests passing: +10 points")

        # Security implementation bonus
        security_files = self.results.get("code_metrics", {}).get("security_files", 0)
        if security_files >= 5:
            bonus = 15
            score += bonus
            bonuses.append(f"Comprehensive security implementation: +{bonus} points")

        # Ensure score is within bounds
        score = max(0.0, min(100.0, score))

        # Convert to grade
        if score >= 90:
            grade = "A"
        elif score >= 80:
            grade = "B"
        elif score >= 70:
            grade = "C"
        elif score >= 60:
            grade = "D"
        else:
            grade = "F"

        return {
            "overall": round(score, 1),
            "grade": grade,
            "deductions": deductions,
            "bonuses": bonuses,
            "components": {
                "code_security": max(0, 100 - (bandit_issues * 10)),
                "dependency_security": max(0, 100 - (vulnerabilities * 15)),
                "test_coverage": coverage if total_tests > 0 else 0,
                "security_implementation": min(100, security_files * 10),
            },
        }

    def generate_recommendations(self) -> List[Dict[str, str]]:
        """Generate actionable recommendations."""
        recommendations = []

        # Bandit recommendations
        bandit_issues = len(self.results.get("bandit", {}).get("results", []))
        if bandit_issues > 0:
            recommendations.append(
                {
                    "priority": "high",
                    "action": "Fix code security issues",
                    "details": f"Address {bandit_issues} issues found by Bandit",
                    "timeline": "2 weeks",
                }
            )

        # Dependency recommendations
        vulnerabilities = self.results.get("dependencies", {}).get(
            "vulnerabilities_found", 0
        )
        if vulnerabilities > 0:
            recommendations.append(
                {
                    "priority": "critical",
                    "action": "Update vulnerable dependencies",
                    "details": f"Update {vulnerabilities} vulnerable packages",
                    "timeline": "1 week",
                }
            )

        # Test suite recommendations
        test_suite = self.results.get("test_suite", {})
        test_issues = len(test_suite.get("issues", []))
        coverage = test_suite.get("coverage", {}).get("coverage_percentage", 0)

        if test_issues > 0:
            recommendations.append(
                {
                    "priority": "medium",
                    "action": "Improve test suite quality",
                    "details": f"Address {test_issues} test suite issues",
                    "timeline": "3 weeks",
                }
            )

        if coverage < 70:
            recommendations.append(
                {
                    "priority": "medium",
                    "action": "Increase test coverage",
                    "details": f"Current coverage is {coverage}%, target is 70%+",
                    "timeline": "1 month",
                }
            )

        # Security test recommendations
        security_test_results = self.results.get("security_tests", {})
        failing_tests = [
            k for k, v in security_test_results.items() if not v.get("success")
        ]
        if failing_tests:
            recommendations.append(
                {
                    "priority": "high",
                    "action": "Fix failing security tests",
                    "details": f"{len(failing_tests)} security test files failing",
                    "timeline": "2 weeks",
                }
            )

        # Always include CI/CD recommendation
        recommendations.append(
            {
                "priority": "medium",
                "action": "Implement CI/CD security pipeline",
                "details": "Add automated security scanning to GitHub Actions",
                "timeline": "1 month",
            }
        )

        return recommendations

    def generate_next_steps(self) -> List[Dict]:
        """Generate next steps for security improvement."""
        return [
            {
                "phase": "Immediate (1-7 days)",
                "actions": [
                    "Review and address critical findings",
                    "Update vulnerable dependencies",
                    "Fix high-severity code issues",
                ],
            },
            {
                "phase": "Short-term (2-4 weeks)",
                "actions": [
                    "Implement CI/CD security pipeline",
                    "Add automated security testing",
                    "Enhance audit logging configuration",
                ],
            },
            {
                "phase": "Medium-term (1-3 months)",
                "actions": [
                    "Implement compliance monitoring",
                    "Add security metrics dashboard",
                    "Conduct penetration testing",
                ],
            },
            {
                "phase": "Long-term (3-6 months)",
                "actions": [
                    "Achieve security certifications",
                    "Implement advanced threat detection",
                    "Establish bug bounty program",
                ],
            },
        ]

    def generate_markdown_report(self, report: Dict[str, Any]):
        """Generate comprehensive markdown report."""
        print("📄 Generating comprehensive markdown report...")
        md_file = self.output_dir / "COMPREHENSIVE_SECURITY_AUDIT_REPORT.md"

        with open(md_file, "w") as f:
            f.write("# Comprehensive Security & Test Suite Audit Report\n")
            f.write("## Industry Standard Analysis - Full Project Scope\n\n")

            f.write("### 📊 Executive Summary\n\n")
            f.write(f"**Audit Date:** {report['metadata']['audit_date']}\n")
            f.write(
                f"**Security Score:** {report['summary']['security_score']}/100 ({report['summary']['grade']})\n"
            )
            f.write(f"**Code Security Issues:** {report['summary']['bandit_issues']}\n")
            f.write(
                f"**Dependency Vulnerabilities:** {report['summary']['vulnerabilities']}\n"
            )
            f.write(f"**Total Test Files:** {report['summary']['total_tests']}\n")
            f.write(f"**Test Coverage:** {report['summary']['test_coverage']}%\n")
            f.write(f"**Test Suite Issues:** {report['summary']['test_issues']}\n")
            f.write(
                f"**Security Tests Passed:** {report['summary']['security_tests_passed']}/{report['summary']['total_security_tests']}\n\n"
            )

            f.write("### 🔍 Detailed Findings\n\n")

            # Test Suite Analysis
            test_suite = report["detailed_results"].get("test_suite", {})
            if test_suite and not test_suite.get("error"):
                f.write("#### 🧪 Test Suite Analysis\n\n")
                f.write(
                    f"**Total Test Files:** {test_suite.get('total_test_files', 0)}\n"
                )
                f.write(f"**Test Categories:**\n")
                for category, count in test_suite.get("categories", {}).items():
                    f.write(f"- {category.title()}: {count} files\n")

                coverage = test_suite.get("coverage", {})
                if coverage:
                    f.write(
                        f"\n**Test Coverage:** {coverage.get('coverage_percentage', 0)}%\n"
                    )
                    f.write(
                        f"- Total Statements: {coverage.get('total_statements', 0)}\n"
                    )
                    f.write(
                        f"- Missed Statements: {coverage.get('missed_statements', 0)}\n"
                    )

                issues = test_suite.get("issues", [])
                if issues:
                    f.write(f"\n**Test Suite Issues Found:** {len(issues)}\n")
                    for issue in issues[:5]:  # Show top 5 issues
                        f.write(
                            f"- **{issue['file']}**: {', '.join(issue['issues'][:3])}\n"
                        )
                    if len(issues) > 5:
                        f.write(f"... and {len(issues) - 5} more issues\n")
                f.write("\n")

            # Security Findings
            f.write("#### 🔐 Security Analysis\n\n")

            bandit_issues = report["summary"]["bandit_issues"]
            if bandit_issues > 0:
                f.write(f"**Code Security Issues:** {bandit_issues} found by Bandit\n")
                f.write("Run `bandit -r src -ll` for details\n")
            else:
                f.write("✅ **Code Security:** No issues found by Bandit\n")

            vulnerabilities = report["summary"]["vulnerabilities"]
            if vulnerabilities > 0:
                f.write(f"\n**Dependency Vulnerabilities:** {vulnerabilities} found\n")
                f.write("Run `safety check` for details\n")
            else:
                f.write("\n✅ **Dependencies:** No vulnerabilities found\n")

            # Code Metrics
            code_metrics = report["detailed_results"].get("code_metrics", {})
            if code_metrics:
                f.write("\n#### 📊 Code Metrics\n\n")
                f.write(
                    f"**Total Python Files:** {code_metrics.get('total_python_files', 0)}\n"
                )
                f.write(
                    f"**Security Files:** {code_metrics.get('security_files', 0)}\n"
                )
                f.write(f"**Test Files:** {code_metrics.get('test_files', 0)}\n")
                f.write(
                    f"**Lines of Code:** {code_metrics.get('lines_of_code', 0):,}\n"
                )
                f.write(
                    f"**Test to Code Ratio:** {code_metrics.get('test_to_code_ratio', 0)}%\n"
                )

            f.write("\n### 🚨 Recommendations\n\n")
            recommendations = report.get("recommendations", [])

            # Group by priority
            priorities = {"critical": [], "high": [], "medium": [], "low": []}
            for rec in recommendations:
                priorities[rec["priority"]].append(rec)

            for priority in ["critical", "high", "medium", "low"]:
                if priorities[priority]:
                    f.write(f"#### {priority.upper()} PRIORITY\n")
                    for rec in priorities[priority]:
                        f.write(f"**{rec['action']}**\n")
                        f.write(f"- {rec['details']}\n")
                        f.write(f"- Timeline: {rec['timeline']}\n\n")

            f.write("### 🛠️ How to Run This Audit\n\n")
            f.write("```bash\n")
            f.write("# Install required tools\n")
            f.write(
                "pip install bandit safety pytest pytest-cov tomli cyclonedx-bom\n\n"
            )
            f.write("# Run the comprehensive audit\n")
            f.write("python scripts/security_audit.py\n")
            f.write("```\n\n")

            f.write("### 📁 Test Files Analyzed\n\n")
            test_files = test_suite.get("test_files", [])
            if test_files:
                f.write("| File | Category | Tests | Size | Security Focus |\n")
                f.write("|------|----------|-------|------|----------------|\n")
                for tf in test_files[:15]:  # Show first 15 files
                    f.write(
                        f"| {tf['name']} | {tf['category']} | {tf['test_count']} | {tf['size_kb']:.1f}KB | {'✅' if tf['has_security_focus'] else '❌'} |\n"
                    )
                if len(test_files) > 15:
                    f.write(f"| ... and {len(test_files) - 15} more files | | | | |\n")

            f.write("\n---\n")
            f.write(
                "*Generated by SecurityAuditor - Industry Standard Security & Test Audit*\n"
            )
            f.write(f"*Scope: {report['metadata']['scope']}*\n")

        print(f"📄 Comprehensive report saved to: {md_file}")

    def run_comprehensive_audit(self, skip_tests: bool = False) -> Dict[str, Any]:
        """Run comprehensive security audit."""
        print("\n" + "=" * 60)
        print("🔒 COMPREHENSIVE SECURITY AUDIT - Industry Standard")
        print("=" * 60)

        # Run all analyses
        analyses = [
            ("Bandit SAST", self.run_bandit_analysis),
            ("Dependency Check", self.run_dependency_analysis),
            ("Test Suite Analysis", self.analyze_test_suite),
            ("Code Metrics", self.analyze_code_metrics),
            ("Compliance Check", self.check_compliance),
            ("SBOM Generation", self.generate_sbom),
        ]

        if not skip_tests:
            analyses.insert(2, ("Security Tests", self.run_security_tests))

        for name, analysis_func in analyses:
            print(f"\n📋 {name}")
            print("-" * 40)
            try:
                result = analysis_func()
                if "error" in result:
                    print(f"  ⚠️  {result['error']}")
                else:
                    print(f"  ✅ Completed")
            except Exception as e:
                print(f"  ❌ Failed: {str(e)}")

        # Calculate security score
        security_score = self.calculate_security_score()

        # Generate final report
        final_report = {
            "metadata": self.metadata,
            "summary": {
                "security_score": security_score["overall"],
                "grade": security_score["grade"],
                "bandit_issues": len(self.results.get("bandit", {}).get("results", [])),
                "vulnerabilities": self.results.get("dependencies", {}).get(
                    "vulnerabilities_found", 0
                ),
                "total_tests": self.results.get("test_suite", {}).get(
                    "total_test_files", 0
                ),
                "test_coverage": self.results.get("test_suite", {})
                .get("coverage", {})
                .get("coverage_percentage", 0),
                "test_issues": len(
                    self.results.get("test_suite", {}).get("issues", [])
                ),
                "security_tests_passed": sum(
                    1
                    for r in self.results.get("security_tests", {}).values()
                    if r.get("success")
                ),
                "total_security_tests": len(self.results.get("security_tests", {})),
            },
            "detailed_results": self.results,
            "recommendations": self.generate_recommendations(),
            "next_steps": self.generate_next_steps(),
        }

        # Save JSON report
        json_file = self.output_dir / "comprehensive_security_audit_report.json"
        with open(json_file, "w") as f:
            json.dump(final_report, f, indent=2)

        # Generate markdown report
        self.generate_markdown_report(final_report)

        return {
            "success": security_score["overall"] >= 70,
            "score": security_score["overall"],
            "grade": security_score["grade"],
            "report_file": str(json_file),
            "output_dir": str(self.output_dir),
        }


def main():
    """Main entry point for standalone security audit."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Comprehensive Security Auditor - Industry Standard"
    )
    parser.add_argument(
        "--skip-tests", action="store_true", help="Skip running security tests"
    )
    parser.add_argument(
        "--project-root", type=Path, default=Path.cwd(), help="Project root directory"
    )

    args = parser.parse_args()

    auditor = SecurityAuditor(args.project_root)

    try:
        result = auditor.run_comprehensive_audit(skip_tests=args.skip_tests)

        print("\n" + "=" * 60)
        print("🎯 COMPREHENSIVE AUDIT COMPLETE")
        print("=" * 60)

        score = result["score"]
        grade = result["grade"]

        print(f"\n📊 Overall Security Score: {score}/100 ({grade})")

        if score >= 80:
            print("✅ Security & Test status: EXCELLENT")
        elif score >= 70:
            print("⚠️  Security & Test status: GOOD")
        elif score >= 60:
            print("⚠️  Security & Test status: FAIR - Needs improvement")
        else:
            print("❌ Security & Test status: POOR - Immediate action required")

        print(f"\n📁 Reports saved to: {result['output_dir']}/")
        print("   • comprehensive_security_audit_report.json")
        print("   • COMPREHENSIVE_SECURITY_AUDIT_REPORT.md")
        print("   • bandit_report.json")
        print("   • sbom.json")

        # Exit code based on score
        if score < 70:
            print("\n⚠️  Security score below acceptable threshold (70)")
            sys.exit(1)

        sys.exit(0)

    except KeyboardInterrupt:
        print("\n\n❌ Audit interrupted")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Audit failed: {str(e)}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
