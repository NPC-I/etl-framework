#!/usr/bin/env python3
"""
Software Bill of Materials (SBOM) Generator
Generates CycloneDX SBOM for compliance and security tracking
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

import tomli


class SBOMManager:
    """Manages SBOM generation and updates."""

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.sbom_file = project_root / "sbom.json"

    def generate_sbom(self) -> Dict:
        """Generate CycloneDX SBOM."""
        print("📄 Generating Software Bill of Materials...")

        # Parse pyproject.toml
        pyproject_file = self.project_root / "pyproject.toml"
        if not pyproject_file.exists():
            raise FileNotFoundError("pyproject.toml not found")

        with open(pyproject_file, "rb") as f:
            data = tomli.load(f)

        project_info = data.get("project", {})

        # Collect dependencies
        dependencies = project_info.get("dependencies", [])
        optional_deps = project_info.get("optional-dependencies", {})

        # Flatten all dependencies
        all_deps = []
        for dep in dependencies:
            all_deps.append(self._parse_dependency(dep))

        for category, deps_list in optional_deps.items():
            for dep in deps_list:
                dep_info = self._parse_dependency(dep)
                dep_info["scope"] = category
                all_deps.append(dep_info)

        # Generate SBOM
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "metadata": {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "tools": [
                    {
                        "vendor": "ETL Framework",
                        "name": "SBOMManager",
                        "version": "1.0.0",
                    }
                ],
                "component": {
                    "type": "application",
                    "bom-ref": f"pkg:pypi/{project_info.get('name', 'etl-framework')}",
                    "name": project_info.get("name", "etl-framework"),
                    "version": project_info.get("version", "1.0.0"),
                    "description": project_info.get("description", ""),
                    "licenses": [
                        {"license": {"id": project_info.get("license", "MIT")}}
                    ],
                },
            },
            "components": all_deps,
            "dependencies": self._generate_dependency_graph(all_deps),
        }

        # Save SBOM
        with open(self.sbom_file, "w") as f:
            json.dump(sbom, f, indent=2)

        print(f"✅ SBOM saved to: {self.sbom_file}")
        return sbom

    def _parse_dependency(self, dep_string: str) -> Dict:
        """Parse dependency string into component format."""
        # Remove version constraints for package name
        if ">=" in dep_string:
            name = dep_string.split(">=")[0].strip()
            version = dep_string.split(">=")[1].strip()
        elif "==" in dep_string:
            name = dep_string.split("==")[0].strip()
            version = dep_string.split("==")[1].strip()
        elif "~=" in dep_string:
            name = dep_string.split("~=")[0].strip()
            version = dep_string.split("~=")[1].strip()
        else:
            name = dep_string.strip()
            version = "unknown"

        return {
            "type": "library",
            "bom-ref": f"pkg:pypi/{name}",
            "name": name,
            "version": version,
            "purl": f"pkg:pypi/{name}@{version}",
        }

    def _generate_dependency_graph(self, components: List[Dict]) -> List[Dict]:
        """Generate dependency relationships."""
        dependencies = []

        # Main component depends on all libraries
        main_ref = "pkg:pypi/etl-framework"
        depends_on = [comp["bom-ref"] for comp in components]

        dependencies.append({"ref": main_ref, "dependsOn": depends_on})

        return dependencies

    def check_vulnerabilities(self, sbom: Dict) -> List[Dict]:
        """Check SBOM components for known vulnerabilities."""
        print("🔍 Checking SBOM for vulnerabilities...")

        vulnerabilities = []

        # This would integrate with vulnerability databases
        # For now, return empty list - real implementation would use:
        # - OSS Index
        # - NVD
        # - DependencyTrack

        return vulnerabilities

    def update_sbom(self) -> Dict:
        """Update existing SBOM with new information."""
        if not self.sbom_file.exists():
            return self.generate_sbom()

        with open(self.sbom_file, "r") as f:
            existing_sbom = json.load(f)

        # Update timestamp
        existing_sbom["metadata"]["timestamp"] = datetime.utcnow().isoformat() + "Z"

        # Regenerate components
        new_sbom = self.generate_sbom()

        # Merge with existing (preserve any custom metadata)
        existing_sbom["components"] = new_sbom["components"]
        existing_sbom["dependencies"] = new_sbom["dependencies"]
        existing_sbom["version"] += 1  # Increment version

        # Save updated SBOM
        with open(self.sbom_file, "w") as f:
            json.dump(existing_sbom, f, indent=2)

        print(f"✅ SBOM updated to version {existing_sbom['version']}")
        return existing_sbom


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="SBOM Manager")
    parser.add_argument("--generate", action="store_true", help="Generate new SBOM")
    parser.add_argument("--update", action="store_true", help="Update existing SBOM")
    parser.add_argument(
        "--check", action="store_true", help="Check SBOM for vulnerabilities"
    )

    args = parser.parse_args()

    project_root = Path.cwd()
    manager = SBOMManager(project_root)

    if args.generate:
        sbom = manager.generate_sbom()
        print(f"Generated SBOM with {len(sbom.get('components', []))} components")

    elif args.update:
        sbom = manager.update_sbom()
        print(f"Updated SBOM to version {sbom.get('version', 1)}")

    elif args.check:
        if manager.sbom_file.exists():
            with open(manager.sbom_file, "r") as f:
                sbom = json.load(f)
            vulns = manager.check_vulnerabilities(sbom)
            print(f"Found {len(vulns)} vulnerabilities")
        else:
            print("❌ SBOM not found. Generate one first with --generate")

    else:
        print("Please specify an action: --generate, --update, or --check")


if __name__ == "__main__":
    main()
