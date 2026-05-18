"""Package.json auditor — detects risky configurations, install scripts, and supply chain indicators."""

import json
import re
from dataclasses import dataclass, field

from git_guardian.models.package import Finding, RiskLevel


@dataclass
class AuditReport:
    """Audit report for a package.json file."""

    package_name: str
    findings: list[Finding] = field(default_factory=list)
    scripts: dict[str, str] = field(default_factory=dict)
    risky_configs: list[str] = field(default_factory=list)

    @property
    def is_clean(self) -> bool:
        return not self.findings


class PackageAuditor:
    """Audits package.json for risky configurations."""

    # Scripts that run automatically during install
    INSTALL_SCRIPTS = {"preinstall", "postinstall", "install", "preuninstall", "postuninstall"}

    # Scripts that are always risky
    RISKY_SCRIPTS = {"preinstall", "preuninstall", "postuninstall"}

    # Dangerous script patterns
    DANGEROUS_PATTERNS = [
        (r"curl\s.*\|\s*sh", "Pipe from curl to shell"),
        (r"wget\s.*\|\s*sh", "Pipe from wget to shell"),
        (r"eval\s*\(", "Dynamic code evaluation"),
        (r"child_process", "Child process execution"),
        (r"exec\s*\(", "Shell command execution"),
        (r"spawn\s*\(", "Process spawning"),
        (r"process\.env", "Environment variable access"),
        (r"require\s*\(\s*['\"]fs['\"]", "File system access"),
        (r"require\s*\(\s*['\"]net['\"]", "Network access"),
        (r"require\s*\(\s*['\"]http['\"]", "HTTP access"),
        (r"https?://", "External URL reference"),
        (r"base64", "Base64 encoding/decoding"),
        (r"atob\s*\(", "Base64 decoding"),
        (r"\\x[0-9a-f]{2}", "Hex encoded characters"),
        (r"0x[0-9a-f]{40}", "Ethereum address"),
        (r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}", "Bitcoin address"),
    ]

    # Fields that can be abused
    SUSPICIOUS_FIELDS = {
        "browser": "Browser field can override module resolution",
        "browserify": "Browserify transform config",
        "eslintConfig": "ESLint config (usually safe but can execute code)",
        "babel": "Babel config (can execute arbitrary code)",
        "postcss": "PostCSS config (can execute plugins)",
        "jest": "Jest config (can execute code via setupFiles)",
    }

    def audit_package_json(self, package_json: dict, package_name: str = "") -> AuditReport:
        """Audit a package.json for risky configurations.

        Args:
            package_json: Parsed package.json content
            package_name: Package name for reporting

        Returns:
            AuditReport with findings
        """
        findings: list[Finding] = []
        risky_configs: list[str] = []
        scripts = package_json.get("scripts", {})

        # 1. Check install scripts
        self._check_install_scripts(scripts, findings, risky_configs)

        # 2. Check all scripts for dangerous patterns
        self._check_script_patterns(scripts, findings, risky_configs)

        # 3. Check file field abuse
        self._check_files_field(package_json, findings, risky_configs)

        # 4. Check suspicious config fields
        self._check_suspicious_fields(package_json, findings, risky_configs)

        # 5. Check for typosquat indicators
        self._check_typosquat_indicators(package_json, findings, risky_configs)

        # 6. Check registry and publish config
        self._check_publish_config(package_json, findings, risky_configs)

        # 7. Check dependency anomalies
        self._check_dependency_anomalies(package_json, findings, risky_configs)

        return AuditReport(
            package_name=package_name or package_json.get("name", "unknown"),
            findings=findings,
            scripts=scripts,
            risky_configs=risky_configs,
        )

    def _check_install_scripts(
        self, scripts: dict, findings: list[Finding], risky: list[str]
    ) -> None:
        for script_name in self.RISKY_SCRIPTS & set(scripts.keys()):
            cmd = scripts[script_name]
            findings.append(Finding(
                rule_id="AUDIT-001",
                title=f"Risky script: {script_name}",
                description=f"Package has a {script_name} script that runs automatically: '{cmd[:200]}'",
                risk_level=RiskLevel.HIGH,
                file_path="package.json",
                code_snippet=f'"{script_name}": "{cmd[:300]}"',
                recommendation=f"Review the {script_name} script carefully. It runs automatically during npm install.",
            ))
            risky.append(f"{script_name}: {cmd[:100]}")

    def _check_script_patterns(
        self, scripts: dict, findings: list[Finding], risky: list[str]
    ) -> None:
        for script_name, cmd in scripts.items():
            for pattern, desc in self.DANGEROUS_PATTERNS:
                if re.search(pattern, cmd, re.IGNORECASE):
                    findings.append(Finding(
                        rule_id="AUDIT-002",
                        title=f"Dangerous pattern in {script_name}",
                        description=f"Script '{script_name}' contains {desc}: '{cmd[:200]}'",
                        risk_level=RiskLevel.MEDIUM,
                        file_path="package.json",
                        code_snippet=f'"{script_name}": "{cmd[:300]}"',
                        recommendation=f"Verify the {desc} in this script is necessary and safe.",
                    ))
                    risky.append(f"{script_name}: {desc}")

    def _check_files_field(
        self, pkg: dict, findings: list[Finding], risky: list[str]
    ) -> None:
        files = pkg.get("files", [])
        if not files:
            return

        # Check for overly broad file inclusion
        dangerous_includes = [".", "*", "**/*", "src", "lib", "dist"]
        for inc in files:
            if inc in dangerous_includes:
                findings.append(Finding(
                    rule_id="AUDIT-003",
                    title="Overly broad files field",
                    description=f"The 'files' field includes '{inc}' which may publish more files than intended.",
                    risk_level=RiskLevel.LOW,
                    file_path="package.json",
                    recommendation="Be explicit about which files to include in the package.",
                ))
                risky.append(f"files includes broad pattern: {inc}")

    def _check_suspicious_fields(
        self, pkg: dict, findings: list[Finding], risky: list[str]
    ) -> None:
        for field, desc in self.SUSPICIOUS_FIELDS.items():
            if field in pkg:
                findings.append(Finding(
                    rule_id="AUDIT-004",
                    title=f"Suspicious config field: {field}",
                    description=f"Package has '{field}' config. {desc}.",
                    risk_level=RiskLevel.LOW,
                    file_path="package.json",
                    recommendation=f"Review the {field} configuration.",
                ))
                risky.append(f"Has {field} config")

    def _check_typosquat_indicators(
        self, pkg: dict, findings: list[Finding], risky: list[str]
    ) -> None:
        name = pkg.get("name", "")

        # Check for common typosquat patterns
        # - Very similar to popular package names
        # - Missing scope prefix
        # - Description mentions a different package
        desc = pkg.get("description", "").lower()
        popular_refs = ["lodash", "react", "express", "webpack", "babel", "typescript"]
        for pop in popular_refs:
            if pop in desc and pop not in name.lower():
                findings.append(Finding(
                    rule_id="AUDIT-005",
                    title="Possible typosquat: misleading description",
                    description=f"Description references '{pop}' but package name is '{name}'.",
                    risk_level=RiskLevel.MEDIUM,
                    file_path="package.json",
                    recommendation="Verify this package is legitimate and not impersonating a popular package.",
                ))
                risky.append(f"Description references {pop} but name is {name}")

    def _check_publish_config(
        self, pkg: dict, findings: list[Finding], risky: list[str]
    ) -> None:
        publish_config = pkg.get("publishConfig", {})
        registry = publish_config.get("registry", "")

        # Check for non-default registry
        if registry and "registry.npmjs.org" not in registry:
            findings.append(Finding(
                rule_id="AUDIT-006",
                title="Non-default publish registry",
                description=f"Package publishes to non-default registry: '{registry}'.",
                risk_level=RiskLevel.MEDIUM,
                file_path="package.json",
                recommendation="Verify the registry is legitimate.",
            ))
            risky.append(f"Publishes to: {registry}")

        # Check for restricted access
        access = publish_config.get("access", "")
        if access == "restricted":
            findings.append(Finding(
                rule_id="AUDIT-007",
                title="Restricted package access",
                description="Package uses restricted access, which limits who can install it.",
                risk_level=RiskLevel.LOW,
                file_path="package.json",
                recommendation="Restricted packages are unusual for public npm.",
            ))

    def _check_dependency_anomalies(
        self, pkg: dict, findings: list[Finding], risky: list[str]
    ) -> None:
        # Check for install dependencies vs dev dependencies
        deps = pkg.get("dependencies", {})
        dev_deps = pkg.get("devDependencies", {})

        # Flag if a popular package is in deps but shouldn't be
        # (this is a heuristic, not definitive)
        if len(deps) > 50:
            findings.append(Finding(
                rule_id="AUDIT-008",
                title="Excessive production dependencies",
                description=f"Package has {len(deps)} production dependencies. This increases supply chain attack surface.",
                risk_level=RiskLevel.LOW,
                file_path="package.json",
                recommendation="Consider if all dependencies are truly needed in production.",
            ))

        # Check for dependencies with unusual version patterns
        for dep_name, version in deps.items():
            if version == "*" or version == "latest":
                findings.append(Finding(
                    rule_id="AUDIT-009",
                    title=f"Unpinned dependency: {dep_name}",
                    description=f"Dependency '{dep_name}' uses version '{version}', which is unpinned.",
                    risk_level=RiskLevel.MEDIUM,
                    file_path="package.json",
                    recommendation="Pin dependency versions to avoid unexpected updates.",
                ))
                risky.append(f"Unpinned dep: {dep_name}@{version}")
