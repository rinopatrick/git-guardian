"""Lockfile integrity analyzer — detects dependency injection, hash mismatches, and registry tampering."""

import json
import re
from dataclasses import dataclass, field
from typing import Any

from git_guardian.models.package import Finding, RiskLevel


@dataclass
class LockfileEntry:
    """A single lockfile entry."""

    name: str
    version: str
    resolved: str | None = None
    integrity: str | None = None
    dependencies: dict[str, str] = field(default_factory=dict)
    dev: bool = False
    optional: bool = False
    has_install_script: bool = False


@dataclass
class LockfileAnalysisResult:
    """Result of lockfile analysis."""

    package_name: str
    lockfile_type: str  # npm, yarn, pnpm
    total_entries: int = 0
    findings: list[Finding] = field(default_factory=list)
    injected_deps: list[str] = field(default_factory=list)
    integrity_issues: list[str] = field(default_factory=list)
    suspicious_entries: list[str] = field(default_factory=list)

    @property
    def is_clean(self) -> bool:
        return not self.findings


# Known legitimate registries
LEGITIMATE_REGISTRIES = {
    "registry.npmjs.org",
    "registry.yarnpkg.com",
    "npm.pkg.github.com",
}

# Suspicious resolved URL patterns
SUSPICIOUS_REGISTRY_PATTERNS = [
    r"https?://(?:\d{1,3}\.){3}\d{1,3}",  # IP addresses
    r"\.onion/",
    r"localhost",
    r"127\.0\.0\.1",
    r"0\.0\.0\.0",
]

# Packages that legitimately have install scripts
KNOWN_INSTALL_SCRIPT_PACKAGES = {
    "node-sass", "node-gyp", "bcrypt", "argon2", "sharp",
    "better-sqlite3", "sqlite3", "canvas", "cpu-features",
    "fsevents", "chromedriver", "geckodriver", "selenium-webdriver",
}


class LockfileAnalyzer:
    """Analyzes lockfiles for dependency injection and integrity issues."""

    def analyze_npm_lockfile(
        self,
        content: str,
        package_name: str,
        declared_deps: dict[str, str] | None = None,
    ) -> LockfileAnalysisResult:
        """Analyze a package-lock.json (v2/v3).

        Args:
            content: Raw JSON content of package-lock.json
            package_name: Root package name for reporting
            declared_deps: Dependencies from package.json (for injection detection)

        Returns:
            LockfileAnalysisResult with findings
        """
        findings: list[Finding] = []
        injected: list[str] = []
        integrity_issues: list[str] = []
        suspicious: list[str] = []

        try:
            lockfile = json.loads(content)
        except json.JSONDecodeError:
            return LockfileAnalysisResult(
                package_name=package_name,
                lockfile_type="npm",
                findings=[Finding(
                    rule_id="LOCK-000",
                    title="Invalid lockfile",
                    description="package-lock.json is not valid JSON.",
                    risk_level=RiskLevel.MEDIUM,
                )],
            )

        lockfile_version = lockfile.get("lockfileVersion", 1)
        packages = lockfile.get("packages", {})
        deps = lockfile.get("dependencies", {})

        # v2/v3 format uses "packages" key
        entries: list[LockfileEntry] = []
        if packages:
            for path, info in packages.items():
                name = path.split("node_modules/")[-1] if "node_modules/" in path else path
                if not name:
                    continue
                entry = LockfileEntry(
                    name=name,
                    version=info.get("version", ""),
                    resolved=info.get("resolved"),
                    integrity=info.get("integrity"),
                    dependencies=info.get("dependencies", {}),
                    dev=info.get("dev", False) or info.get("devOptional", False),
                    optional=info.get("optional", False),
                    has_install_script=info.get("hasInstallScript", False),
                )
                entries.append(entry)
        # v1 format uses "dependencies" key
        elif deps:
            for name, info in deps.items():
                entry = LockfileEntry(
                    name=name,
                    version=info.get("version", ""),
                    resolved=info.get("resolved"),
                    integrity=info.get("integrity"),
                    dependencies=info.get("requires", {}),
                    dev=info.get("dev", False),
                    optional=info.get("optional", False),
                    has_install_script=info.get("requiresBuild", False),
                )
                entries.append(entry)

        # 1. Check for injected dependencies
        if declared_deps:
            lockfile_dep_names = {e.name for e in entries}
            declared_dep_names = set(declared_deps.keys())
            extra = lockfile_dep_names - declared_dep_names
            # Remove common transitive patterns (scoped packages, etc.)
            for dep in extra:
                if dep.startswith("@") or dep in KNOWN_INSTALL_SCRIPT_PACKAGES:
                    continue
                injected.append(dep)
                findings.append(Finding(
                    rule_id="LOCK-001",
                    title=f"Injected dependency: {dep}",
                    description=f"'{dep}' appears in lockfile but not in package.json dependencies. Possible dependency injection.",
                    risk_level=RiskLevel.HIGH,
                    file_path="package-lock.json",
                    recommendation="Verify this dependency is expected. It may be a transitive dependency or an injection.",
                ))

        # 2. Check integrity hashes
        for entry in entries:
            if entry.resolved and not entry.integrity:
                if not entry.optional and not entry.dev:
                    integrity_issues.append(entry.name)
                    findings.append(Finding(
                        rule_id="LOCK-002",
                        title=f"Missing integrity: {entry.name}",
                        description=f"Package '{entry.name}' has a resolved URL but no integrity hash.",
                        risk_level=RiskLevel.MEDIUM,
                        file_path="package-lock.json",
                        recommendation="Packages should have integrity hashes to prevent tampering.",
                    ))

        # 3. Check resolved URLs
        for entry in entries:
            if not entry.resolved:
                continue
            for pattern in SUSPICIOUS_REGISTRY_PATTERNS:
                if re.search(pattern, entry.resolved, re.IGNORECASE):
                    suspicious.append(entry.name)
                    findings.append(Finding(
                        rule_id="LOCK-003",
                        title=f"Suspicious registry: {entry.name}",
                        description=f"Package '{entry.name}' resolves to suspicious URL: {entry.resolved}",
                        risk_level=RiskLevel.HIGH,
                        file_path="package-lock.json",
                        recommendation="Verify the registry URL is legitimate.",
                    ))
                    break
            else:
                # Check for non-standard registries
                is_known = any(reg in entry.resolved for reg in LEGITIMATE_REGISTRIES)
                if not is_known and entry.resolved.startswith("http"):
                    suspicious.append(entry.name)
                    findings.append(Finding(
                        rule_id="LOCK-004",
                        title=f"Non-standard registry: {entry.name}",
                        description=f"Package '{entry.name}' resolves to non-standard registry: {entry.resolved}",
                        risk_level=RiskLevel.MEDIUM,
                        file_path="package-lock.json",
                        recommendation="Verify this registry is expected and trustworthy.",
                    ))

        # 4. Check for install scripts in unexpected packages
        for entry in entries:
            if entry.has_install_script and entry.name not in KNOWN_INSTALL_SCRIPT_PACKAGES:
                findings.append(Finding(
                    rule_id="LOCK-005",
                    title=f"Install script: {entry.name}",
                    description=f"Package '{entry.name}' has install scripts. It runs code during npm install.",
                    risk_level=RiskLevel.MEDIUM,
                    file_path="package-lock.json",
                    recommendation="Review what this package's install scripts do.",
                ))

        return LockfileAnalysisResult(
            package_name=package_name,
            lockfile_type="npm",
            total_entries=len(entries),
            findings=findings,
            injected_deps=injected,
            integrity_issues=integrity_issues,
            suspicious_entries=suspicious,
        )

    def analyze_yarn_lockfile(
        self,
        content: str,
        package_name: str,
    ) -> LockfileAnalysisResult:
        """Analyze a yarn.lock file.

        Yarn lock format is a custom text format. We parse it heuristically.
        """
        findings: list[Finding] = []
        entries: list[LockfileEntry] = []

        # Parse yarn.lock entries
        # Format: "package@version":\n  version "X.Y.Z"\n  resolved "URL"\n  integrity SHA-XXX
        current_entry: dict[str, Any] = {}
        current_name = ""

        for line in content.split("\n"):
            line = line.rstrip()

            # New entry header
            if line and not line.startswith(" ") and not line.startswith("#"):
                if current_name and current_entry:
                    entries.append(LockfileEntry(
                        name=current_name,
                        version=current_entry.get("version", ""),
                        resolved=current_entry.get("resolved"),
                        integrity=current_entry.get("integrity"),
                    ))
                # Parse header: "package@^version":
                match = re.match(r'^"?([^@"]+)@', line)
                current_name = match.group(1) if match else line.strip('"').split("@")[0]
                current_entry = {}

            # Entry properties
            if line.startswith("  version "):
                current_entry["version"] = line.split('"')[1] if '"' in line else line.split()[-1]
            elif line.startswith("  resolved "):
                current_entry["resolved"] = line.split('"')[1] if '"' in line else line.split()[-1]
            elif line.startswith("  integrity "):
                current_entry["integrity"] = line.split()[-1]

        # Don't forget the last entry
        if current_name and current_entry:
            entries.append(LockfileEntry(
                name=current_name,
                version=current_entry.get("version", ""),
                resolved=current_entry.get("resolved"),
                integrity=current_entry.get("integrity"),
            ))

        # Run same checks as npm
        for entry in entries:
            if entry.resolved and not entry.integrity:
                findings.append(Finding(
                    rule_id="LOCK-002",
                    title=f"Missing integrity: {entry.name}",
                    description=f"Package '{entry.name}' has resolved URL but no integrity hash.",
                    risk_level=RiskLevel.MEDIUM,
                    file_path="yarn.lock",
                ))

            if entry.resolved:
                for pattern in SUSPICIOUS_REGISTRY_PATTERNS:
                    if re.search(pattern, entry.resolved, re.IGNORECASE):
                        findings.append(Finding(
                            rule_id="LOCK-003",
                            title=f"Suspicious registry: {entry.name}",
                            description=f"Package '{entry.name}' resolves to suspicious URL: {entry.resolved}",
                            risk_level=RiskLevel.HIGH,
                            file_path="yarn.lock",
                        ))
                        break

        return LockfileAnalysisResult(
            package_name=package_name,
            lockfile_type="yarn",
            total_entries=len(entries),
            findings=findings,
        )

    def analyze_pnpm_lockfile(
        self,
        content: str,
        package_name: str,
    ) -> LockfileAnalysisResult:
        """Analyze a pnpm-lock.yaml file.

        Simplified YAML parsing without external dependencies.
        """
        findings: list[Finding] = []
        entries: list[LockfileEntry] = []

        # Simple YAML-like parsing for pnpm lock format
        # Look for package entries with version and resolution
        import_sections = re.findall(
            r"(/[^:]+):\s*\n\s+resolution:\s*\{[^}]*\}",
            content,
            re.MULTILINE,
        )

        # Extract package info from the content
        pkg_pattern = re.compile(
            r"(/[^\s@]+)@([^:]+):\s*\n"
            r"(?:.*\n)*?"
            r"\s+version:\s*(.+)\n"
            r"(?:.*\n)*?"
            r"\s+resolution:\s*\{[^}]*integrity:\s*([^\}]+)\}",
            re.MULTILINE,
        )

        for match in pkg_pattern.finditer(content):
            name = match.group(1).split("/")[-1]
            version = match.group(3).strip()
            integrity = match.group(4).strip() if match.group(4) else None

            entries.append(LockfileEntry(
                name=name,
                version=version,
                integrity=integrity,
            ))

        # Basic integrity checks
        for entry in entries:
            if not entry.integrity:
                findings.append(Finding(
                    rule_id="LOCK-002",
                    title=f"Missing integrity: {entry.name}",
                    description=f"Package '{entry.name}' has no integrity hash.",
                    risk_level=RiskLevel.MEDIUM,
                    file_path="pnpm-lock.yaml",
                ))

        return LockfileAnalysisResult(
            package_name=package_name,
            lockfile_type="pnpm",
            total_entries=len(entries),
            findings=findings,
        )
