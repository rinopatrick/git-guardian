"""License compliance scanner — detects GPL contamination, license conflicts, and risky licenses."""

import re
from dataclasses import dataclass, field

from git_guardian.models.package import Finding, PackageInfo, RiskLevel


# License categories
COPYLEFT_LICENSES = {
    "GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later",
    "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later",
    "AGPL-1.0", "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later",
    "LGPL-2.0", "LGPL-2.0-only", "LGPL-2.0-or-later",
    "LGPL-2.1", "LGPL-2.1-only", "LGPL-2.1-or-later",
    "LGPL-3.0", "LGPL-3.0-only", "LGPL-3.0-or-later",
    "CC-BY-SA-1.0", "CC-BY-SA-2.0", "CC-BY-SA-2.5",
    "CC-BY-SA-3.0", "CC-BY-SA-4.0",
    "EUPL-1.1", "EUPL-1.2",
    "OSL-3.0",
    "CDDL-1.0", "CDDL-1.1",
    "MPL-1.0", "MPL-1.1", "MPL-2.0",
}

WEAK_COPYLEFT = {
    "LGPL-2.0", "LGPL-2.0-only", "LGPL-2.0-or-later",
    "LGPL-2.1", "LGPL-2.1-only", "LGPL-2.1-or-later",
    "LGPL-3.0", "LGPL-3.0-only", "LGPL-3.0-or-later",
    "MPL-1.0", "MPL-1.1", "MPL-2.0",
    "CDDL-1.0", "CDDL-1.1",
    "EPL-1.0", "EPL-2.0",
}

PERMISSIVE_LICENSES = {
    "MIT", "ISC", "BSD-2-Clause", "BSD-3-Clause",
    "Apache-2.0", "0BSD", "Unlicense", "CC0-1.0",
    "WTFPL", "Zlib", "Artistic-2.0",
}

RISKY_LICENSES = {
    "WTFPL",  # ambiguous legal standing
    "Unlicense",  # not recognized in all jurisdictions
    "CC0-1.0",  # patent issues in some contexts
}

NO_LICENSE_RISK = "UNKNOWN"

# Known license conflict pairs
LICENSE_CONFLICTS = [
    ("GPL-2.0", "Apache-2.0", "GPL-2.0 is incompatible with Apache-2.0 patent clauses"),
    ("GPL-2.0-only", "Apache-2.0", "GPL-2.0-only is incompatible with Apache-2.0"),
    ("GPL-3.0", "OpenSSL", "GPL-3.0 has OpenSSL linking issues"),
]


@dataclass
class LicenseReport:
    """License compliance report for a package."""

    package_name: str
    license_id: str | None
    license_type: str  # permissive, copyleft, weak-copyleft, unknown, none
    is_risky: bool
    findings: list[Finding] = field(default_factory=list)
    dependency_licenses: dict[str, str] = field(default_factory=dict)
    conflicts: list[str] = field(default_factory=list)

    @property
    def is_compliant(self) -> bool:
        return not self.findings and not self.conflicts


def classify_license(license_id: str | None) -> tuple[str, bool]:
    """Classify a license string into a type and risk flag.

    Returns:
        (license_type, is_risky)
    """
    if not license_id:
        return "none", True

    # Normalize
    normalized = license_id.strip()
    # Handle expressions like "(MIT OR Apache-2.0)"
    if " OR " in normalized or " AND " in normalized:
        return "expression", False

    # Remove surrounding parens
    normalized = normalized.strip("()")

    if normalized in COPYLEFT_LICENSES:
        if normalized in WEAK_COPYLEFT:
            return "weak-copyleft", True
        return "copyleft", True
    if normalized in PERMISSIVE_LICENSES:
        if normalized in RISKY_LICENSES:
            return "permissive", True
        return "permissive", False

    return "unknown", True


class LicenseScanner:
    """Scans packages for license compliance issues."""

    def scan_package(self, package_info: PackageInfo) -> LicenseReport:
        """Scan a single package for license issues.

        Args:
            package_info: Package metadata

        Returns:
            LicenseReport with findings
        """
        findings: list[Finding] = []
        license_id = package_info.license
        license_type, is_risky = classify_license(license_id)

        # No license
        if license_type == "none":
            findings.append(Finding(
                rule_id="LIC-001",
                title="No license declared",
                description=f"Package '{package_info.name}' has no license. Using it may have legal implications.",
                risk_level=RiskLevel.HIGH,
                recommendation="Avoid packages without a license or contact the author for clarification.",
            ))

        # Unknown license
        if license_type == "unknown":
            findings.append(Finding(
                rule_id="LIC-002",
                title="Unknown license",
                description=f"Package '{package_info.name}' has unrecognized license: '{license_id}'.",
                risk_level=RiskLevel.MEDIUM,
                recommendation="Verify the license is compatible with your project.",
            ))

        # Copyleft in npm package
        if license_type == "copyleft":
            findings.append(Finding(
                rule_id="LIC-003",
                title="Copyleft license detected",
                description=f"Package '{package_info.name}' uses copyleft license '{license_id}'. This may require your code to be open-sourced.",
                risk_level=RiskLevel.HIGH,
                recommendation="Consult legal counsel before using copyleft-licensed packages in proprietary software.",
            ))

        # Weak copyleft
        if license_type == "weak-copyleft":
            findings.append(Finding(
                rule_id="LIC-004",
                title="Weak copyleft license",
                description=f"Package '{package_info.name}' uses weak copyleft '{license_id}'. Modifications may need to be open-sourced.",
                risk_level=RiskLevel.MEDIUM,
                recommendation="Understand the obligations of this license before modifying the code.",
            ))

        # Risky permissive
        if is_risky and license_type == "permissive":
            findings.append(Finding(
                rule_id="LIC-005",
                title="Risky permissive license",
                description=f"Package '{package_info.name}' uses '{license_id}' which has ambiguous legal standing.",
                risk_level=RiskLevel.LOW,
                recommendation="Consider using packages with more widely recognized licenses.",
            ))

        return LicenseReport(
            package_name=package_info.name,
            license_id=license_id,
            license_type=license_type,
            is_risky=is_risky,
            findings=findings,
        )

    def scan_dependency_tree(
        self,
        root_package: str,
        dependency_licenses: dict[str, str | None],
    ) -> LicenseReport:
        """Scan an entire dependency tree for license conflicts.

        Args:
            root_package: Root package name
            dependency_licenses: Dict of package_name -> license_id

        Returns:
            LicenseReport with all findings and conflicts
        """
        findings: list[Finding] = []
        conflicts: list[str] = []

        # Classify all licenses
        license_map: dict[str, str] = {}
        for pkg, lic in dependency_licenses.items():
            ltype, _ = classify_license(lic)
            license_map[pkg] = lic or "NONE"

            # Flag no-license deps
            if not lic:
                findings.append(Finding(
                    rule_id="LIC-010",
                    title=f"Dependency without license: {pkg}",
                    description=f"Transitive dependency '{pkg}' has no license.",
                    risk_level=RiskLevel.MEDIUM,
                    file_path=f"dependency:{pkg}",
                    recommendation="Consider alternatives with clear licensing.",
                ))

            # Flag copyleft deps
            if ltype == "copyleft":
                findings.append(Finding(
                    rule_id="LIC-011",
                    title=f"Copyleft dependency: {pkg}",
                    description=f"Transitive dependency '{pkg}' uses copyleft license '{lic}'.",
                    risk_level=RiskLevel.HIGH,
                    file_path=f"dependency:{pkg}",
                    recommendation="This may impose open-source obligations on your project.",
                ))

        # Check for conflicts between licenses
        for pkg_a, lic_a in dependency_licenses.items():
            for pkg_b, lic_b in dependency_licenses.items():
                if pkg_a >= pkg_b:
                    continue
                for l1, l2, reason in LICENSE_CONFLICTS:
                    if (lic_a and l1 in lic_a and lic_b and l2 in lic_b) or \
                       (lic_b and l1 in lic_b and lic_a and l2 in lic_a):
                        conflicts.append(
                            f"Conflict between {pkg_a} ({lic_a}) and {pkg_b} ({lic_b}): {reason}"
                        )

        if conflicts:
            findings.append(Finding(
                rule_id="LIC-020",
                title="License conflicts detected",
                description=f"Found {len(conflicts)} license conflict(s) in dependency tree.",
                risk_level=RiskLevel.HIGH,
                recommendation="Resolve license conflicts before shipping.",
            ))

        return LicenseReport(
            package_name=root_package,
            license_id=dependency_licenses.get(root_package),
            license_type=classify_license(dependency_licenses.get(root_package))[0],
            is_risky=classify_license(dependency_licenses.get(root_package))[1],
            findings=findings,
            dependency_licenses=license_map,
            conflicts=conflicts,
        )
