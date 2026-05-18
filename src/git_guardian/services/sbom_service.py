"""SBOM generator — produces CycloneDX 1.5 and SPDX 2.3 from dependency trees."""

import json
import uuid
from datetime import datetime, timezone
from dataclasses import dataclass, field

from git_guardian.models.package import Finding, PackageInfo


@dataclass
class SBOMComponent:
    """A component in the SBOM."""

    name: str
    version: str
    purl: str  # Package URL
    license_id: str | None = None
    description: str | None = None
    author: str | None = None
    supplier: str | None = None
    hash_sha256: str | None = None
    dependencies: list[str] = field(default_factory=list)
    vulnerabilities: list[dict] = field(default_factory=list)


@dataclass
class SBOMResult:
    """Result of SBOM generation."""

    format: str  # cyclonedx, spdx
    content: str
    component_count: int
    vulnerability_count: int


class SBOMService:
    """Generates SBOMs in CycloneDX and SPDX formats."""

    def generate_cyclonedx(
        self,
        root_package: PackageInfo,
        dependencies: dict[str, dict] | None = None,
        findings: list[Finding] | None = None,
    ) -> SBOMResult:
        """Generate CycloneDX 1.5 JSON SBOM.

        Args:
            root_package: Root package info
            dependencies: Dict of name -> {version, license, description, ...}
            findings: Security findings to include as vulnerabilities

        Returns:
            SBOMResult with CycloneDX JSON
        """
        deps = dependencies or {}
        vulns = findings or []

        components = []
        for name, info in deps.items():
            version = info.get("version", "unknown")
            purl = f"pkg:npm/{name}@{version}"

            component = {
                "type": "library",
                "name": name,
                "version": version,
                "purl": purl,
            }
            if info.get("license"):
                component["licenses"] = [{"license": {"id": info["license"]}}]
            if info.get("description"):
                component["description"] = info["description"]
            if info.get("author"):
                component["author"] = info["author"]

            components.append(component)

        # Build vulnerabilities
        cdx_vulns = []
        for f in vulns:
            vuln = {
                "id": f.rule_id,
                "description": f.description,
                "ratings": [{
                    "severity": f.risk_level.value,
                    "method": "other",
                }],
            }
            if f.recommendation:
                vuln["recommendation"] = f.recommendation
            cdx_vulns.append(vuln)

        # Root component
        root_purl = f"pkg:npm/{root_package.name}@{root_package.latest_version}"
        root_component = {
            "type": "library",
            "name": root_package.name,
            "version": root_package.latest_version,
            "purl": root_purl,
        }
        if root_package.license:
            root_component["licenses"] = [{"license": {"id": root_package.license}}]
        if root_package.description:
            root_component["description"] = root_package.description

        bom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tools": [{
                    "vendor": "git-guardian",
                    "name": "git-guardian",
                    "version": "0.6.0",
                }],
                "component": root_component,
            },
            "components": components,
        }

        if cdx_vulns:
            bom["vulnerabilities"] = cdx_vulns

        return SBOMResult(
            format="cyclonedx",
            content=json.dumps(bom, indent=2),
            component_count=len(components),
            vulnerability_count=len(cdx_vulns),
        )

    def generate_spdx(
        self,
        root_package: PackageInfo,
        dependencies: dict[str, dict] | None = None,
        findings: list[Finding] | None = None,
    ) -> SBOMResult:
        """Generate SPDX 2.3 tag-value SBOM.

        Args:
            root_package: Root package info
            dependencies: Dict of name -> {version, license, ...}
            findings: Security findings

        Returns:
            SBOMResult with SPDX tag-value text
        """
        deps = dependencies or {}
        vulns = findings or []

        doc_namespace = f"https://git-guardian/spdx/{root_package.name}-{root_package.latest_version}"
        lines: list[str] = []

        # Document info
        lines.append(f"SPDXVersion: SPDX-2.3")
        lines.append(f"DataLicense: CC0-1.0")
        lines.append(f"SPDXID: SPDXRef-DOCUMENT")
        lines.append(f"DocumentName: {root_package.name}@{root_package.latest_version}")
        lines.append(f"DocumentNamespace: {doc_namespace}")
        lines.append(f"Creator: Tool: git-guardian-0.6.0")
        lines.append(f"Created: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")
        lines.append("")

        # Root package
        lines.append(f"PackageName: {root_package.name}")
        lines.append(f"SPDXID: SPDXRef-Package-{root_package.name.replace('/', '-')}")
        lines.append(f"PackageVersion: {root_package.latest_version}")
        lines.append(f"PackageDownloadLocation: https://registry.npmjs.org/{root_package.name}")
        lines.append(f"PrimaryPackagePurpose: LIBRARY")
        if root_package.license:
            lines.append(f"PackageLicenseDeclared: {root_package.license}")
        lines.append(f"ExternalRef: PACKAGE-MANAGER purl pkg:npm/{root_package.name}@{root_package.latest_version}")
        lines.append("")

        # Dependencies
        pkg_num = 1
        for name, info in deps.items():
            version = info.get("version", "unknown")
            safe_name = name.replace("/", "-")
            pkg_num += 1

            lines.append(f"PackageName: {name}")
            lines.append(f"SPDXID: SPDXRef-Pkg-{safe_name}-{pkg_num}")
            lines.append(f"PackageVersion: {version}")
            lines.append(f"PackageDownloadLocation: https://registry.npmjs.org/{name}")
            if info.get("license"):
                lines.append(f"PackageLicenseDeclared: {info['license']}")
            lines.append(f"ExternalRef: PACKAGE-MANAGER purl pkg:npm/{name}@{version}")
            lines.append("")

        # Vulnerabilities (as annotations)
        for f in vulns:
            lines.append(f"## Vulnerability: {f.rule_id}")
            lines.append(f"SPDXID: SPDXRef-Vuln-{f.rule_id.replace('/', '-')}")
            lines.append(f"Summary: {f.title}")
            lines.append(f"Detail: {f.description[:200]}")
            lines.append(f"Severity: {f.risk_level.value}")
            if f.recommendation:
                lines.append(f"Recommendation: {f.recommendation}")
            lines.append("")

        return SBOMResult(
            format="spdx",
            content="\n".join(lines),
            component_count=len(deps),
            vulnerability_count=len(vulns),
        )
