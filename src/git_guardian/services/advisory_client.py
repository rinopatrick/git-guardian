"""GitHub Advisory Database client — checks npm packages for known CVEs/GHSAs."""

import json
import time
import urllib.request
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime

from git_guardian.models.package import Finding, RiskLevel


@dataclass
class Advisory:
    """A security advisory."""

    ghsa_id: str
    cve_id: str | None = None
    severity: str = "unknown"  # low, medium, high, critical
    summary: str = ""
    description: str = ""
    affected_versions: list[str] = field(default_factory=list)
    patched_versions: list[str] = field(default_factory=list)
    published_at: str = ""
    references: list[str] = field(default_factory=list)
    cvss_score: float | None = None
    cwes: list[str] = field(default_factory=list)


@dataclass
class AdvisoryReport:
    """Advisory report for a package."""

    package_name: str
    advisories: list[Advisory] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def has_advisories(self) -> bool:
        return len(self.advisories) > 0

    @property
    def critical_count(self) -> int:
        return sum(1 for a in self.advisories if a.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for a in self.advisories if a.severity == "high")


# In-memory cache: package_name -> (advisories, timestamp)
_cache: dict[str, tuple[list[Advisory], float]] = {}
CACHE_TTL = 3600  # 1 hour


class AdvisoryClient:
    """Queries the GitHub Advisory Database for npm package vulnerabilities."""

    BASE_URL = "https://api.github.com/advisories"

    def _query_advisories(self, package_name: str) -> list[Advisory]:
        """Query GitHub Advisory API for a package."""
        params = urllib.parse.urlencode({
            "ecosystem": "npm",
            "package": package_name,
            "per_page": 100,
        })
        url = f"{self.BASE_URL}?{params}"

        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )

        advisories: list[Advisory] = []
        try:
            resp = urllib.request.urlopen(req, timeout=30)
            data = json.loads(resp.read())

            for item in data:
                # Extract severity
                severity = "unknown"
                cvss_score = None
                if item.get("severity"):
                    severity = item["severity"]
                elif item.get("cvss", {}).get("score"):
                    cvss_score = item["cvss"]["score"]
                    if cvss_score >= 9.0:
                        severity = "critical"
                    elif cvss_score >= 7.0:
                        severity = "high"
                    elif cvss_score >= 4.0:
                        severity = "medium"
                    else:
                        severity = "low"

                # Extract affected versions
                affected = []
                patched = []
                for vuln in item.get("vulnerabilities", []):
                    pkg = vuln.get("package", {})
                    if pkg.get("name") == package_name:
                        if vuln.get("vulnerable_version_range"):
                            affected.append(vuln["vulnerable_version_range"])
                        if vuln.get("first_patched_version"):
                            patched.append(vuln["first_patched_version"].get("identifier", ""))

                # Extract CWEs
                cwes = [cwe.get("cwe_id", "") for cwe in item.get("cwes", [])]

                # Extract references
                refs = [ref.get("url", "") for ref in item.get("references", [])]

                advisories.append(Advisory(
                    ghsa_id=item.get("ghsa_id", ""),
                    cve_id=item.get("cve_id"),
                    severity=severity,
                    summary=item.get("summary", ""),
                    description=item.get("description", "")[:500],
                    affected_versions=affected,
                    patched_versions=patched,
                    published_at=item.get("published_at", ""),
                    references=refs,
                    cvss_score=cvss_score or item.get("cvss", {}).get("score"),
                    cwes=cwes,
                ))

        except urllib.error.HTTPError as e:
            if e.code != 404:
                print(f"  Advisory API error: {e.code}")
        except Exception as e:
            print(f"  Advisory API error: {e}")

        return advisories

    def get_advisories(self, package_name: str) -> list[Advisory]:
        """Get advisories for a package (with caching)."""
        now = time.time()
        if package_name in _cache:
            advisories, ts = _cache[package_name]
            if now - ts < CACHE_TTL:
                return advisories

        advisories = self._query_advisories(package_name)
        _cache[package_name] = (advisories, now)
        return advisories

    def scan_package(
        self,
        package_name: str,
        current_version: str | None = None,
    ) -> AdvisoryReport:
        """Scan a package for known advisories.

        Args:
            package_name: npm package name
            current_version: Current version to check against patches

        Returns:
            AdvisoryReport with advisories and findings
        """
        advisories = self.get_advisories(package_name)
        findings: list[Finding] = []

        for adv in advisories:
            risk_map = {
                "critical": RiskLevel.CRITICAL,
                "high": RiskLevel.HIGH,
                "medium": RiskLevel.MEDIUM,
                "low": RiskLevel.LOW,
            }
            risk = risk_map.get(adv.severity, RiskLevel.MEDIUM)

            # Check if current version is affected
            is_patched = False
            if current_version and adv.patched_versions:
                is_patched = any(
                    current_version >= p for p in adv.patched_versions if p
                )

            description = f"{adv.summary}\n"
            if adv.cve_id:
                description += f"CVE: {adv.cve_id}\n"
            if adv.affected_versions:
                description += f"Affected: {', '.join(adv.affected_versions)}\n"
            if adv.patched_versions:
                description += f"Patched: {', '.join(adv.patched_versions)}\n"
            if is_patched:
                description += "Status: Current version appears to be patched.\n"
            elif current_version:
                description += "Status: Current version may still be vulnerable!\n"

            findings.append(Finding(
                rule_id=adv.ghsa_id,
                title=adv.summary[:100],
                description=description,
                risk_level=risk,
                recommendation=f"Update to patched version: {', '.join(adv.patched_versions) if adv.patched_versions else 'See advisory'}",
            ))

        return AdvisoryReport(
            package_name=package_name,
            advisories=advisories,
            findings=findings,
        )

    def get_stats(self) -> dict:
        """Get cache stats."""
        return {
            "cached_packages": len(_cache),
            "total_cached_advisories": sum(len(a) for a, _ in _cache.values()),
        }
