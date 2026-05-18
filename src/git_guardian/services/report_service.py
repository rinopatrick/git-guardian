"""AI-powered security report generator — multi-pass narrative reports.

This is the biggest token burner: each report requires 3-4 AI calls with
full context, consuming 15,000-25,000 tokens per package.
"""

import json
import re
import urllib.request
from dataclasses import dataclass, field

from git_guardian.config import settings
from git_guardian.models.package import Finding, PackageInfo, RiskLevel


EXECUTIVE_SUMMARY_PROMPT = """You are a senior security analyst writing an executive summary for a supply chain security report.
Given the scan results for an npm package, write a concise executive summary (3-5 sentences) that:
1. States the overall risk assessment
2. Highlights the most critical findings
3. Provides a clear recommendation (safe to use / audit required / avoid)

Be direct and actionable. Avoid hedging language."""

DETAILED_FINDINGS_PROMPT = """You are a security researcher explaining findings to a developer.
For each finding, write a clear explanation that includes:
1. What the finding means in plain language
2. Why it's a security concern
3. How it could be exploited
4. What the developer should do about it

Be technical but accessible. Use concrete examples."""

DEPENDENCY_RISK_PROMPT = """You are a supply chain security expert analyzing dependency risk.
Given the dependency information, write a risk assessment that covers:
1. The attack surface created by the dependency tree
2. Which dependencies are highest risk and why
3. Whether the package follows good dependency hygiene
4. Specific risks from transitive dependencies"""

RECOMMENDATIONS_PROMPT = """You are a security advisor providing actionable recommendations.
Based on all findings, provide:
1. Immediate actions (must-do before using this package)
2. Short-term mitigations (reduce risk if using this package)
3. Long-term alternatives (safer packages or approaches)
4. Monitoring suggestions (what to watch for ongoing)

Be specific and practical."""


@dataclass
class SecurityReport:
    """A comprehensive security report for a package."""

    package_name: str
    version: str
    overall_risk: RiskLevel
    executive_summary: str = ""
    findings_narrative: str = ""
    dependency_risk: str = ""
    recommendations: str = ""
    total_tokens: int = 0
    total_findings: int = 0
    risk_breakdown: dict[str, int] = field(default_factory=dict)


class ReportService:
    """Generates multi-pass AI security reports."""

    def __init__(self) -> None:
        self.base_url = settings.ai_base_url
        self.model = settings.ai_model
        self.total_tokens = 0

    def _call_api(self, messages: list[dict], max_tokens: int = 2000) -> str | None:
        """Call MiMo API using urllib."""
        data = json.dumps({
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": 0.2,
        }).encode()

        url = f"{self.base_url}/chat/completions"
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
        )

        try:
            resp = urllib.request.urlopen(req, timeout=120)
            result = json.loads(resp.read())
            content = result["choices"][0]["message"]["content"]
            usage = result.get("usage", {})
            self.total_tokens += usage.get("total_tokens", 0)
            return content
        except Exception as e:
            print(f"  Report API error: {e}")
            return None

    def _build_findings_context(self, findings: list[Finding]) -> str:
        """Build context string from findings."""
        if not findings:
            return "No security findings detected."

        lines = []
        for f in findings:
            lines.append(f"- [{f.risk_level.value.upper()}] {f.title}")
            lines.append(f"  {f.description}")
            if f.file_path:
                lines.append(f"  File: {f.file_path}")
            if f.recommendation:
                lines.append(f"  Recommendation: {f.recommendation}")
            lines.append("")
        return "\n".join(lines)

    def _build_package_context(self, pkg: PackageInfo) -> str:
        """Build context string from package info."""
        deps_count = len(pkg.versions[-1].dependencies) if pkg.versions else 0
        return f"""Package: {pkg.name}
Version: {pkg.latest_version}
Description: {pkg.description or 'N/A'}
Author: {pkg.author.name if pkg.author else 'N/A'}
License: {pkg.license or 'N/A'}
Weekly Downloads: {pkg.weekly_downloads:,}
Dependencies: {deps_count}
Created: {pkg.created_at or 'N/A'}
Last Updated: {pkg.updated_at or 'N/A'}"""

    def _build_dependency_context(self, dep_info: dict | None) -> str:
        """Build context from dependency scan results."""
        if not dep_info:
            return "No dependency scan data available."

        lines = [f"Total dependencies: {dep_info.get('total', 'unknown')}"]
        for name, info in dep_info.get("packages", {}).items():
            lines.append(f"- {name}@{info.get('version', '?')}: {info.get('license', 'no license')}")
        return "\n".join(lines[:50])  # Limit to 50 deps

    def generate_report(
        self,
        package_info: PackageInfo,
        findings: list[Finding],
        dep_info: dict | None = None,
        advisory_findings: list[Finding] | None = None,
        network_summary: str | None = None,
        health_score: float | None = None,
    ) -> SecurityReport:
        """Generate a comprehensive multi-pass security report.

        This burns significant tokens through 4 separate AI calls.

        Args:
            package_info: Package metadata
            findings: All security findings
            dep_info: Dependency scan results
            advisory_findings: Known vulnerability findings
            network_summary: Network behavior summary
            health_score: Package health score (0-100)

        Returns:
            SecurityReport with all narrative sections
        """
        self.total_tokens = 0

        # Combine all findings
        all_findings = findings + (advisory_findings or [])

        # Risk breakdown
        risk_breakdown: dict[str, int] = {}
        for f in all_findings:
            risk_breakdown[f.risk_level.value] = risk_breakdown.get(f.risk_level.value, 0) + 1

        # Determine overall risk
        if risk_breakdown.get("critical", 0) > 0:
            overall_risk = RiskLevel.CRITICAL
        elif risk_breakdown.get("high", 0) > 0:
            overall_risk = RiskLevel.HIGH
        elif risk_breakdown.get("medium", 0) > 0:
            overall_risk = RiskLevel.MEDIUM
        elif risk_breakdown.get("low", 0) > 0:
            overall_risk = RiskLevel.LOW
        else:
            overall_risk = RiskLevel.SAFE

        # Build context strings
        pkg_context = self._build_package_context(package_info)
        findings_context = self._build_findings_context(all_findings)
        dep_context = self._build_dependency_context(dep_info)

        extra_context = ""
        if network_summary:
            extra_context += f"\nNetwork behavior: {network_summary}"
        if health_score is not None:
            extra_context += f"\nHealth score: {health_score}/100"

        # Pass 1: Executive Summary
        exec_response = self._call_api(
            messages=[
                {"role": "system", "content": EXECUTIVE_SUMMARY_PROMPT},
                {"role": "user", "content": f"{pkg_context}\n\nRisk breakdown: {json.dumps(risk_breakdown)}\nTotal findings: {len(all_findings)}\n\n{findings_context}{extra_context}"},
            ],
            max_tokens=500,
        )
        executive_summary = exec_response or "Report generation failed."

        # Pass 2: Detailed Findings Narrative
        detailed_response = self._call_api(
            messages=[
                {"role": "system", "content": DETAILED_FINDINGS_PROMPT},
                {"role": "user", "content": f"{pkg_context}\n\nFindings:\n{findings_context}"},
            ],
            max_tokens=2000,
        )
        findings_narrative = detailed_response or "Detailed analysis unavailable."

        # Pass 3: Dependency Risk Assessment
        dep_response = self._call_api(
            messages=[
                {"role": "system", "content": DEPENDENCY_RISK_PROMPT},
                {"role": "user", "content": f"{pkg_context}\n\nDependency tree:\n{dep_context}\n\nFindings:\n{findings_context}"},
            ],
            max_tokens=1500,
        )
        dependency_risk = dep_response or "Dependency analysis unavailable."

        # Pass 4: Recommendations
        rec_response = self._call_api(
            messages=[
                {"role": "system", "content": RECOMMENDATIONS_PROMPT},
                {"role": "user", "content": f"{pkg_context}\n\nRisk level: {overall_risk.value}\nRisk breakdown: {json.dumps(risk_breakdown)}\n\nFindings:\n{findings_context}\n\nDependency risk:\n{dependency_risk}{extra_context}"},
            ],
            max_tokens=1500,
        )
        recommendations = rec_response or "Recommendations unavailable."

        return SecurityReport(
            package_name=package_info.name,
            version=package_info.latest_version,
            overall_risk=overall_risk,
            executive_summary=executive_summary,
            findings_narrative=findings_narrative,
            dependency_risk=dependency_risk,
            recommendations=recommendations,
            total_tokens=self.total_tokens,
            total_findings=len(all_findings),
            risk_breakdown=risk_breakdown,
        )
