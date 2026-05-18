"""Version diff analyzer — compares two versions of a package to detect injection attacks."""

import json
import re
import urllib.request
from dataclasses import dataclass, field

from git_guardian.config import settings
from git_guardian.models.package import Finding, PackageInfo, RiskLevel


SYSTEM_PROMPT = """You are a security researcher comparing two versions of an npm package.
The goal is to detect if malicious code was injected between versions.

Analyze the differences and look for:
1. **New suspicious code** — eval, exec, spawn, fetch to unknown URLs, base64 decode
2. **Changed behavior** — existing functions modified to exfiltrate data
3. **New dependencies** — especially ones that handle network/filesystem
4. **Obfuscation additions** — encoded strings, minified code added to readable source
5. **Install script changes** — new or modified lifecycle hooks
6. **Environment variable harvesting** — new env var access
7. **Network callbacks** — new HTTP requests, WebSocket connections
8. **Credential access** — new file reads of sensitive paths (~/.ssh, .npmrc, etc.)

Respond in this JSON format:
{
    "risk_assessment": "safe|low|medium|high|critical",
    "is_suspicious": true/false,
    "confidence": 0.0-1.0,
    "changes": [
        {
            "file": "filename",
            "change_type": "added|modified|removed",
            "description": "What changed",
            "risk": "low|medium|high|critical",
            "malicious_indicator": true/false
        }
    ],
    "summary": "Overall assessment of version changes",
    "verdict": "safe-update|suspicious-changes|likely-malicious"
}"""


@dataclass
class VersionDiffResult:
    """Result of comparing two versions."""

    package_name: str
    old_version: str
    new_version: str
    files_added: list[str] = field(default_factory=list)
    files_removed: list[str] = field(default_factory=list)
    files_modified: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    summary: str = ""
    verdict: str = ""
    total_tokens: int = 0


class VersionDiffAnalyzer:
    """Compares two versions of a package using AI analysis."""

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
            "temperature": 0.1,
        }).encode()

        url = f"{self.base_url}/chat/completions"
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
        )

        try:
            resp = urllib.request.urlopen(req, timeout=60)
            result = json.loads(resp.read())
            content = result["choices"][0]["message"]["content"]
            usage = result.get("usage", {})
            self.total_tokens += usage.get("total_tokens", 0)
            return content
        except Exception as e:
            print(f"  AI API error: {e}")
            return None

    def _extract_json(self, content: str) -> dict | None:
        """Extract JSON from API response."""
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            pass
        match = re.search(r"```(?:json)?\s*(.*?)```", content, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                pass
        match = re.search(r"\{.*\}", content, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                pass
        return None

    def _compute_diff(
        self, old_files: dict[str, str], new_files: dict[str, str]
    ) -> tuple[list[str], list[str], list[str]]:
        """Compute file-level diff between two versions."""
        old_set = set(old_files.keys())
        new_set = set(new_files.keys())

        added = sorted(new_set - old_set)
        removed = sorted(old_set - new_set)

        # Modified: files that exist in both but content differs
        modified = []
        for path in sorted(old_set & new_set):
            if old_files[path] != new_files[path]:
                modified.append(path)

        return added, removed, modified

    def _build_diff_content(
        self,
        old_files: dict[str, str],
        new_files: dict[str, str],
        added: list[str],
        removed: list[str],
        modified: list[str],
        max_chars: int = 20000,
    ) -> str:
        """Build a text representation of the diff for AI analysis."""
        parts: list[str] = []
        total = 0

        # New files
        for path in added[:20]:
            content = new_files.get(path, "")[:3000]
            section = f"\n+++ NEW FILE: {path} +++\n{content}"
            if total + len(section) > max_chars:
                break
            parts.append(section)
            total += len(section)

        # Modified files
        for path in modified[:20]:
            old_content = old_files.get(path, "")[:1500]
            new_content = new_files.get(path, "")[:1500]
            section = f"\n~~~ MODIFIED: {path} ~~~\nOLD:\n{old_content}\nNEW:\n{new_content}"
            if total + len(section) > max_chars:
                break
            parts.append(section)
            total += len(section)

        # Removed files (just names)
        if removed:
            parts.append(f"\n--- REMOVED FILES ---\n" + "\n".join(removed[:50]))

        return "\n".join(parts)

    def compare_versions(
        self,
        package_name: str,
        old_version: str,
        old_files: dict[str, str],
        new_version: str,
        new_files: dict[str, str],
    ) -> VersionDiffResult:
        """Compare two versions of a package.

        Args:
            package_name: Package name
            old_version: Old version string
            old_files: Files from old version
            new_version: New version string
            new_files: Files from new version

        Returns:
            VersionDiffResult with findings
        """
        self.total_tokens = 0

        added, removed, modified = self._compute_diff(old_files, new_files)

        if not added and not removed and not modified:
            return VersionDiffResult(
                package_name=package_name,
                old_version=old_version,
                new_version=new_version,
                summary="No differences found between versions.",
                verdict="safe-update",
            )

        # Build diff content for AI
        diff_content = self._build_diff_content(
            old_files, new_files, added, removed, modified
        )

        context = f"""Package: {package_name}
Comparing: {old_version} -> {new_version}
Files added: {len(added)}
Files removed: {len(removed)}
Files modified: {len(modified)}
"""

        response = self._call_api(
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"{context}\n{diff_content}"},
            ],
            max_tokens=2000,
        )

        findings: list[Finding] = []
        summary = ""
        verdict = ""

        if response:
            result = self._extract_json(response)
            if result:
                risk_map = {
                    "low": RiskLevel.LOW,
                    "medium": RiskLevel.MEDIUM,
                    "high": RiskLevel.HIGH,
                    "critical": RiskLevel.CRITICAL,
                }

                for change in result.get("changes", []):
                    if change.get("malicious_indicator"):
                        findings.append(Finding(
                            rule_id="VERDIFF-001",
                            title=f"Suspicious change in {change.get('file', 'unknown')}",
                            description=change.get("description", "Suspicious modification detected"),
                            risk_level=risk_map.get(change.get("risk", "medium"), RiskLevel.MEDIUM),
                            file_path=change.get("file"),
                            recommendation="Review this change carefully before upgrading.",
                        ))

                summary = result.get("summary", "")
                verdict = result.get("verdict", "")

        return VersionDiffResult(
            package_name=package_name,
            old_version=old_version,
            new_version=new_version,
            files_added=added,
            files_removed=removed,
            files_modified=modified,
            findings=findings,
            summary=summary,
            verdict=verdict,
            total_tokens=self.total_tokens,
        )
