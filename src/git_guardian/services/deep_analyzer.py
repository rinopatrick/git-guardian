"""Deep AI analyzer — analyzes ALL files in a package for maximum token consumption."""

import json
import re
import urllib.request
from dataclasses import dataclass, field

from git_guardian.config import settings
from git_guardian.models.package import Finding, PackageInfo, RiskLevel


SYSTEM_PROMPT = """You are a senior security researcher performing a deep audit of an npm package.
Analyze the provided code files thoroughly for:

1. **Supply chain attack vectors** — install scripts, build hooks, lifecycle abuse
2. **Data exfiltration** — env vars, tokens, SSH keys, .npmrc, browser data sent externally
3. **Obfuscation** — encoded strings, eval chains, dynamic imports hiding intent
4. **Backdoors** — reverse shells, C2 callbacks, hidden admin endpoints
5. **Credential theft** — keychain access, browser credential scraping, clipboard hijacking
6. **Crypto theft** — wallet address swapping, clipboard replacement, mining
7. **Typosquatting indicators** — intentional name confusion, misleading descriptions
8. **Dependency confusion** — references to private registries, internal package names

Respond in this JSON format:
{
    "risk_level": "safe|low|medium|high|critical",
    "is_malicious": true/false,
    "confidence": 0.0-1.0,
    "findings": [
        {
            "title": "Short description",
            "description": "Detailed explanation with specific code references",
            "file": "filename where issue was found",
            "severity": "low|medium|high|critical",
            "category": "exfiltration|obfuscation|backdoor|credential-theft|crypto|install-script|dependency-confusion"
        }
    ],
    "summary": "Overall assessment in 2-3 sentences",
    "attack_vector": "How this package could be exploited (if malicious)",
    "recommended_action": "safe-to-use|audit-required|avoid"
}

Be thorough. Analyze every file for hidden patterns. Cross-reference between files for multi-stage attacks."""


@dataclass
class DeepAnalysisResult:
    """Result of deep AI analysis of a package."""

    package_name: str
    files_analyzed: int
    total_tokens: int
    findings: list[Finding] = field(default_factory=list)
    summary: str = ""
    attack_vector: str = ""
    recommended_action: str = ""
    risk_level: RiskLevel = RiskLevel.SAFE


class DeepAnalyzer:
    """Analyzes ALL files in a package using AI for maximum token consumption."""

    def __init__(self) -> None:
        self.base_url = settings.ai_base_url
        self.model = settings.ai_model
        self.max_code_per_file = 6000  # chars per file
        self.max_files_per_batch = 10  # files per API call
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
            # Track tokens
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

        # Try markdown code block
        match = re.search(r"```(?:json)?\s*(.*?)```", content, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                pass

        # Try to find JSON object in text
        match = re.search(r"\{.*\}", content, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                pass

        return None

    def _filter_files(self, files: dict[str, str]) -> dict[str, str]:
        """Filter files to analyze — skip binary, images, and test files."""
        skip_extensions = {
            ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
            ".woff", ".woff2", ".ttf", ".eot",
            ".map", ".min.js", ".min.css",
            ".lock", ".yml", ".yaml", ".toml",
        }

        skip_patterns = [
            r"node_modules/",
            r"\.git/",
            r"test/",
            r"tests/",
            r"__tests__/",
            r"\.spec\.",
            r"\.test\.",
            r"CHANGELOG",
            r"LICENSE",
            r"README",
        ]

        filtered: dict[str, str] = {}
        for path, content in files.items():
            # Skip by extension
            if any(path.lower().endswith(ext) for ext in skip_extensions):
                continue

            # Skip by pattern
            if any(re.search(pat, path, re.IGNORECASE) for pat in skip_patterns):
                continue

            # Skip empty or tiny files
            if len(content.strip()) < 50:
                continue

            filtered[path] = content

        return filtered

    def _batch_files(self, files: dict[str, str]) -> list[list[tuple[str, str]]]:
        """Split files into batches for API calls."""
        batches: list[list[tuple[str, str]]] = []
        current_batch: list[tuple[str, str]] = []
        current_size = 0

        for path, content in files.items():
            truncated = content[:self.max_code_per_file]
            file_size = len(truncated)

            if len(current_batch) >= self.max_files_per_batch or \
               current_size + file_size > 30000:
                if current_batch:
                    batches.append(current_batch)
                current_batch = [(path, truncated)]
                current_size = file_size
            else:
                current_batch.append((path, truncated))
                current_size += file_size

        if current_batch:
            batches.append(current_batch)

        return batches

    def analyze_package(
        self,
        package_info: PackageInfo,
        files: dict[str, str],
    ) -> DeepAnalysisResult:
        """Deep analyze ALL files in a package.

        This burns significant tokens by analyzing every file, not just suspicious ones.

        Args:
            package_info: Package metadata
            files: Dict of file_path -> content

        Returns:
            DeepAnalysisResult with findings
        """
        self.total_tokens = 0

        # Filter and batch files
        filtered = self._filter_files(files)
        batches = self._batch_files(filtered)

        all_findings: list[Finding] = []
        summaries: list[str] = []
        attack_vectors: list[str] = []
        recommended_actions: list[str] = []

        context = f"""Package: {package_info.name}
Version: {package_info.latest_version}
Description: {package_info.description or 'N/A'}
Author: {package_info.author.name if package_info.author else 'N/A'}
License: {package_info.license or 'N/A'}
Total files: {len(files)} (analyzing {len(filtered)})
"""

        for batch_idx, batch in enumerate(batches):
            # Build the code block
            code_block = ""
            for path, content in batch:
                code_block += f"\n--- FILE: {path} ---\n{content}\n"

            user_message = f"""{context}
Batch {batch_idx + 1}/{len(batches)} — analyzing {len(batch)} files:

{code_block}"""

            response = self._call_api(
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_message},
                ],
                max_tokens=2000,
            )

            if not response:
                continue

            result = self._extract_json(response)
            if not result:
                continue

            # Extract findings
            for f in result.get("findings", []):
                sev = f.get("severity", "medium")
                risk_map = {
                    "low": RiskLevel.LOW,
                    "medium": RiskLevel.MEDIUM,
                    "high": RiskLevel.HIGH,
                    "critical": RiskLevel.CRITICAL,
                }
                all_findings.append(Finding(
                    rule_id="DEEP-AI",
                    title=f.get("title", "Deep analysis finding"),
                    description=f.get("description", ""),
                    risk_level=risk_map.get(sev, RiskLevel.MEDIUM),
                    file_path=f.get("file"),
                    recommendation=f.get("category", ""),
                ))

            if result.get("summary"):
                summaries.append(result["summary"])
            if result.get("attack_vector"):
                attack_vectors.append(result["attack_vector"])
            if result.get("recommended_action"):
                recommended_actions.append(result["recommended_action"])

        # Determine overall risk
        if all_findings:
            max_risk = max(
                all_findings,
                key=lambda f: ["safe", "low", "medium", "high", "critical"].index(f.risk_level.value)
            )
            risk_level = max_risk.risk_level
        else:
            risk_level = RiskLevel.SAFE

        return DeepAnalysisResult(
            package_name=package_info.name,
            files_analyzed=len(filtered),
            total_tokens=self.total_tokens,
            findings=all_findings,
            summary=" | ".join(summaries),
            attack_vector=" | ".join(attack_vectors),
            recommended_action=recommended_actions[-1] if recommended_actions else "safe-to-use",
            risk_level=risk_level,
        )
