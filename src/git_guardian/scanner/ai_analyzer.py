"""AI-powered code analysis using mimo-v2.5-pro."""

import json
import urllib.request

from git_guardian.config import settings
from git_guardian.models.package import Finding, PackageInfo, RiskLevel

SYSTEM_PROMPT = """You are a security expert analyzing npm packages for malicious code.

Analyze the provided code and determine if it's malicious or benign. Look for:
1. Data exfiltration (sending env vars, tokens, or user data to external servers)
2. Obfuscation techniques (hiding malicious intent)
3. Supply chain attack patterns
4. Backdoors or reverse shells
5. Cryptocurrency miners
6. Credential theft

Respond in this JSON format:
{
    "risk_level": "safe|low|medium|high|critical",
    "is_malicious": true/false,
    "confidence": 0.0-1.0,
    "findings": [
        {
            "title": "Short description",
            "description": "Detailed explanation",
            "evidence": "Specific code that's suspicious"
        }
    ],
    "summary": "Overall assessment in 1-2 sentences"
}

Be thorough but avoid false positives. Only flag truly suspicious patterns."""


class AICodeAnalyzer:
    """Analyzes code using AI (mimo-v2.5-pro)."""

    def __init__(self, enabled: bool | None = None) -> None:
        """Initialize AI analyzer.

        Args:
            enabled: Whether AI analysis is enabled (defaults to settings)
        """
        self.enabled = enabled if enabled is not None else settings.ai_enabled
        self.base_url = settings.ai_base_url
        self.model = settings.ai_model

    def _call_api(self, messages: list[dict], max_tokens: int = 1000) -> str | None:
        """Call MiMo API using urllib (avoids requests gzip issue)."""
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

        resp = urllib.request.urlopen(req, timeout=30)
        result = json.loads(resp.read())
        return result["choices"][0]["message"]["content"]

    def analyze_code(
        self,
        code: str,
        filename: str,
        context: str = "",
    ) -> Finding | None:
        """Analyze a code snippet for malicious intent.

        Args:
            code: Code content to analyze
            filename: Name of the file
            context: Additional context (e.g., package description)

        Returns:
            Finding if suspicious, None if safe
        """
        if not self.enabled:
            return None

        # Truncate code to fit context window
        max_code_length = 8000
        if len(code) > max_code_length:
            code = code[:max_code_length] + "\n... (truncated)"

        user_message = f"""Analyze this npm package code for security issues.

File: {filename}
{f"Context: {context}" if context else ""}

```javascript
{code}
```"""

        try:
            content = self._call_api(
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_message},
                ],
                max_tokens=1000,
            )

            if not content:
                return None

            # Parse JSON response
            try:
                result = json.loads(content)
            except json.JSONDecodeError:
                # Try to extract JSON from markdown code block
                import re

                json_match = re.search(r"```(?:json)?\s*(.*?)```", content, re.DOTALL)
                if json_match:
                    result = json.loads(json_match.group(1))
                else:
                    return None

            # Check if malicious
            is_malicious = result.get("is_malicious", False)
            confidence = result.get("confidence", 0.0)
            risk_level_str = result.get("risk_level", "safe")

            if not is_malicious or confidence < 0.5:
                return None

            # Map risk level
            risk_map = {
                "safe": RiskLevel.SAFE,
                "low": RiskLevel.LOW,
                "medium": RiskLevel.MEDIUM,
                "high": RiskLevel.HIGH,
                "critical": RiskLevel.CRITICAL,
            }
            risk_level = risk_map.get(risk_level_str, RiskLevel.MEDIUM)

            # Build finding from AI response
            findings = result.get("findings", [])
            summary = result.get("summary", "AI detected suspicious patterns")

            if findings:
                first_finding = findings[0]
                return Finding(
                    rule_id="AI-ANALYSIS",
                    title=first_finding.get("title", "Suspicious code detected"),
                    description=first_finding.get("description", summary),
                    risk_level=risk_level,
                    file_path=filename,
                    line_number=None,
                    code_snippet=first_finding.get("evidence", ""),
                    recommendation="Review this code carefully. AI analysis indicates potential malicious intent.",
                )
            else:
                return Finding(
                    rule_id="AI-ANALYSIS",
                    title="Suspicious code detected by AI",
                    description=summary,
                    risk_level=risk_level,
                    file_path=filename,
                    line_number=None,
                    code_snippet=None,
                    recommendation="Review this code carefully. AI analysis indicates potential malicious intent.",
                )

        except Exception as e:
            # Don't fail the scan if AI analysis fails
            print(f"AI analysis failed: {e}")
            return None

    def analyze_package(
        self,
        package_info: PackageInfo,
        files: dict[str, str],
        existing_findings: list[Finding],
    ) -> Finding | None:
        """Analyze an entire package using AI.

        Args:
            package_info: Package metadata
            files: Dict of file contents
            existing_findings: Findings from pattern detection

        Returns:
            Overall AI finding or None
        """
        if not self.enabled or not self.client:
            return None

        # Build context about the package
        context = f"Package: {package_info.name}\n"
        context += f"Description: {package_info.description or 'N/A'}\n"
        context += f"Author: {package_info.author.name if package_info.author else 'N/A'}\n"
        context += f"License: {package_info.license or 'N/A'}\n"

        if existing_findings:
            context += "\nExisting findings from pattern detection:\n"
            for finding in existing_findings[:5]:  # Limit to 5 findings
                context += f"- {finding.rule_id}: {finding.title}\n"

        # Analyze the most suspicious files
        # Priority: files with existing findings, then install scripts, then main files
        suspicious_files: list[str] = []

        # Files with existing findings
        flagged_paths = {f.file_path for f in existing_findings if f.file_path}
        suspicious_files.extend(flagged_paths)

        # Install scripts
        for path in files:
            if "install" in path.lower() or "postinstall" in path.lower():
                if path not in suspicious_files:
                    suspicious_files.append(path)

        # Main entry point
        for path in ["index.js", "main.js", "src/index.js", "lib/index.js"]:
            if path in files and path not in suspicious_files:
                suspicious_files.append(path)

        # Analyze top suspicious files
        for filepath in suspicious_files[:3]:
            if filepath in files:
                finding = self.analyze_code(
                    code=files[filepath],
                    filename=filepath,
                    context=context,
                )
                if finding:
                    return finding

        return None
