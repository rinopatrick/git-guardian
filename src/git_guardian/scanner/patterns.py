"""Pattern detection engine for malicious npm packages."""

import re
from dataclasses import dataclass

from git_guardian.models.package import Finding, RiskLevel

# Keywords that indicate dangerous function calls
_DANGEROUS_CALLS = [
    "eval",
    "Function",
]


@dataclass
class PatternRule:
    """A detection rule for malicious patterns."""

    rule_id: str
    title: str
    description: str
    risk_level: RiskLevel
    pattern: re.Pattern[str]
    recommendation: str = ""


def _build_patterns() -> list[PatternRule]:
    """Build all detection patterns."""
    patterns: list[PatternRule] = []

    # Obfuscation patterns
    patterns.append(PatternRule(
        rule_id="OBFUSC-001",
        title="Base64 encoded code execution",
        description="Code uses base64 decode followed by code execution, a common obfuscation technique.",
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"(?:atob|Buffer\.from)\s*\(", re.IGNORECASE),
        recommendation="Remove dynamic code execution and decode base64 content directly if needed.",
    ))
    patterns.append(PatternRule(
        rule_id="OBFUSC-002",
        title="Dynamic code execution via Function constructor",
        description="Code uses Function() constructor to execute dynamic code.",
        risk_level=RiskLevel.MEDIUM,
        pattern=re.compile(r"new\s+Function\s*\(", re.IGNORECASE),
        recommendation="Avoid dynamic code execution. Use static function definitions.",
    ))
    patterns.append(PatternRule(
        rule_id="OBFUSC-003",
        title="Hex encoded strings",
        description="Code contains hex-encoded strings that may hide malicious intent.",
        risk_level=RiskLevel.LOW,
        pattern=re.compile(r"\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){5,}", re.IGNORECASE),
        recommendation="Use readable string literals instead of hex encoding.",
    ))
    patterns.append(PatternRule(
        rule_id="OBFUSC-004",
        title="Unicode escape sequences",
        description="Code contains many unicode escape sequences, potentially hiding content.",
        risk_level=RiskLevel.LOW,
        pattern=re.compile(r"\\u[0-9a-f]{4}(?:\\u[0-9a-f]{4}){5,}", re.IGNORECASE),
        recommendation="Use readable string literals instead of unicode escapes.",
    ))

    # Environment variable harvesting
    patterns.append(PatternRule(
        rule_id="ENV-001",
        title="Environment variable access",
        description="Code accesses environment variables which may contain secrets.",
        risk_level=RiskLevel.MEDIUM,
        pattern=re.compile(
            r"process\.env\[|process\.env\.\w+|os\.environ|getenv\s*\(",
            re.IGNORECASE,
        ),
        recommendation="Minimize environment variable access. Document why each is needed.",
    ))
    patterns.append(PatternRule(
        rule_id="ENV-002",
        title="Bulk environment variable collection",
        description="Code collects all environment variables (process.env spread).",
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(
            r"\{\s*\.\.\.process\.env\s*\}|Object\.entries\s*\(\s*process\.env\s*\)"
        ),
        recommendation="Never spread or enumerate all env vars. Access specific vars only.",
    ))

    # Network exfiltration
    patterns.append(PatternRule(
        rule_id="NET-001",
        title="Suspicious HTTP request",
        description="Code makes HTTP requests to external servers.",
        risk_level=RiskLevel.MEDIUM,
        pattern=re.compile(
            r"(?:https?://|fetch\s*\(|axios\.|http\.get|https\.get|request\s*\(|XMLHttpRequest)",
            re.IGNORECASE,
        ),
        recommendation="Verify the destination URL is legitimate and expected.",
    ))
    patterns.append(PatternRule(
        rule_id="NET-002",
        title="WebSocket connection",
        description="Code opens WebSocket connections which can be used for C2 communication.",
        risk_level=RiskLevel.MEDIUM,
        pattern=re.compile(r"new\s+WebSocket\s*\(|ws://|wss://", re.IGNORECASE),
        recommendation="Verify WebSocket connections are to trusted endpoints.",
    ))
    patterns.append(PatternRule(
        rule_id="NET-003",
        title="DNS resolution",
        description="Code performs DNS lookups which can be used for data exfiltration.",
        risk_level=RiskLevel.LOW,
        pattern=re.compile(
            r"dns\.lookup|dns\.resolve|require\s*\(\s*['\"]dns['\"]", re.IGNORECASE
        ),
        recommendation="DNS lookups in packages are unusual. Verify necessity.",
    ))

    # File system access
    patterns.append(PatternRule(
        rule_id="FS-001",
        title="File system write",
        description="Code writes to the file system outside package scope.",
        risk_level=RiskLevel.MEDIUM,
        pattern=re.compile(
            r"fs\.write|fs\.appendFile|fs\.mkdir|fs\.copyFile|fs\.rename|fs\.unlink",
            re.IGNORECASE,
        ),
        recommendation="File system writes should be limited to documented use cases.",
    ))
    patterns.append(PatternRule(
        rule_id="FS-002",
        title="File system read outside package",
        description="Code reads files from outside the package directory.",
        risk_level=RiskLevel.MEDIUM,
        pattern=re.compile(
            r"fs\.readFile|fs\.readdir|fs\.readSync|require\s*\(\s*['\"]fs['\"]",
            re.IGNORECASE,
        ),
        recommendation="File reads should be limited to the package's own files.",
    ))

    # Crypto wallet theft
    patterns.append(PatternRule(
        rule_id="CRYPTO-001",
        title="Crypto wallet address pattern",
        description="Code contains cryptocurrency wallet addresses.",
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(
            r"(?:0x[0-9a-fA-F]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})",
        ),
        recommendation="Verify any crypto addresses are legitimate and documented.",
    ))
    patterns.append(PatternRule(
        rule_id="CRYPTO-002",
        title="Clipboard access",
        description="Code accesses the clipboard which can be used to swap crypto addresses.",
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(
            r"clipboard|navigator\.clipboard|pbcopy|pbpaste|xclip|xsel",
            re.IGNORECASE,
        ),
        recommendation="Clipboard access in packages is highly suspicious.",
    ))

    # Install script abuse
    patterns.append(PatternRule(
        rule_id="SCRIPT-001",
        title="Pre-install script",
        description="Package has a preinstall script that runs before installation.",
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r'"preinstall"\s*:'),
        recommendation="Preinstall scripts run automatically and can be malicious.",
    ))
    patterns.append(PatternRule(
        rule_id="SCRIPT-002",
        title="Post-install script",
        description="Package has a postinstall script that runs after installation.",
        risk_level=RiskLevel.MEDIUM,
        pattern=re.compile(r'"postinstall"\s*:'),
        recommendation="Postinstall scripts should be reviewed for safety.",
    ))
    patterns.append(PatternRule(
        rule_id="SCRIPT-003",
        title="Install script",
        description="Package has an install script.",
        risk_level=RiskLevel.MEDIUM,
        pattern=re.compile(r'"install"\s*:'),
        recommendation="Install scripts should be reviewed for safety.",
    ))

    # Process execution
    patterns.append(PatternRule(
        rule_id="EXEC-001",
        title="Child process execution",
        description="Code executes child processes which can run arbitrary commands.",
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(
            r"child_process|exec\s*\(|execSync|spawn\s*\(|spawnSync|execFile",
            re.IGNORECASE,
        ),
        recommendation="Child process execution is dangerous. Verify necessity.",
    ))
    patterns.append(PatternRule(
        rule_id="EXEC-002",
        title="Shell command execution",
        description="Code executes shell commands.",
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(
            r"shell\.exec|shelljs|\.exec\s*\(\s*['\"]",
            re.IGNORECASE,
        ),
        recommendation="Shell execution is dangerous. Verify necessity.",
    ))

    # Known malicious patterns
    patterns.append(PatternRule(
        rule_id="MALWARE-001",
        title="Reverse shell pattern",
        description="Code contains patterns resembling reverse shell connections.",
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(
            r"(?:nc\s+-[el]|netcat|/bin/sh|/bin/bash|mkfifo|telnet)",
            re.IGNORECASE,
        ),
        recommendation="This is likely malicious. Do not use this package.",
    ))
    patterns.append(PatternRule(
        rule_id="MALWARE-002",
        title="Cryptocurrency miner",
        description="Code contains patterns resembling cryptocurrency mining.",
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(
            r"(?:stratum\+tcp|coinhive|cryptonight|hashrate|miner)",
            re.IGNORECASE,
        ),
        recommendation="This is likely a crypto miner. Do not use this package.",
    ))

    return patterns


# Compiled patterns
_PATTERNS = _build_patterns()


class PatternDetector:
    """Detects malicious patterns in code."""

    def scan_file(self, filepath: str, content: str) -> list[Finding]:
        """Scan a single file for malicious patterns.

        Args:
            filepath: Path to the file (for reporting)
            content: File content to scan

        Returns:
            List of findings
        """
        findings: list[Finding] = []

        for rule in _PATTERNS:
            matches = list(rule.pattern.finditer(content))
            if not matches:
                continue

            # Find line number for first match
            first_match = matches[0]
            line_number = content[: first_match.start()].count("\n") + 1

            # Get code snippet around the match
            lines = content.split("\n")
            start_line = max(0, line_number - 2)
            end_line = min(len(lines), line_number + 2)
            snippet = "\n".join(lines[start_line:end_line])

            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    title=rule.title,
                    description=rule.description,
                    risk_level=rule.risk_level,
                    file_path=filepath,
                    line_number=line_number,
                    code_snippet=snippet,
                    recommendation=rule.recommendation,
                )
            )

        return findings

    def scan_package(self, files: dict[str, str]) -> list[Finding]:
        """Scan all files in a package.

        Args:
            files: Dict mapping file paths to contents

        Returns:
            List of all findings
        """
        all_findings: list[Finding] = []

        for filepath, content in files.items():
            findings = self.scan_file(filepath, content)
            all_findings.extend(findings)

        # Deduplicate findings by rule_id + file_path
        seen: set[tuple[str, str]] = set()
        unique_findings: list[Finding] = []
        for finding in all_findings:
            key = (finding.rule_id, finding.file_path or "")
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)

        return unique_findings

    def get_rules(self) -> list[PatternRule]:
        """Get all detection rules."""
        return _PATTERNS.copy()
