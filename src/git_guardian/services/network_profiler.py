"""Network behavior profiler — maps all outbound connections a package makes."""

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from git_guardian.models.package import Finding, RiskLevel


# Known telemetry/analytics domains
TELEMETRY_DOMAINS = {
    "google-analytics.com", "googletagmanager.com", "analytics.google.com",
    "segment.io", "segment.com", "cdn.segment.com",
    "mixpanel.com", "api.mixpanel.com",
    "amplitude.com", "api.amplitude.com",
    "hotjar.com", "script.hotjar.com",
    "sentry.io", "sentry.com",
    "bugsnag.com",
    "newrelic.com", "nr-data.net",
    "datadoghq.com", "browser-intake-datadoghq.com",
    "intercom.io", "widget.intercom.io",
    "fullstory.com",
    "heap.io",
    "pendo.io",
    "hubspot.com",
}

# Known suspicious TLDs
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",  # Freenom TLDs (often used for malware)
    ".xyz", ".top", ".club", ".work", ".buzz",
}

# Known suspicious URL patterns
SUSPICIOUS_URL_PATTERNS = [
    (r"\.onion/", "Tor hidden service reference"),
    (r"pastebin\.com", "Pastebin reference (data exfiltration)"),
    (r"ngrok\.io", "Ngrok tunnel (reverse proxy)"),
    (r"localtunnel", "LocalTunnel (reverse proxy)"),
    (r"serveo\.net", "Serveo tunnel (reverse proxy)"),
    (r"webhook\.site", "Webhook.site (data exfiltration)"),
    (r"requestbin", "RequestBin (data exfiltration)"),
    (r"pipedream", "Pipedream webhook"),
    (r"discord\.com/api/webhooks", "Discord webhook"),
    (r"hooks\.slack\.com", "Slack webhook"),
    (r"api\.telegram\.org", "Telegram API (C2 channel)"),
]


@dataclass
class NetworkEndpoint:
    """A network endpoint found in code."""

    url: str
    domain: str
    protocol: str
    category: str  # legitimate, telemetry, suspicious, unknown
    description: str = ""
    file_path: str = ""
    risk_level: RiskLevel = RiskLevel.LOW


@dataclass
class NetworkReport:
    """Network behavior report for a package."""

    package_name: str
    endpoints: list[NetworkEndpoint] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    domains: set[str] = field(default_factory=set)
    has_telemetry: bool = False
    has_suspicious: bool = False

    @property
    def endpoint_count(self) -> int:
        return len(self.endpoints)


# URL extraction patterns
URL_PATTERNS = [
    # HTTP/HTTPS URLs
    re.compile(r"""(?:https?://|ftp://)([^\s<>'")\]]+)""", re.IGNORECASE),
    # fetch() calls
    re.compile(r"""fetch\s*\(\s*['"`]([^'"`]+)['"`]""", re.IGNORECASE),
    # axios/request calls
    re.compile(r"""(?:axios|request|got|node-fetch|superagent)\s*(?:\.\w+)?\s*\(\s*['"`]([^'"`]+)['"`]""", re.IGNORECASE),
    # http.get/https.get
    re.compile(r"""(?:http|https)\.get\s*\(\s*['"`]([^'"`]+)['"`]""", re.IGNORECASE),
    # WebSocket
    re.compile(r"""new\s+WebSocket\s*\(\s*['"`]([^'"`]+)['"`]""", re.IGNORECASE),
    # XMLHttpRequest
    re.compile(r"""\.open\s*\(\s*['"`]\w+['"`]\s*,\s*['"`]([^'"`]+)['"`]""", re.IGNORECASE),
    # DNS
    re.compile(r"""dns\.(?:lookup|resolve)\s*\(\s*['"`]([^'"`]+)['"`]""", re.IGNORECASE),
]


def _extract_domain(url: str) -> str:
    """Extract domain from a URL."""
    try:
        parsed = urlparse(url)
        return parsed.hostname or url
    except Exception:
        return url


def _classify_endpoint(domain: str, url: str) -> tuple[str, RiskLevel]:
    """Classify an endpoint by its domain."""
    domain_lower = domain.lower()

    # Check known telemetry
    for telem in TELEMETRY_DOMAINS:
        if telem in domain_lower:
            return "telemetry", RiskLevel.LOW

    # Check suspicious patterns
    for pattern, desc in SUSPICIOUS_URL_PATTERNS:
        if re.search(pattern, url, re.IGNORECASE):
            return "suspicious", RiskLevel.HIGH

    # Check suspicious TLDs
    for tld in SUSPICIOUS_TLDS:
        if domain_lower.endswith(tld):
            return "suspicious", RiskLevel.MEDIUM

    # Localhost/loopback
    if domain_lower in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):
        return "local", RiskLevel.LOW

    return "unknown", RiskLevel.LOW


class NetworkProfiler:
    """Profiles network behavior of npm packages."""

    def profile_package(
        self,
        package_name: str,
        files: dict[str, str],
    ) -> NetworkReport:
        """Analyze all files for network endpoints.

        Args:
            package_name: Package name
            files: Dict of file_path -> content

        Returns:
            NetworkReport with endpoints and findings
        """
        endpoints: list[NetworkEndpoint] = []
        domains: set[str] = set()
        findings: list[Finding] = []

        for filepath, content in files.items():
            # Skip non-JS files
            if not any(filepath.endswith(ext) for ext in (".js", ".ts", ".mjs", ".cjs", ".json", ".sh")):
                continue

            for pattern in URL_PATTERNS:
                for match in pattern.finditer(content):
                    url = match.group(1) if match.lastindex else match.group(0)
                    # Clean up URL
                    url = url.rstrip(",;)")
                    domain = _extract_domain(url)
                    category, risk = _classify_endpoint(domain, url)

                    # Get protocol
                    protocol = "https"
                    if url.startswith("http://"):
                        protocol = "http"
                    elif url.startswith("ws://") or url.startswith("wss://"):
                        protocol = "ws"

                    endpoints.append(NetworkEndpoint(
                        url=url,
                        domain=domain,
                        protocol=protocol,
                        category=category,
                        file_path=filepath,
                        risk_level=risk,
                    ))
                    domains.add(domain)

        # Generate findings
        telemetry_eps = [e for e in endpoints if e.category == "telemetry"]
        suspicious_eps = [e for e in endpoints if e.category == "suspicious"]

        if telemetry_eps:
            findings.append(Finding(
                rule_id="NET-PROFILE-001",
                title="Telemetry/analytics detected",
                description=f"Package sends data to {len(telemetry_eps)} telemetry endpoint(s): {', '.join(set(e.domain for e in telemetry_eps)[:5])}",
                risk_level=RiskLevel.LOW,
                recommendation="Review what data is being collected and if it's disclosed.",
            ))

        if suspicious_eps:
            for ep in suspicious_eps:
                findings.append(Finding(
                    rule_id="NET-PROFILE-002",
                    title=f"Suspicious endpoint: {ep.domain}",
                    description=f"Package connects to suspicious endpoint: {ep.url}",
                    risk_level=ep.risk_level,
                    file_path=ep.file_path,
                    recommendation="Investigate why this package connects to this endpoint.",
                ))

        # Count unique domains
        http_domains = {e.domain for e in endpoints if e.protocol in ("http", "https")}
        if len(http_domains) > 10:
            findings.append(Finding(
                rule_id="NET-PROFILE-003",
                title="Many outbound connections",
                description=f"Package connects to {len(http_domains)} different domains.",
                risk_level=RiskLevel.MEDIUM,
                recommendation="Many outbound connections increase the attack surface.",
            ))

        return NetworkReport(
            package_name=package_name,
            endpoints=endpoints,
            findings=findings,
            domains=domains,
            has_telemetry=bool(telemetry_eps),
            has_suspicious=bool(suspicious_eps),
        )
