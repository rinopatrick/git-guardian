"""Tests for the GitHub bot."""

import hashlib
import hmac

from git_guardian.github.bot import (
    extract_package_changes,
    format_github_comment,
    verify_webhook_signature,
)

# --- verify_webhook_signature tests ---


def test_verify_signature_valid() -> None:
    secret = "test-secret"
    payload = b'{"action":"opened"}'
    sig = "sha256=" + hmac.new(
        secret.encode(), payload, hashlib.sha256
    ).hexdigest()
    assert verify_webhook_signature(payload, sig, secret) is True


def test_verify_signature_invalid() -> None:
    payload = b'{"action":"opened"}'
    assert verify_webhook_signature(payload, "sha256=invalid", "secret") is False


def test_verify_signature_wrong_prefix() -> None:
    payload = b'{"action":"opened"}'
    assert verify_webhook_signature(payload, "sha1=abc", "secret") is False


# --- extract_package_changes tests ---


def test_extract_from_npm_install() -> None:
    packages = extract_package_changes(
        "npm install lodash express", "Update dependencies"
    )
    assert "lodash" in packages or "express" in packages


def test_extract_from_yarn_add() -> None:
    packages = extract_package_changes(
        "yarn add axios", "Add HTTP client"
    )
    assert "axios" in packages


def test_extract_from_version_specifier() -> None:
    packages = extract_package_changes(
        "Bumped lodash@4.17.21", "Update lodash"
    )
    assert "lodash" in packages


def test_extract_empty_body() -> None:
    packages = extract_package_changes("", "Fix typo in readme")
    assert packages == []


def test_extract_no_duplicates() -> None:
    packages = extract_package_changes(
        "npm install lodash\nnpm install lodash", "Add lodash"
    )
    assert len(packages) == len(set(packages))


# --- format_github_comment tests ---


def test_format_comment_all_safe() -> None:
    results = [
        {
            "package_name": "lodash",
            "version": "4.17.21",
            "risk_level": "safe",
            "findings_count": 0,
            "findings": [],
        }
    ]
    comment = format_github_comment(results)
    assert "\u2705" in comment
    assert "safe" in comment
    assert "Git Guardian" in comment


def test_format_comment_with_findings() -> None:
    results = [
        {
            "package_name": "bad-pkg",
            "version": "1.0.0",
            "risk_level": "high",
            "findings_count": 2,
            "findings": [
                {
                    "rule_id": "EXEC-001",
                    "title": "Child process execution",
                    "risk_level": "high",
                    "description": "Executes child processes",
                },
                {
                    "rule_id": "NET-001",
                    "title": "Suspicious HTTP request",
                    "risk_level": "medium",
                    "description": "Makes HTTP requests",
                },
            ],
        }
    ]
    comment = format_github_comment(results)
    assert "\U0001f534" in comment
    assert "HIGH" in comment
    assert "EXEC-001" in comment
    assert "Child process execution" in comment


def test_format_comment_with_error() -> None:
    results = [
        {
            "package_name": "missing-pkg",
            "error": "Package not found",
        }
    ]
    comment = format_github_comment(results)
    assert "Error:" in comment
    assert "Package not found" in comment


def test_format_comment_multiple_packages() -> None:
    results = [
        {
            "package_name": "safe-pkg",
            "version": "1.0.0",
            "risk_level": "safe",
            "findings_count": 0,
            "findings": [],
        },
        {
            "package_name": "bad-pkg",
            "version": "2.0.0",
            "risk_level": "critical",
            "findings_count": 1,
            "findings": [
                {
                    "rule_id": "MALWARE-001",
                    "title": "Reverse shell",
                    "risk_level": "critical",
                    "description": "Reverse shell pattern",
                }
            ],
        },
    ]
    comment = format_github_comment(results)
    assert "safe-pkg" in comment
    assert "bad-pkg" in comment
    assert "\U0001f6a8" in comment
