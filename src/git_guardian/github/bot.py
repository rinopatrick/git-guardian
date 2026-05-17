"""GitHub bot for scanning packages in PRs and issues."""

import hashlib
import hmac
import json
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from git_guardian.config import settings
from git_guardian.scanner.npm import NpmRegistryClient
from git_guardian.scanner.patterns import PatternDetector
from git_guardian.scanner.typosquat import TyposquatDetector

router = APIRouter(prefix="/github", tags=["github"])


class WebhookPayload(BaseModel):
    """GitHub webhook payload."""

    action: str
    pull_request: dict[str, Any] | None = None
    issue: dict[str, Any] | None = None
    repository: dict[str, Any] | None = None


def verify_webhook_signature(payload: bytes, signature: str, secret: str) -> bool:
    """Verify GitHub webhook signature."""
    if not signature.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(
        secret.encode(), payload, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def extract_package_changes(pr_body: str, pr_title: str) -> list[str]:
    """Extract package names from PR description or title."""
    packages = []

    # Common patterns for package additions
    import re

    # Match npm package names in text
    patterns = [
        r"(?:add|install|upgrade|update|bump)\s+(?:@[\w-]+/[\w-]+|[\w-]+)",
        r"(?:@[\w-]+/[\w-]+|[\w-]+)@[\d.]+",
        r"npm\s+(?:install|add)\s+(.+?)(?:\s|$)",
        r"yarn\s+add\s+(.+?)(?:\s|$)",
    ]

    text = f"{pr_title} {pr_body}"
    for pattern in patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        for match in matches:
            # Clean up package name
            pkg = match.strip().split("@")[0].strip()
            if pkg and not pkg.startswith("-"):
                packages.append(pkg)

    return list(set(packages))


async def scan_package_for_comment(package_name: str) -> dict[str, Any]:
    """Scan a package and return results for GitHub comment."""
    npm = NpmRegistryClient()
    detector = PatternDetector()
    typosquat = TyposquatDetector(npm.get_popular_packages())

    try:
        # Get package info
        pkg = npm.get_package(package_name)

        # Get files
        files = npm.get_package_files(package_name)

        # Pattern detection
        findings = detector.scan_package(files)

        # Typosquat check
        typosquat_findings = typosquat.scan_package_name(package_name)
        findings.extend(typosquat_findings)

        # Determine risk level
        if not findings:
            risk_level = "safe"
        else:
            risk_order = ["critical", "high", "medium", "low", "safe"]
            risk_level = "safe"
            for level in risk_order:
                if any(f.risk_level.value == level for f in findings):
                    risk_level = level
                    break

        return {
            "package_name": package_name,
            "version": pkg.latest_version,
            "risk_level": risk_level,
            "findings_count": len(findings),
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "risk_level": f.risk_level.value,
                    "description": f.description[:200],
                }
                for f in findings[:10]  # Limit to top 10
            ],
        }

    except Exception as e:
        return {
            "package_name": package_name,
            "error": str(e),
        }
    finally:
        npm.close()


def format_github_comment(results: list[dict[str, Any]]) -> str:
    """Format scan results as GitHub comment markdown."""
    comment = "## Git Guardian Security Scan\n\n"

    has_issues = False
    for result in results:
        if "error" in result:
            comment += f"### {result['package_name']}\n"
            comment += f"Error: {result['error']}\n\n"
            continue

        pkg = result["package_name"]
        version = result["version"]
        risk = result["risk_level"]
        count = result["findings_count"]

        # Risk emoji
        risk_emoji = {
            "safe": "✅",
            "low": "ℹ️",
            "medium": "⚠️",
            "high": "🔴",
            "critical": "🚨",
        }.get(risk, "❓")

        comment += f"### {risk_emoji} {pkg}@{version}\n"
        comment += f"**Risk Level:** {risk.upper()} | **Findings:** {count}\n\n"

        if count > 0:
            has_issues = True
            comment += "| Rule | Risk | Title |\n"
            comment += "|------|------|-------|\n"
            for finding in result["findings"]:
                comment += f"| {finding['rule_id']} | {finding['risk_level'].upper()} | {finding['title']} |\n"
            comment += "\n"

    if not has_issues:
        comment += "All scanned packages appear to be safe! ✅\n"

    comment += "\n---\n*Powered by [Git Guardian](https://github.com/rinopantrick/git-guardian)*"
    return comment


@router.post("/webhook")
async def github_webhook(request: Request) -> dict[str, str]:
    """Handle GitHub webhook events."""
    # Get signature
    signature = request.headers.get("X-Hub-Signature-256", "")
    if not signature:
        raise HTTPException(status_code=401, detail="Missing signature")

    # Get payload
    payload = await request.body()

    # Verify signature (skip if no secret configured)
    webhook_secret = settings.github_webhook_secret
    if webhook_secret and not verify_webhook_signature(payload, signature, webhook_secret):
        raise HTTPException(status_code=401, detail="Invalid signature")

    # Parse event
    event = request.headers.get("X-GitHub-Event", "")
    data = json.loads(payload)

    # Handle PR events
    if event == "pull_request":
        action = data.get("action", "")
        if action in ["opened", "synchronize", "reopened"]:
            pr = data.get("pull_request", {})
            title = pr.get("title", "")
            body = pr.get("body", "")

            # Extract packages from PR
            packages = extract_package_changes(body, title)

            if packages:
                # Scan packages
                results = []
                for pkg in packages[:5]:  # Limit to 5 packages
                    result = await scan_package_for_comment(pkg)
                    results.append(result)

                # Format comment
                comment = format_github_comment(results)

                # TODO: Post comment to PR using GitHub API
                # This requires GitHub App installation token
                return {"status": "scanned", "packages": len(packages)}

    # Handle issue events
    elif event == "issues":
        action = data.get("action", "")
        if action == "opened":
            issue = data.get("issue", {})
            title = issue.get("title", "")
            body = issue.get("body", "")

            # Extract packages from issue
            packages = extract_package_changes(body, title)

            if packages:
                # Scan packages
                results = []
                for pkg in packages[:5]:
                    result = await scan_package_for_comment(pkg)
                    results.append(result)

                # Format comment
                comment = format_github_comment(results)

                # TODO: Post comment to issue using GitHub API
                return {"status": "scanned", "packages": len(packages)}

    return {"status": "ignored", "event": event}


@router.post("/scan-pr")
async def scan_pr_packages(packages: list[str]) -> dict[str, Any]:
    """API endpoint to scan packages from a PR."""
    results = []
    for pkg in packages[:10]:  # Limit to 10
        result = await scan_package_for_comment(pkg)
        results.append(result)

    comment = format_github_comment(results)

    return {
        "results": results,
        "comment": comment,
    }
