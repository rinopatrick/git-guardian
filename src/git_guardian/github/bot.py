"""GitHub bot for scanning packages in PRs and issues."""

import hashlib
import hmac
import json
import time
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from git_guardian.config import settings
from git_guardian.scanner.service import ScanService

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

    import re

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
            pkg = match.strip().split("@")[0].strip()
            if pkg and not pkg.startswith("-"):
                packages.append(pkg)

    return list(set(packages))


def scan_package_for_comment(package_name: str) -> dict[str, Any]:
    """Scan a package and return results for GitHub comment."""
    try:
        with ScanService() as service:
            result = service.scan_package(package_name)

        return {
            "package_name": package_name,
            "version": result.package.latest_version,
            "risk_level": result.risk_level.value,
            "findings_count": len(result.findings),
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "risk_level": f.risk_level.value,
                    "description": f.description[:200],
                }
                for f in result.findings[:10]
            ],
        }
    except Exception as e:
        return {
            "package_name": package_name,
            "error": str(e),
        }


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
                fid = finding['rule_id']
                frisk = finding['risk_level'].upper()
                ftitle = finding['title']
                comment += f"| {fid} | {frisk} | {ftitle} |\n"
            comment += "\n"

    if not has_issues:
        comment += "All scanned packages appear to be safe! ✅\n"

    comment += "\n---\n*Powered by [Git Guardian](https://github.com/rinopantrick/git-guardian)*"
    return comment


def get_installation_token(installation_id: int) -> str | None:
    """Get GitHub App installation access token.

    Creates a JWT from the app's private key, then exchanges it for
    an installation-scoped access token.
    """
    if not settings.github_app_id or not settings.github_private_key:
        return None

    try:
        import jwt as pyjwt

        now = int(time.time())
        payload = {
            "iat": now - 60,
            "exp": now + 600,
            "iss": settings.github_app_id,
        }
        token = pyjwt.encode(payload, settings.github_private_key, algorithm="RS256")

        resp = httpx.post(
            f"https://api.github.com/app/installations/{installation_id}/access_tokens",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=10.0,
        )
        resp.raise_for_status()
        return resp.json().get("token")
    except Exception:
        return None


def post_github_comment(
    repo_full_name: str,
    issue_number: int,
    comment_body: str,
    installation_id: int | None = None,
) -> bool:
    """Post a comment to a GitHub PR or issue.

    Args:
        repo_full_name: e.g. "owner/repo"
        issue_number: PR or issue number
        comment_body: Markdown comment body
        installation_id: GitHub App installation ID (from webhook payload)

    Returns:
        True if comment was posted successfully
    """
    # Try GitHub App token first
    token = None
    if installation_id:
        token = get_installation_token(installation_id)

    # Fall back to configured token
    if not token:
        return False

    try:
        resp = httpx.post(
            f"https://api.github.com/repos/{repo_full_name}/issues/{issue_number}/comments",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            json={"body": comment_body},
            timeout=10.0,
        )
        resp.raise_for_status()
        return True
    except Exception:
        return False


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

    # Extract repo info and installation ID
    repo = data.get("repository", {})
    repo_full_name = repo.get("full_name", "")
    installation_id = data.get("installation", {}).get("id")

    # Handle PR events
    if event == "pull_request":
        action = data.get("action", "")
        if action in ["opened", "synchronize", "reopened"]:
            pr = data.get("pull_request", {})
            title = pr.get("title", "")
            body = pr.get("body", "")
            pr_number = pr.get("number")

            packages = extract_package_changes(body, title)

            if packages:
                results = []
                for pkg in packages[:5]:
                    result = scan_package_for_comment(pkg)
                    results.append(result)

                comment = format_github_comment(results)

                if repo_full_name and pr_number:
                    post_github_comment(
                        repo_full_name, pr_number, comment, installation_id
                    )

                return {"status": "scanned", "packages": str(len(packages))}

    # Handle issue events
    elif event == "issues":
        action = data.get("action", "")
        if action == "opened":
            issue = data.get("issue", {})
            title = issue.get("title", "")
            body = issue.get("body", "")
            issue_number = issue.get("number")

            packages = extract_package_changes(body, title)

            if packages:
                results = []
                for pkg in packages[:5]:
                    result = scan_package_for_comment(pkg)
                    results.append(result)

                comment = format_github_comment(results)

                if repo_full_name and issue_number:
                    post_github_comment(
                        repo_full_name, issue_number, comment, installation_id
                    )

                return {"status": "scanned", "packages": str(len(packages))}

    return {"status": "ignored", "event": event}


@router.post("/scan-pr")
async def scan_pr_packages(packages: list[str]) -> dict[str, Any]:
    """API endpoint to scan packages from a PR."""
    results = []
    for pkg in packages[:10]:
        result = scan_package_for_comment(pkg)
        results.append(result)

    comment = format_github_comment(results)

    return {
        "results": results,
        "comment": comment,
    }
