"""npm registry client for fetching package metadata and tarballs."""

import io
import tarfile
from datetime import datetime

import httpx

from git_guardian.config import settings
from git_guardian.models.package import PackageAuthor, PackageInfo, PackageVersion


class NpmRegistryClient:
    """Client for interacting with the npm registry."""

    def __init__(self, base_url: str | None = None) -> None:
        self.base_url = base_url or settings.npm_registry
        self.client = httpx.Client(
            base_url=self.base_url,
            timeout=30.0,
            headers={"Accept": "application/json"},
        )

    def get_package(self, name: str) -> PackageInfo:
        """Fetch package metadata from npm registry.

        Args:
            name: Package name (e.g., 'lodash', '@scope/package')

        Returns:
            PackageInfo with metadata

        Raises:
            httpx.HTTPStatusError: If package not found (404)
        """
        response = self.client.get(f"/{name}")
        response.raise_for_status()
        data = response.json()

        # Parse versions
        versions = []
        for version_str, version_data in data.get("versions", {}).items():
            author = None
            if "author" in version_data:
                author_data = version_data["author"]
                if isinstance(author_data, str):
                    author = PackageAuthor(name=author_data)
                elif isinstance(author_data, dict):
                    author = PackageAuthor(**author_data)

            # Parse publish time
            published_at = None
            time_data = data.get("time", {})
            if version_str in time_data:
                try:
                    published_at = datetime.fromisoformat(
                        time_data[version_str].replace("Z", "+00:00")
                    )
                except (ValueError, TypeError):
                    pass

            versions.append(
                PackageVersion(
                    version=version_str,
                    description=version_data.get("description"),
                    author=author,
                    license=version_data.get("license"),
                    dependencies=version_data.get("dependencies", {}),
                    scripts=version_data.get("scripts", {}),
                    dist=version_data.get("dist", {}),
                    published_at=published_at,
                )
            )

        # Get latest version info
        latest_version = data.get("dist-tags", {}).get("latest", "0.0.0")
        latest_data = data.get("versions", {}).get(latest_version, {})

        # Parse author
        author = None
        if "author" in latest_data:
            author_data = latest_data["author"]
            if isinstance(author_data, str):
                author = PackageAuthor(name=author_data)
            elif isinstance(author_data, dict):
                author = PackageAuthor(**author_data)

        # Parse dates
        created_at = None
        updated_at = None
        time_data = data.get("time", {})
        if "created" in time_data:
            try:
                created_at = datetime.fromisoformat(
                    time_data["created"].replace("Z", "+00:00")
                )
            except (ValueError, TypeError):
                pass
        if "modified" in time_data:
            try:
                updated_at = datetime.fromisoformat(
                    time_data["modified"].replace("Z", "+00:00")
                )
            except (ValueError, TypeError):
                pass

        return PackageInfo(
            name=data.get("name", name),
            description=latest_data.get("description"),
            latest_version=latest_version,
            versions=versions,
            author=author,
            license=latest_data.get("license"),
            repository_url=_extract_repo_url(data.get("repository")),
            homepage=data.get("homepage"),
            keywords=data.get("keywords", []),
            created_at=created_at,
            updated_at=updated_at,
        )

    def get_package_files(
        self, name: str, version: str | None = None
    ) -> dict[str, str]:
        """Fetch and extract package tarball to get file contents.

        Args:
            name: Package name
            version: Specific version (defaults to latest)

        Returns:
            Dict mapping file paths to their contents
        """
        # Get version info first
        if version is None:
            package = self.get_package(name)
            version = package.latest_version

        # Get tarball URL
        response = self.client.get(f"/{name}/{version}")
        response.raise_for_status()
        data = response.json()

        tarball_url = data.get("dist", {}).get("tarball")
        if not tarball_url:
            return {}

        # Download tarball
        tarball_response = httpx.get(tarball_url, timeout=60.0)
        tarball_response.raise_for_status()

        # Extract and read files
        files: dict[str, str] = {}
        try:
            with tarfile.open(fileobj=io.BytesIO(tarball_response.content), mode="r:gz") as tar:
                for member in tar.getmembers():
                    if member.isfile() and _should_scan_file(member.name):
                        try:
                            f = tar.extractfile(member)
                            if f:
                                content = f.read().decode("utf-8", errors="ignore")
                                # Remove 'package/' prefix from path
                                path = member.name
                                if path.startswith("package/"):
                                    path = path[8:]
                                files[path] = content
                        except (UnicodeDecodeError, OSError):
                            continue
        except tarfile.TarError:
            pass

        return files

    def get_popular_packages(self, limit: int = 100) -> list[str]:
        """Get list of popular npm package names (for typosquat detection).

        Uses the npm API to get most downloaded packages.

        Args:
            limit: Number of packages to return

        Returns:
            List of package names
        """
        # npm doesn't have a direct "popular" endpoint
        # We'll use a known list of very popular packages
        # In production, this would come from npm API or a maintained list
        POPULAR_PACKAGES = [
            "lodash", "express", "react", "vue", "angular", "jquery", "axios",
            "moment", "chalk", "commander", "debug", "dotenv", "eslint",
            "fs-extra", "glob", "inquirer", "jest", "jsonwebtoken", "mongoose",
            "next", "node-fetch", "nodemon", "passport", "prettier", "ramda",
            "redux", "request", "rimraf", "rxjs", "semver", "socket.io",
            "styled-components", "tailwindcss", "typescript", "underscore",
            "uuid", "webpack", "yargs", "zod", "prisma", "trpc",
        ]
        return POPULAR_PACKAGES[:limit]

    def close(self) -> None:
        """Close the HTTP client."""
        self.client.close()

    def __enter__(self) -> "NpmRegistryClient":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


def _extract_repo_url(repo: str | dict | None) -> str | None:
    """Extract repository URL from npm repository field."""
    if repo is None:
        return None
    if isinstance(repo, str):
        return repo
    if isinstance(repo, dict):
        return repo.get("url")
    return None


def _should_scan_file(filename: str) -> bool:
    """Determine if a file should be scanned for security issues."""
    # Scan JavaScript/TypeScript files
    scan_extensions = {
        ".js", ".mjs", ".cjs", ".jsx",
        ".ts", ".tsx", ".mts", ".cts",
        ".json", ".sh", ".bash",
    }

    # Skip node_modules and test fixtures
    skip_patterns = [
        "node_modules/",
        "test/fixtures/",
        "__tests__/",
        ".git/",
    ]

    # Check skip patterns
    for pattern in skip_patterns:
        if pattern in filename:
            return False

    # Check extension
    for ext in scan_extensions:
        if filename.endswith(ext):
            return True

    return False
