"""Tests for the npm registry client."""

from unittest.mock import MagicMock, patch

from git_guardian.scanner.npm import NpmRegistryClient, _should_scan_file

# --- _should_scan_file tests ---


def test_should_scan_js_file() -> None:
    assert _should_scan_file("index.js") is True


def test_should_scan_ts_file() -> None:
    assert _should_scan_file("src/app.ts") is True


def test_should_scan_json_file() -> None:
    assert _should_scan_file("package.json") is True


def test_should_scan_shell_file() -> None:
    assert _should_scan_file("scripts/setup.sh") is True


def test_should_not_scan_binary() -> None:
    assert _should_scan_file("image.png") is False


def test_should_not_scan_node_modules() -> None:
    assert _should_scan_file("node_modules/lodash/index.js") is False


def test_should_not_scan_test_fixtures() -> None:
    assert _should_scan_file("test/fixtures/data.json") is False


def test_should_not_scan_git() -> None:
    assert _should_scan_file(".git/config") is False


# --- NpmRegistryClient tests ---


@patch("git_guardian.scanner.npm.httpx.Client")
def test_get_package(mock_client_class: MagicMock) -> None:
    mock_client = MagicMock()
    mock_client_class.return_value = mock_client

    mock_response = MagicMock()
    mock_response.json.return_value = {
        "name": "test-pkg",
        "dist-tags": {"latest": "1.0.0"},
        "versions": {
            "1.0.0": {
                "description": "A test",
                "author": "Test Author",
                "license": "MIT",
                "dependencies": {},
                "scripts": {},
                "dist": {},
            }
        },
        "time": {
            "created": "2024-01-01T00:00:00.000Z",
            "modified": "2024-06-01T00:00:00.000Z",
            "1.0.0": "2024-01-01T00:00:00.000Z",
        },
    }
    mock_client.get.return_value = mock_response

    npm = NpmRegistryClient()
    pkg = npm.get_package("test-pkg")

    assert pkg.name == "test-pkg"
    assert pkg.latest_version == "1.0.0"
    assert pkg.author.name == "Test Author"
    assert pkg.license == "MIT"
    npm.close()


@patch("git_guardian.scanner.npm.httpx.Client")
def test_get_package_dict_author(mock_client_class: MagicMock) -> None:
    mock_client = MagicMock()
    mock_client_class.return_value = mock_client

    mock_response = MagicMock()
    mock_response.json.return_value = {
        "name": "test-pkg",
        "dist-tags": {"latest": "2.0.0"},
        "versions": {
            "2.0.0": {
                "description": "Test",
                "author": {"name": "Author", "email": "a@b.com"},
                "license": "ISC",
                "dependencies": {"lodash": "^4.0.0"},
                "scripts": {"test": "jest"},
                "dist": {"tarball": "https://example.com/tarball.tgz"},
            }
        },
        "time": {},
    }
    mock_client.get.return_value = mock_response

    npm = NpmRegistryClient()
    pkg = npm.get_package("test-pkg")

    assert pkg.author.name == "Author"
    assert pkg.author.email == "a@b.com"
    assert pkg.versions[0].dependencies == {"lodash": "^4.0.0"}
    npm.close()


@patch("git_guardian.scanner.npm.httpx.Client")
def test_get_popular_packages(mock_client_class: MagicMock) -> None:
    npm = NpmRegistryClient()
    packages = npm.get_popular_packages()

    assert isinstance(packages, list)
    assert len(packages) > 0
    assert "lodash" in packages
    assert "express" in packages
    npm.close()


@patch("git_guardian.scanner.npm.httpx.Client")
def test_get_popular_packages_limited(mock_client_class: MagicMock) -> None:
    npm = NpmRegistryClient()
    packages = npm.get_popular_packages(limit=5)

    assert len(packages) == 5
    npm.close()
