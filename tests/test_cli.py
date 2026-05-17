"""Tests for CLI."""

from typer.testing import CliRunner

from git_guardian.cli import app

runner = CliRunner()


def test_version_command() -> None:
    """Test version command."""
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "Git Guardian" in result.output


def test_rules_command() -> None:
    """Test rules command lists detection rules."""
    result = runner.invoke(app, ["rules"])
    assert result.exit_code == 0
    assert "Detection Rules" in result.output
    assert "Total rules:" in result.output
