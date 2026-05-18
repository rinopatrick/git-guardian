"""Package health scoring — multi-dimensional quality assessment."""

from dataclasses import dataclass, field
from datetime import datetime, timezone

from git_guardian.models.package import PackageInfo, RiskLevel


@dataclass
class HealthDimension:
    """A single health dimension score."""

    name: str
    score: float  # 0-100
    weight: float  # 0-1
    details: str = ""
    issues: list[str] = field(default_factory=list)


@dataclass
class HealthReport:
    """Complete health report for a package."""

    package_name: str
    overall_score: float  # 0-100
    grade: str  # A, B, C, D, F
    dimensions: list[HealthDimension] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    @property
    def risk_level(self) -> RiskLevel:
        if self.overall_score >= 80:
            return RiskLevel.SAFE
        if self.overall_score >= 60:
            return RiskLevel.LOW
        if self.overall_score >= 40:
            return RiskLevel.MEDIUM
        if self.overall_score >= 20:
            return RiskLevel.HIGH
        return RiskLevel.CRITICAL


def _grade(score: float) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


class HealthScorer:
    """Scores packages across multiple health dimensions."""

    def score_package(self, package_info: PackageInfo) -> HealthReport:
        """Generate a health report for a package.

        Dimensions:
        - Popularity (downloads, dependents)
        - Maintenance (last update, version cadence)
        - Quality (description, keywords, homepage, repo)
        - Security (license, known issues)
        - Dependencies (count, complexity)
        """
        dimensions: list[HealthDimension] = []
        recommendations: list[str] = []

        # 1. Popularity
        pop_score, pop_issues = self._score_popularity(package_info)
        dimensions.append(HealthDimension(
            name="Popularity",
            score=pop_score,
            weight=0.20,
            details=f"{package_info.weekly_downloads:,} weekly downloads",
            issues=pop_issues,
        ))

        # 2. Maintenance
        maint_score, maint_issues = self._score_maintenance(package_info)
        dimensions.append(HealthDimension(
            name="Maintenance",
            score=maint_score,
            weight=0.25,
            details=f"Last updated: {package_info.updated_at or 'unknown'}",
            issues=maint_issues,
        ))

        # 3. Quality
        qual_score, qual_issues = self._score_quality(package_info)
        dimensions.append(HealthDimension(
            name="Quality",
            score=qual_score,
            weight=0.15,
            details="Documentation and metadata completeness",
            issues=qual_issues,
        ))

        # 4. Security posture
        sec_score, sec_issues = self._score_security(package_info)
        dimensions.append(HealthDimension(
            name="Security",
            score=sec_score,
            weight=0.25,
            details="License and security indicators",
            issues=sec_issues,
        ))

        # 5. Dependencies
        dep_score, dep_issues = self._score_dependencies(package_info)
        dimensions.append(HealthDimension(
            name="Dependencies",
            score=dep_score,
            weight=0.15,
            details=f"{len(package_info.versions[-1].dependencies) if package_info.versions else 0} dependencies",
            issues=dep_issues,
        ))

        # Aggregate
        total_weight = sum(d.weight for d in dimensions)
        overall = sum(d.score * d.weight for d in dimensions) / total_weight if total_weight > 0 else 0

        # Collect recommendations
        for d in dimensions:
            for issue in d.issues:
                recommendations.append(f"[{d.name}] {issue}")

        return HealthReport(
            package_name=package_info.name,
            overall_score=round(overall, 1),
            grade=_grade(overall),
            dimensions=dimensions,
            recommendations=recommendations,
        )

    def _score_popularity(self, pkg: PackageInfo) -> tuple[float, list[str]]:
        issues: list[str] = []
        downloads = pkg.weekly_downloads

        if downloads >= 1_000_000:
            score = 100
        elif downloads >= 100_000:
            score = 85
        elif downloads >= 10_000:
            score = 70
        elif downloads >= 1_000:
            score = 50
        elif downloads >= 100:
            score = 30
            issues.append("Very low download count — may be unmaintained or niche")
        else:
            score = 10
            issues.append("Near-zero downloads — high risk of abandonment")

        return score, issues

    def _score_maintenance(self, pkg: PackageInfo) -> tuple[float, list[str]]:
        issues: list[str] = []
        now = datetime.now(timezone.utc)

        if not pkg.updated_at:
            return 20, ["No update date available"]

        # Handle both naive and aware datetimes
        updated = pkg.updated_at
        if updated.tzinfo is None:
            updated = updated.replace(tzinfo=timezone.utc)

        days_since = (now - updated).days

        if days_since <= 30:
            score = 100
        elif days_since <= 90:
            score = 85
        elif days_since <= 180:
            score = 70
        elif days_since <= 365:
            score = 50
            issues.append("Not updated in over 6 months")
        elif days_since <= 730:
            score = 30
            issues.append("Not updated in over a year — possibly abandoned")
        else:
            score = 10
            issues.append("Not updated in over 2 years — likely abandoned")

        # Version count
        if len(pkg.versions) < 3:
            issues.append("Very few published versions")
            score = min(score, 60)

        return score, issues

    def _score_quality(self, pkg: PackageInfo) -> tuple[float, list[str]]:
        issues: list[str] = []
        score = 50  # baseline

        if pkg.description:
            score += 10
        else:
            issues.append("No description provided")

        if pkg.keywords:
            score += 10
        else:
            issues.append("No keywords — harder to discover")

        if pkg.homepage:
            score += 10
        else:
            issues.append("No homepage URL")

        if pkg.repository_url:
            score += 15
        else:
            issues.append("No repository URL — can't review source")

        if pkg.author and pkg.author.name:
            score += 5
        else:
            issues.append("No author information")

        return min(score, 100), issues

    def _score_security(self, pkg: PackageInfo) -> tuple[float, list[str]]:
        issues: list[str] = []
        score = 70  # baseline

        if not pkg.license:
            score -= 30
            issues.append("No license declared")
        elif pkg.license in ("GPL-2.0", "GPL-3.0", "AGPL-3.0"):
            score -= 15
            issues.append(f"Copyleft license ({pkg.license}) may impose obligations")

        # Check latest version for install scripts
        if pkg.versions:
            latest = pkg.versions[-1]
            risky_scripts = {"preinstall", "postinstall", "install", "preuninstall", "postuninstall"}
            found_scripts = risky_scripts & set(latest.scripts.keys())
            if found_scripts:
                score -= 20
                issues.append(f"Has install scripts: {', '.join(found_scripts)}")

        return max(score, 0), issues

    def _score_dependencies(self, pkg: PackageInfo) -> tuple[float, list[str]]:
        issues: list[str] = []

        if not pkg.versions:
            return 50, ["No version data"]

        latest = pkg.versions[-1]
        dep_count = len(latest.dependencies)

        if dep_count == 0:
            score = 100
        elif dep_count <= 5:
            score = 90
        elif dep_count <= 10:
            score = 75
        elif dep_count <= 20:
            score = 60
            issues.append("Many dependencies — increases attack surface")
        elif dep_count <= 50:
            score = 40
            issues.append("Heavy dependency tree — high attack surface")
        else:
            score = 20
            issues.append(f"Very heavy: {dep_count} dependencies — significant supply chain risk")

        return score, issues
