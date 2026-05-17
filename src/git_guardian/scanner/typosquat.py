"""Typosquatting detection for npm packages."""

from dataclasses import dataclass

from git_guardian.models.package import Finding, RiskLevel


@dataclass
class TyposquatMatch:
    """A potential typosquatting match."""

    package_name: str
    target_package: str
    distance: int
    match_type: str


# Keyboard adjacency map for QWERTY layout
_KEYBOARD_ADJACENT: dict[str, set[str]] = {
    "q": {"w", "a"},
    "w": {"q", "e", "a", "s"},
    "e": {"w", "r", "s", "d"},
    "r": {"e", "t", "d", "f"},
    "t": {"r", "y", "f", "g"},
    "y": {"t", "u", "g", "h"},
    "u": {"y", "i", "h", "j"},
    "i": {"u", "o", "j", "k"},
    "o": {"i", "p", "k", "l"},
    "p": {"o", "l"},
    "a": {"q", "w", "s", "z"},
    "s": {"a", "w", "e", "d", "z", "x"},
    "d": {"s", "e", "r", "f", "x", "c"},
    "f": {"d", "r", "t", "g", "c", "v"},
    "g": {"f", "t", "y", "h", "v", "b"},
    "h": {"g", "y", "u", "j", "b", "n"},
    "j": {"h", "u", "i", "k", "n", "m"},
    "k": {"j", "i", "o", "l", "m"},
    "l": {"k", "o", "p"},
    "z": {"a", "s", "x"},
    "x": {"z", "s", "d", "c"},
    "c": {"x", "d", "f", "v"},
    "v": {"c", "f", "g", "b"},
    "b": {"v", "g", "h", "n"},
    "n": {"b", "h", "j", "m"},
    "m": {"n", "j", "k"},
}

# Homoglyphs - characters that look similar
_HOMOGLYPHS: dict[str, list[str]] = {
    "a": ["\u0430"],  # Cyrillic а
    "e": ["\u0435"],  # Cyrillic е
    "o": ["\u043e"],  # Cyrillic о
    "p": ["\u0440"],  # Cyrillic р
    "c": ["\u0441"],  # Cyrillic с
    "x": ["\u0445"],  # Cyrillic х
    "i": ["\u0456"],  # Ukrainian і
    "s": ["\u0455"],  # Ukrainian ѕ
}

# Build reverse homoglyph map
_HOMOGLYPHS_REVERSE: dict[str, str] = {}
for latin, cyrillics in _HOMOGLYPHS.items():
    for cyrillic in cyrillics:
        _HOMOGLYPHS_REVERSE[cyrillic] = latin


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate Levenshtein distance between two strings.

    Args:
        s1: First string
        s2: Second string

    Returns:
        Edit distance
    """
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row

    return prev_row[-1]


def keyboard_distance(c1: str, c2: str) -> int:
    """Calculate keyboard distance between two characters.

    Args:
        c1: First character
        c2: Second character

    Returns:
        0 if same, 1 if adjacent, 2 if not adjacent
    """
    if c1 == c2:
        return 0
    c1_lower = c1.lower()
    c2_lower = c2.lower()
    if c2_lower in _KEYBOARD_ADJACENT.get(c1_lower, set()):
        return 1
    return 2


def keyboard_typo_distance(s1: str, s2: str) -> float:
    """Calculate distance based on keyboard layout.

    Args:
        s1: First string
        s2: Second string

    Returns:
        Weighted distance score
    """
    if len(s1) != len(s2):
        return float("inf")

    total_distance = 0
    for c1, c2 in zip(s1, s2):
        total_distance += keyboard_distance(c1, c2)

    return total_distance


def has_homoglyphs(name: str) -> tuple[bool, str]:
    """Check if a package name contains homoglyph characters.

    Args:
        name: Package name to check

    Returns:
        Tuple of (has_homoglyphs, normalized_name)
    """
    normalized = ""
    has_any = False

    for char in name:
        if char in _HOMOGLYPHS_REVERSE:
            normalized += _HOMOGLYPHS_REVERSE[char]
            has_any = True
        else:
            normalized += char

    return has_any, normalized


class TyposquatDetector:
    """Detects typosquatting attempts in package names."""

    def __init__(self, popular_packages: list[str] | None = None) -> None:
        """Initialize with list of popular package names.

        Args:
            popular_packages: List of popular package names to check against
        """
        self.popular_packages = popular_packages or []
        # Normalize all popular package names
        self._normalized: dict[str, str] = {}
        for pkg in self.popular_packages:
            self._normalized[pkg.lower()] = pkg

    def check_package(self, package_name: str) -> list[TyposquatMatch]:
        """Check if a package name is a potential typosquat.

        Args:
            package_name: Package name to check

        Returns:
            List of potential typosquat matches
        """
        matches: list[TyposquatMatch] = []
        name_lower = package_name.lower()

        # Skip scoped packages for now (they're harder to typosquat)
        if name_lower.startswith("@"):
            return matches

        for popular_name in self.popular_packages:
            popular_lower = popular_name.lower()

            # Skip if same name
            if name_lower == popular_lower:
                continue

            # 1. Check Levenshtein distance
            distance = levenshtein_distance(name_lower, popular_lower)
            if distance <= 2 and distance > 0:
                matches.append(
                    TyposquatMatch(
                        package_name=package_name,
                        target_package=popular_name,
                        distance=distance,
                        match_type="levenshtein",
                    )
                )

            # 2. Check keyboard adjacency (only for same-length strings)
            if len(name_lower) == len(popular_lower):
                kb_distance = keyboard_typo_distance(name_lower, popular_lower)
                if kb_distance <= 2 and kb_distance > 0:
                    matches.append(
                        TyposquatMatch(
                            package_name=package_name,
                            target_package=popular_name,
                            distance=int(kb_distance),
                            match_type="keyboard",
                        )
                    )

            # 3. Check homoglyphs
            has_gl, normalized = has_homoglyphs(package_name)
            if has_gl and normalized.lower() == popular_lower:
                matches.append(
                    TyposquatMatch(
                        package_name=package_name,
                        target_package=popular_name,
                        distance=0,
                        match_type="homoglyph",
                    )
                )

            # 4. Check substring confusion
            # e.g., "lodash-util" pretending to be "lodash"
            if (
                name_lower.startswith(popular_lower + "-")
                or name_lower.startswith(popular_lower + "_")
                or name_lower.endswith("-" + popular_lower)
                or name_lower.endswith("_" + popular_lower)
            ):
                matches.append(
                    TyposquatMatch(
                        package_name=package_name,
                        target_package=popular_name,
                        distance=0,
                        match_type="namespace",
                    )
                )

        # Deduplicate by target package, preferring higher-risk match types
        match_type_priority = {"homoglyph": 0, "namespace": 1, "levenshtein": 2, "keyboard": 3}
        matches.sort(key=lambda m: match_type_priority.get(m.match_type, 99))

        seen_targets: set[str] = set()
        unique_matches: list[TyposquatMatch] = []
        for match in matches:
            if match.target_package not in seen_targets:
                seen_targets.add(match.target_package)
                unique_matches.append(match)

        return unique_matches

    def scan_package_name(self, package_name: str) -> list[Finding]:
        """Scan a package name for typosquatting and return findings.

        Args:
            package_name: Package name to scan

        Returns:
            List of findings
        """
        matches = self.check_package(package_name)
        findings: list[Finding] = []

        for match in matches:
            risk_level = RiskLevel.HIGH if match.match_type == "homoglyph" else RiskLevel.MEDIUM

            findings.append(
                Finding(
                    rule_id=f"TYPOSQUAT-{match.match_type.upper()}",
                    title=f"Potential typosquat of '{match.target_package}'",
                    description=(
                        f"Package '{match.package_name}' may be impersonating "
                        f"'{match.target_package}' (match type: {match.match_type}, "
                        f"distance: {match.distance})"
                    ),
                    risk_level=risk_level,
                    file_path=None,
                    line_number=None,
                    code_snippet=None,
                    recommendation=(
                        f"Verify this is not a typosquatting attack. "
                        f"If intentional, document the relationship to '{match.target_package}'."
                    ),
                )
            )

        return findings
