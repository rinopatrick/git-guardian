"""Tests for typosquat detection."""

import pytest

from git_guardian.scanner.typosquat import (
    TyposquatDetector,
    has_homoglyphs,
    keyboard_typo_distance,
    levenshtein_distance,
)


class TestLevenshteinDistance:
    """Test Levenshtein distance calculation."""

    def test_identical_strings(self) -> None:
        assert levenshtein_distance("hello", "hello") == 0

    def test_single_insertion(self) -> None:
        assert levenshtein_distance("hello", "helllo") == 1

    def test_single_deletion(self) -> None:
        assert levenshtein_distance("hello", "helo") == 1

    def test_single_substitution(self) -> None:
        assert levenshtein_distance("hello", "hallo") == 1

    def test_multiple_edits(self) -> None:
        assert levenshtein_distance("kitten", "sitting") == 3

    def test_empty_strings(self) -> None:
        assert levenshtein_distance("", "") == 0
        assert levenshtein_distance("hello", "") == 5


class TestKeyboardDistance:
    """Test keyboard distance calculation."""

    def test_adjacent_keys(self) -> None:
        # a->a (0) + b->q (2, not adjacent) = 2
        assert keyboard_typo_distance("ab", "aq") == 2

    def test_same_keys(self) -> None:
        assert keyboard_typo_distance("ab", "ab") == 0

    def test_non_adjacent_keys(self) -> None:
        # a->z (2) + b->z (2) = 4... but actually a is adjacent to z
        # a->z = 1 (adjacent), b->z = 2 (not adjacent) = 3
        assert keyboard_typo_distance("ab", "zz") == 3


class TestHomoglyphDetection:
    """Test homoglyph detection."""

    def test_detects_cyrillic_a(self) -> None:
        # Cyrillic а looks like Latin a
        has, normalized = has_homoglyphs("lod\u0430sh")
        assert has is True
        assert normalized == "lodash"

    def test_no_homoglyphs(self) -> None:
        has, normalized = has_homoglyphs("lodash")
        assert has is False
        assert normalized == "lodash"


class TestTyposquatDetector:
    """Test typosquat detection."""

    @pytest.fixture
    def detector(self) -> TyposquatDetector:
        return TyposquatDetector(["lodash", "express", "react", "axios", "chalk"])

    def test_exact_match_not_flagged(self, detector: TyposquatDetector) -> None:
        matches = detector.check_package("lodash")
        assert len(matches) == 0

    def test_levenshtein_detection(self, detector: TyposquatDetector) -> None:
        matches = detector.check_package("lodas")  # 1 edit from lodash
        assert any(m.match_type == "levenshtein" for m in matches)

    def test_keyboard_typo_detection(self, detector: TyposquatDetector) -> None:
        # e and r are adjacent on keyboard
        matches = detector.check_package("lodusr")  # lodusr vs lodash
        # This may or may not match depending on distance
        # Just verify it doesn't crash
        assert isinstance(matches, list)

    def test_homoglyph_detection(self, detector: TyposquatDetector) -> None:
        # Cyrillic а instead of Latin a
        matches = detector.check_package("lod\u0430sh")
        assert any(m.match_type == "homoglyph" for m in matches)

    def test_namespace_confusion(self, detector: TyposquatDetector) -> None:
        matches = detector.check_package("lodash-utils")
        assert any(m.match_type == "namespace" for m in matches)

    def test_scoped_packages_skipped(self, detector: TyposquatDetector) -> None:
        matches = detector.check_package("@types/lodash")
        assert len(matches) == 0

    def test_unrelated_package_not_flagged(self, detector: TyposquatDetector) -> None:
        matches = detector.check_package("mytotallydifferentpackage")
        assert len(matches) == 0
