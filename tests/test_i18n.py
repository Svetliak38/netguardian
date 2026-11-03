"""Translation catalog consistency tests."""

from __future__ import annotations

import re
import unittest

from netguardian import i18n

PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


class CatalogTests(unittest.TestCase):
    def test_both_languages_define_the_same_keys(self) -> None:
        english = set(i18n.catalog("en"))
        russian = set(i18n.catalog("ru"))
        self.assertEqual(english - russian, set(), "keys missing in Russian")
        self.assertEqual(russian - english, set(), "keys missing in English")

    def test_placeholders_match_between_languages(self) -> None:
        english = i18n.catalog("en")
        russian = i18n.catalog("ru")
        for key in english:
            with self.subTest(key=key):
                self.assertEqual(
                    set(PLACEHOLDER.findall(english[key])),
                    set(PLACEHOLDER.findall(russian[key])),
                )

    def test_no_empty_messages(self) -> None:
        for language in i18n.SUPPORTED_LANGUAGES:
            for key, value in i18n.catalog(language).items():
                with self.subTest(language=language, key=key):
                    self.assertTrue(value.strip())

    def test_formatting(self) -> None:
        i18n.set_language("en")
        self.assertIn("3", i18n.t("scan.found", count=3))
        i18n.set_language("ru")
        self.assertIn("3", i18n.t("scan.found", count=3))

    def test_unknown_key_falls_back_to_itself(self) -> None:
        self.assertEqual(i18n.t("no.such.key"), "no.such.key")

    def test_language_aliases(self) -> None:
        self.assertEqual(i18n.normalize_language("ru-RU"), "ru")
        self.assertEqual(i18n.normalize_language("EN_us"), "en")
        self.assertEqual(i18n.normalize_language("de"), "en")
        self.assertEqual(i18n.normalize_language(""), "en")

    def test_set_language_returns_the_active_code(self) -> None:
        self.assertEqual(i18n.set_language("ru"), "ru")
        self.assertEqual(i18n.get_language(), "ru")
        i18n.set_language("en")


if __name__ == "__main__":
    unittest.main()
