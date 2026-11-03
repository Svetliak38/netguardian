"""Subject parsing tests for Microsoft signer verification."""

from __future__ import annotations

import unittest

from netguardian.security import signer_is_microsoft

REAL_MICROSOFT = (
    "CN=Microsoft Corporation, O=Microsoft Corporation, "
    "L=Redmond, S=Washington, C=US"
)


class SignerIsMicrosoftTests(unittest.TestCase):
    def test_real_microsoft_subject_is_accepted(self):
        self.assertTrue(signer_is_microsoft(REAL_MICROSOFT))

    def test_common_name_only_subject_is_accepted(self):
        self.assertTrue(signer_is_microsoft("CN=Microsoft Corporation"))

    def test_plain_organization_name_is_accepted(self):
        self.assertTrue(signer_is_microsoft("O=Microsoft"))

    def test_quoted_values_are_accepted(self):
        subject = 'CN="Microsoft Corporation", O="Microsoft Corporation"'
        self.assertTrue(signer_is_microsoft(subject))

    def test_whitespace_around_values_is_ignored(self):
        self.assertTrue(signer_is_microsoft("CN=Microsoft Corporation ,  O= Microsoft Corporation "))

    def test_case_is_ignored(self):
        self.assertTrue(signer_is_microsoft("CN=mIcRoSoFt CoRpOrAtIoN"))

    def test_organization_merely_containing_the_word_is_rejected(self):
        # The regression this guard exists for: a substring check accepted it.
        self.assertFalse(signer_is_microsoft("CN=TcpView, O=Evil Microsoft Ltd"))
        self.assertFalse(signer_is_microsoft("CN=Update Helper, O=Microsoft Reseller LLC"))
        self.assertFalse(signer_is_microsoft("CN=Microsoft Windows Update, O=Totally Legit Ltd"))

    def test_foreign_signers_are_rejected(self):
        self.assertFalse(signer_is_microsoft("CN=Contoso Ltd, O=Contoso Ltd, C=US"))
        self.assertFalse(signer_is_microsoft("CN=Sysinternals, O=NirSoft"))

    def test_empty_input_is_rejected(self):
        self.assertFalse(signer_is_microsoft(""))
        self.assertFalse(signer_is_microsoft("   "))
        self.assertFalse(signer_is_microsoft(None))  # type: ignore[arg-type]

    def test_unparseable_subject_is_rejected(self):
        self.assertFalse(signer_is_microsoft("just some text with microsoft inside"))
        self.assertFalse(signer_is_microsoft("Microsoft"))  # bare word, not an attribute

    def test_common_name_fallback_does_not_accept_wrapped_names(self):
        self.assertFalse(signer_is_microsoft("CN=Microsoft Corporation (fake)"))
        self.assertFalse(signer_is_microsoft("CN=Fake Microsoft Corporation"))

    def test_escaped_comma_is_not_treated_as_separator(self):
        self.assertFalse(signer_is_microsoft(r"CN=TcpView, O=Microsoft\, Inc."))

    def test_multi_valued_rdn_is_split(self):
        self.assertTrue(signer_is_microsoft("CN=Microsoft Corporation+O=Microsoft Corporation"))

    def test_organization_wins_over_common_name(self):
        # A CN that looks like Microsoft must not rescue a foreign organization.
        self.assertFalse(signer_is_microsoft("CN=Microsoft Corporation, O=Contoso Ltd"))


if __name__ == "__main__":
    unittest.main()
