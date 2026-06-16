# Copyright (c) Microsoft. All rights reserved.
"""Tests for CmsPromptSigner and CmsPromptSignatureMiddleware."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from cryptography.x509 import Certificate

from agent_framework_prompt_signing._cms import (
    _CMS_SIGNED_DATA_OID,
    CmsPromptSignatureMiddleware,
    CmsPromptSigner,
    _verify_cms,
)
from agent_framework_prompt_signing._models import SignedPrompt, load_prompt_catalog

from .conftest import EC_CERT_ID, FIXTURES_DIR, RSA_CERT_ID, SIGNED_PROMPT


def _load_rsa_cms_prompt(cert_id_variant: str = "assistant_rsa") -> SignedPrompt:
    """Load a pre-signed CMS prompt from the fixtures directory."""
    catalog = load_prompt_catalog([FIXTURES_DIR / "cms_prompts"])
    return next(
        sp for sp in catalog if sp.certificate_id == (RSA_CERT_ID if "no_cert_id" not in cert_id_variant else "")
    )


def _make_fake_cms_prompt() -> SignedPrompt:
    """Return a SignedPrompt with the CMS OID prefix but otherwise invalid DER."""
    return SignedPrompt(text=SIGNED_PROMPT, signature=_CMS_SIGNED_DATA_OID + b"\x00" * 32, certificate_id=RSA_CERT_ID)


# ------------------------------------------------------------------
# CmsPromptSigner — fallback to parent for raw (non-CMS) signatures
# ------------------------------------------------------------------


class TestCmsPromptSignerFallback:
    def test_non_cms_signature_delegates_to_parent(self, trusted_rsa_cert: Certificate):
        """A raw RSA-PSS fixture signature is passed through to the parent verify()."""
        catalog = load_prompt_catalog([FIXTURES_DIR / "prompts"])
        signed = catalog[0]
        signer = CmsPromptSigner(trusted_certificates={RSA_CERT_ID: trusted_rsa_cert})
        assert signer.verify(signed) is True

    def test_non_cms_tampered_fails_via_parent(self, trusted_rsa_cert: Certificate):
        catalog = load_prompt_catalog([FIXTURES_DIR / "prompts"])
        signed = catalog[0]
        tampered = SignedPrompt(text=SIGNED_PROMPT + "X", signature=signed.signature, certificate_id=RSA_CERT_ID)
        signer = CmsPromptSigner(trusted_certificates={RSA_CERT_ID: trusted_rsa_cert})
        assert signer.verify(tampered) is False


# ------------------------------------------------------------------
# CmsPromptSigner — CMS path
# ------------------------------------------------------------------


class TestCmsPromptSignerCmsPath:
    def test_valid_rsa_cms_signature_passes(self, trusted_rsa_cert: Certificate):
        catalog = load_prompt_catalog([FIXTURES_DIR / "cms_prompts"])
        signed = next(sp for sp in catalog if sp.certificate_id == RSA_CERT_ID)
        signer = CmsPromptSigner(trusted_certificates={RSA_CERT_ID: trusted_rsa_cert})
        assert signer.verify(signed) is True

    def test_valid_ec_cms_signature_passes(self, trusted_ec_cert: Certificate):
        catalog = load_prompt_catalog([FIXTURES_DIR / "cms_prompts"])
        signed = next(sp for sp in catalog if sp.certificate_id == EC_CERT_ID)
        signer = CmsPromptSigner(trusted_certificates={EC_CERT_ID: trusted_ec_cert})
        assert signer.verify(signed) is True

    def test_tampered_content_fails(self, trusted_rsa_cert: Certificate):
        catalog = load_prompt_catalog([FIXTURES_DIR / "cms_prompts"])
        signed = next(sp for sp in catalog if sp.certificate_id == RSA_CERT_ID)
        tampered = SignedPrompt(
            text=SIGNED_PROMPT + " TAMPERED", signature=signed.signature, certificate_id=RSA_CERT_ID
        )
        signer = CmsPromptSigner(trusted_certificates={RSA_CERT_ID: trusted_rsa_cert})
        assert signer.verify(tampered) is False

    def test_unknown_cert_id_returns_false(self, trusted_rsa_cert: Certificate):
        """certificate_id not in trusted set → False."""
        catalog = load_prompt_catalog([FIXTURES_DIR / "cms_prompts"])
        signed = next(sp for sp in catalog if sp.certificate_id == RSA_CERT_ID)
        signer = CmsPromptSigner(trusted_certificates={"unknown-cert": trusted_rsa_cert})
        assert signer.verify(signed) is False

    def test_wrong_trusted_cert_fails(self, untrusted_cert: Certificate):
        """Signature is valid but the trusted cert doesn't match the signing cert."""
        catalog = load_prompt_catalog([FIXTURES_DIR / "cms_prompts"])
        signed = next(sp for sp in catalog if sp.certificate_id == RSA_CERT_ID)
        signer = CmsPromptSigner(trusted_certificates={RSA_CERT_ID: untrusted_cert})
        assert signer.verify(signed) is False

    def test_no_cert_id_tries_all_certs(self, trusted_rsa_cert: Certificate, untrusted_cert: Certificate):
        """No cert_id → all trusted certs are tried; succeeds when correct cert is present."""
        catalog = load_prompt_catalog([FIXTURES_DIR / "cms_prompts"])
        signed = next(sp for sp in catalog if sp.certificate_id == "")
        signer = CmsPromptSigner(trusted_certificates={"wrong": untrusted_cert, RSA_CERT_ID: trusted_rsa_cert})
        assert signer.verify(signed) is True

    def test_no_cert_id_all_wrong_fails(self, untrusted_cert: Certificate):
        catalog = load_prompt_catalog([FIXTURES_DIR / "cms_prompts"])
        signed = next(sp for sp in catalog if sp.certificate_id == "")
        signer = CmsPromptSigner(trusted_certificates={"wrong": untrusted_cert})
        assert signer.verify(signed) is False

    def test_malformed_cms_returns_false(self, trusted_rsa_cert: Certificate):
        """A signature with the CMS OID prefix but invalid DER body is rejected gracefully."""
        signer = CmsPromptSigner(trusted_certificates={RSA_CERT_ID: trusted_rsa_cert})
        assert signer.verify(_make_fake_cms_prompt()) is False


# ------------------------------------------------------------------
# _verify_cms directly
# ------------------------------------------------------------------


class TestVerifyCms:
    def test_valid_rsa_signature_returns_true(self, trusted_rsa_cert: Certificate):
        catalog = load_prompt_catalog([FIXTURES_DIR / "cms_prompts"])
        signed = next(sp for sp in catalog if sp.certificate_id == RSA_CERT_ID)
        assert _verify_cms(trusted_rsa_cert, signed.signature, SIGNED_PROMPT.encode()) is True

    def test_tampered_data_returns_false(self, trusted_rsa_cert: Certificate):
        catalog = load_prompt_catalog([FIXTURES_DIR / "cms_prompts"])
        signed = next(sp for sp in catalog if sp.certificate_id == RSA_CERT_ID)
        assert _verify_cms(trusted_rsa_cert, signed.signature, b"different content") is False

    def test_wrong_cert_returns_false(self, trusted_rsa_cert: Certificate, untrusted_cert: Certificate):
        catalog = load_prompt_catalog([FIXTURES_DIR / "cms_prompts"])
        signed = next(sp for sp in catalog if sp.certificate_id == RSA_CERT_ID)
        assert _verify_cms(untrusted_cert, signed.signature, SIGNED_PROMPT.encode()) is False

    def test_malformed_der_returns_false(self, trusted_rsa_cert: Certificate):
        assert _verify_cms(trusted_rsa_cert, b"\x00" * 64, SIGNED_PROMPT.encode()) is False


# ------------------------------------------------------------------
# CmsPromptSignatureMiddleware
# ------------------------------------------------------------------


class TestCmsPromptSignatureMiddleware:
    def test_init_replaces_signer_with_cms_signer(self, trusted_rsa_cert: Certificate, cms_prompts_dir: Path):
        mw = CmsPromptSignatureMiddleware(
            prompt_directories=[cms_prompts_dir],
            trusted_certificates={RSA_CERT_ID: trusted_rsa_cert},
        )
        assert isinstance(mw._signer, CmsPromptSigner)

    def test_cms_middleware_preserves_trusted_certs(self, trusted_rsa_cert: Certificate, cms_prompts_dir: Path):
        mw = CmsPromptSignatureMiddleware(
            prompt_directories=[cms_prompts_dir],
            trusted_certificates={RSA_CERT_ID: trusted_rsa_cert},
        )
        assert RSA_CERT_ID in mw._signer.trusted_certificates

    async def test_cms_middleware_verifies_cms_signed_prompt(
        self, trusted_rsa_cert: Certificate, cms_prompts_dir: Path
    ):
        """End-to-end: middleware accepts an agent whose instructions are CMS-signed."""
        mw = CmsPromptSignatureMiddleware(
            prompt_directories=[cms_prompts_dir],
            trusted_certificates={RSA_CERT_ID: trusted_rsa_cert},
        )

        class FakeCtx:
            agent = SimpleNamespace(instructions=SIGNED_PROMPT)
            messages = []
            result = None
            metadata: dict = {}

        next_called = False

        async def call_next():
            nonlocal next_called
            next_called = True

        await mw.process(FakeCtx(), call_next)
        assert next_called is True

    async def test_cms_middleware_still_passes_raw_signature(self, trusted_rsa_cert: Certificate, prompts_dir: Path):
        """CmsPromptSignatureMiddleware falls back to raw RSA-PSS for non-CMS signatures."""
        mw = CmsPromptSignatureMiddleware(
            prompt_directories=[prompts_dir],
            trusted_certificates={RSA_CERT_ID: trusted_rsa_cert},
        )

        class FakeCtx:
            agent = SimpleNamespace(instructions=SIGNED_PROMPT)
            messages = []
            result = None
            metadata: dict = {}

        next_called = False

        async def call_next():
            nonlocal next_called
            next_called = True

        await mw.process(FakeCtx(), call_next)
        assert next_called is True
