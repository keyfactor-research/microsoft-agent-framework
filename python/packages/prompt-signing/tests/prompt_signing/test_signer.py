# Copyright (c) Microsoft. All rights reserved.
"""Tests for PromptSigner and signature utilities."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import Certificate

from agent_framework_prompt_signing._signer import (
    PromptSigner,
    _verify_with_public_key,
    load_certificates_from_file,
    load_certificates_from_pem,
)

from .conftest import FIXTURES_DIR


class TestVerification:
    def test_no_trusted_certs_raises(self):
        with pytest.raises(ValueError, match="At least one trusted certificate"):
            PromptSigner(trusted_certificates={})


class TestPEMLoading:
    def test_load_from_pem_bytes(self, trusted_rsa_cert: Certificate):
        pem_bytes = trusted_rsa_cert.public_bytes(serialization.Encoding.PEM)
        certs = load_certificates_from_pem(pem_bytes)
        assert len(certs) == 1
        assert certs[0].subject == trusted_rsa_cert.subject

    def test_load_from_pem_string(self, trusted_rsa_cert: Certificate):
        pem_str = trusted_rsa_cert.public_bytes(serialization.Encoding.PEM).decode()
        certs = load_certificates_from_pem(pem_str)
        assert len(certs) == 1

    def test_load_pem_bundle(self, trusted_rsa_cert: Certificate, trusted_ec_cert: Certificate):
        bundle = trusted_rsa_cert.public_bytes(serialization.Encoding.PEM) + trusted_ec_cert.public_bytes(
            serialization.Encoding.PEM
        )
        certs = load_certificates_from_pem(bundle)
        assert len(certs) == 2

    def test_load_from_file(self, tmp_path: Path):
        cert_file = FIXTURES_DIR / "trusted_rsa_cert.pem"
        certs = load_certificates_from_file(cert_file)
        assert len(certs) == 1


class TestInternalHelpers:
    def test_verify_with_public_key_unsupported_type_raises(self):
        with pytest.raises(TypeError, match="Unsupported public key type"):
            _verify_with_public_key(MagicMock(), b"sig", b"data")


class TestTrustedCertificatesProperty:
    def test_returns_copy(self, trusted_rsa_cert: Certificate):
        signer = PromptSigner(trusted_certificates={"cert-1": trusted_rsa_cert})
        certs = signer.trusted_certificates
        certs["injected"] = trusted_rsa_cert
        assert "injected" not in signer.trusted_certificates
