# Copyright (c) Microsoft. All rights reserved.
"""Shared fixtures for prompt-signing tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography import x509

FIXTURES_DIR = Path(__file__).parent / "fixtures"

# Prompt text that matches the pre-signed fixture YAMLs.
SIGNED_PROMPT = "You are a helpful assistant."
RSA_CERT_ID = "test-rsa-signer"
EC_CERT_ID = "test-ec-signer"


def _load_cert(filename: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate((FIXTURES_DIR / filename).read_bytes())


@pytest.fixture(scope="session")
def trusted_rsa_cert() -> x509.Certificate:
    """Pre-generated trusted RSA certificate matching the RSA-signed fixture prompts."""
    return _load_cert("trusted_rsa_cert.pem")


@pytest.fixture(scope="session")
def trusted_ec_cert() -> x509.Certificate:
    """Pre-generated trusted EC certificate matching the EC CMS-signed fixture prompts."""
    return _load_cert("trusted_ec_cert.pem")


@pytest.fixture(scope="session")
def untrusted_cert() -> x509.Certificate:
    """Pre-generated certificate that was NOT used to sign any fixture prompt."""
    return _load_cert("untrusted_cert.pem")


@pytest.fixture(scope="session")
def prompts_dir() -> Path:
    """Directory containing pre-signed raw RSA-PSS prompt YAML files."""
    return FIXTURES_DIR / "prompts"


@pytest.fixture(scope="session")
def cms_prompts_dir() -> Path:
    """Directory containing pre-signed CMS prompt YAML files."""
    return FIXTURES_DIR / "cms_prompts"
