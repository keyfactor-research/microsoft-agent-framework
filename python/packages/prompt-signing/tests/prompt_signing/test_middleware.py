# Copyright (c) Microsoft. All rights reserved.
"""Tests for PromptSignatureMiddleware with YAML prompt catalog."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from agent_framework import MiddlewareTermination
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import Certificate

from agent_framework_prompt_signing._middleware import PromptSignatureMiddleware
from agent_framework_prompt_signing._models import load_prompt_catalog

from .conftest import FIXTURES_DIR, RSA_CERT_ID, SIGNED_PROMPT


class FakeAgentContext:
    """Minimal stand-in for agent_framework.AgentContext."""

    def __init__(self, instructions: str | None = SIGNED_PROMPT):
        self.agent = SimpleNamespace(instructions=instructions)
        self.messages = []
        self.result = None
        self.is_streaming = False
        self.metadata: dict = {}
        self.kwargs: dict = {}


def _write_cert(directory: Path, filename: str, cert: Certificate) -> Path:
    path = directory / filename
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return path


class TestLoadPromptCatalog:
    def test_loads_fixture_yaml(self, prompts_dir: Path):
        catalog = load_prompt_catalog([prompts_dir])
        assert len(catalog) == 1
        assert catalog[0].text == SIGNED_PROMPT
        assert catalog[0].certificate_id == RSA_CERT_ID

    def test_skips_missing_directory(self, tmp_path: Path):
        assert load_prompt_catalog([tmp_path / "nonexistent"]) == []

    def test_skips_invalid_yaml(self, tmp_path: Path):
        (tmp_path / "bad.yaml").write_text("not: a: valid: prompt file", encoding="utf-8")
        assert load_prompt_catalog([tmp_path]) == []

    def test_skips_yaml_with_non_dict_root(self, tmp_path: Path):
        """A YAML file whose root is a list (not a mapping) is skipped."""
        (tmp_path / "list.yaml").write_text("- item1\n- item2\n", encoding="utf-8")
        assert load_prompt_catalog([tmp_path]) == []


class TestMiddlewareVerification:
    @pytest.fixture()
    def middleware(self, trusted_rsa_cert: Certificate) -> PromptSignatureMiddleware:
        return PromptSignatureMiddleware(
            prompt_directories=[FIXTURES_DIR / "prompts"],
            trusted_certificates={RSA_CERT_ID: trusted_rsa_cert},
        )

    async def test_valid_signature_allows_execution(self, middleware: PromptSignatureMiddleware):
        next_called = False

        async def call_next():
            nonlocal next_called
            next_called = True

        await middleware.process(FakeAgentContext(instructions=SIGNED_PROMPT), call_next)
        assert next_called is True

    async def test_cached_verification_skips_recheck(self, middleware: PromptSignatureMiddleware):
        await middleware.process(FakeAgentContext(instructions=SIGNED_PROMPT), AsyncMock())
        next_mock = AsyncMock()
        await middleware.process(FakeAgentContext(instructions=SIGNED_PROMPT), next_mock)
        next_mock.assert_awaited_once()

    async def test_unknown_prompt_blocked(self, middleware: PromptSignatureMiddleware):
        with pytest.raises(MiddlewareTermination):
            await middleware.process(FakeAgentContext(instructions="Some unknown prompt"), AsyncMock())

    async def test_missing_instructions_blocked(self, middleware: PromptSignatureMiddleware):
        with pytest.raises(MiddlewareTermination):
            await middleware.process(FakeAgentContext(instructions=None), AsyncMock())

    async def test_untrusted_certificate_blocked(self, untrusted_cert: Certificate):
        mw = PromptSignatureMiddleware(
            prompt_directories=[FIXTURES_DIR / "prompts"],
            trusted_certificates={RSA_CERT_ID: untrusted_cert},
        )
        with pytest.raises(MiddlewareTermination):
            await mw.process(FakeAgentContext(instructions=SIGNED_PROMPT), AsyncMock())

    async def test_custom_rejection_message(self, untrusted_cert: Certificate):
        custom_msg = "CUSTOM REJECTION"
        mw = PromptSignatureMiddleware(
            prompt_directories=[FIXTURES_DIR / "prompts"],
            trusted_certificates={RSA_CERT_ID: untrusted_cert},
            rejection_message=custom_msg,
        )
        ctx = FakeAgentContext(instructions=SIGNED_PROMPT)
        with pytest.raises(MiddlewareTermination):
            await mw.process(ctx, AsyncMock())
        assert custom_msg in ctx.result.messages[0].text

    async def test_trusted_certificate_paths(self, tmp_path: Path, trusted_rsa_cert: Certificate):
        cert_file = _write_cert(tmp_path, "trusted.pem", trusted_rsa_cert)
        mw = PromptSignatureMiddleware(
            prompt_directories=[FIXTURES_DIR / "prompts"],
            trusted_certificate_paths={RSA_CERT_ID: cert_file},
        )
        next_called = False

        async def call_next():
            nonlocal next_called
            next_called = True

        await mw.process(FakeAgentContext(instructions=SIGNED_PROMPT), call_next)
        assert next_called is True

    async def test_mixed_certs_and_paths(
        self, tmp_path: Path, trusted_rsa_cert: Certificate, untrusted_cert: Certificate
    ):
        cert_file = _write_cert(tmp_path, "trusted.pem", trusted_rsa_cert)
        mw = PromptSignatureMiddleware(
            prompt_directories=[FIXTURES_DIR / "prompts"],
            trusted_certificates={"untrusted": untrusted_cert},
            trusted_certificate_paths={RSA_CERT_ID: cert_file},
        )
        next_called = False

        async def call_next():
            nonlocal next_called
            next_called = True

        await mw.process(FakeAgentContext(instructions=SIGNED_PROMPT), call_next)
        assert next_called is True

    async def test_cached_false_blocks_without_reverification(self, middleware: PromptSignatureMiddleware):
        """A prompt rejected once is rejected again from cache without re-verifying."""
        with pytest.raises(MiddlewareTermination):
            await middleware.process(FakeAgentContext(instructions="Unknown prompt not in catalog"), AsyncMock())

        with pytest.raises(MiddlewareTermination):
            await middleware.process(FakeAgentContext(instructions="Unknown prompt not in catalog"), AsyncMock())

    async def test_instructions_from_default_options(self, trusted_rsa_cert: Certificate):
        """Middleware reads instructions from agent.default_options dict when present."""
        mw = PromptSignatureMiddleware(
            prompt_directories=[FIXTURES_DIR / "prompts"],
            trusted_certificates={RSA_CERT_ID: trusted_rsa_cert},
        )

        class FakeCtxWithDefaultOptions:
            agent = SimpleNamespace(default_options={"instructions": SIGNED_PROMPT})
            messages = []
            result = None
            metadata: dict = {}

        next_called = False

        async def call_next():
            nonlocal next_called
            next_called = True

        await mw.process(FakeCtxWithDefaultOptions(), call_next)
        assert next_called is True

    def test_catalog_property_returns_loaded_prompts(self, middleware: PromptSignatureMiddleware):
        assert len(middleware.catalog) == 1
        assert middleware.catalog[0].text == SIGNED_PROMPT

    def test_catalog_property_returns_copy(self, middleware: PromptSignatureMiddleware):
        """Mutating the returned catalog list does not affect the middleware's internal state."""
        middleware.catalog.clear()
        assert len(middleware.catalog) == 1

    def test_no_certs_raises(self, tmp_path: Path):
        with pytest.raises(ValueError, match="At least one trusted certificate"):
            PromptSignatureMiddleware(prompt_directories=[tmp_path])
