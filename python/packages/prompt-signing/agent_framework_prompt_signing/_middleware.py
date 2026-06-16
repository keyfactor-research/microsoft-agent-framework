# Copyright (c) Microsoft. All rights reserved.
"""Agent Framework middleware that validates digitally signed system prompts."""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, Sequence
from pathlib import Path
from typing import NoReturn, cast

from agent_framework import AgentContext, AgentMiddleware, AgentResponse, Message, MiddlewareTermination
from cryptography.x509 import Certificate

from agent_framework_prompt_signing._models import SignedPrompt, load_prompt_catalog
from agent_framework_prompt_signing._signer import PromptSigner, load_certificates_from_file

logger = logging.getLogger(__name__)


class PromptSignatureMiddleware(AgentMiddleware):
    """Middleware that blocks agent execution when the system prompt has not been signed by a trusted certificate.

    The middleware scans one or more directories for YAML prompt files.
    Each YAML file contains a prompt, its digital signature, and the
    certificate ID used to sign it.  At runtime the middleware matches
    the agent's ``instructions`` against the catalog of signed prompts
    and verifies the signature with the referenced certificate.

    Usage::

        middleware = PromptSignatureMiddleware(
            prompt_directories=["prompts/"],
            trusted_certificates={"cert-1": cert},
        )
        agent = Agent(
            client=my_client,
            instructions="You are a helpful assistant.",
            middleware=[middleware],
        )
    """

    def __init__(
        self,
        prompt_directories: Sequence[str | Path],
        trusted_certificates: dict[str, Certificate] | None = None,
        *,
        trusted_certificate_paths: dict[str, str | Path] | None = None,
        rejection_message: str = (
            "System prompt signature verification failed. The agent cannot process this request."
        ),
    ) -> None:
        cert_map: dict[str, Certificate] = {}
        if trusted_certificates:
            cert_map.update(trusted_certificates)
        if trusted_certificate_paths:
            for cert_id, path in trusted_certificate_paths.items():
                loaded = load_certificates_from_file(path)
                if loaded:
                    cert_map[cert_id] = loaded[0]
        if not cert_map:
            raise ValueError(
                "At least one trusted certificate is required. "
                "Pass trusted_certificates and/or trusted_certificate_paths."
            )

        self._catalog = load_prompt_catalog(prompt_directories)
        self._prompt_index: dict[str, SignedPrompt] = {sp.text: sp for sp in self._catalog}
        self._signer = PromptSigner(cert_map)
        self._rejection_message = rejection_message
        self._cache: dict[str, bool] = {}

    @property
    def catalog(self) -> list[SignedPrompt]:
        """Return the loaded prompt catalog."""
        return list(self._catalog)

    async def process(
        self,
        context: AgentContext,
        call_next: Callable[[], Awaitable[None]],
    ) -> None:
        """Verify the agent's system prompt signature before allowing execution."""
        current_instructions = self._get_instructions(context)

        if current_instructions is None:
            logger.warning("Agent has no instructions to verify.")
            self._terminate(context)

        cached = self._cache.get(current_instructions)
        if cached is True:
            await call_next()
            return
        if cached is False:
            self._terminate(context)

        signed_prompt = self._prompt_index.get(current_instructions)
        if signed_prompt is None:
            logger.warning(
                "Agent instructions not found in the signed prompt catalog. "
                "The prompt may be unsigned or tampered with."
            )
            self._cache[current_instructions] = False
            self._terminate(context)

        if not self._signer.verify(signed_prompt):
            logger.warning("System prompt signature verification FAILED.")
            self._cache[current_instructions] = False
            self._terminate(context)

        logger.info("System prompt signature verified successfully.")
        self._cache[current_instructions] = True
        await call_next()

    @staticmethod
    def _get_instructions(context: AgentContext) -> str | None:
        """Extract the instructions string from the agent."""
        agent = context.agent
        default_opts = getattr(agent, "default_options", None)
        if isinstance(default_opts, dict) and "instructions" in default_opts:
            return cast(str, default_opts["instructions"])
        return cast("str | None", getattr(agent, "instructions", None))

    def _terminate(self, context: AgentContext) -> NoReturn:
        """Stop the pipeline and set an error response."""
        context.result = AgentResponse(messages=[Message("assistant", [self._rejection_message])])
        raise MiddlewareTermination
