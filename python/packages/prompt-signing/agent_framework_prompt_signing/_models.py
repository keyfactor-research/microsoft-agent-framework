# Copyright (c) Microsoft. All rights reserved.
"""Data models for signed prompt verification."""

from __future__ import annotations

import base64
import logging
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import yaml

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SignedPrompt:
    """A system prompt bundled with its cryptographic signature.

    Attributes:
        text: The system prompt text.
        signature: The detached digital signature (raw bytes).
        certificate_id: Identifier of the certificate used to sign.
    """

    text: str
    signature: bytes
    certificate_id: str = ""

    @classmethod
    def from_base64(
        cls,
        text: str,
        signature_b64: str,
        certificate_id: str = "",
    ) -> SignedPrompt:
        """Create a SignedPrompt from a base64-encoded signature string."""
        return cls(
            text=text,
            signature=base64.b64decode(signature_b64),
            certificate_id=certificate_id,
        )

    @property
    def signature_b64(self) -> str:
        """Return the signature as a base64-encoded string."""
        return base64.b64encode(self.signature).decode("ascii")


def load_prompt_catalog(
    directories: Sequence[str | Path],
) -> list[SignedPrompt]:
    """Scan *directories* for YAML files and return all signed prompts found.

    Each YAML file is expected to have the following structure::

        prompt: |
          You are a helpful assistant.
        signature: <base64-encoded signature>
        certificate_id: <id of the certificate used to sign>

    Files that cannot be parsed are logged as warnings and skipped.
    """
    prompts: list[SignedPrompt] = []
    for directory in directories:
        dir_path = Path(directory)
        if not dir_path.is_dir():
            logger.warning("Prompt catalog directory does not exist: %s", dir_path)
            continue
        for yaml_file in sorted(dir_path.glob("*.yaml")):
            try:
                raw: Any = yaml.safe_load(yaml_file.read_text(encoding="utf-8"))
                if not isinstance(raw, dict):
                    logger.warning("Skipping %s: root is not a mapping", yaml_file)
                    continue
                data = cast(dict[str, Any], raw)
                prompts.append(
                    SignedPrompt.from_base64(
                        text=data["prompt"],
                        signature_b64=data["signature"],
                        certificate_id=data.get("certificate_id", ""),
                    )
                )
            except Exception:
                logger.warning("Failed to load prompt from %s", yaml_file, exc_info=True)
    return prompts
