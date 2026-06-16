# Copyright (c) Microsoft. All rights reserved.
"""Utilities for verifying system prompts signed with X.509 certificates."""

from __future__ import annotations

import logging
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agent_framework_prompt_signing._models import SignedPrompt

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, types
from cryptography.x509 import Certificate, load_pem_x509_certificate

logger = logging.getLogger(__name__)


def load_certificates_from_pem(pem_data: str | bytes) -> list[Certificate]:
    """Load one or more X.509 certificates from PEM-encoded data.

    Supports PEM bundles (multiple certificates concatenated).
    """
    if isinstance(pem_data, str):
        pem_data = pem_data.encode("utf-8")

    certs: list[Certificate] = []
    marker = b"-----BEGIN CERTIFICATE-----"
    parts = pem_data.split(marker)
    for part in parts[1:]:
        cert_pem = marker + part
        certs.append(load_pem_x509_certificate(cert_pem))
    return certs


def load_certificates_from_file(path: str | Path) -> list[Certificate]:
    """Load certificates from a PEM file on disk."""
    return load_certificates_from_pem(Path(path).read_bytes())


def _verify_with_public_key(
    public_key: types.PublicKeyTypes,
    signature: bytes,
    data: bytes,
) -> bool:
    """Verify *signature* over *data* using a public key. Returns True on success."""
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.AUTO,
                ),
                hashes.SHA256(),
            )
            return True
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
            return True
    except InvalidSignature:
        return False
    raise TypeError(f"Unsupported public key type: {type(public_key).__name__}")


class PromptSigner:
    """Verifies system prompts against trusted X.509 certificates.

    Certificates are indexed by an ID string. When verifying a
    :class:`SignedPrompt` that carries a ``certificate_id``, only the
    matching certificate is tried.  If no ID is present, all trusted
    certificates are tried.

    Usage::

        signer = PromptSigner(trusted_certificates={"my-cert": cert})
        is_valid = signer.verify(signed)
    """

    def __init__(
        self,
        trusted_certificates: Sequence[Certificate] | dict[str, Certificate],
    ) -> None:
        if isinstance(trusted_certificates, dict):
            self._cert_map: dict[str, Certificate] = dict(trusted_certificates)
        else:
            self._cert_map = {str(cert.serial_number): cert for cert in trusted_certificates}
        if not self._cert_map:
            raise ValueError("At least one trusted certificate is required.")

    @property
    def trusted_certificates(self) -> dict[str, Certificate]:
        """Return a copy of the trusted certificate map."""
        return dict(self._cert_map)

    def verify(self, signed_prompt: SignedPrompt) -> bool:
        """Verify *signed_prompt* against the trusted certificates.

        If the prompt has a ``certificate_id``, only that certificate is
        checked.  Otherwise all trusted certificates are tried.

        Returns ``True`` if the signature is valid, ``False`` otherwise.
        """
        data = signed_prompt.text.encode("utf-8")

        if signed_prompt.certificate_id:
            cert = self._cert_map.get(signed_prompt.certificate_id)
            if cert is None:
                logger.debug("Certificate ID '%s' not found in trusted set.", signed_prompt.certificate_id)
                return False
            certs_to_try = [cert]
        else:
            certs_to_try = list(self._cert_map.values())

        for cert in certs_to_try:
            public_key = cert.public_key()
            try:
                if _verify_with_public_key(public_key, signed_prompt.signature, data):
                    logger.debug("Prompt signature verified with certificate: %s", cert.subject)
                    return True
            except TypeError:
                continue
        return False
