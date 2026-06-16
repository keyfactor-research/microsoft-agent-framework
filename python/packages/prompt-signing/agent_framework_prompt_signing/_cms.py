# Copyright (c) Microsoft. All rights reserved.
"""CMS/PKCS#7 detached-signature support for prompt verification."""

from __future__ import annotations

import logging
from typing import Any, cast

from asn1crypto import cms as _asn1_cms_untyped
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes
from cryptography.hazmat.primitives.hashes import Hash
from cryptography.x509 import Certificate

from agent_framework_prompt_signing._middleware import PromptSignatureMiddleware
from agent_framework_prompt_signing._models import SignedPrompt
from agent_framework_prompt_signing._signer import PromptSigner

logger = logging.getLogger(__name__)

# Cast untyped asn1crypto module to Any so pyright doesn't propagate Unknown through it.
_asn1_cms: Any = cast(Any, _asn1_cms_untyped)

# DER OID for id-signedData (1.2.840.113549.1.7.2) — identifies a CMS envelope.
_CMS_SIGNED_DATA_OID = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02"

# Supported digest algorithms mapped to their cryptography hash classes.
_HASH_ALGORITHMS: dict[str, type[hashes.HashAlgorithm]] = {
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
}


class CmsPromptSigner(PromptSigner):
    """Extends PromptSigner to also accept CMS/PKCS#7 detached signatures.

    RSA, ECDSA, and ML-DSA (post-quantum) CMS signatures are all supported.
    """

    def verify(self, signed_prompt: SignedPrompt) -> bool:
        """Verify the prompt signature, dispatching to CMS parsing for CMS envelopes."""
        if _CMS_SIGNED_DATA_OID not in signed_prompt.signature[:32]:
            return super().verify(signed_prompt)

        cert_map = self.trusted_certificates
        if signed_prompt.certificate_id:
            cert = cert_map.get(signed_prompt.certificate_id)
            if cert is None:
                logger.debug("Certificate ID '%s' not found in trusted set.", signed_prompt.certificate_id)
                return False
            certs_to_try = [cert]
        else:
            certs_to_try = list(cert_map.values())

        data = signed_prompt.text.encode("utf-8")
        return any(_verify_cms(cert, signed_prompt.signature, data) for cert in certs_to_try)


class CmsPromptSignatureMiddleware(PromptSignatureMiddleware):
    """PromptSignatureMiddleware that uses CmsPromptSigner for verification."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._signer = CmsPromptSigner(self._signer.trusted_certificates)


def _verify_cms(cert: Certificate, signature: bytes, data: bytes) -> bool:
    """Verify a DER-encoded CMS detached signature using asn1crypto + cryptography (the python library).

    Parses the SignedData structure, validates the content digest against the
    messageDigest signed attribute, and verifies the cryptographic signature
    using the trusted certificate's public key.
    """
    try:
        content_info: Any = _asn1_cms.ContentInfo.load(signature)
        if content_info["content_type"].native != "signed_data":
            logger.debug("CMS content type is not SignedData.")
            return False
        signed_data: Any = content_info["content"]
        return any(_verify_signer_info(signer_info, cert, data) for signer_info in signed_data["signer_infos"])
    except Exception:
        logger.debug("CMS verification failed.", exc_info=True)
        return False


def _verify_signer_info(signer_info: Any, cert: Certificate, data: bytes) -> bool:
    """Verify a single SignerInfo against a trusted certificate and the raw content."""
    digest_alg_name = signer_info["digest_algorithm"]["algorithm"].native
    signed_attrs = signer_info["signed_attrs"]

    if signed_attrs.native:
        # Signed attributes present: verify content digest then verify sig over signed attrs.
        msg_digest = _extract_message_digest(signed_attrs)
        if msg_digest is None:
            logger.debug("messageDigest attribute not found in signed attributes.")
            return False

        hash_alg = _make_hash_algorithm(digest_alg_name, len(msg_digest))
        if hash_alg is None:
            logger.debug("Unsupported digest algorithm: %s", digest_alg_name)
            return False

        computed_digest = _compute_digest(data, hash_alg)
        if computed_digest != msg_digest:
            logger.debug("Content digest mismatch in signed attributes.")
            return False

        # Re-encode signed attrs with SET OF tag (0x31) replacing [0] IMPLICIT tag (0xa0).
        to_verify = b"\x31" + signer_info["signed_attrs"].dump()[1:]
        hash_alg_for_sig = _make_hash_algorithm(digest_alg_name, len(msg_digest))
    else:
        to_verify = data
        hash_alg_for_sig = _make_hash_algorithm(digest_alg_name, 0)

    sig_bytes = bytes(signer_info["signature"])
    sig_alg = signer_info["signature_algorithm"]["algorithm"].native
    return _verify_signature(cert.public_key(), sig_bytes, to_verify, hash_alg_for_sig, sig_alg)


def _compute_digest(data: bytes, hash_alg: hashes.HashAlgorithm) -> bytes:
    """Return the digest of *data* using *hash_alg*."""
    hasher = Hash(hash_alg)
    hasher.update(data)
    return hasher.finalize()


def _extract_message_digest(signed_attrs: Any) -> bytes | None:
    """Return the messageDigest value from a SignedAttributes set, or None if absent."""
    for attr in signed_attrs:
        if attr["type"].native == "message_digest":
            return bytes(attr["values"][0].native)
    return None


def _make_hash_algorithm(alg_name: str, digest_len: int) -> hashes.HashAlgorithm | None:
    """Return a hash algorithm instance for *alg_name*.

    For XOFs like SHAKE-256, *digest_len* determines the output size.
    Returns None for unsupported algorithms.
    """
    cls = _HASH_ALGORITHMS.get(alg_name)
    if cls is not None:
        return cls()
    if alg_name == "shake256":
        return hashes.SHAKE256(digest_len)
    if alg_name == "shake128":
        return hashes.SHAKE128(digest_len)
    return None


def _verify_signature(
    public_key: CertificatePublicKeyTypes,
    sig_bytes: bytes,
    data: bytes,
    hash_alg: hashes.HashAlgorithm | None,
    sig_alg: str,
) -> bool:
    """Verify *sig_bytes* over *data* using the given public key and algorithms."""
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            if hash_alg is None:
                return False
            if "pss" in sig_alg:
                public_key.verify(
                    sig_bytes,
                    data,
                    padding.PSS(mgf=padding.MGF1(hash_alg), salt_length=padding.PSS.AUTO),
                    hash_alg,
                )
            else:
                public_key.verify(sig_bytes, data, padding.PKCS1v15(), hash_alg)
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            if hash_alg is None:
                return False
            public_key.verify(sig_bytes, data, ec.ECDSA(hash_alg))
        else:
            # ML-DSA and other post-quantum types: verify(signature, data) with no hash argument.
            public_key.verify(sig_bytes, data)  # type: ignore[call-arg]
        return True
    except (InvalidSignature, Exception):
        return False
