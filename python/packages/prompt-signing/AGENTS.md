# Prompt Signing Package (agent-framework-prompt-signing)

Security middleware that cryptographically verifies agent system prompts are signed by trusted X.509 certificates before allowing execution.

## Main Classes

### Middleware

- **`PromptSignatureMiddleware`** — Agent middleware that verifies RSA-PSS or ECDSA prompt signatures against a YAML catalog
- **`CmsPromptSignatureMiddleware`** — Extends `PromptSignatureMiddleware` to also accept CMS/PKCS#7 detached signatures (RSA, ECDSA, ML-DSA)

### Verification

- **`PromptSigner`** — Verifies `SignedPrompt` objects against trusted X.509 certificates
- **`CmsPromptSigner`** — Extends `PromptSigner` to also verify CMS/PKCS#7 envelopes

### Models

- **`SignedPrompt`** — Immutable dataclass holding prompt text, raw signature bytes, and optional `certificate_id`
- **`load_prompt_catalog(directories)`** — Scans directories for YAML files and returns a list of `SignedPrompt` objects

## Usage

Prompts are signed externally and stored as YAML files. The middleware loads the catalog at startup and verifies each agent's instructions before allowing execution.

```python
from cryptography.x509 import load_pem_x509_certificate
from agent_framework_prompt_signing import CmsPromptSignatureMiddleware

with open("trusted_cert.pem", "rb") as f:
    certificate = load_pem_x509_certificate(f.read())

middleware = CmsPromptSignatureMiddleware(
    prompt_directories=["prompts/"],
    trusted_certificates={"cert-1": certificate},
)
```

## Prompt Catalog Format (YAML)

```yaml
prompt: "The exact system prompt text."
signature: "base64-encoded-detached-signature"
certificate_id: "cert-identifier"
```

## Import Path

```python
from agent_framework_prompt_signing import (
    CmsPromptSignatureMiddleware,
    CmsPromptSigner,
    PromptSignatureMiddleware,
    PromptSigner,
    SignedPrompt,
)
```
