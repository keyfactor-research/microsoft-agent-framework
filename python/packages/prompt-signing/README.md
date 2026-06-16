# agent-framework-prompt-signing

Prompt-signing security middleware for [Microsoft Agent Framework](https://github.com/microsoft/agent-framework). Cryptographically verifies that agent system prompts are signed by trusted X.509 certificates before allowing execution, preventing prompt injection and tampering.

## Installation

```bash
pip install agent-framework-prompt-signing
```

## Quick start

```python
from agent_framework import Agent
from agent_framework_prompt_signing import PromptSignatureMiddleware

# Point the middleware at a directory of pre-signed YAML prompt files
# and a trusted X.509 certificate. Signing is done out-of-band.
middleware = PromptSignatureMiddleware(
    prompt_directories=["prompts/"],
    trusted_certificate_paths={"my-cert": "trusted_cert.pem"},
)
agent = Agent(client=..., instructions="You are a helpful assistant.", middleware=[middleware])
```

See [PROMPT_SIGNING_SETUP.md](../../../../PROMPT_SIGNING_SETUP.md) for full setup and usage instructions.
