# agent-signing

Sign and verify AI agent setups. Detects when tools, agents, or their configurations change -- and optionally proves *who* signed them.

- **Order-independent** -- reordering tools or agents in code does not invalidate the signature
- **Framework-agnostic** -- auto-discovers metadata from LangChain/LangGraph, CrewAI, or plain dicts
- **Three signing modes** -- HMAC (shared secret), Ed25519 (asymmetric keypair), JWT (identity tokens)
- **Zero framework dependencies** -- detection is duck-typed; `cryptography` is the only runtime dependency

## Installation

```bash
pip install agent-signing
```

Optional dependencies for running the demos:

```bash
pip install agent-signing[demo-langchain]  # LangChain / LangGraph demos
pip install agent-signing[demo-crewai]     # CrewAI demo
```

## Quick start

```python
from agent_signing import AgentSigner

signer = AgentSigner()
signer.add_tool({"name": "search", "description": "Search the web", "parameters": {"query": "str"}})
signer.add_tool({"name": "calculator", "description": "Evaluate math", "parameters": {"expr": "str"}})
signature = signer.sign()

# Later -- rebuild the same setup and verify
verifier = AgentSigner()
verifier.add_tool({"name": "calculator", "description": "Evaluate math", "parameters": {"expr": "str"}})
verifier.add_tool({"name": "search", "description": "Search the web", "parameters": {"query": "str"}})
result = verifier.verify(signature)
assert result.valid  # True -- order doesn't matter
```

## Signing modes

### HMAC (shared secret)

```python
signer = AgentSigner(secret="my-secret-key")
signer.add_tool(my_tool)
signature = signer.sign()

verifier = AgentSigner(secret="my-secret-key")
verifier.add_tool(my_tool)
assert verifier.verify(signature)
```

### Ed25519 (asymmetric key pair)

Proves *who* signed the agent setup. Sign with a private key, verify with the corresponding public key.

```python
from agent_signing import AgentSigner, generate_keypair

private_key, public_key = generate_keypair()

# Sign
signer = AgentSigner(private_key=private_key)
signer.add_tool(my_tool)
signature = signer.sign()

# Verify (can be a different machine -- only needs the public key)
verifier = AgentSigner(public_key=public_key)
verifier.add_tool(my_tool)
result = verifier.verify(signature)
assert result.valid
```

### JWT identity token

Attach an identity token from an OAuth/OIDC provider. The token's claims are decoded and returned on verification.

```python
signer = AgentSigner(identity_token="eyJhbG...")
signer.add_tool(my_tool)
signature = signer.sign()

verifier = AgentSigner()
verifier.add_tool(my_tool)
result = verifier.verify(signature)
assert result.valid
print(result.identity)  # {"sub": "user@example.com", "iss": "https://accounts.google.com"}
```

Ed25519 and JWT can be combined for both cryptographic proof and identity context.

## Signature files

Write signatures to disk with `sign_to_file()` and verify with `verify_file()`. The file includes the signing timestamp, public key, hash, and signature.

```python
from agent_signing import AgentSigner, generate_keypair

private_key, public_key = generate_keypair()

signer = AgentSigner(private_key=private_key)
signer.add_tool(my_tool)
signer.sign_to_file("agent_signature.json")
# Creates:
# {
#   "signed_at": "2025-06-15T12:00:00+00:00",
#   "public_key": "abcd1234...",
#   "hash": "842f9705...",
#   "signature": "{\"hash\": ...}"
# }

# Later -- verify against the file
verifier = AgentSigner(public_key=public_key)
verifier.add_tool(my_tool)
result = verifier.verify_file("agent_signature.json")
assert result.valid

# Inspect the file contents
record = AgentSigner.load_signature_file("agent_signature.json")
print(record["signed_at"], record["public_key"])
```

## Framework support

### LangChain / LangGraph

`add_tool()` accepts any LangChain `BaseTool` (including `@tool`-decorated functions) and auto-extracts `name`, `description`, and `args` (parameter schema).

`add_agent()` accepts a LangGraph `CompiledStateGraph` (from `create_react_agent`) and auto-discovers all tools bound to the agent.

```python
from langchain_core.tools import tool
from langchain.agents import create_agent
from agent_signing import AgentSigner, generate_keypair

@tool
def search(query: str) -> str:
    """Search the web."""
    return "results"

agent = create_agent(llm, [search])

private_key, public_key = generate_keypair()
signer = AgentSigner(private_key=private_key)
signer.add_agent(agent)  # auto-discovers all tools bound to the agent
signer.sign_to_file("agent_signature.json")
```

### CrewAI

`add_tool()` accepts CrewAI `BaseTool` objects and extracts `name`, `description`, and `args_schema`.

`add_agent()` accepts CrewAI `Agent` objects and extracts `role`, `goal`, `backstory`, `llm`, and `tools`.

```python
from crewai import Agent
from crewai.tools import tool
from agent_signing import AgentSigner, generate_keypair

@tool("search")
def search(query: str) -> str:
    """Search for information."""
    return "results"

researcher = Agent(
    role="Researcher",
    goal="Find accurate information",
    backstory="You are a skilled researcher.",
    tools=[search],
)

private_key, public_key = generate_keypair()
signer = AgentSigner(private_key=private_key)
signer.add_tool(search)
signer.add_agent(researcher)
signer.sign_to_file("agent_signature.json")
```

### Plain dicts

For any other framework, pass plain dicts:

```python
signer.add_tool({"name": "search", "description": "Search the web", "parameters": {"query": "str"}})
signer.add_agent({"name": "researcher", "role": "Researcher", "goal": "Find info"})
```

## What gets signed

The signature covers the *semantic definition* of the agent setup, not the source code. Specifically:

| Component | Fields extracted |
|-----------|----------------|
| **LangChain tool** | `name`, `description`, `args` (JSON schema) |
| **CrewAI tool** | `name`, `description`, `args_schema` (JSON schema) |
| **LangGraph agent** | tools discovered via `nodes["tools"]` |
| **CrewAI agent** | `role`, `goal`, `backstory`, `llm`, `tools` |
| **Dict** | all keys passed |

The signature changes when any of these fields change. It does **not** change when:
- Tools or agents are reordered in code
- Unrelated code around the agent setup changes
- Runtime state (e.g., conversation history) changes

## API reference

### `AgentSigner(secret=None, private_key=None, public_key=None, identity_token=None)`

| Parameter | Type | Description |
|-----------|------|-------------|
| `secret` | `str \| None` | HMAC shared secret |
| `private_key` | `bytes \| None` | Ed25519 private key (32 bytes) for signing |
| `public_key` | `bytes \| None` | Ed25519 public key (32 bytes) for verification |
| `identity_token` | `str \| None` | JWT string to attach to the signature |

### Methods

| Method | Description |
|--------|-------------|
| `add_tool(tool)` | Register a tool (framework object or dict) |
| `add_agent(agent)` | Register an agent (framework object or dict) |
| `sign() -> str` | Compute and return the signature |
| `sign_to_file(path) -> str` | Sign and write a JSON signature file (timestamp, public key, hash, signature) |
| `verify(signature) -> VerificationResult` | Verify against a previous signature |
| `verify_file(path) -> VerificationResult` | Verify against a signature file |
| `load_signature_file(path) -> dict` | *(static)* Read and return a signature file's contents |

### `VerificationResult`

| Field | Type | Description |
|-------|------|-------------|
| `valid` | `bool` | Whether verification passed |
| `reason` | `str` | Human-readable explanation |
| `identity` | `dict \| None` | Decoded JWT claims (when JWT was used) |

Supports `bool()` -- use `if result:` directly.

### `generate_keypair() -> tuple[bytes, bytes]`

Returns `(private_key, public_key)` as raw 32-byte Ed25519 keys.

## License

[Apache 2.0](LICENSE)
