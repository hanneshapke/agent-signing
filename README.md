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
pip install agent-signing[server]          # Registry server (FastAPI + uvicorn)
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

## Command-line interface

Installing the package adds an `agent-signing` command for key generation, signing, verification, and publishing -- no Python code required.

```bash
agent-signing --help            # list commands
agent-signing <command> --help  # options for a command
```

### Manifest format

`sign` and `verify` read the agent setup from a JSON manifest with `tools` and/or `agents` arrays. Each entry is a plain dict (see [Plain dicts](#plain-dicts)); at least one tool or agent is required.

```json
{
  "tools": [
    {"name": "search", "description": "Search the web", "parameters": {"query": "str"}},
    {"name": "calculator", "description": "Evaluate math", "parameters": {"expression": "str"}}
  ],
  "agents": [
    {"name": "researcher", "role": "Researcher", "goal": "Find info", "tools": ["search"]}
  ]
}
```

### `generate-keypair`

Generate an Ed25519 key pair, written as hex-encoded files.

```bash
agent-signing generate-keypair --out-dir ./keys --prefix agent
# writes ./keys/agent.private.key and ./keys/agent.public.key
```

| Option | Default | Description |
|--------|---------|-------------|
| `--out-dir` | `.` | Directory to write the key files into |
| `--prefix` | `agent` | Filename prefix (`<prefix>.private.key`, `<prefix>.public.key`) |

### `sign`

Sign a manifest and write a signature file. Choose a mode with `--secret` (HMAC) or `--private-key` (Ed25519); with neither, the bare aggregate hash is written.

```bash
# HMAC
agent-signing sign manifest.json --secret "my-secret"

# Ed25519, attaching identity + self-declared metadata, embedding components
agent-signing sign manifest.json \
    --private-key keys/agent.private.key \
    --identity-token "eyJhbG..." \
    --name "Ada Lovelace" --email ada@example.com \
    --include-components \
    -o agent_signature.json
```

| Option | Default | Description |
|--------|---------|-------------|
| `manifest` | -- | *(positional)* Path to the JSON manifest |
| `-o`, `--output` | `agent_signature.json` | Output signature file |
| `--secret` | -- | HMAC shared secret |
| `--private-key` | -- | Path to a hex-encoded Ed25519 private key file |
| `--identity-token` | -- | JWT identity token to attach |
| `--name` | -- | Self-declared signer name (informational) |
| `--email` | -- | Self-declared signer email (informational) |
| `--include-components` | off | Embed the signed tool/agent definitions in the file |

### `verify`

Re-derive the signature from a manifest and check it against a signature file. Exits non-zero on mismatch. Supply `--secret` or `--public-key` to match the signing mode; when a JWT was attached, the decoded identity is printed.

```bash
agent-signing verify manifest.json -s agent_signature.json --public-key keys/agent.public.key
```

| Option | Default | Description |
|--------|---------|-------------|
| `manifest` | -- | *(positional)* Path to the JSON manifest |
| `-s`, `--signature-file` | `agent_signature.json` | Signature file to verify against |
| `--registry-url` | -- | Fetch the approved signature from this registry instead of a local file |
| `--secret` | -- | HMAC shared secret used at signing time |
| `--public-key` | -- | Path to a hex-encoded Ed25519 public key file |

With `--registry-url`, the current setup's hash is looked up on the registry and verified against the registered signature — no local signature file required:

```bash
agent-signing verify manifest.json --registry-url http://localhost:8000 --public-key keys/agent.public.key
```

### `upload`

Publish an existing signature file to a registry server.

```bash
agent-signing upload http://localhost:8000 -s agent_signature.json
```

| Option | Default | Description |
|--------|---------|-------------|
| `registry_url` | -- | *(positional)* Base URL of the registry |
| `-s`, `--signature-file` | `agent_signature.json` | Signature file to upload |

The signature file carries whatever `sign` wrote into it, so `--name`, `--email`, and embedded `--include-components` are published too. See [Publishing the signed setup](#publishing-the-signed-setup).

## Signature registry

The optional registry server lets teams publish and inspect signatures in a central location.

### Running the server

```bash
pip install agent-signing[server]
uvicorn server.backend.main:app --reload
```

Open `http://localhost:8000` to browse the web UI -- search by hash or view recent signatures.

### Publishing signatures

Use `publish()` to submit a signature to the registry. It accepts an optional `path` to publish from an existing signature file, or signs on-the-fly.

```python
from agent_signing import AgentSigner, generate_keypair

private_key, public_key = generate_keypair()

signer = AgentSigner(private_key=private_key)
signer.add_tool(my_tool)
signer.sign_to_file("agent_signature.json")

# Publish from the signature file
signer.publish("http://localhost:8000", path="agent_signature.json")

# Or sign and publish in one step (no file needed)
signer.publish("http://localhost:8000")
```

### Publishing the signed setup

By default a published record contains only the hash and signature -- the registry never sees *which* tools and agents were signed. Pass `include_components=True` to also publish the signed component definitions. The registry re-derives the aggregate hash from them and confirms it matches the signed hash, so the tool/agent summary it displays is **verifiable** rather than self-asserted: a tampered list is flagged instead of trusted.

You can also attach a self-declared `name` and `email`. These are *not* covered by the signature (anyone can claim any name), so the registry labels them as self-declared.

```python
signer = AgentSigner(
    private_key=private_key,
    name="Ada Lovelace",
    email="ada@example.com",
)
signer.add_tool(my_tool)
signer.add_agent(my_agent)

# Embed the signed components so the registry can verify and display them
signer.publish("http://localhost:8000", include_components=True)
```

Or from the command line:

```bash
agent-signing sign manifest.json --private-key agent.private.key \
    --name "Ada Lovelace" --email ada@example.com --include-components
agent-signing upload http://localhost:8000 -s agent_signature.json
```

For each signature, the web UI then runs a real in-browser Ed25519 verification and shows the signer's key fingerprint, any decoded JWT identity, the delay between signing and registration, other signatures on the same hash (co-signatures), and -- when components were published -- the verified list of signed tools and agents.

### Verifying against the registry

`verify_from_registry()` is the network counterpart to `verify_file()`: instead of reading the approved signature from a local file, it fetches it from the shared registry. It computes the current setup's aggregate hash, looks it up on the registry (`GET /signatures/{hash}`), and verifies the setup against the registered signature(s).

```python
verifier = AgentSigner(public_key=public_key)
verifier.add_tool(my_tool)

result = verifier.verify_from_registry("http://localhost:8000")
if result.valid:
    print(result.reason)
    print(result.record["signed_at"])  # the matched registry record
```

A tampered setup hashes to a different value, for which no signature is registered, so the lookup returns nothing and verification fails. Trust is anchored in the material held by the verifier, **never** in the fetched record:

- **Ed25519** (`public_key` set): the registered signature must validate against your pinned public key. A record an attacker self-published under their own key for a tampered setup is rejected.
- **HMAC** (`secret` set): the registered signature must match an HMAC recomputed with your shared secret.
- **Neither**: only confirms that *a* signature for this exact setup is registered; the signer is not authenticated.

When multiple parties have co-signed the same hash, the first record that passes is returned in `result.record`.

### Registry API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/signatures` | `POST` | Submit a signature record |
| `/signatures/{hash}` | `GET` | Look up signatures by aggregate hash |
| `/signatures?limit=20&offset=0` | `GET` | List recent signatures (paginated) |
| `/` | `GET` | Web UI |

The `POST /signatures` body accepts optional `name`, `email`, and `components` fields in addition to the required `hash`, `signature`, `signed_at`, and `public_key`. When `components` are present the response includes `components_verified` and a `summary` of the signed tools and agents.

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

### `AgentSigner(secret=None, private_key=None, public_key=None, identity_token=None, name=None, email=None)`

| Parameter | Type | Description |
|-----------|------|-------------|
| `secret` | `str \| None` | HMAC shared secret |
| `private_key` | `bytes \| None` | Ed25519 private key (32 bytes) for signing |
| `public_key` | `bytes \| None` | Ed25519 public key (32 bytes) for verification |
| `identity_token` | `str \| None` | JWT string to attach to the signature |
| `name` | `str \| None` | Self-declared signer name (informational; not signed) |
| `email` | `str \| None` | Self-declared signer email (informational; not signed) |

### Methods

| Method | Description |
|--------|-------------|
| `add_tool(tool)` | Register a tool (framework object or dict) |
| `add_agent(agent)` | Register an agent (framework object or dict) |
| `components` | *(property)* The extracted tool/agent components that get signed |
| `sign() -> str` | Compute and return the signature |
| `sign_to_file(path, include_components=False) -> str` | Sign and write a JSON signature file (timestamp, public key, hash, signature; plus name/email and components when set) |
| `verify(signature) -> VerificationResult` | Verify against a previous signature |
| `verify_file(path) -> VerificationResult` | Verify against a signature file |
| `load_signature_file(path) -> dict` | *(static)* Read and return a signature file's contents |
| `publish(registry_url, path=None, include_components=False) -> dict` | Publish a signature to a registry server |

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
