"""
Agent signing and verification logic.

Signs the semantic definition of an agent setup — its tools, agents, and
their configurations — producing a deterministic, order-independent signature.
If any tool definition, agent config, or parameter changes, the signature
is invalidated.

Supports three signing modes:
- HMAC (shared secret) — default
- Ed25519 (asymmetric key pair) — proves signer identity
- JWT identity token — attaches identity claims from an OAuth/OIDC provider

Supports LangChain/LangGraph, CrewAI, and plain dicts via duck-typing
(no hard dependencies on any framework).
"""

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate an Ed25519 key pair.

    Returns
    -------
    tuple[bytes, bytes]
        (private_key_bytes, public_key_bytes) — raw 32-byte keys.
    """
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return private_bytes, public_bytes


def _decode_jwt_claims(token: str) -> dict[str, Any]:
    """Decode a JWT payload without verifying the signature.

    Only extracts the claims from the payload section (second segment).
    JWT signature verification is the caller's responsibility.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format: expected 3 dot-separated segments")
    payload = parts[1]
    # Add padding if needed
    padding = 4 - len(payload) % 4
    if padding != 4:
        payload += "=" * padding
    return json.loads(base64.urlsafe_b64decode(payload))


@dataclass
class VerificationResult:
    """Result returned by ``AgentSigner.verify()``."""

    valid: bool
    reason: str
    identity: dict[str, Any] | None = field(default=None)

    def __bool__(self) -> bool:
        return self.valid

    def __repr__(self) -> str:
        return f"VerificationResult(valid={self.valid}, reason={self.reason!r})"


class AgentSigner:
    """Sign and verify agent setups.

    Accepts framework tool/agent objects (LangChain, CrewAI, etc.) or plain
    dicts.  Automatically extracts the relevant configuration and produces
    an order-independent signature.

    Parameters
    ----------
    secret : str | None
        Optional HMAC secret.  When provided the signature is an HMAC-SHA256
        keyed with this secret, making it unforgeable without the key.
    private_key : bytes | None
        Ed25519 private key (raw 32 bytes) for signing.
    public_key : bytes | None
        Ed25519 public key (raw 32 bytes) for verification.
    identity_token : str | None
        JWT string to attach to the signature for identity context.
    """

    def __init__(
        self,
        secret: str | None = None,
        private_key: bytes | None = None,
        public_key: bytes | None = None,
        identity_token: str | None = None,
    ) -> None:
        self._secret = secret.encode() if secret else None
        self._private_key = private_key
        self._public_key = public_key
        self._identity_token = identity_token
        self._components: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_tool(self, tool: Any) -> None:
        """Register a tool for signing.

        Accepts a LangChain ``BaseTool``, CrewAI ``BaseTool``, or a plain
        dict with at least a ``name`` key.
        """
        self._components.append(self._extract_tool(tool))

    def add_agent(self, agent: Any) -> None:
        """Register an agent for signing.

        Accepts a LangGraph ``CompiledStateGraph``, CrewAI ``Agent``, or a
        plain dict with at least a ``name`` or ``role`` key.
        """
        self._components.append(self._extract_agent(agent))

    def sign(self) -> str:
        """Compute and return the signature.

        Returns
        -------
        str
            - HMAC mode: hex digest string
            - Ed25519 mode: base64-encoded signature
            - JWT mode: JSON string with hash, signature, and identity
            - Combined modes: JSON string with all fields
        """
        aggregate = self._compute_aggregate()

        # Determine the signature value
        if self._private_key:
            key = Ed25519PrivateKey.from_private_bytes(self._private_key)
            sig_bytes = key.sign(aggregate.encode())
            signature = base64.b64encode(sig_bytes).decode()
        elif self._secret:
            signature = hmac.new(self._secret, aggregate.encode(), hashlib.sha256).hexdigest()
        else:
            signature = aggregate

        # If JWT or Ed25519, return structured JSON
        if self._identity_token or self._private_key:
            result: dict[str, Any] = {
                "hash": aggregate,
                "signature": signature,
            }
            if self._identity_token:
                result["identity_token"] = self._identity_token
                result["identity"] = _decode_jwt_claims(self._identity_token)
            return json.dumps(result, sort_keys=True)

        return signature

    def verify(self, signature: str) -> VerificationResult:
        """Verify the current setup against a previously produced signature.

        Auto-detects the format (plain hex string vs JSON envelope).
        """
        aggregate = self._compute_aggregate()

        # Try to parse as JSON envelope
        try:
            envelope = json.loads(signature)
            if isinstance(envelope, dict) and "signature" in envelope:
                return self._verify_envelope(aggregate, envelope)
        except (json.JSONDecodeError, TypeError):
            pass

        # Plain string — HMAC or raw aggregate
        if self._public_key:
            return VerificationResult(
                valid=False,
                reason="Expected Ed25519 signed envelope but got plain string.",
            )

        current = self._compute_signature_value(aggregate)
        if hmac.compare_digest(current, signature):
            return VerificationResult(valid=True, reason="Signature valid.")
        return VerificationResult(valid=False, reason="Signature mismatch — agent setup has changed.")

    # ------------------------------------------------------------------
    # Extraction — duck-typed framework detection
    # ------------------------------------------------------------------

    def _extract_tool(self, tool: Any) -> dict[str, Any]:
        if isinstance(tool, dict):
            return {"type": "tool", **tool}

        extracted: dict[str, Any] = {"type": "tool"}

        # LangChain BaseTool: has .name, .description, .args (property returning JSON schema dict)
        if hasattr(tool, "name") and hasattr(tool, "description"):
            extracted["name"] = tool.name
            extracted["description"] = tool.description
            if hasattr(tool, "args"):
                extracted["parameters"] = tool.args
            elif hasattr(tool, "args_schema") and tool.args_schema is not None:
                extracted["parameters"] = tool.args_schema.model_json_schema()
            return extracted

        raise TypeError(f"Cannot extract tool info from {type(tool).__name__}")

    def _extract_agent(self, agent: Any) -> dict[str, Any]:
        if isinstance(agent, dict):
            return {"type": "agent", **agent}

        extracted: dict[str, Any] = {"type": "agent"}

        # LangGraph CompiledStateGraph: has .nodes dict with a "tools" ToolNode
        if hasattr(agent, "nodes") and isinstance(getattr(agent, "nodes", None), dict):
            tools_node = agent.nodes.get("tools")
            # tools_by_name may be on the node directly (older LangGraph)
            # or on node.bound (newer LangGraph wraps ToolNode in PregelNode)
            tool_map = None
            if tools_node and hasattr(tools_node, "tools_by_name"):
                tool_map = tools_node.tools_by_name
            elif tools_node and hasattr(getattr(tools_node, "bound", None), "tools_by_name"):
                tool_map = tools_node.bound.tools_by_name
            if tool_map:
                extracted["tools"] = sorted(
                    [self._extract_tool(t) for t in tool_map.values()],
                    key=lambda d: json.dumps(d, sort_keys=True),
                )
            return extracted

        # CrewAI Agent: has .role, .goal, .backstory
        if hasattr(agent, "role") and hasattr(agent, "goal"):
            extracted["role"] = agent.role
            extracted["goal"] = agent.goal
            if hasattr(agent, "backstory") and agent.backstory:
                extracted["backstory"] = agent.backstory
            if hasattr(agent, "llm") and agent.llm is not None:
                extracted["llm"] = str(agent.llm)
            if hasattr(agent, "tools") and agent.tools:
                extracted["tools"] = sorted(
                    [self._extract_tool(t) for t in agent.tools],
                    key=lambda d: json.dumps(d, sort_keys=True),
                )
            return extracted

        raise TypeError(f"Cannot extract agent info from {type(agent).__name__}")

    # ------------------------------------------------------------------
    # Hashing
    # ------------------------------------------------------------------

    def _compute_aggregate(self) -> str:
        """Compute the order-independent aggregate hash of all components."""
        component_hashes = sorted(
            hashlib.sha256(
                json.dumps(c, sort_keys=True, default=str).encode()
            ).hexdigest()
            for c in self._components
        )
        h = hashlib.sha256()
        for ch in component_hashes:
            h.update(ch.encode())
        return h.hexdigest()

    def _compute_signature_value(self, aggregate: str) -> str:
        """Produce HMAC or plain aggregate (for non-Ed25519 modes)."""
        if self._secret:
            return hmac.new(self._secret, aggregate.encode(), hashlib.sha256).hexdigest()
        return aggregate

    # ------------------------------------------------------------------
    # Envelope verification
    # ------------------------------------------------------------------

    def _verify_envelope(self, aggregate: str, envelope: dict) -> VerificationResult:
        """Verify a JSON envelope containing signature + optional identity."""
        stored_hash = envelope.get("hash", "")
        sig_value = envelope.get("signature", "")
        identity = None

        # Check aggregate hash matches
        if not hmac.compare_digest(aggregate, stored_hash):
            return VerificationResult(
                valid=False,
                reason="Signature mismatch — agent setup has changed.",
            )

        # Verify Ed25519 signature if we have a public key
        if self._public_key:
            try:
                key = Ed25519PublicKey.from_public_bytes(self._public_key)
                key.verify(base64.b64decode(sig_value), aggregate.encode())
            except Exception:
                return VerificationResult(
                    valid=False,
                    reason="Ed25519 signature verification failed.",
                )

        # Decode JWT identity if present
        if "identity_token" in envelope:
            try:
                identity = _decode_jwt_claims(envelope["identity_token"])
            except Exception:
                return VerificationResult(
                    valid=False,
                    reason="Failed to decode identity token.",
                )

        return VerificationResult(
            valid=True,
            reason="Signature valid.",
            identity=identity,
        )
