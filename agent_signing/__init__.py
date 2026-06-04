"""Agent signing module."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("agent-signing")
except PackageNotFoundError:  # running from source without installed metadata
    __version__ = "0.0.0"

from agent_signing.signer import AgentSigner, VerificationResult, generate_keypair

__all__ = ["AgentSigner", "VerificationResult", "generate_keypair"]
