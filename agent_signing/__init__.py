"""Agent signing module."""

from importlib.metadata import version

__version__ = version("agent-signing")

from agent_signing.signer import AgentSigner, VerificationResult, generate_keypair

__all__ = ["AgentSigner", "VerificationResult", "generate_keypair"]
