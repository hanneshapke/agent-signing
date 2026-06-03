"""Pydantic models for the signature registry API."""

from typing import Any

from pydantic import BaseModel


class ToolInfo(BaseModel):
    """A signed tool, summarised for display."""

    name: str | None = None
    description: str | None = None
    parameters: list[str] = []


class AgentInfo(BaseModel):
    """A signed agent, summarised for display."""

    name: str | None = None
    role: str | None = None
    goal: str | None = None
    llm: str | None = None
    tools: list[str] = []


class SetupSummary(BaseModel):
    """A human-readable summary of the signed tools and agents."""

    tool_count: int = 0
    agent_count: int = 0
    tools: list[ToolInfo] = []
    agents: list[AgentInfo] = []


class SignatureSubmission(BaseModel):
    """Request body for POST /signatures.

    Matches the JSON structure produced by AgentSigner.sign_to_file().
    ``name``/``email`` are self-declared signer metadata.  ``components`` is the
    optional list of signed tool/agent dicts; when present the registry
    re-derives the hash from them to confirm they match what was signed.
    """

    signed_at: str
    public_key: str | None = None
    hash: str
    signature: str
    name: str | None = None
    email: str | None = None
    components: list[dict[str, Any]] | None = None


class SignatureResponse(BaseModel):
    """Response body for signature records."""

    signed_at: str
    public_key: str | None
    hash: str
    signature: str
    registered_at: str
    name: str | None = None
    email: str | None = None
    # None = no components submitted; True/False = re-derived hash (mis)matched.
    components_verified: bool | None = None
    summary: SetupSummary | None = None
    # Google-authenticated submitter (bound via a personal upload token).
    submitter_email: str | None = None
    submitter_name: str | None = None
    submitter_verified: bool | None = None


class SignatureListResponse(BaseModel):
    """Response body for GET /signatures."""

    signatures: list[SignatureResponse]
    total: int
