"""Pydantic models for the signature registry API."""

from pydantic import BaseModel


class SignatureSubmission(BaseModel):
    """Request body for POST /signatures.

    Matches the JSON structure produced by AgentSigner.sign_to_file().
    """

    signed_at: str
    public_key: str | None
    hash: str
    signature: str


class SignatureResponse(BaseModel):
    """Response body for signature records."""

    signed_at: str
    public_key: str | None
    hash: str
    signature: str
    registered_at: str


class SignatureListResponse(BaseModel):
    """Response body for GET /signatures."""

    signatures: list[SignatureResponse]
    total: int
