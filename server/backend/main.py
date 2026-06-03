"""FastAPI application for the Agent Signing Registry."""

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from agent_signing.signer import aggregate_hash

from .database import get_by_hash, get_recent, init_db, insert_signature
from .models import SignatureListResponse, SignatureResponse, SignatureSubmission

FRONTEND_DIR = Path(__file__).parent.parent / "frontend"


def _summarize(components: list[dict[str, Any]]) -> dict[str, Any]:
    """Derive a display summary of the signed tools and agents."""
    tools: list[dict[str, Any]] = []
    agents: list[dict[str, Any]] = []
    for c in components:
        kind = c.get("type")
        if kind == "tool":
            params = c.get("parameters")
            param_names = list(params.keys()) if isinstance(params, dict) else []
            tools.append(
                {
                    "name": c.get("name"),
                    "description": c.get("description"),
                    "parameters": param_names,
                }
            )
        elif kind == "agent":
            nested = c.get("tools")
            tool_names: list[str] = []
            if isinstance(nested, list):
                for t in nested:
                    if isinstance(t, dict) and t.get("name"):
                        tool_names.append(t["name"])
                    elif isinstance(t, str):
                        tool_names.append(t)
            agents.append(
                {
                    "name": c.get("name"),
                    "role": c.get("role"),
                    "goal": c.get("goal"),
                    "llm": c.get("llm"),
                    "tools": tool_names,
                }
            )
    return {
        "tool_count": len(tools),
        "agent_count": len(agents),
        "tools": tools,
        "agents": agents,
    }


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="Agent Signing Registry",
    version="0.1.0",
    lifespan=lifespan,
)


@app.post("/signatures", response_model=SignatureResponse, status_code=201)
async def submit_signature(body: SignatureSubmission):
    """Submit a signature record to the registry.

    When the submission includes the signed ``components``, the registry
    re-derives the aggregate hash from them and records whether it matches the
    submitted hash, so the served tool/agent summary is verifiable rather than
    self-asserted.
    """
    components_verified: bool | None = None
    summary: dict[str, Any] | None = None
    if body.components is not None:
        summary = _summarize(body.components)
        components_verified = aggregate_hash(body.components) == body.hash

    result = insert_signature(
        signed_at=body.signed_at,
        public_key=body.public_key,
        hash_val=body.hash,
        signature=body.signature,
        name=body.name,
        email=body.email,
        components_verified=components_verified,
        summary=summary,
    )
    return result


@app.get("/signatures/{hash_value}", response_model=list[SignatureResponse])
async def lookup_signature(hash_value: str):
    """Look up signature records by aggregate hash."""
    results = get_by_hash(hash_value)
    if not results:
        raise HTTPException(status_code=404, detail="No signatures found for this hash.")
    return results


@app.get("/signatures", response_model=SignatureListResponse)
async def list_signatures(limit: int = 20, offset: int = 0):
    """List recent signatures."""
    sigs, total = get_recent(limit=min(limit, 100), offset=offset)
    return SignatureListResponse(signatures=sigs, total=total)


@app.get("/")
async def serve_frontend():
    """Serve the frontend UI."""
    return FileResponse(FRONTEND_DIR / "index.html")


app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")
