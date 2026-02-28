"""FastAPI application for the Agent Signing Registry."""

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .database import get_by_hash, get_recent, init_db, insert_signature
from .models import SignatureListResponse, SignatureResponse, SignatureSubmission

FRONTEND_DIR = Path(__file__).parent.parent / "frontend"


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
    """Submit a signature record to the registry."""
    result = insert_signature(
        signed_at=body.signed_at,
        public_key=body.public_key,
        hash_val=body.hash,
        signature=body.signature,
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
