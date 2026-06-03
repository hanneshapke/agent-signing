"""CLI entry point for the registry server."""

import uvicorn


def main():
    uvicorn.run("server.backend.main:app", host="127.0.0.1", port=8000, reload=True)
