"""Command-line interface for agent-signing.

Provides commands for generating keys, signing agent setups, uploading
signatures to a registry, and verifying signatures.
"""

import argparse
import json
import sys
from pathlib import Path

from agent_signing.signer import AgentSigner, VerificationResult, generate_keypair


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-signing",
        description="Sign, upload, and verify AI agent setups.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # --- generate-keypair ---
    kp = sub.add_parser(
        "generate-keypair",
        help="Generate an Ed25519 key pair and write to files.",
    )
    kp.add_argument(
        "--out-dir",
        default=".",
        help="Directory to write key files into (default: current directory).",
    )
    kp.add_argument(
        "--prefix",
        default="agent",
        help='Filename prefix for key files (default: "agent").',
    )

    # --- sign ---
    sign_p = sub.add_parser(
        "sign",
        help="Sign an agent setup defined in a JSON manifest.",
    )
    sign_p.add_argument(
        "manifest",
        help="Path to a JSON manifest describing tools and agents.",
    )
    sign_p.add_argument(
        "-o", "--output",
        default="agent_signature.json",
        help="Output signature file path (default: agent_signature.json).",
    )
    sign_p.add_argument(
        "--secret",
        help="HMAC shared secret for signing.",
    )
    sign_p.add_argument(
        "--private-key",
        help="Path to Ed25519 private key file (raw 32 bytes, hex-encoded).",
    )
    sign_p.add_argument(
        "--identity-token",
        help="JWT identity token to attach to the signature.",
    )

    # --- verify ---
    verify_p = sub.add_parser(
        "verify",
        help="Verify an agent setup against a signature file.",
    )
    verify_p.add_argument(
        "manifest",
        help="Path to a JSON manifest describing tools and agents.",
    )
    verify_p.add_argument(
        "-s", "--signature-file",
        default="agent_signature.json",
        help="Signature file to verify against (default: agent_signature.json).",
    )
    verify_p.add_argument(
        "--secret",
        help="HMAC shared secret used during signing.",
    )
    verify_p.add_argument(
        "--public-key",
        help="Path to Ed25519 public key file (raw 32 bytes, hex-encoded).",
    )

    # --- upload ---
    upload_p = sub.add_parser(
        "upload",
        help="Upload a signature to a registry server.",
    )
    upload_p.add_argument(
        "registry_url",
        help="Base URL of the registry server (e.g. http://localhost:8000).",
    )
    upload_p.add_argument(
        "-s", "--signature-file",
        default="agent_signature.json",
        help="Signature file to upload (default: agent_signature.json).",
    )

    return parser


def _load_manifest(path: str) -> dict:
    """Load and validate a JSON manifest file.

    Expected format::

        {
            "tools": [
                {"name": "search", "description": "Search the web", "parameters": {...}},
                ...
            ],
            "agents": [
                {"name": "researcher", "role": "Researcher", "goal": "Find info"},
                ...
            ]
        }
    """
    manifest_path = Path(path)
    if not manifest_path.exists():
        print(f"Error: manifest file not found: {path}", file=sys.stderr)
        sys.exit(1)

    try:
        data = json.loads(manifest_path.read_text())
    except json.JSONDecodeError as exc:
        print(f"Error: invalid JSON in manifest: {exc}", file=sys.stderr)
        sys.exit(1)

    if not isinstance(data, dict):
        print("Error: manifest must be a JSON object with 'tools' and/or 'agents' keys.", file=sys.stderr)
        sys.exit(1)

    tools = data.get("tools", [])
    agents = data.get("agents", [])

    if not tools and not agents:
        print("Error: manifest must contain at least one tool or agent.", file=sys.stderr)
        sys.exit(1)

    return data


def _read_hex_key(path: str) -> bytes:
    """Read a hex-encoded key file and return raw bytes."""
    key_path = Path(path)
    if not key_path.exists():
        print(f"Error: key file not found: {path}", file=sys.stderr)
        sys.exit(1)
    try:
        return bytes.fromhex(key_path.read_text().strip())
    except ValueError:
        print(f"Error: key file is not valid hex: {path}", file=sys.stderr)
        sys.exit(1)


def _populate_signer(signer: AgentSigner, manifest: dict) -> None:
    """Add tools and agents from a manifest dict to a signer."""
    for tool in manifest.get("tools", []):
        signer.add_tool(tool)
    for agent in manifest.get("agents", []):
        signer.add_agent(agent)


def cmd_generate_keypair(args: argparse.Namespace) -> None:
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    private_bytes, public_bytes = generate_keypair()

    priv_path = out_dir / f"{args.prefix}.private.key"
    pub_path = out_dir / f"{args.prefix}.public.key"

    priv_path.write_text(private_bytes.hex() + "\n")
    pub_path.write_text(public_bytes.hex() + "\n")

    print(f"Private key written to: {priv_path}")
    print(f"Public key written to:  {pub_path}")


def cmd_sign(args: argparse.Namespace) -> None:
    manifest = _load_manifest(args.manifest)

    private_key = _read_hex_key(args.private_key) if args.private_key else None

    signer = AgentSigner(
        secret=args.secret,
        private_key=private_key,
        identity_token=args.identity_token,
    )
    _populate_signer(signer, manifest)

    signature = signer.sign_to_file(args.output)
    record = AgentSigner.load_signature_file(args.output)

    print(f"Signature written to: {args.output}")
    print(f"  signed_at:  {record['signed_at']}")
    if record.get("public_key"):
        print(f"  public_key: {record['public_key']}")
    print(f"  hash:       {record['hash']}")


def cmd_verify(args: argparse.Namespace) -> None:
    manifest = _load_manifest(args.manifest)

    sig_path = Path(args.signature_file)
    if not sig_path.exists():
        print(f"Error: signature file not found: {args.signature_file}", file=sys.stderr)
        sys.exit(1)

    public_key = _read_hex_key(args.public_key) if args.public_key else None

    verifier = AgentSigner(
        secret=args.secret,
        public_key=public_key,
    )
    _populate_signer(verifier, manifest)

    result: VerificationResult = verifier.verify_file(sig_path)

    if result.valid:
        print(f"Verification PASSED: {result.reason}")
        if result.identity:
            print(f"  Identity: {json.dumps(result.identity, indent=2)}")
    else:
        print(f"Verification FAILED: {result.reason}", file=sys.stderr)
        sys.exit(1)


def cmd_upload(args: argparse.Namespace) -> None:
    sig_path = Path(args.signature_file)
    if not sig_path.exists():
        print(f"Error: signature file not found: {args.signature_file}", file=sys.stderr)
        sys.exit(1)

    # Use a bare signer just to call publish with a file path
    signer = AgentSigner()
    try:
        response = signer.publish(args.registry_url, path=sig_path)
    except ConnectionError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"Signature uploaded to: {args.registry_url}")
    if "registered_at" in response:
        print(f"  registered_at: {response['registered_at']}")
    if "hash" in response:
        print(f"  hash:          {response['hash']}")


def main(argv: list[str] | None = None) -> None:
    parser = _build_parser()
    args = parser.parse_args(argv)

    commands = {
        "generate-keypair": cmd_generate_keypair,
        "sign": cmd_sign,
        "verify": cmd_verify,
        "upload": cmd_upload,
    }
    commands[args.command](args)


if __name__ == "__main__":
    main()
