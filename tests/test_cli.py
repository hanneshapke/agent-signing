"""Tests for the agent-signing CLI."""

import json

import pytest
from agent_signing.cli import main
from agent_signing.signer import generate_keypair


SAMPLE_MANIFEST = {
    "tools": [
        {"name": "search", "description": "Search the web", "parameters": {"query": "str"}},
        {"name": "calculator", "description": "Evaluate math", "parameters": {"expression": "str"}},
    ],
    "agents": [
        {"name": "researcher", "role": "Researcher", "goal": "Find info", "tools": ["search"]},
    ],
}


@pytest.fixture()
def manifest_file(tmp_path):
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(SAMPLE_MANIFEST))
    return path


@pytest.fixture()
def keypair_files(tmp_path):
    priv, pub = generate_keypair()
    priv_path = tmp_path / "test.private.key"
    pub_path = tmp_path / "test.public.key"
    priv_path.write_text(priv.hex())
    pub_path.write_text(pub.hex())
    return priv_path, pub_path


class TestGenerateKeypair:
    def test_creates_key_files(self, tmp_path):
        main(["generate-keypair", "--out-dir", str(tmp_path), "--prefix", "mykey"])

        priv_path = tmp_path / "mykey.private.key"
        pub_path = tmp_path / "mykey.public.key"
        assert priv_path.exists()
        assert pub_path.exists()

        # Keys should be 32 bytes = 64 hex chars (plus trailing newline)
        priv_hex = priv_path.read_text().strip()
        pub_hex = pub_path.read_text().strip()
        assert len(bytes.fromhex(priv_hex)) == 32
        assert len(bytes.fromhex(pub_hex)) == 32

    def test_default_prefix(self, tmp_path):
        main(["generate-keypair", "--out-dir", str(tmp_path)])
        assert (tmp_path / "agent.private.key").exists()
        assert (tmp_path / "agent.public.key").exists()

    def test_creates_output_directory(self, tmp_path):
        out = tmp_path / "subdir" / "keys"
        main(["generate-keypair", "--out-dir", str(out)])
        assert (out / "agent.private.key").exists()


class TestSign:
    def test_sign_plain(self, tmp_path, manifest_file):
        output = tmp_path / "sig.json"
        main(["sign", str(manifest_file), "-o", str(output)])

        assert output.exists()
        record = json.loads(output.read_text())
        assert "signed_at" in record
        assert "hash" in record
        assert "signature" in record
        assert len(record["hash"]) == 64

    def test_sign_with_secret(self, tmp_path, manifest_file):
        output = tmp_path / "sig.json"
        main(["sign", str(manifest_file), "-o", str(output), "--secret", "my-secret"])

        record = json.loads(output.read_text())
        assert record["public_key"] is None
        assert len(record["hash"]) == 64

    def test_sign_with_ed25519(self, tmp_path, manifest_file, keypair_files):
        priv_path, _ = keypair_files
        output = tmp_path / "sig.json"
        main(["sign", str(manifest_file), "-o", str(output), "--private-key", str(priv_path)])

        record = json.loads(output.read_text())
        assert record["public_key"] is not None
        assert len(record["public_key"]) == 64  # 32 bytes hex

    def test_sign_with_identity_token(self, tmp_path, manifest_file):
        import base64
        header = base64.urlsafe_b64encode(json.dumps({"alg": "none"}).encode()).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(json.dumps({"sub": "user@test.com"}).encode()).rstrip(b"=").decode()
        token = f"{header}.{payload}.fakesig"

        output = tmp_path / "sig.json"
        main(["sign", str(manifest_file), "-o", str(output), "--identity-token", token])

        record = json.loads(output.read_text())
        assert "signature" in record

    def test_sign_missing_manifest(self, tmp_path):
        with pytest.raises(SystemExit):
            main(["sign", str(tmp_path / "nonexistent.json")])

    def test_sign_empty_manifest(self, tmp_path):
        empty = tmp_path / "empty.json"
        empty.write_text(json.dumps({"tools": [], "agents": []}))
        with pytest.raises(SystemExit):
            main(["sign", str(empty)])

    def test_sign_invalid_json(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("not json {{{")
        with pytest.raises(SystemExit):
            main(["sign", str(bad)])


class TestVerify:
    def test_verify_valid_plain(self, tmp_path, manifest_file):
        output = tmp_path / "sig.json"
        main(["sign", str(manifest_file), "-o", str(output)])
        # Should not raise
        main(["verify", str(manifest_file), "-s", str(output)])

    def test_verify_valid_hmac(self, tmp_path, manifest_file):
        output = tmp_path / "sig.json"
        main(["sign", str(manifest_file), "-o", str(output), "--secret", "key123"])
        main(["verify", str(manifest_file), "-s", str(output), "--secret", "key123"])

    def test_verify_valid_ed25519(self, tmp_path, manifest_file, keypair_files):
        priv_path, pub_path = keypair_files
        output = tmp_path / "sig.json"
        main(["sign", str(manifest_file), "-o", str(output), "--private-key", str(priv_path)])
        main(["verify", str(manifest_file), "-s", str(output), "--public-key", str(pub_path)])

    def test_verify_fails_on_changed_manifest(self, tmp_path, manifest_file):
        output = tmp_path / "sig.json"
        main(["sign", str(manifest_file), "-o", str(output)])

        # Create a different manifest
        different = tmp_path / "different.json"
        different.write_text(json.dumps({
            "tools": [{"name": "other", "description": "Different tool", "parameters": {}}],
        }))

        with pytest.raises(SystemExit):
            main(["verify", str(different), "-s", str(output)])

    def test_verify_fails_wrong_secret(self, tmp_path, manifest_file):
        output = tmp_path / "sig.json"
        main(["sign", str(manifest_file), "-o", str(output), "--secret", "correct"])
        with pytest.raises(SystemExit):
            main(["verify", str(manifest_file), "-s", str(output), "--secret", "wrong"])

    def test_verify_fails_wrong_public_key(self, tmp_path, manifest_file, keypair_files):
        priv_path, _ = keypair_files
        output = tmp_path / "sig.json"
        main(["sign", str(manifest_file), "-o", str(output), "--private-key", str(priv_path)])

        # Generate a different key pair
        _, other_pub = generate_keypair()
        other_pub_path = tmp_path / "other.public.key"
        other_pub_path.write_text(other_pub.hex())

        with pytest.raises(SystemExit):
            main(["verify", str(manifest_file), "-s", str(output), "--public-key", str(other_pub_path)])

    def test_verify_missing_signature_file(self, tmp_path, manifest_file):
        with pytest.raises(SystemExit):
            main(["verify", str(manifest_file), "-s", str(tmp_path / "nonexistent.json")])


class TestUpload:
    def test_upload_missing_signature_file(self, tmp_path):
        with pytest.raises(SystemExit):
            main(["upload", "http://localhost:9999", "-s", str(tmp_path / "missing.json")])

    def test_upload_connection_error(self, tmp_path, manifest_file):
        # Sign first to create a signature file
        sig_file = tmp_path / "sig.json"
        main(["sign", str(manifest_file), "-o", str(sig_file)])

        # Upload to unreachable server should fail
        with pytest.raises(SystemExit):
            main(["upload", "http://localhost:1", "-s", str(sig_file)])


class TestMainEntryPoint:
    def test_no_command_shows_error(self):
        with pytest.raises(SystemExit):
            main([])

    def test_help_exits_cleanly(self):
        with pytest.raises(SystemExit) as exc_info:
            main(["--help"])
        assert exc_info.value.code == 0

    def test_subcommand_help(self):
        for cmd in ["sign", "verify", "upload", "generate-keypair"]:
            with pytest.raises(SystemExit) as exc_info:
                main([cmd, "--help"])
            assert exc_info.value.code == 0
