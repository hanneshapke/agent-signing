"""Tests for AgentSigner — uses plain dicts (no framework deps)."""

import base64
import json

import pytest
from agent_signing.signer import AgentSigner, generate_keypair


def _make_jwt(claims: dict) -> str:
    """Build a fake (unsigned) JWT for testing. Header and signature are stubs."""
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none"}).encode()).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    return f"{header}.{payload}.fakesig"


TOOL_SEARCH = {"name": "search", "description": "Search the web", "parameters": {"query": "str"}}
TOOL_CALC = {
    "name": "calculator",
    "description": "Evaluate math",
    "parameters": {"expression": "str"},
}
AGENT_RESEARCHER = {
    "name": "researcher",
    "role": "Researcher",
    "goal": "Find info",
    "tools": ["search"],
}


class TestSigning:
    def test_sign_returns_hex_string(self):
        signer = AgentSigner()
        signer.add_tool(TOOL_SEARCH)
        sig = signer.sign()
        assert isinstance(sig, str)
        assert len(sig) == 64  # SHA-256 hex

    def test_same_setup_same_signature(self):
        s1 = AgentSigner()
        s1.add_tool(TOOL_SEARCH)
        s1.add_tool(TOOL_CALC)

        s2 = AgentSigner()
        s2.add_tool(TOOL_SEARCH)
        s2.add_tool(TOOL_CALC)

        assert s1.sign() == s2.sign()


class TestOrderIndependence:
    def test_tools_different_order(self):
        s1 = AgentSigner()
        s1.add_tool(TOOL_SEARCH)
        s1.add_tool(TOOL_CALC)

        s2 = AgentSigner()
        s2.add_tool(TOOL_CALC)
        s2.add_tool(TOOL_SEARCH)

        assert s1.sign() == s2.sign()

    def test_agents_different_order(self):
        agent_a = {"name": "agent_a", "role": "A"}
        agent_b = {"name": "agent_b", "role": "B"}

        s1 = AgentSigner()
        s1.add_agent(agent_a)
        s1.add_agent(agent_b)

        s2 = AgentSigner()
        s2.add_agent(agent_b)
        s2.add_agent(agent_a)

        assert s1.sign() == s2.sign()

    def test_mixed_tools_and_agents_different_order(self):
        s1 = AgentSigner()
        s1.add_tool(TOOL_SEARCH)
        s1.add_agent(AGENT_RESEARCHER)

        s2 = AgentSigner()
        s2.add_agent(AGENT_RESEARCHER)
        s2.add_tool(TOOL_SEARCH)

        assert s1.sign() == s2.sign()


class TestChangeDetection:
    def test_changed_tool_description(self):
        s1 = AgentSigner()
        s1.add_tool(TOOL_SEARCH)

        s2 = AgentSigner()
        s2.add_tool({**TOOL_SEARCH, "description": "Search the internet"})

        assert s1.sign() != s2.sign()

    def test_changed_tool_parameters(self):
        s1 = AgentSigner()
        s1.add_tool(TOOL_CALC)

        s2 = AgentSigner()
        s2.add_tool({**TOOL_CALC, "parameters": {"expr": "str"}})

        assert s1.sign() != s2.sign()

    def test_added_tool(self):
        s1 = AgentSigner()
        s1.add_tool(TOOL_SEARCH)

        s2 = AgentSigner()
        s2.add_tool(TOOL_SEARCH)
        s2.add_tool(TOOL_CALC)

        assert s1.sign() != s2.sign()

    def test_removed_tool(self):
        s1 = AgentSigner()
        s1.add_tool(TOOL_SEARCH)
        s1.add_tool(TOOL_CALC)

        s2 = AgentSigner()
        s2.add_tool(TOOL_SEARCH)

        assert s1.sign() != s2.sign()

    def test_changed_agent_config(self):
        s1 = AgentSigner()
        s1.add_agent(AGENT_RESEARCHER)

        s2 = AgentSigner()
        s2.add_agent({**AGENT_RESEARCHER, "goal": "Find detailed info"})

        assert s1.sign() != s2.sign()


class TestVerification:
    def test_verify_valid(self):
        signer = AgentSigner()
        signer.add_tool(TOOL_SEARCH)
        sig = signer.sign()

        signer2 = AgentSigner()
        signer2.add_tool(TOOL_SEARCH)
        result = signer2.verify(sig)

        assert result.valid is True
        assert bool(result) is True

    def test_verify_fails_on_change(self):
        signer = AgentSigner()
        signer.add_tool(TOOL_SEARCH)
        sig = signer.sign()

        signer2 = AgentSigner()
        signer2.add_tool(TOOL_CALC)
        result = signer2.verify(sig)

        assert result.valid is False
        assert bool(result) is False


class TestHMAC:
    def test_secret_produces_different_signature(self):
        s1 = AgentSigner()
        s1.add_tool(TOOL_SEARCH)

        s2 = AgentSigner(secret="my-secret")
        s2.add_tool(TOOL_SEARCH)

        assert s1.sign() != s2.sign()

    def test_same_secret_same_signature(self):
        s1 = AgentSigner(secret="key")
        s1.add_tool(TOOL_SEARCH)

        s2 = AgentSigner(secret="key")
        s2.add_tool(TOOL_SEARCH)

        assert s1.sign() == s2.sign()

    def test_wrong_secret_fails_verification(self):
        s1 = AgentSigner(secret="correct")
        s1.add_tool(TOOL_SEARCH)
        sig = s1.sign()

        s2 = AgentSigner(secret="wrong")
        s2.add_tool(TOOL_SEARCH)
        result = s2.verify(sig)

        assert result.valid is False


class TestDuckTypedExtraction:
    def test_object_with_name_and_description(self):
        """Simulate a framework tool object via a simple namespace."""

        class FakeTool:
            name = "fake"
            description = "A fake tool"
            args = {"input": {"type": "string"}}

        signer = AgentSigner()
        signer.add_tool(FakeTool())
        sig = signer.sign()
        assert len(sig) == 64

    def test_object_with_role_and_goal(self):
        """Simulate a CrewAI-style agent."""

        class FakeAgent:
            role = "Writer"
            goal = "Write well"
            backstory = "Expert writer"
            llm = "gpt-4o"
            tools = []

        signer = AgentSigner()
        signer.add_agent(FakeAgent())
        sig = signer.sign()
        assert len(sig) == 64

    def test_unknown_tool_type_raises(self):
        signer = AgentSigner()
        with pytest.raises(TypeError):
            signer.add_tool(42)

    def test_unknown_agent_type_raises(self):
        signer = AgentSigner()
        with pytest.raises(TypeError):
            signer.add_agent(42)


class TestEd25519Signing:
    def test_sign_and_verify_with_keypair(self):
        priv, pub = generate_keypair()

        signer = AgentSigner(private_key=priv)
        signer.add_tool(TOOL_SEARCH)
        sig = signer.sign()

        # Signature is JSON envelope
        envelope = json.loads(sig)
        assert "hash" in envelope
        assert "signature" in envelope

        verifier = AgentSigner(public_key=pub)
        verifier.add_tool(TOOL_SEARCH)
        result = verifier.verify(sig)

        assert result.valid is True

    def test_wrong_public_key_fails(self):
        priv1, _ = generate_keypair()
        _, pub2 = generate_keypair()

        signer = AgentSigner(private_key=priv1)
        signer.add_tool(TOOL_SEARCH)
        sig = signer.sign()

        verifier = AgentSigner(public_key=pub2)
        verifier.add_tool(TOOL_SEARCH)
        result = verifier.verify(sig)

        assert result.valid is False
        assert "Ed25519" in result.reason

    def test_setup_change_fails_ed25519(self):
        priv, pub = generate_keypair()

        signer = AgentSigner(private_key=priv)
        signer.add_tool(TOOL_SEARCH)
        sig = signer.sign()

        verifier = AgentSigner(public_key=pub)
        verifier.add_tool(TOOL_CALC)
        result = verifier.verify(sig)

        assert result.valid is False

    def test_generate_keypair_returns_32_bytes(self):
        priv, pub = generate_keypair()
        assert len(priv) == 32
        assert len(pub) == 32


class TestJWTIdentity:
    def test_sign_with_jwt_returns_identity(self):
        token = _make_jwt({"sub": "user@example.com", "iss": "https://auth.example.com"})

        signer = AgentSigner(identity_token=token)
        signer.add_tool(TOOL_SEARCH)
        sig = signer.sign()

        envelope = json.loads(sig)
        assert envelope["identity"]["sub"] == "user@example.com"
        assert envelope["identity"]["iss"] == "https://auth.example.com"
        assert envelope["identity_token"] == token

    def test_verify_with_jwt_returns_identity(self):
        token = _make_jwt({"sub": "alice", "iss": "github"})

        signer = AgentSigner(identity_token=token)
        signer.add_tool(TOOL_SEARCH)
        sig = signer.sign()

        verifier = AgentSigner()
        verifier.add_tool(TOOL_SEARCH)
        result = verifier.verify(sig)

        assert result.valid is True
        assert result.identity["sub"] == "alice"
        assert result.identity["iss"] == "github"

    def test_jwt_setup_change_fails(self):
        token = _make_jwt({"sub": "alice"})

        signer = AgentSigner(identity_token=token)
        signer.add_tool(TOOL_SEARCH)
        sig = signer.sign()

        verifier = AgentSigner()
        verifier.add_tool(TOOL_CALC)
        result = verifier.verify(sig)

        assert result.valid is False


class TestCombined:
    def test_ed25519_plus_jwt(self):
        priv, pub = generate_keypair()
        token = _make_jwt({"sub": "deployer@corp.com", "iss": "https://sso.corp.com"})

        signer = AgentSigner(private_key=priv, identity_token=token)
        signer.add_tool(TOOL_SEARCH)
        signer.add_agent(AGENT_RESEARCHER)
        sig = signer.sign()

        envelope = json.loads(sig)
        assert "signature" in envelope
        assert "identity_token" in envelope
        assert envelope["identity"]["sub"] == "deployer@corp.com"

        verifier = AgentSigner(public_key=pub)
        verifier.add_tool(TOOL_SEARCH)
        verifier.add_agent(AGENT_RESEARCHER)
        result = verifier.verify(sig)

        assert result.valid is True
        assert result.identity["sub"] == "deployer@corp.com"

    def test_ed25519_plus_jwt_wrong_key_fails(self):
        priv1, _ = generate_keypair()
        _, pub2 = generate_keypair()
        token = _make_jwt({"sub": "alice"})

        signer = AgentSigner(private_key=priv1, identity_token=token)
        signer.add_tool(TOOL_SEARCH)
        sig = signer.sign()

        verifier = AgentSigner(public_key=pub2)
        verifier.add_tool(TOOL_SEARCH)
        result = verifier.verify(sig)

        assert result.valid is False


class TestSignatureFile:
    def test_sign_to_file_creates_valid_json(self, tmp_path):
        priv, pub = generate_keypair()
        path = tmp_path / "sig.json"

        signer = AgentSigner(private_key=priv)
        signer.add_tool(TOOL_SEARCH)
        signer.sign_to_file(path)

        record = json.loads(path.read_text())
        assert "signed_at" in record
        assert "public_key" in record
        assert "hash" in record
        assert "signature" in record
        assert len(record["hash"]) == 64
        assert record["public_key"] == pub.hex()

    def test_verify_file_valid(self, tmp_path):
        priv, pub = generate_keypair()
        path = tmp_path / "sig.json"

        signer = AgentSigner(private_key=priv)
        signer.add_tool(TOOL_SEARCH)
        signer.sign_to_file(path)

        verifier = AgentSigner(public_key=pub)
        verifier.add_tool(TOOL_SEARCH)
        result = verifier.verify_file(path)
        assert result.valid is True

    def test_verify_file_fails_on_change(self, tmp_path):
        priv, pub = generate_keypair()
        path = tmp_path / "sig.json"

        signer = AgentSigner(private_key=priv)
        signer.add_tool(TOOL_SEARCH)
        signer.sign_to_file(path)

        verifier = AgentSigner(public_key=pub)
        verifier.add_tool(TOOL_CALC)
        result = verifier.verify_file(path)
        assert result.valid is False

    def test_sign_to_file_hmac(self, tmp_path):
        path = tmp_path / "sig.json"

        signer = AgentSigner(secret="my-key")
        signer.add_tool(TOOL_SEARCH)
        signer.sign_to_file(path)

        record = json.loads(path.read_text())
        assert record["public_key"] is None
        assert "signed_at" in record

        verifier = AgentSigner(secret="my-key")
        verifier.add_tool(TOOL_SEARCH)
        result = verifier.verify_file(path)
        assert result.valid is True

    def test_load_signature_file(self, tmp_path):
        priv, pub = generate_keypair()
        path = tmp_path / "sig.json"

        signer = AgentSigner(private_key=priv)
        signer.add_tool(TOOL_SEARCH)
        signer.sign_to_file(path)

        record = AgentSigner.load_signature_file(path)
        assert record["public_key"] == pub.hex()


def _registry_record(signer: AgentSigner) -> dict:
    """Build the registry record shape a GET /signatures/{hash} would return."""
    return {
        "signed_at": "2026-01-01T00:00:00+00:00",
        "public_key": signer._public_key_hex(),
        "hash": signer._compute_aggregate(),
        "signature": signer.sign(),
        "registered_at": "2026-01-01T00:00:01+00:00",
    }


class TestRegistryVerification:
    """verify_from_registry() — fetch the approved signature from the registry."""

    def test_valid_ed25519(self, monkeypatch):
        priv, pub = generate_keypair()
        signer = AgentSigner(private_key=priv)
        signer.add_tool(TOOL_SEARCH)
        record = _registry_record(signer)

        verifier = AgentSigner(public_key=pub)
        verifier.add_tool(TOOL_SEARCH)
        monkeypatch.setattr(verifier, "_fetch_registry_records", lambda u, h, t: [record])

        result = verifier.verify_from_registry("http://registry.example")
        assert result.valid is True
        assert result.record is record
        assert "Ed25519" in result.reason

    def test_valid_hmac(self, monkeypatch):
        signer = AgentSigner(secret="team-secret")
        signer.add_tool(TOOL_SEARCH)
        record = _registry_record(signer)

        verifier = AgentSigner(secret="team-secret")
        verifier.add_tool(TOOL_SEARCH)
        monkeypatch.setattr(verifier, "_fetch_registry_records", lambda u, h, t: [record])

        assert verifier.verify_from_registry("http://registry.example").valid is True

    def test_wrong_hmac_secret_fails(self, monkeypatch):
        signer = AgentSigner(secret="team-secret")
        signer.add_tool(TOOL_SEARCH)
        record = _registry_record(signer)

        verifier = AgentSigner(secret="other-secret")
        verifier.add_tool(TOOL_SEARCH)
        monkeypatch.setattr(verifier, "_fetch_registry_records", lambda u, h, t: [record])

        assert verifier.verify_from_registry("http://registry.example").valid is False

    def test_unregistered_setup_is_invalid(self, monkeypatch):
        _, pub = generate_keypair()
        verifier = AgentSigner(public_key=pub)
        verifier.add_tool(TOOL_SEARCH)
        # Registry has nothing for this hash (404 -> empty list).
        monkeypatch.setattr(verifier, "_fetch_registry_records", lambda u, h, t: [])

        result = verifier.verify_from_registry("http://registry.example")
        assert result.valid is False
        assert "No signature registered" in result.reason

    def test_rejects_signature_from_untrusted_key(self, monkeypatch):
        # An attacker self-signs their own setup and publishes it...
        attacker_priv, _ = generate_keypair()
        attacker = AgentSigner(private_key=attacker_priv)
        attacker.add_tool(TOOL_SEARCH)
        rogue_record = _registry_record(attacker)

        # ...but the verifier trusts a *different* public key.
        _, trusted_pub = generate_keypair()
        verifier = AgentSigner(public_key=trusted_pub)
        verifier.add_tool(TOOL_SEARCH)
        monkeypatch.setattr(verifier, "_fetch_registry_records", lambda u, h, t: [rogue_record])

        result = verifier.verify_from_registry("http://registry.example")
        assert result.valid is False

    def test_picks_trusted_record_among_cosignatures(self, monkeypatch):
        priv, pub = generate_keypair()
        good = AgentSigner(private_key=priv)
        good.add_tool(TOOL_SEARCH)
        good_record = _registry_record(good)

        attacker_priv, _ = generate_keypair()
        rogue = AgentSigner(private_key=attacker_priv)
        rogue.add_tool(TOOL_SEARCH)
        rogue_record = _registry_record(rogue)

        verifier = AgentSigner(public_key=pub)
        verifier.add_tool(TOOL_SEARCH)
        monkeypatch.setattr(
            verifier, "_fetch_registry_records", lambda u, h, t: [rogue_record, good_record]
        )

        result = verifier.verify_from_registry("http://registry.example")
        assert result.valid is True
        assert result.record is good_record

    def test_jwt_identity_surfaced(self, monkeypatch):
        token = _make_jwt({"sub": "alice", "iss": "github"})
        signer = AgentSigner(identity_token=token)
        signer.add_tool(TOOL_SEARCH)
        record = _registry_record(signer)

        verifier = AgentSigner()
        verifier.add_tool(TOOL_SEARCH)
        monkeypatch.setattr(verifier, "_fetch_registry_records", lambda u, h, t: [record])

        result = verifier.verify_from_registry("http://registry.example")
        assert result.valid is True
        assert result.identity["sub"] == "alice"


class TestRegistryFetch:
    """The HTTP layer of verify_from_registry()."""

    class _FakeResponse:
        def __init__(self, payload):
            self._payload = json.dumps(payload).encode()

        def read(self):
            return self._payload

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def test_fetch_and_verify_over_http(self, monkeypatch):
        import urllib.request

        priv, pub = generate_keypair()
        signer = AgentSigner(private_key=priv)
        signer.add_tool(TOOL_SEARCH)
        record = _registry_record(signer)
        aggregate = signer._compute_aggregate()

        def fake_urlopen(req, timeout=None):
            assert req.full_url.endswith("/signatures/" + aggregate)
            return self._FakeResponse([record])

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

        verifier = AgentSigner(public_key=pub)
        verifier.add_tool(TOOL_SEARCH)
        result = verifier.verify_from_registry("http://localhost:8000/")
        assert result.valid is True
        assert result.record["public_key"] == pub.hex()

    def test_404_returns_empty(self, monkeypatch):
        import urllib.error
        import urllib.request

        def fake_urlopen(req, timeout=None):
            raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, None)

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

        verifier = AgentSigner()
        verifier.add_tool(TOOL_SEARCH)
        assert verifier._fetch_registry_records("http://localhost:8000", "abc", 5) == []

    def test_unreachable_raises_connection_error(self, monkeypatch):
        import urllib.error
        import urllib.request

        def fake_urlopen(req, timeout=None):
            raise urllib.error.URLError("connection refused")

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

        verifier = AgentSigner()
        verifier.add_tool(TOOL_SEARCH)
        with pytest.raises(ConnectionError):
            verifier.verify_from_registry("http://localhost:8000")

    def test_server_error_raises_value_error(self, monkeypatch):
        import io
        import urllib.error
        import urllib.request

        def fake_urlopen(req, timeout=None):
            raise urllib.error.HTTPError(req.full_url, 500, "Server Error", {}, io.BytesIO(b"boom"))

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

        verifier = AgentSigner()
        verifier.add_tool(TOOL_SEARCH)
        with pytest.raises(ValueError):
            verifier.verify_from_registry("http://localhost:8000")
