"""Demo: signing a LangChain agent setup with agent-signing."""

from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langchain.agents import create_agent as create_react_agent

from agent_signing import AgentSigner, generate_keypair

# --- Define tools ---


@tool
def add(a: float, b: float) -> float:
    """Add two numbers."""
    return a + b


@tool
def multiply(a: float, b: float) -> float:
    """Multiply two numbers."""
    return a * b


@tool
def search(query: str) -> str:
    """Look up information about a topic."""
    return (
        f"Result for '{query}': LangChain is a framework for building LLM applications."
    )


# --- Build the agent ---

llm = ChatOpenAI(model="gpt-4o-mini", api_key="fake-key-for-demo")
agent = create_react_agent(llm, [add, multiply, search])


# --- Sign the agent setup ---

private_key, public_key = generate_keypair()

signer = AgentSigner(private_key=private_key)
signer.add_agent(agent)  # auto-discovers all tools bound to the agent
signature = signer.sign()

print("Signature created.")
print(f"  {signature[:80]}...")


# --- Verify (same agent — tools auto-discovered again) ---

verifier = AgentSigner(public_key=public_key)
verifier.add_agent(agent)
result = verifier.verify(signature)

print(f"\nVerification: valid={result.valid}, reason={result.reason}")
