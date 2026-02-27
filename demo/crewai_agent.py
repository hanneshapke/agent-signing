"""Demo: signing a CrewAI agent setup with agent-signing."""

from crewai import Agent, Crew, Task
from crewai.tools import tool

from agent_signing import AgentSigner, generate_keypair


# --- Define tools ---

@tool("search")
def search(query: str) -> str:
    """Search for information about a topic."""
    return f"Result for '{query}': CrewAI is a framework for orchestrating AI agents."


@tool("calculator")
def calculator(expression: str) -> str:
    """Evaluate a math expression."""
    return str(eval(expression))  # noqa: S307


# --- Define agents ---

researcher = Agent(
    role="Researcher",
    goal="Find accurate information on the given topic",
    backstory="You are a skilled researcher who finds key facts quickly.",
    tools=[search],
)

writer = Agent(
    role="Writer",
    goal="Write a clear, concise summary based on research",
    backstory="You are a technical writer who distills complex topics into simple prose.",
)


# --- Sign the agent setup ---

private_key, public_key = generate_keypair()

signer = AgentSigner(private_key=private_key)
signer.add_tool(search)
signer.add_tool(calculator)
signer.add_agent(researcher)  # auto-extracts role, goal, backstory, tools
signer.add_agent(writer)
signer.sign_to_file("agent_signature.json")

print("Signature written to agent_signature.json")
record = AgentSigner.load_signature_file("agent_signature.json")
print(f"  signed_at:  {record['signed_at']}")
print(f"  public_key: {record['public_key']}")
print(f"  hash:       {record['hash']}")


# --- Verify (different order — still valid) ---

verifier = AgentSigner(public_key=public_key)
verifier.add_agent(writer)       # swapped order
verifier.add_agent(researcher)
verifier.add_tool(calculator)
verifier.add_tool(search)
result = verifier.verify_file("agent_signature.json")

print(f"\nVerification: valid={result.valid}, reason={result.reason}")
