# Agent-to-Agent (A2A) Communication Risks

## attack

Agents exchange tasks, context and results over HTTP/JSON-RPC (e.g. the A2A protocol), message buses, or custom APIs. When those channels lack authentication, integrity, authorisation or semantic validation, an attacker can spoof a peer, tamper with or replay messages, register a fake agent in discovery, or extract sensitive context sent to an untrusted peer. A compromised agent becomes a pivot: downstream agents treat its messages as trusted instructions (OWASP ASI07, PDF pp. 27-29). Agent *identity* forgery is covered in agent-impersonation.md; this file focuses on the channel and the receiving/sending code.

## preconditions

- Multi-agent system where at least one agent communicates over a network channel (HTTP, gRPC, WebSocket, queue) or via a discovery registry / Agent Card.
- Receiving agent exposes an endpoint without verifying caller credentials, or a sending agent connects without verifying the peer.
- Inbound message content flows into the receiving agent's prompt or tool selection without validation.
- Sensitive context (credentials, PII, internal documents, full conversation history) is included in outbound messages.

## attack_flow

1. **Spoofed caller:** attacker reaches Agent B's endpoint directly and sends a task; B has no auth check and executes it with its own privileges.
2. **Discovery spoofing:** attacker registers a fake agent (cloned Agent Card) in a registry; Agent A selects it and routes privileged tasks to it (OWASP ASI07 scenario 6).
3. **MITM on cleartext:** messages over `http://` are modified in transit to inject instructions (ASI07 scenario 1).
4. **Replay:** a captured delegation message is replayed to trigger stale actions (ASI07 example 3).
5. **Context leakage:** Agent A sends the full conversation, including secrets, to a remote agent chosen dynamically.

## observable_code_patterns

```python
# Receiving side: inbound agent endpoint with no auth dependency, payload goes straight to the agent
@app.post("/a2a/tasks")
async def handle(task: dict):
    return await agent.run(task["message"])        # caller never authenticated

# Sending side: cleartext + no credentials + agent URL from discovery/user input
resp = httpx.post(f"http://{peer_host}/a2a", json={"message": history})

# Sending side: whole state/memory forwarded to a remote agent
payload = {"context": state["messages"], "secrets": cfg.api_keys}

# TLS verification disabled
httpx.post(url, json=msg, verify=False)
```

## possible_static_signals

- Web route handler (FastAPI/Flask/Express) whose request body reaches an agent run/invoke call, with no auth dependency/middleware/decorator on the route or app.
- Outbound HTTP call to an agent endpoint with `http://` non-loopback URL, `verify=False`, or no `Authorization`/auth header.
- Remote agent URL derived from non-constant data (discovery response, model output, user input) with no allowlist check before use.
- Agent Card / `securitySchemes` absent or empty in an A2A server definition (the A2A spec defines security schemes in the Agent Card and requires servers to reject requests lacking valid credentials).
- No signature verification on Agent Cards where the code fetches cards remotely (A2A spec has an "Agent Card Signing" section).
- Taint: secrets/credential variables or full message history -> outbound agent message body.

## false_positive_cases

- Auth enforced by an API gateway, service mesh (mTLS) or platform ingress not visible in code.
- Agents communicating in-process (same Python process) -- not a network trust boundary.
- Loopback/dev endpoints, test servers, examples.
- Context forwarding to a peer that is part of the same trust domain by design.

## false_negative_cases

- Custom or wrapped HTTP clients that hide the URL/headers.
- Auth present but semantically broken (accepts any token, no audience check, no replay protection).
- Message buses (Kafka, Redis pub/sub) where auth is broker-level configuration.
- Semantic manipulation in validly authenticated messages from a compromised peer -- authentication does not prevent this.
- Covert/side-channel leakage (timing, metadata) mentioned by OWASP -- not statically observable.

## framework_examples

```python
# A2A-style server (illustrative): Agent Card advertises no security scheme
agent_card = {"name": "billing-agent", "url": "http://billing:9000/", "skills": [...]}  # no securitySchemes

# AutoGen distributed runtime / custom HTTP relay (illustrative)
await http.post(peer_url, json={"sender": "planner", "content": msg})   # no signing, no auth

# LangGraph RemoteGraph to an untrusted URL (illustrative)
from langgraph.pregel.remote import RemoteGraph
remote = RemoteGraph("agent", url=user_supplied_url)
```

## owasp_mapping

- **Primary:** ASI07 (Insecure Inter-Agent Communication) -- missing authentication, integrity, authorisation; discovery spoofing; replay (PDF pp. 27-29).
- **Secondary:** ASI03 (Identity & Privilege Abuse) -- "Cross-Agent Trust Exploitation (Confused Deputy)" and forged agent persona (PDF pp. 15-16); ASI08 when a spoofed message fans out downstream.
- **CWE (where applicable):** CWE-306, CWE-862, CWE-319, CWE-295 (TLS verify disabled), CWE-345, CWE-294 (replay).

## confidence

**Medium.** Route-level auth absence and cleartext/`verify=False` are detectable with moderate precision. Whether auth exists at the infrastructure layer is the dominant FP source. Message integrity/replay protection and semantic validation are mostly not statically verifiable.

## references

- OWASP Top 10 for Agentic Applications 2026 (ASI07 pp. 27-29; ASI03 pp. 15-17): https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- A2A Protocol Specification (security schemes, Agent Card signing): https://a2a-protocol.org/latest/specification/
- Palo Alto Networks -- A2A protocol risks: https://live.paloaltonetworks.com/t5/community-blogs/safeguarding-ai-agents-an-in-depth-look-at-a2a-protocol-risks/ba-p/1235996
- CWE-306 Missing Authentication for Critical Function: https://cwe.mitre.org/data/definitions/306.html
- CWE-319 Cleartext Transmission of Sensitive Information: https://cwe.mitre.org/data/definitions/319.html
