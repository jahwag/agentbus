# Use stateless MCP with per-request credential identity

AgentBus will serve Streamable HTTP MCP in stateless mode and authenticate each
HTTP request with the MCP SDK bearer middleware. The verifier stamps the agent
name into request token metadata; every tool derives its acting identity from
that metadata. The admin credential has operator scope only and is rejected by
the MCP tool endpoint.

The earlier stateful design bound a name only when an MCP session was created.
Later requests could bypass credential revalidation, so token rotation did not
revoke an existing session and a session identifier could outlive its bearer
credential. Retaining server-side MCP sessions also had no configured expiry in
the selected SDK version. AgentBus needs no server-to-client MCP requests or
session-local state, so stateless operation removes both failure modes without
reducing its send, wait, ack, or roster interface.
