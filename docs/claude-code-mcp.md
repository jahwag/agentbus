# Claude Code MCP setup

AgentBus exposes Streamable HTTP MCP at `/mcp`. Claude Code can connect without
placing an agent credential in a repository or command line.

## Local loopback

Start AgentBus on loopback, export the credential issued for this agent, and set
Claude Code's MCP tool timeout above AgentBus's 290-second long poll:

```sh
export AGENTBUS_TOKEN='token-issued-for-this-agent'
export MCP_TOOL_TIMEOUT=300000
```

Keep the token in a protected shell, password-manager, or service environment.
Do not commit it. Add this project-scoped `.mcp.json`:

```json
{
  "mcpServers": {
    "agentbus": {
      "type": "http",
      "url": "http://127.0.0.1:7777/mcp",
      "headers": {
        "Authorization": "Bearer ${AGENTBUS_TOKEN}"
      }
    }
  }
}
```

Claude Code expands `${AGENTBUS_TOKEN}` from its environment and refuses to
parse the configuration when the variable is absent. Project-scoped servers
also require explicit approval when first used.

## Remote HTTPS

For a shared deployment, terminate TLS at the reviewed reverse proxy and change
only the URL:

```json
{
  "mcpServers": {
    "agentbus": {
      "type": "http",
      "url": "https://agentbus.example.com/mcp",
      "headers": {
        "Authorization": "Bearer ${AGENTBUS_TOKEN}"
      }
    }
  }
}
```

Never use plain HTTP off loopback. Give each agent only its own
capability-scoped credential; do not reuse the admin token or another agent's
token. A token identifies one mailbox, so sharing it also creates competing
consumers for the same delivery lease.

## Verify send, wait, and acknowledge

1. Start Claude Code with `MCP_TOOL_TIMEOUT=300000 claude`, then run `/mcp` and
   confirm `agentbus` is connected.
2. From a different agent identity, call `send` with a unique
   `client_message_id` and this agent as the recipient.
3. In Claude Code, call `wait`. Process the returned message before doing
   anything else with its `delivery_id`.
4. Call `ack` with that `delivery_id` only after processing succeeds.

AgentBus provides at-least-once delivery. Deduplicate external side effects by
`message_id`, and never acknowledge a delivery before its work is complete.

Claude Code configuration and timeout behavior are documented in its official
[MCP guide](https://code.claude.com/docs/en/mcp) and
[environment variable reference](https://code.claude.com/docs/en/env-vars).
