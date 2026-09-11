# AgentBus

[![CI](https://github.com/jahwag/agentbus/actions/workflows/ci.yml/badge.svg)](https://github.com/jahwag/agentbus/actions/workflows/ci.yml)
[![CodeQL](https://github.com/jahwag/agentbus/actions/workflows/codeql.yml/badge.svg)](https://github.com/jahwag/agentbus/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Discord](https://img.shields.io/badge/Discord-The%20Orchard-5865F2?logo=discord&logoColor=white)](https://discord.gg/pR4qeMH4u4)

AgentBus is a small durable mailbox for cooperating AI agents. It provides
direct messages and broadcasts over HTTP and Streamable HTTP MCP, survives
restarts, and redelivers messages until they are acknowledged.

![AgentBus restart and redelivery demo](docs/assets/agentbus-demo.gif)

Send → wait → restart → redeliver → acknowledge.

## Why AgentBus?

Agent processes stop, restart, time out, and run at different speeds. Passing
messages through terminal output or temporary files works until one side is not
listening.

AgentBus gives each agent a durable mailbox:

- **Direct messages and broadcasts.** Address one agent or a group.
- **At-least-once delivery.** Unacknowledged messages return with
  `redelivery=true`.
- **Stable delivery IDs.** Consumers can make side effects idempotent.
- **Restart-safe state.** A single SQLite database stores messages, receipts,
  leases, and audit history.
- **Agent-native access.** Use the CLI, HTTP API, or MCP from Codex, Claude, and
  other MCP-capable clients.

It is one Go daemon with no external broker to operate.

## Try it

AgentBus requires Go 1.25 or newer.

```bash
git clone https://github.com/jahwag/agentbus.git
cd agentbus
make build
./bin/agentbusd --listen 127.0.0.1:7777 --db ./agentbus.db
```

In another terminal:

```bash
curl http://127.0.0.1:7777/readyz
```

For a complete local exercise—including authentication, durable delivery,
restart redelivery, acknowledgement, pruning, and the operator UI—run:

```bash
make acceptance
```

The acceptance script uses an isolated temporary database and cleans up after
itself.

For prebuilt Linux and macOS archives, checksums, SBOMs, and provenance, see
the [latest release](https://github.com/jahwag/agentbus/releases/latest).

## How delivery works

1. A sender supplies a unique `client_message_id`.
2. AgentBus commits the message before reporting success.
3. A consumer waits for its next mailbox delivery.
4. AgentBus leases that delivery to the consumer.
5. The consumer performs its side effect and acknowledges the delivery ID.
6. If the lease expires first, the same delivery ID is returned with
   `redelivery=true`.

Consumers should deduplicate external side effects by delivery ID and
acknowledge only after processing succeeds.

Broadcasts create an independent receipt for every intended recipient. One
slow consumer does not block the others.

Operator mailboxes are UI principals, not agent consumers: they never appear
in the agent roster or receive `wait`/`ack` deliveries. A direct agent reply to
an operator is retained in the conversation and recent-route views without a
mailbox receipt, so it is visible in the chat UI but is not an at-least-once
agent delivery. Normal retention pruning removes these records on the same
schedule as other settled message history.

## Where it fits

Use AgentBus when:

- a small group of local or remote agents needs restart-safe coordination;
- agents already speak MCP or can call a small HTTP API;
- you want durable delivery without operating a general-purpose broker;
- a single-node SQLite-backed service is the right operational size.

Use NATS, Kafka, Redis Streams, RabbitMQ, or a managed queue when you need
multi-node high availability, very high throughput, partitioned event streams,
complex routing, or a broad non-agent messaging platform.

AgentBus is intentionally narrower: named agent mailboxes, broadcasts,
redelivery, acknowledgement, leases, and an operator audit trail.

## Interfaces

- **MCP:** Streamable HTTP tools for agent registration, send, wait,
  acknowledgement, roster lookup, and related coordination.
- **CLI:** Administrative and mailbox commands through `bin/agentbus`.
- **HTTP:** Health, readiness, mailbox, audit, and operator endpoints.
- **Operator UI:** Overview and message-conversation views with explicit
  content reveal. Externally bound operators may send direct, attributed
  messages; native administrator-code sessions remain inspection-only.

Run the binaries with `--help` for the current command and configuration
surface:

```bash
./bin/agentbus --help
./bin/agentbusd --help
```

A ready-to-adapt Codex MCP configuration is available at
[`deploy/codex/agentbus.toml`](deploy/codex/agentbus.toml).
For Claude Code, see the [secure Streamable HTTP MCP setup](docs/claude-code-mcp.md).

## Security and deployment

The unauthenticated local setup above is for a trusted development workstation
only. For shared hosts or networks:

- enable authentication and issue a separate capability-scoped token to each
  agent;
- keep the daemon on loopback or behind an authenticated TLS reverse proxy;
- protect the SQLite database and token files with restrictive permissions;
- never place tokens in command arguments, repository files, or logs.

AgentBus can validate native agent tokens and OIDC workload access tokens at
the same `/mcp` resource. OIDC mode uses provider discovery/JWKS and supports a
stable `oid` subject plus a required application role:

```text
AGENTBUS_OIDC_ISSUER=https://identity.example.com/tenant/v2.0
AGENTBUS_OIDC_AUDIENCE=EXPECTED_ACCESS_TOKEN_AUD
AGENTBUS_OIDC_SUBJECT_CLAIM=oid
AGENTBUS_OIDC_REQUIRED_ROLE=AgentBus.Agent
AGENTBUS_MCP_RESOURCE_URI=https://agentbus.example.com/mcp
```

Bind each validated `(issuer, subject)` to one local mailbox with
`agentbus bind-identity`. Operators and agents are separate principal kinds;
operator identities cannot call agent MCP tools.

For short-lived Entra client-credential tokens, run
`agentbus-mcp-bridge` as the local stdio MCP process. It uses
`DefaultAzureCredential`, caches and refreshes access tokens, and accepts
`AGENTBUS_MCP_URL` plus `AGENTBUS_SCOPE` or `AGENTBUS_AUDIENCE`. A native
`AGENTBUS_TOKEN` remains the portable fallback. The Entra path requires an
explicit `AZURE_TOKEN_CREDENTIALS`; use `prod` for unattended services so the
credential chain cannot fall through to a cached CLI/developer identity.

For Entra v2 specifically, set the daemon's `AGENTBUS_OIDC_AUDIENCE` to the
resource application's bare client-ID GUID because that is the access token's
`aud`. The bridge's token-request audience remains
`api://RESOURCE_APP_ID` (or use the explicit
`api://RESOURCE_APP_ID/.default` scope).

Browser authentication is provider-neutral and independent of MCP resource
authorization. Deployments can choose any combination of three modes:

- Native OpenID Connect Authorization Code login with PKCE, state, and nonce.
  AgentBus validates the ID token itself, resolves its `(issuer, subject)`
  through an explicit `operator` binding, and issues its own opaque UI session.
- Trusted-edge JWT assertion exchange. This remains useful when an access proxy
  already owns browser login, but the proxy does not become the MCP
  authorization server.
- A loopback one-time code minted with the administrator credential. This is
  the portable local recovery and single-host mode.

Native browser OIDC uses standard discovery and JWKS and works with Entra ID,
Keycloak, Authentik, Okta, and other conforming providers:

```text
AGENTBUS_UI_PUBLIC_ORIGIN=https://agentbus.example.com
AGENTBUS_UI_OIDC_ISSUER=https://identity.example.com/tenant/v2.0
AGENTBUS_UI_OIDC_CLIENT_ID=agentbus-browser-client
AGENTBUS_UI_OIDC_CLIENT_SECRET_FILE=/run/credentials/agentbusd/oidc-client-secret
AGENTBUS_UI_OIDC_REDIRECT_URL=https://agentbus.example.com/ui/auth/oidc/callback
AGENTBUS_UI_OIDC_SCOPES=openid profile email
AGENTBUS_UI_OIDC_SUBJECT_CLAIM=oid
AGENTBUS_UI_OIDC_REQUIRED_ROLE=AgentBus.Operator
```

`AGENTBUS_UI_OIDC_ISSUER` and `AGENTBUS_UI_OIDC_CLIENT_ID` must be set together.
The redirect URL defaults to the exact callback under
`AGENTBUS_UI_PUBLIC_ORIGIN` and cannot point elsewhere when a public origin is
configured. Supply the optional confidential-client secret through
`AGENTBUS_UI_OIDC_CLIENT_SECRET_FILE` where possible, or through
`AGENTBUS_UI_OIDC_CLIENT_SECRET`; omit both for providers that allow public
clients. Scopes default to `openid profile email`; `openid` is always added.
The subject claim is restricted to `sub` or `oid` and defaults to `sub`.
Required role is optional and expects a top-level JSON `roles` string array;
providers that use groups, nested realm roles, or another claim need a
provider-side claim mapping. Discovery is lazy and retryable: provider downtime
does not prevent daemon startup, but login remains unavailable until discovery
succeeds. Encrypted flow state does not consume server admission slots;
consumed-state replay markers, concurrent token exchanges, and per-principal
sessions are bounded. Bind the resulting identity before login:

```bash
agentbus bind-identity \
  --admin-token-file /run/credentials/agentbusd/admin-token \
  --name operator \
  --kind operator \
  --issuer https://identity.example.com/tenant/v2.0 \
  --subject-file /etc/agentbus/operator-subject
```

The subject file must be owner-only (or a systemd credential), bounded, and
free of newline/NUL bytes. `--subject` remains available for interactive use,
but `--subject-file` keeps stable identity identifiers out of process arguments.

Public native OIDC requires TLS, an exact public Host, and outbound HTTPS/DNS
from the daemon for discovery, JWKS retrieval, and token exchange. The Caddy
example contains a dedicated `/ui` route that preserves Host, and
`deploy/systemd/agentbusd-oidc.conf.example` shows secret-file loading and the
network-policy override required by the intentionally loopback-only base unit.
HTTPS sessions and flow state use `__Host-` cookies with `Path=/`.

For trusted-edge mode, configure `AGENTBUS_UI_ASSERTION_ISSUER`,
`AGENTBUS_UI_ASSERTION_AUDIENCE`, `AGENTBUS_UI_ASSERTION_JWKS_URL`, and
`AGENTBUS_UI_PUBLIC_ORIGIN`; then bind the assertion identity to an `operator`
mailbox. Set `AGENTBUS_UI_LOGOUT_URL` to the edge provider's HTTPS logout
endpoint so ending the product session also ends the upstream session instead
of immediately exchanging a still-valid assertion again.

Read [SECURITY.md](SECURITY.md) before exposing AgentBus beyond a trusted local
machine. Operational defaults and recovery procedures live in
[RUNBOOK.md](RUNBOOK.md), with deployable examples under [`deploy/`](deploy/).

## Project scope

AgentBus is a focused coordination primitive, not an agent runtime or task
scheduler. [Clem](https://github.com/jahwag/clem) runs and isolates coding
agents; AgentBus lets agents exchange durable messages. The projects are
independent and can be used separately.

The protocol and implementation decisions are documented in
[`docs/adr/`](docs/adr/).

## Community

- Questions and usage help: [The Orchard Discord](https://discord.gg/pR4qeMH4u4)
- Bugs and feature requests: [GitHub Issues](https://github.com/jahwag/agentbus/issues)
- Contribution expectations: [CONTRIBUTING.md](CONTRIBUTING.md)
- Support policy: [SUPPORT.md](SUPPORT.md)
- License: [MIT](LICENSE)
