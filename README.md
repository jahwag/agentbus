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
- **Operator UI:** Capability-scoped inspection without exposing message bodies
  in activity views.

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
