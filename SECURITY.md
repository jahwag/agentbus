# Security policy

Only the latest released version is supported. Do not report vulnerabilities
in a public issue or Discord channel. Open a
[private GitHub security advisory](https://github.com/jahwag/agentbus/security/advisories/new).
If that is unavailable, contact
[@jahwag by direct message in The Orchard Discord](https://discord.gg/pR4qeMH4u4).

We aim to acknowledge reports within three business days, provide an initial
assessment within seven business days, and coordinate remediation and
disclosure. These are response targets, not service-level guarantees. Include
affected versions, impact, reproduction steps, and any proposed mitigation.

## Deployment boundary

AgentBus auth-off mode is intentionally insecure and must remain on loopback.
Authenticated deployments must also bind the daemon to loopback and terminate
TLS at the supplied Caddy layer. Store the admin credential and each agent
credential in separate mode-0600 files. Do not put secrets on command lines,
in unit definitions, or in an interactive shell environment. A service manager
may load an agent token from its root-owned mode-0600 environment file so the
agent process receives only its own credential.

AgentBus is not end-to-end encrypted. TLS protects network transit, while
message content remains readable in SQLite by the daemon account, root, and
authorized operators.

Per-agent credentials only provide a meaningful isolation boundary when agents
run as separate unprivileged operating-system identities. An agent running as
root or as the daemon user can read or replace credentials and the database; no
application-level token scheme can repair that deployment.

The operator dashboard is a loopback-only inspection surface for authenticated
deployments. Keep `/ui`, `/ui/*`, `/activity`, `/audit`, and `/backlog` blocked
at the public reverse proxy and use an SSH tunnel. Never paste the root admin
bearer into a browser: `agentbus ui-session` exchanges it on the daemon host for
a two-minute, single-use code and a read-only HttpOnly browser session. Message
content is fetched only by an explicit same-origin reveal POST and must remain
escaped text; a UI session must never be accepted by administrator mutation or
agent endpoints.

HTTP cookies are scoped to a host, not a port. Use the documented
`agentbus.localhost` dashboard URL instead of the generic loopback IP so the
cookie is not sent to ordinary `127.0.0.1` development sites. A hostile local
process serving another port under that exact hostname can still capture the
read-only session if the operator visits it; eliminating that residual requires
local HTTPS. The session has no mutation authority and expires server-side.

All message content is untrusted, including content from an authenticated peer.
Authentication establishes sender provenance but does not authorize secret
access, destructive operations, or publication. Report any path by which a bus
message bypasses the consumer's configured permission boundary.

Do not attach databases, token files, Caddy logs containing authorization
headers, or raw agent conversations to an issue. Remove credentials from any
reproduction and rotate a credential immediately if it may have been exposed.
