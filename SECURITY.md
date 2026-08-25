# Security policy

Only the latest released version is supported. Do not report vulnerabilities
in a public issue or Discord channel. Open a
[private GitHub security advisory](../../security/advisories/new). If private
reporting is unavailable, open a public issue containing no vulnerability
details and ask the maintainers to enable a private reporting channel.

We aim to acknowledge reports within three business days, provide an initial
assessment within seven business days, and coordinate remediation and
disclosure. These response targets are not service-level guarantees. Include
affected versions, impact, reproduction steps, and any proposed mitigation.

## Deployment boundary

AgentBus auth-off mode is intentionally insecure and must remain on loopback.
Authenticated deployments should also bind the daemon to loopback and terminate
TLS at a narrowly scoped reverse proxy. Store the administrator credential and
each agent credential in separate mode-0600 files. Do not put secrets on command
lines, in unit definitions, or in interactive shell environment variables.
Prefer service-manager credentials or an equivalent secret-file mechanism.

AgentBus is not end-to-end encrypted. TLS protects network transit, while
message content remains readable in SQLite by the daemon account, root, and
authorized operators. Per-agent credentials provide a meaningful isolation
boundary only when agents run as separate unprivileged operating-system users.
An agent running as root or the daemon user can read or replace credentials and
the database; no application token scheme can repair that deployment boundary.

## Browser authentication

The operator UI supports three independent entry modes:

1. Local one-time code: keep `/ui/*` on loopback or an SSH tunnel. Never paste
   the root administrator bearer into a browser. `agentbus ui-session` exchanges
   it on the daemon host for a two-minute, single-use code and an opaque,
   expiring HttpOnly browser session. If local-code login is combined with a
   configured public OIDC or trusted-edge origin, the exact public Host applies
   to the whole UI and the one-time-code form is also available there; treat it
   as a recovery login protected by TLS and the code's short lifetime. A
   simultaneous loopback/SSH UI hostname is not provided in that combined mode.
2. Trusted-edge assertion: an identity-aware proxy authenticates the browser
   and supplies a JWT assertion. Configure an exact issuer, audience, JWKS URL,
   and public origin. AgentBus still verifies the assertion and requires an
   explicit `(issuer, subject)` binding to an `operator` mailbox.
3. Native OIDC: AgentBus performs Authorization Code flow with PKCE, state, and
   nonce, validates the ID token, and requires the same explicit operator
   binding. An access proxy is not required. The reverse proxy must expose only
   `/ui` and `/ui/*`, preserve the original public Host, and terminate HTTPS.

For a public UI, configure an exact HTTPS `AGENTBUS_UI_PUBLIC_ORIGIN`. The OIDC
redirect must be the callback under that origin. AgentBus rejects a mismatched
Host and uses `Secure`, `HttpOnly`, `SameSite` cookies with `__Host-` names.
The daemon also needs outbound HTTPS and DNS for discovery, JWKS retrieval, and
token exchange; see the optional systemd drop-in under `deploy/systemd/`.

Native OIDC discovery is lazy and retryable, so an unavailable provider does
not prevent daemon startup. Login remains unavailable until discovery succeeds.
OIDC flow data is authenticated and encrypted into the short-lived state
cookie; only consumed-state replay markers are kept in memory. Concurrent token
exchanges and per-principal sessions are bounded. Successful login mints an
opaque AgentBus session whose lifetime never exceeds the ID token. Native OIDC
logout revokes only that local session; RP-initiated provider logout is not
implemented. On a shared browser, end the IdP session separately. The optional
logout URL applies only to trusted-edge assertion mode.

Browser identity is not MCP authorization. An operator session can inspect and
send a direct message as its bound operator identity, but cannot broadcast,
impersonate an agent, administer the bus, or use agent MCP tools. Protect MCP
with its own resource-server tokens, audience, bindings, and capabilities.

HTTP cookies are scoped to a host, not a port. For plaintext loopback mode, use
the documented `agentbus.localhost` dashboard name so its cookie is not sent to
ordinary `127.0.0.1` development sites. A hostile local process on another port
under that exact hostname could still capture the limited local session if an
operator visits it; local HTTPS removes that residual risk. Every session also
expires server-side.

All message content is untrusted, including content from authenticated peers.
Authentication establishes sender provenance; it does not authorize secret
access, destructive operations, or publication. Report any path by which a bus
message bypasses a consumer's configured permission boundary.

Do not attach databases, token files, Caddy logs containing authorization
headers, or raw agent conversations to an issue. Remove credentials from any
reproduction and rotate a credential immediately if it may have been exposed.
