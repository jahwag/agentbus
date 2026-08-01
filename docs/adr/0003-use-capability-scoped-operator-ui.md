# Use capability-scoped operator UI sessions

AgentBus serves its operator console on the existing loopback HTTP listener.
The UI has Overview and Messages surfaces. Activity and recent-route pages
contain bounded body-free metadata; opening a single message or conversation
is an explicit same-origin POST, and all agent content is rendered as escaped
untrusted text.

There are three browser entry modes:

1. The administrator CLI exchanges the root bearer for a two-minute,
   single-use code. The browser receives an in-memory, expiring HttpOnly
   session accepted only by `/ui/*`. This session is inspection-only.
2. A deployment may configure a trusted-edge JWT issuer, audience, JWKS URL,
   header, and exact public origin. AgentBus verifies the assertion, resolves
   its `(issuer, subject)` through an explicit external identity binding, and
   requires an `operator` mailbox before minting the same kind of opaque
   browser session.
3. A deployment may configure a standard OpenID Connect browser client and an
   exact public origin. AgentBus performs Authorization Code flow with state,
   nonce, and PKCE S256, validates the ID token's issuer, audience, expiry,
   nonce, optional role, and configured `sub` or `oid` subject, then resolves
   the `(issuer, subject)` through the same explicit `operator` binding before
   minting the same opaque browser session.

An externally authenticated operator session may send one direct message.
AgentBus derives `from` exclusively from the bound session principal, embeds a
server-generated command identifier in each form so an HTTP retry reuses the
same idempotency key, refuses broadcast and unknown agent recipients, and
commits a body-free `operator_send` audit event with the message. Operator
sessions have no administrator authority and cannot use agent MCP tools.
Unbinding the external identity increments the mailbox credential generation
and invalidates existing trusted-edge and native-OIDC operator sessions. OIDC
discovery is lazy, cooldown-protected, and retryable so provider downtime does
not prevent daemon startup. Flow data is authenticated and encrypted into the
short-lived state cookie, so anonymous starts consume no server admission pool.
A bounded in-memory consumed-state cache rejects replay, including after the
provider returns an error. Token exchanges and per-principal sessions are
independently bounded. Browser session expiry never exceeds ID-token expiry.

Operator mailboxes do not participate in agent delivery queues or the agent
roster. A direct agent reply addressed to an operator is retained for recent
routing and conversation inspection without creating a receipt that no agent
consumer could acknowledge. It therefore has UI-history semantics rather than
at-least-once mailbox-delivery semantics and remains subject to ordinary
retention pruning.

The dashboard is part of the daemon lifecycle and is available when at least
one browser entry mode is configured. `agentbusd --ui=false` removes every
dashboard route without creating a second listener or affecting agent traffic.
When OIDC or trusted-edge login is configured without a native administrator
token, only `/ui/*` may use the exact public host; unauthenticated REST routes
remain loopback-only.

UI form submissions prefer an exact `Origin`. Browsers that omit it or
serialize it as `null` are accepted only when browser-controlled Fetch
Metadata identifies a same-origin top-level document navigation. Missing,
cross-site, or contradictory metadata remains forbidden. Public deployments
also require an exact configured Host and use `Secure`, `HttpOnly`,
`SameSite=Strict`, `__Host-` cookies scoped to `Path=/`. Loopback development
retains the narrower plaintext cookie names and paths.

Putting the administrator bearer in browser JavaScript was rejected because a
single stored-XSS mistake would gain mint, skip, retire, and prune authority.
Embedding bodies in hidden HTML or collapsed rows was rejected because it
loads content before operator consent. Treating an edge assertion or browser
ID token as MCP authority was rejected because browser identity and MCP
resource authorization have different clients, audiences, capabilities, and
lifecycles. Requiring an access proxy for native OIDC was rejected because it
would make a deployment preference into a product dependency. Forwarding an
upstream JWT into the UI was rejected in favor of a one-time protocol exchange
and an audience-restricted, opaque AgentBus session.
