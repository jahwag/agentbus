# Use capability-scoped operator UI sessions

AgentBus serves its operator console on the existing loopback HTTP listener.
The UI has Overview and Messages surfaces. Activity and recent-route pages
contain bounded body-free metadata; opening a single message or conversation
is an explicit same-origin POST, and all agent content is rendered as escaped
untrusted text.

There are two browser entry modes:

1. The administrator CLI exchanges the root bearer for a two-minute,
   single-use code. The browser receives an in-memory, expiring HttpOnly
   session accepted only by `/ui/*`. This session is inspection-only.
2. A deployment may configure a trusted-edge JWT issuer, audience, JWKS URL,
   header, and exact public origin. AgentBus verifies the assertion, resolves
   its `(issuer, subject)` through an explicit external identity binding, and
   requires an `operator` mailbox before minting the same kind of opaque
   browser session.

An externally authenticated operator session may send one direct message.
AgentBus derives `from` exclusively from the bound session principal, embeds a
server-generated command identifier in each form so an HTTP retry reuses the
same idempotency key, refuses broadcast and unknown agent recipients, and
commits a body-free `operator_send` audit event with the message. Operator
sessions have no administrator authority and cannot use agent MCP tools.
Unbinding the external identity increments the mailbox credential generation
and invalidates existing operator sessions.

Operator mailboxes do not participate in agent delivery queues or the agent
roster. A direct agent reply addressed to an operator is retained for recent
routing and conversation inspection without creating a receipt that no agent
consumer could acknowledge. It therefore has UI-history semantics rather than
at-least-once mailbox-delivery semantics and remains subject to ordinary
retention pruning.

The dashboard is part of the daemon lifecycle and is enabled by default only
when administrator authentication is configured. `agentbusd --ui=false`
removes every dashboard route without creating a second listener or affecting
agent traffic.

UI form submissions prefer an exact `Origin`. Browsers that omit it or
serialize it as `null` are accepted only when browser-controlled Fetch
Metadata identifies a same-origin top-level document navigation. Missing,
cross-site, or contradictory metadata remains forbidden. Public deployments
also require an exact configured Host and use a `Secure`, `HttpOnly`,
`SameSite=Strict` cookie.

Putting the administrator bearer in browser JavaScript was rejected because a
single stored-XSS mistake would gain mint, skip, retire, and prune authority.
Embedding bodies in hidden HTML or collapsed rows was rejected because it
loads content before operator consent. Treating the edge assertion as MCP
authority was rejected because browser perimeter identity and MCP resource
authorization have different clients and lifecycles.
