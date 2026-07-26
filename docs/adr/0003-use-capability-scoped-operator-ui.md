# Use a capability-scoped operator UI

AgentBus serves its read-only operator dashboard on the existing loopback HTTP
listener, reachable through an SSH tunnel and blocked by the public reverse
proxy. The administrator CLI exchanges the root bearer for a two-minute,
single-use code; the browser receives an in-memory, expiring HttpOnly operator
session accepted only by `/ui/*`. Dashboard queries return bounded routing
metadata without content, while a separate same-origin POST performs one
content reveal and renders it as escaped untrusted text.

The dashboard is part of the daemon lifecycle and is enabled by default only
when administrator authentication is configured. `agentbusd --ui=false`
removes every dashboard route without creating a second listener or affecting
agent traffic. The shipped unit relies on the default so it remains compatible
with the immediately preceding binary during rollback.

UI form submissions prefer an exact `Origin`. Browsers that
omit it or serialize it as `null` are accepted only when browser-controlled
Fetch Metadata identifies a same-origin top-level document navigation. Missing,
cross-site, or contradictory metadata remains forbidden; the loopback Host
allowlist and Strict SameSite operator cookie still apply independently.

Putting the administrator bearer in browser JavaScript was rejected because a
single stored-XSS mistake would gain mint, skip, retire, and prune authority.
Embedding bodies in hidden HTML or collapsed rows was rejected because it loads
content before operator consent. A separate listener was rejected because the
daemon is already loopback-only and an additional port would add deployment
state without improving the authority boundary; route-scoped capabilities and
the Caddy deny list provide that boundary on the existing listener.
