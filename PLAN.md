# AgentBus — implemented design (v4)

AgentBus is a durable agent-to-agent mailbox for a single-digit fleet of
Claude Code and Codex sessions. Discord remains the human-facing surface.

## Outcomes

- Agents receive only mail addressed to them, without rereading shared chat.
- Idle waiting consumes zero tokens through `agentbus wait`; Codex MCP waiting
  is explicitly near-zero because its tool call may time out periodically.
- A committed send survives daemon and consumer crashes.
- Delivery is at-least-once. Agent side effects are not exactly-once and must
  deduplicate by `message_id`.
- Local and VPS deployments use the same HTTP transports and one static Go
  binary pair: `agentbusd` and `agentbus`.
- Operators can inspect body-free traffic and explicitly reveal one retained
  message through an SSH-tunnel-only dashboard without exposing the root admin
  bearer to a browser.

## Architecture

- One `agentbusd` process owns one SQLite database. Multiple daemons sharing a
  database are unsupported because notification is process-local.
- Go with `modernc.org/sqlite`; WAL, `synchronous=FULL`, busy timeout,
  `AUTOINCREMENT`, numbered atomic migrations, and restrictive file modes.
- Streamable HTTP MCP and plain HTTP are thin adapters over one delivery
  module. Delivery state transitions exist only in that module.
- Local auth-off mode binds loopback only and is explicitly insecure. VPS
  auth-on mode also binds loopback and uses per-agent bearer credentials behind
  Caddy TLS. Network plaintext is not a supported deployment mode.

## Chosen delivery model

Three adversarial alternatives were evaluated: a cursor-backed stable batch,
per-recipient receipts, and visibility-timeout claims. M1 uses materialized
receipts grouped into stable batch deliveries.

Materialized receipts were selected because future-only broadcasts, poison
mail, retirement, and pruning become explicit state transitions instead of
proofs over a mutable global cursor. A batch delivery keeps the common agent
loop to one acknowledgement token. Visibility leases were rejected because
renewal, expiry clocks, takeover fencing, and delayed crash recovery add no
value while one logical consumer owns each identity.

### Agent-facing interface

```text
send(client_message_id, to, body, data?, reply_to?, allow_new?)
  -> {message_id, seq, from, to, ts, body, data?, reply_to?}

wait(timeout)
  -> timeout | {delivery_id, redelivery, messages[]}

ack(delivery_id)
  -> success
```

The authenticated principal supplies `from` and inbox identity. Auth-off
adapters accept an explicit local name claim. Cursors and batch watermarks are
private implementation state and never cross the interface.

`client_message_id` is required and bounded. Reusing it with the same
canonical command returns the original message. Reusing it with a different
recipient or payload returns an idempotency conflict.

### Mailboxes and receipts

- A mailbox is `reserved`, `active`, or `retired`.
- `allow_new` may reserve an unknown direct address and create its receipt.
  Reserved mailboxes receive direct mail but are absent from broadcasts and
  the active roster.
- `mint` activates a reserved or absent mailbox in auth-on mode. A reserved
  mailbox activates on its first acting call in auth-off mode.
- A direct send materializes one pending receipt.
- A broadcast materializes one pending receipt for every active mailbox at
  send commit, excluding the sender. Later identities never receive it.
- A receipt is `pending`, `offered`, `acked`, or `dead`.

### Stable deliveries

- At most one outstanding delivery exists per mailbox, enforced in SQLite.
- `wait` with no outstanding delivery groups a bounded ordered prefix of
  pending receipts into an immutable delivery and marks them offered.
- Repeated `wait` before acknowledgement returns the same delivery ID and
  membership with `redelivery=true`.
- `ack` atomically marks that delivery completed and all of its receipts
  acked. Re-acking a retained completed delivery succeeds idempotently.
- Unknown, foreign, or superseded delivery IDs conflict without revealing
  another mailbox's state.
- Duplicate sessions sharing one identity can process the same delivery.
  Shared identities are unsupported in M1; preventing this requires a real
  consumer lease and fencing, not delivery-ID tricks. Deployment therefore
  assigns one distinct identity and credential to every running agent and
  checks that invariant during acceptance.

## Administration and retention

- `mint <name>` creates or rotates an agent credential and activates its
  mailbox. The secret is returned once; only its SHA-256 digest is stored.
  Rotation increments a non-secret credential generation. Authenticated waits
  revalidate that generation after waking and before serializing mail, so an
  old parked request cannot receive messages after a rekey.
- `skip <name> <message_id> --reason ...` marks exactly one pending/offered
  receipt dead. If it belongs to an outstanding delivery, that delivery is
  superseded and its surviving receipts are requeued. Already-processed
  survivors can execute again, and later pending mail can join the rebuilt
  batch; side effects therefore deduplicate by `message_id`.
- `retire <name> --reason ...` works for reserved, active, and previously
  unknown direct addresses. It revokes credentials, supersedes outstanding
  delivery state, and dead-letters pending/offered receipts.
- `prune` removes message payloads only after every receipt has been terminal
  for 30 days. Message send age does not shorten that window. Outstanding and
  unacked mail is never silently removed. Completed delivery records remain
  for the same acknowledgement-idempotency window; after pruning, an ancient
  acknowledgement can conflict.
- Admin operations require the admin credential in auth-on mode and are
  recorded in an audit log. The admin credential is not an implicit agent and
  cannot use ordinary send/wait/ack calls. Audit inspection is cursor-paginated
  by event ID (100 events by default, 1,000 maximum), and operator reasons are
  capped at 1 KiB so inspection memory remains bounded.
- Body-free activity inspection records monotonic send, enqueue, offer, ack,
  and dead-letter transitions beginning at an explicit tracking timestamp.
  SQLite triggers update the counters in the same transaction as delivery
  state; current pending/offered/outstanding gauges remain derived from their
  authoritative tables. Historical activity is not guessed from pruned data.
  Output includes retired mailboxes, is deterministically capped at 256 rows,
  and is administrator-only over HTTP/CLI rather than an agent MCP tool.

## Operator inspection

- The built-in `/ui/` dashboard exists only in auth-on mode and only accepts a
  loopback Host. Caddy returns 404 for `/ui`, `/ui/*`, `/activity`, `/audit`,
  and `/backlog`; browser access uses an SSH local-forward instead.
- `agentbus ui-session` uses the protected administrator token to mint a
  128-bit, single-use login code with a two-minute lifetime. A same-origin form
  POST consumes it and rotates a random HttpOnly, host-only, SameSite=Strict
  operator session. Sessions are memory-only, bounded, expire after eight
  hours, and disappear on logout or daemon restart.
- Operator sessions authorize only read-only `/ui/*` handlers. They are never
  accepted as bearer credentials by agent or administrator endpoints.
- Dashboard pages query at most 51 retained routes in descending global
  sequence order and paginate with an exclusive `before_seq`. The body-free
  route projection includes sender, destination, timestamp, and aggregate
  receipt states, but not body, data, reply target, or client idempotency key.
- Content reveal is a separate same-origin POST carrying `message_id` in its
  form body. The server queries content only after that action and renders body
  and JSON as escaped text under a no-script CSP. UI responses are no-store,
  non-frameable, non-sniffable, and do not enable CORS.

## Addressing and message shape

- Direct address: a normalized name matching
  `[a-z0-9][a-z0-9._-]{0,63}`.
- Broadcast address: `*` at the adapters; represented as a distinct address
  kind inside the delivery module.
- Message: `{seq, message_id, from, to, ts, body, data?, reply_to?}`.
- `reply_to` is a stable `message_id`, not a database sequence.
- Request limit: 256 KiB. Encoded message limit: 64 KiB. The complete encoded
  delivery envelope is limited to 100 messages and 256 KiB. JSON depth is
  bounded.

## Waiting and notification

- SQLite is truth; in-process notification is only a latency hint.
- A waiter validates/activates its principal, registers, rechecks durable
  state, and parks in a predicate loop. Sends notify only after commit.
- Parked waiters hold no database connection or transaction.
- Parked waits are capped globally and at one per mailbox. This limits resource
  use and catches simultaneous idle consumers, but it cannot fence a second
  consumer that starts after the first delivery has returned.
- `agentbus wait` loops over normal timeouts and retryable connection errors
  outside the LLM and exits only with mail.
- MCP `wait` may return a normal timeout. Codex therefore has near-zero, not
  absolute-zero, idle token cost.
- Re-arming remains durable polling discipline in M1, not a subscription
  guarantee. A harness Stop hook is deferred.

## Security posture

- Auth-on credentials derive sender and mailbox identity; caller-supplied
  names carry no authority.
- MCP is stateless and verifies the bearer credential on every HTTP request;
  token rotation therefore revokes existing clients, and the admin credential
  never has agent scope.
- Auth-off mode refuses non-loopback binds, non-loopback Host headers, and
  browser Origin requests. Any local process can still impersonate an agent,
  so this mode is unsuitable for hostile local workloads.
- Admin credentials are read from protected files/systemd credentials, never
  command-line literals. Agent credentials are written directly to mode-0600
  files rather than printed by provisioning commands.
- Bearer identity is only an accident-prevention boundary when all coding
  agents run as the same Unix user (especially root). Strong isolation requires
  distinct unprivileged users and per-user credential readability.
- Message bodies are untrusted data. Authenticated sender stamping establishes
  provenance, not authority. Agent permission configuration must gate secret
  access, destructive actions, and publication.
- The browser never receives the administrator bearer. Stored message content
  never reaches the body-free dashboard and cannot execute during an explicit
  reveal.
- HTTP servers use bounded bodies and headers, explicit timeouts, graceful
  shutdown, cache prevention for mailbox responses, and generic internal
  errors.
- Reserved-mailbox and unsettled-backlog quotas fail sends explicitly before
  disk exhaustion; no quota path silently drops an accepted obligation.

## Public error classes

Adapters preserve machine-distinct classes for invalid input, unknown
recipient, retired identity, idempotency conflict, delivery conflict,
authentication required, admin required, payload too large, timeout, context
cancellation, and storage unavailable.

## Vertical TDD slices

Each slice is one failing public-behavior test followed by the minimum code to
pass. Tests do not assert private SQL or channel choreography.

1. A direct send creates a receipt; repeated wait returns one stable delivery;
   ack and re-ack succeed; subsequent wait is empty.
2. Required send idempotency returns the complete original message and rejects
   conflicting key reuse.
3. Reserved mailboxes receive old direct mail; broadcasts snapshot only active
   recipients at commit.
4. Delivery batches are ordered, immutable, and bounded by actual encoded
   bytes; forged/foreign/superseded acknowledgements conflict.
5. Skip affects only the named receipt; retirement terminates reserved and
   active mailboxes without pinning retention.
6. Pruning removes only terminal obligations past the retention window.
7. A send committed in every register/check/park race window wakes or is found
   by the waiter; restart redelivers outstanding batches.
8. HTTP and MCP adapters exercise the same send/wait/ack behavior and enforce
   credential-derived identity.
9. The CLI wait loop absorbs timeout, restart, and transient server failures;
   admin subcommands parse documented flags.
10. Daemon startup enforces safe binds, storage permissions, schema migration,
    production HTTP timeouts, readiness, graceful shutdown, and version data.
11. The UI exchanges a one-time code for a restricted session, keeps route
    inspection body-free, escapes explicit reveals, fails closed on origin and
    Host checks, and proves its cookie has no administrator authority.

## Repository and deployment standard

- `make verify` performs format, module-tidiness, vet, and race tests locally.
- CI uses one cached Linux quality job with concurrency cancellation. No OS or
  Go-version matrix runs on every change; cross-build and release work run only
  when needed.
- Reproducible release archives, checksums, SBOM configuration, a distroless
  container, systemd/Caddy examples, security policy, contribution guidance,
  and an executed acceptance record are included.
- Deployment acceptance installs the static binaries and systemd unit on a
  disposable test host, mints distinct credentials, and exercises authenticated
  send/wait/ack plus restart redelivery and SSH-tunnel-only UI inspection.

## Deferred

Consumer leases/fencing for intentionally shared identities; automatic Claude
Stop-hook re-arming; topics; SSE; metrics endpoint; automatic poison-message
attempt limits; database epoch handling across backup rollback.
