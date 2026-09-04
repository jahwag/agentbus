# Two-agent messaging tutorial

This tutorial connects two coding-agent identities, `reviewer` and
`implementer`, to one authenticated AgentBus daemon and walks through a durable
request/reply cycle.

It keeps every token in a protected temporary file. Do not paste tokens into
prompts, command arguments, logs, or repository files.

For production exposure and security tradeoffs, use this as a local exercise
only and read the deployment and security docs instead of copying the sample as
an internet-facing configuration:

- [Security policy](../SECURITY.md)
- [Systemd deployment notes](../deploy/systemd/README.md)
- [Caddy reverse-proxy example](../deploy/Caddyfile.example)

## 1. Start an authenticated daemon

Use a disposable working directory and keep the administrator credential in a
`0600` file:

```bash
workdir=$(mktemp -d)
chmod 700 "$workdir"

printf '%s\n' "$(openssl rand -hex 32)" > "$workdir/admin-token"
chmod 600 "$workdir/admin-token"

./bin/agentbusd \
  --listen 127.0.0.1:7777 \
  --db "$workdir/agentbus.db" \
  --admin-token-file "$workdir/admin-token"
```

Leave the daemon running. In a second terminal, point the CLI at it:

```bash
export AGENTBUS_SERVER=http://127.0.0.1:7777
workdir=/path/to/the/temp-directory-from-terminal-one
```

## 2. Mint separate agent credentials

Mint one credential per identity. The CLI creates the token files with mode
`0600` and refuses to overwrite existing files.

```bash
./bin/agentbus mint \
  --admin-token-file "$workdir/admin-token" \
  --name reviewer \
  --token-out "$workdir/reviewer-token"

./bin/agentbus mint \
  --admin-token-file "$workdir/admin-token" \
  --name implementer \
  --token-out "$workdir/implementer-token"
```

## 3. Send a request from reviewer to implementer

The authenticated token decides the sender identity. Even if a caller supplies a
misleading `--from`, AgentBus records the sender as the principal bound to the
credential.

```bash
./bin/agentbus send \
  --token-file "$workdir/reviewer-token" \
  --from spoofed-name \
  --to implementer \
  --allow-new \
  --client-message-id reviewer-request-001 \
  --body 'Please review the failing test and propose the smallest fix.'
```

Save the returned `message_id`; the reply will reference it with `--reply-to`.

## 4. Wait, process, and acknowledge as implementer

```bash
./bin/agentbus wait \
  --token-file "$workdir/implementer-token" \
  --timeout 30s
```

The response includes a `delivery_id` and one or more messages. Process the
message first, then acknowledge the delivery:

```bash
./bin/agentbus ack \
  --token-file "$workdir/implementer-token" \
  --delivery-id DELIVERY_ID_FROM_WAIT
```

Acknowledgement is separate from `wait` so an interrupted agent can receive the
same unacknowledged delivery again after its lease expires.

## 5. Reply from implementer to reviewer

```bash
./bin/agentbus send \
  --token-file "$workdir/implementer-token" \
  --to reviewer \
  --client-message-id implementer-reply-001 \
  --reply-to REQUEST_MESSAGE_ID_FROM_STEP_3 \
  --body 'I found the failing assertion; the minimal fix is to update the expected delivery state.'
```

Then receive and acknowledge the reply as `reviewer`:

```bash
./bin/agentbus wait \
  --token-file "$workdir/reviewer-token" \
  --timeout 30s

./bin/agentbus ack \
  --token-file "$workdir/reviewer-token" \
  --delivery-id DELIVERY_ID_FROM_WAIT
```

## Deduplication and retries

Every `send` requires a stable `--client-message-id`. Reusing the same value for
a retry makes the send idempotent: AgentBus can return the existing committed
message instead of creating a duplicate. Use a new `--client-message-id` only
when you intentionally want a new message.

Receivers should deduplicate external side effects by the delivered
`message_id`, and only then acknowledge the `delivery_id`. This matches the
at-least-once delivery model described in the README.

## Cleanup

Stop the daemon and remove the temporary directory when the exercise is done:

```bash
rm -rf "$workdir"
```
