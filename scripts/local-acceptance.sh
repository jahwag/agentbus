#!/bin/sh
set -eu

port=${AGENTBUS_ACCEPTANCE_PORT:-17777}
server="http://127.0.0.1:${port}"
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/agentbus-acceptance.XXXXXX")
daemon_pid=
db_path="$tmp_dir/bus.db"
ui_enabled=true

cleanup() {
	if [ -n "$daemon_pid" ]; then
		kill "$daemon_pid" 2>/dev/null || true
		wait "$daemon_pid" 2>/dev/null || true
	fi
	rm -rf "$tmp_dir"
}
trap cleanup EXIT HUP INT TERM

umask 077
mkdir -p "$tmp_dir/bin"
go build -trimpath -o "$tmp_dir/bin/agentbusd" ./cmd/agentbusd
go build -trimpath -o "$tmp_dir/bin/agentbus" ./cmd/agentbus

random_hex=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
printf 'aba_%s\n' "$random_hex" >"$tmp_dir/admin.token"

start_daemon() {
	"$tmp_dir/bin/agentbusd" \
		--listen "127.0.0.1:${port}" \
		--db "$db_path" \
		--admin-token-file "$tmp_dir/admin.token" \
		--ui="$ui_enabled" \
		>"$tmp_dir/daemon.log" 2>&1 &
	daemon_pid=$!
	i=0
	while :; do
		if ! kill -0 "$daemon_pid" 2>/dev/null; then
			echo 'agentbusd exited before becoming ready' >&2
			sed -n '1,120p' "$tmp_dir/daemon.log" >&2
			exit 1
		fi
		if curl --fail --silent --show-error "$server/readyz" >/dev/null 2>&1; then
			sleep 0.05
			if kill -0 "$daemon_pid" 2>/dev/null; then
				break
			fi
		fi
		i=$((i + 1))
		if [ "$i" -ge 100 ]; then
			echo 'agentbusd did not become ready' >&2
			sed -n '1,120p' "$tmp_dir/daemon.log" >&2
			exit 1
		fi
		sleep 0.05
	done
}

stop_daemon() {
	kill "$daemon_pid"
	wait "$daemon_pid" || true
	daemon_pid=
}

if curl --fail --silent --show-error "$server/healthz" >/dev/null 2>&1; then
	echo "acceptance port ${port} is already in use" >&2
	exit 1
fi
start_daemon

"$tmp_dir/bin/agentbus" mint --server "$server" \
	--admin-token-file "$tmp_dir/admin.token" --name lead \
	--token-out "$tmp_dir/lead.token" >/dev/null
"$tmp_dir/bin/agentbus" mint --server "$server" \
	--admin-token-file "$tmp_dir/admin.token" --name worker \
	--token-out "$tmp_dir/worker.token" >/dev/null

lead_token=$(sed -n '1p' "$tmp_dir/lead.token")
admin_token=$(sed -n '1p' "$tmp_dir/admin.token")
printf 'header = "Authorization: Bearer %s"\n' "$lead_token" >"$tmp_dir/lead.curl"
printf 'header = "Authorization: Bearer %s"\n' "$admin_token" >"$tmp_dir/admin.curl"
unset lead_token admin_token

identity_response=$(curl --fail --silent --show-error --config "$tmp_dir/lead.curl" \
	--header 'Content-Type: application/json' \
	--data '{"from":"worker","to":"worker","body":"identity check","client_message_id":"accept-identity"}' \
	"$server/send")
printf '%s' "$identity_response" | grep '"from":"lead"' >/dev/null

admin_status=$(curl --silent --show-error --output "$tmp_dir/admin-send.json" \
	--write-out '%{http_code}' --config "$tmp_dir/admin.curl" \
	--header 'Content-Type: application/json' \
	--data '{"from":"lead","to":"worker","body":"forbidden","client_message_id":"accept-admin-forge"}' \
	"$server/send")
[ "$admin_status" = 403 ]

first_delivery=$("$tmp_dir/bin/agentbus" wait --server "$server" \
	--token-file "$tmp_dir/worker.token")
first_id=$(printf '%s' "$first_delivery" | sed -n 's/.*"delivery_id":"\([^"]*\)".*/\1/p')
[ -n "$first_id" ]
"$tmp_dir/bin/agentbus" ack --server "$server" \
	--token-file "$tmp_dir/worker.token" --delivery-id "$first_id" >/dev/null

"$tmp_dir/bin/agentbus" send --server "$server" \
	--token-file "$tmp_dir/lead.token" --to worker \
	--client-message-id accept-restart --body 'survive restart' >/dev/null
before_restart=$("$tmp_dir/bin/agentbus" wait --server "$server" \
	--token-file "$tmp_dir/worker.token")
before_id=$(printf '%s' "$before_restart" | sed -n 's/.*"delivery_id":"\([^"]*\)".*/\1/p')
[ -n "$before_id" ]

stop_daemon
mkdir -p "$tmp_dir/cold-backup"
for db_file in "$tmp_dir"/bus.db*; do
	cp "$db_file" "$tmp_dir/cold-backup/"
done
start_daemon

after_restart=$("$tmp_dir/bin/agentbus" wait --server "$server" \
	--token-file "$tmp_dir/worker.token")
after_id=$(printf '%s' "$after_restart" | sed -n 's/.*"delivery_id":"\([^"]*\)".*/\1/p')
[ "$after_id" = "$before_id" ]
printf '%s' "$after_restart" | grep '"redelivery":true' >/dev/null
"$tmp_dir/bin/agentbus" ack --server "$server" \
	--token-file "$tmp_dir/worker.token" --delivery-id "$after_id" >/dev/null

# Restore the cold copy into a fresh state directory. It predates the ack, so
# the same immutable delivery must still redeliver there.
stop_daemon
mkdir -m 0700 "$tmp_dir/restored"
for db_file in "$tmp_dir"/cold-backup/bus.db*; do
	cp "$db_file" "$tmp_dir/restored/"
done
db_path="$tmp_dir/restored/bus.db"
start_daemon
after_restore=$("$tmp_dir/bin/agentbus" wait --server "$server" \
	--token-file "$tmp_dir/worker.token")
restore_id=$(printf '%s' "$after_restore" | sed -n 's/.*"delivery_id":"\([^"]*\)".*/\1/p')
[ "$restore_id" = "$before_id" ]
printf '%s' "$after_restore" | grep '"redelivery":true' >/dev/null
"$tmp_dir/bin/agentbus" ack --server "$server" \
	--token-file "$tmp_dir/worker.token" --delivery-id "$restore_id" >/dev/null

"$tmp_dir/bin/agentbus" prune --server "$server" \
	--admin-token-file "$tmp_dir/admin.token" --retention 720h >/dev/null

activity=$("$tmp_dir/bin/agentbus" activity --server "$server" \
	--admin-token-file "$tmp_dir/admin.token")
printf '%s' "$activity" | grep '"tracking_started_at"' >/dev/null
printf '%s' "$activity" | grep '"messages_sent":2' >/dev/null
if printf '%s' "$activity" | grep 'survive restart' >/dev/null; then
	echo 'activity output leaked a message body' >&2
	exit 1
fi

ui_send=$("$tmp_dir/bin/agentbus" send --server "$server" \
	--token-file "$tmp_dir/lead.token" --to worker \
	--client-message-id accept-ui --body 'UI_ACCEPTANCE_SECRET_</pre><script>alert(1)</script>')
ui_message_id=$(printf '%s' "$ui_send" | sed -n 's/.*"message_id":"\([^"]*\)".*/\1/p')
[ -n "$ui_message_id" ]
ui_session=$("$tmp_dir/bin/agentbus" ui-session --server "$server" \
	--admin-token-file "$tmp_dir/admin.token")
ui_code=$(printf '%s' "$ui_session" | sed -n 's/.*"code":"\([^"]*\)".*/\1/p')
[ -n "$ui_code" ]
login_status=$(curl --silent --show-error --output "$tmp_dir/ui-login.out" \
	--write-out '%{http_code}' --cookie-jar "$tmp_dir/ui.cookies" \
	--header 'Sec-Fetch-Site: same-origin' \
	--header 'Sec-Fetch-Mode: navigate' \
	--header 'Sec-Fetch-Dest: document' \
	--data-urlencode "code=$ui_code" "$server/ui/login")
[ "$login_status" = 303 ]
ui_cookie=$(awk '$6 == "agentbus_ui_session" {print $7}' "$tmp_dir/ui.cookies")
[ -n "$ui_cookie" ]

dashboard=$(curl --fail --silent --show-error --cookie "$tmp_dir/ui.cookies" "$server/ui/")
printf '%s' "$dashboard" | grep '>lead<' >/dev/null
printf '%s' "$dashboard" | grep '>worker<' >/dev/null
if printf '%s' "$dashboard" | grep 'UI_ACCEPTANCE_SECRET_' >/dev/null; then
	echo 'dashboard preloaded a message body' >&2
	exit 1
fi

reveal=$(curl --fail --silent --show-error --cookie "$tmp_dir/ui.cookies" \
	--header 'Sec-Fetch-Site: same-origin' \
	--header 'Sec-Fetch-Mode: navigate' \
	--header 'Sec-Fetch-Dest: document' \
	--data-urlencode "message_id=$ui_message_id" "$server/ui/reveal")
printf '%s' "$reveal" | grep 'UI_ACCEPTANCE_SECRET_' >/dev/null
printf '%s' "$reveal" | grep '&lt;script&gt;' >/dev/null
if printf '%s' "$reveal" | grep '<script>' >/dev/null; then
	echo 'reveal rendered message content as markup' >&2
	exit 1
fi

reuse_status=$(curl --silent --show-error --output "$tmp_dir/ui-reuse.out" \
	--write-out '%{http_code}' --header "Origin: $server" \
	--data-urlencode "code=$ui_code" "$server/ui/login")
[ "$reuse_status" = 401 ]
admin_secret=$(sed -n '1p' "$tmp_dir/admin.token")
for secret in "$admin_secret" "$ui_code" "$ui_cookie" 'UI_ACCEPTANCE_SECRET_'; do
	if grep -F "$secret" "$tmp_dir/daemon.log" >/dev/null; then
		echo 'daemon log leaked a UI credential or message body' >&2
		exit 1
	fi
done
unset admin_secret ui_code ui_cookie

grep '@public path /send /wait /ack /roster /mcp /mcp/\* /healthz /readyz' deploy/Caddyfile.example >/dev/null
grep 'respond "HTTPS required" 426' deploy/Caddyfile.example >/dev/null
if grep '@public path .* /ui' deploy/Caddyfile.example >/dev/null; then
	echo 'Caddy public allowlist exposed the operator UI' >&2
	exit 1
fi

stop_daemon
ui_enabled=false
start_daemon
disabled_ui_status=$(curl --silent --show-error --output "$tmp_dir/ui-disabled.out" \
	--write-out '%{http_code}' "$server/ui/")
[ "$disabled_ui_status" = 404 ]
disabled_bootstrap_status=$(curl --silent --show-error --output "$tmp_dir/ui-bootstrap-disabled.out" \
	--write-out '%{http_code}' --config "$tmp_dir/admin.curl" \
	--header 'Content-Type: application/json' --data '{}' "$server/ui/bootstrap")
[ "$disabled_bootstrap_status" = 404 ]
stop_daemon

echo 'AgentBus local acceptance passed: auth binding, admin separation, durable delivery, restart and cold-restore redelivery, ack, prune, body-free activity, browser-compatible capability-scoped UI inspection, and explicit UI disablement.'
