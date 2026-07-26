#!/bin/sh
set -eu

demo_dir=/tmp/agentbus-vhs-demo
server=http://127.0.0.1:7777
pid_file="$demo_dir/agentbusd.pid"
log_file="$demo_dir/agentbusd.log"
db_file="$demo_dir/agentbus.db"

stop() {
	if [ ! -f "$pid_file" ]; then
		return
	fi
	pid=$(sed -n '1p' "$pid_file")
	if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
		kill "$pid"
		i=0
		while kill -0 "$pid" 2>/dev/null; do
			i=$((i + 1))
			if [ "$i" -ge 100 ]; then
				echo "demo daemon did not stop" >&2
				exit 1
			fi
			sleep 0.05
		done
	fi
	rm -f "$pid_file"
}

start() {
	mkdir -p "$demo_dir"
	./bin/agentbusd --listen 127.0.0.1:7777 --db "$db_file" \
		>"$log_file" 2>&1 &
	pid=$!
	printf '%s\n' "$pid" >"$pid_file"

	i=0
	while ! curl --fail --silent "$server/readyz" >/dev/null 2>&1; do
		if ! kill -0 "$pid" 2>/dev/null; then
			sed -n '1,80p' "$log_file" >&2
			exit 1
		fi
		i=$((i + 1))
		if [ "$i" -ge 100 ]; then
			echo "demo daemon did not become ready" >&2
			exit 1
		fi
		sleep 0.05
	done
}

case ${1:-} in
	reset)
		stop
		rm -rf "$demo_dir"
		start
		;;
	restart)
		stop
		start
		;;
	stop)
		stop
		;;
	*)
		echo "usage: $0 reset|restart|stop" >&2
		exit 2
		;;
esac
