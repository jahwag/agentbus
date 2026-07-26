#!/bin/sh
set -eu

dist_dir=${1:-dist}
set -- "$dist_dir"/*_linux_amd64.tar.gz
if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
	echo "expected exactly one Linux amd64 archive under $dist_dir" >&2
	exit 1
fi
archive=$1
listing=$(tar -tzf "$archive")
archive_root=$(printf '%s\n' "$listing" | sed -n '1s@/.*@@p')
if [ -z "$archive_root" ]; then
	echo "archive has no wrapping directory: $archive" >&2
	exit 1
fi

for required in \
	agentbus \
	agentbusd \
	LICENSE \
	README.md \
	PLAN.md \
	CONTEXT.md \
	SECURITY.md \
	CONTRIBUTING.md \
	CODE_OF_CONDUCT.md \
	RELEASE_CHECKS.md \
	SUPPORT.md \
	THIRD_PARTY_NOTICES \
	docs/adr/0001-materialized-mailbox-receipts.md \
	docs/adr/0002-stateless-mcp-per-request-auth.md \
	docs/adr/0003-use-capability-scoped-operator-ui.md \
	deploy/Caddyfile.example \
	deploy/codex/agentbus.toml \
	deploy/systemd/README.md \
	deploy/systemd/agent-credential-dropin.conf.example \
	deploy/systemd/agentbusd.service \
	deploy/systemd/agentbus-prune.service \
	deploy/systemd/agentbus-prune.timer
do
	if ! printf '%s\n' "$listing" | grep -Fqx "$archive_root/$required"; then
		echo "release archive is missing $required" >&2
		exit 1
	fi
done

archive_name=${archive##*/}
if ! grep -Fq "  $archive_name" "$dist_dir/checksums.txt"; then
	echo "checksums.txt does not cover $archive_name" >&2
	exit 1
fi
if [ ! -s "$archive.spdx.json" ]; then
	echo "archive SBOM is missing: $archive.spdx.json" >&2
	exit 1
fi

echo "Release archive verification passed: $archive_name"
