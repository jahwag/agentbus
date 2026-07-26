#!/bin/sh
set -eu

output=${1:-THIRD_PARTY_NOTICES}
tmp=$(mktemp "${TMPDIR:-/tmp}/agentbus-notices.XXXXXX")
modules=$(mktemp "${TMPDIR:-/tmp}/agentbus-modules.XXXXXX")
trap 'rm -f "$tmp" "$modules"' EXIT HUP INT TERM

{
	echo 'AgentBus third-party notices'
	echo '============================'
	echo
	echo 'AgentBus includes the following third-party software. The corresponding'
	echo 'license and notice texts are reproduced below.'
	echo
} >"$tmp"

go list -deps -f \
	'{{with .Module}}{{if not .Main}}{{.Path}}	{{.Version}}	{{.Dir}}{{end}}{{end}}' \
	./... | sort -u >"$modules"

while IFS='	' read -r module version directory; do
	[ -n "$module" ] || continue
	license_files=$(find "$directory" -maxdepth 1 -type f \
		\( -iname 'license*' -o -iname 'copying*' -o -iname 'notice*' \) |
		sort)
	if [ -z "$license_files" ]; then
		echo "no root license file found for $module@$version" >&2
		exit 1
	fi
	{
		echo
		echo '------------------------------------------------------------------------'
		echo "$module"
		echo '------------------------------------------------------------------------'
	} >>"$tmp"
	for license_file in $license_files; do
		{
			echo
			echo "--- ${license_file##*/} ---"
			echo
			sed 's/[[:space:]]*$//' "$license_file"
		} >>"$tmp"
	done
done <"$modules"

go_license="$(go env GOROOT)/LICENSE"
if [ ! -f "$go_license" ]; then
	echo "Go standard-library license not found at $go_license" >&2
	exit 1
fi
{
	echo
	echo '------------------------------------------------------------------------'
	echo 'Go standard library'
	echo '------------------------------------------------------------------------'
	echo
	sed 's/[[:space:]]*$//' "$go_license"
} >>"$tmp"

mv "$tmp" "$output"
