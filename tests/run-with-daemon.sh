#!/bin/sh
# Start pkcs11-daemon on a private port for a module, run a test against the
# proxy library, then stop the daemon.
#
#   run-with-daemon.sh <pkcs11-daemon> <libpkcs11-proxy> <module> <test> [softhsm2-util]
#
# With softhsm2-util given, a scratch SoftHSM token (user PIN 1234) is
# initialised first and <module> is libsofthsm2.
set -eu

daemon=$1 proxy=$2 module=$3 test=$4 util=${5:-}

work=$(mktemp -d "${TMPDIR:-/tmp}/p11proxy-test.XXXXXX")
daemon_pid=
cleanup() {
	[ -n "$daemon_pid" ] && kill "$daemon_pid" 2>/dev/null || true
	rm -rf "$work"
}
trap cleanup EXIT INT TERM

if [ -n "$util" ]; then
	mkdir "$work/tokens"
	printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' \
		"$work" > "$work/softhsm2.conf"
	SOFTHSM2_CONF="$work/softhsm2.conf"
	export SOFTHSM2_CONF
	"$util" --module "$module" --init-token --free --label test \
		--so-pin 12345678 --pin 1234 > /dev/null
fi

port=$((20000 + $$ % 20000))
addr="tcp://127.0.0.1:$port"

PKCS11_DAEMON_SOCKET=$addr "$daemon" "$module" > "$work/daemon.log" 2>&1 &
daemon_pid=$!
sleep 2
kill -0 "$daemon_pid" 2>/dev/null || { echo "daemon failed to start:"; cat "$work/daemon.log"; exit 1; }

status=0
PKCS11_PROXY_SOCKET=$addr "$test" "$proxy" || status=$?
[ "$status" -eq 0 ] || { echo "--- daemon log ---"; cat "$work/daemon.log"; }
exit "$status"
