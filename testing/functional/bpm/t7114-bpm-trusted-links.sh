#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t7114 -- a tree sync takes the registry auth file and CA certificate it
# is given by a path under /etc/shirudo through links of root's into a
# directory of root's elsewhere, absolute, relative and to a directory,
# as distributions link certificates and config managers link files. A
# link another user owns, or a directory others can write that holds a
# link, is refused with its message before any request. Runs after
# t7112, on the publication it left configured.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
REGISTRY="$FIXTURES/tree-oci"
STORE=/usr/local/share/shirudo-t7114
LINKS=/etc/shirudo/t7114
NOBODY=65534
WORK=$(mktemp -d)

[ -s "$FIXTURES/cert.der" ] || test_skip_all "missing fixture: cert.der"
[ -s "$TREE_STATE_FILE" ] || test_skip_all "no tree state to keep"

cleanup()
{
	tree_registry_stop
	rm -rf "$LINKS" "$STORE" "$WORK" || true
}
trap cleanup EXIT

unset BPM_OCI_CA_FILE BPM_OCI_USERNAME BPM_OCI_PASSWORD DOCKER_CONFIG

# A dry run of the sync with auth file $1 and, unless empty, CA $2.
sync_with() (
	[ -z "$2" ] || export BPM_OCI_CA_FILE="$2"
	REGISTRY_AUTH_FILE=$1 BPM_OCI_SCHEME=http "$SHIRUDO_BIN" bpm tree sync \
		--dry-run --report "$WORK/report.json" >/dev/null 2>"$WORK/err"
)

requests()
{
	if [ -e "$WORK/requests.log" ]; then
		wc -l <"$WORK/requests.log"
	else
		echo 0
	fi
}

refused_for()
{
	grep -qF "$1: refusing a file another user could replace" "$WORK/err"
}

install -d -m 0755 "$STORE/auth" "$STORE/certs-1" "$STORE/open" "$LINKS"
chmod 0777 "$STORE/open"
printf '{"auths":{"127.0.0.1:5443":{"auth":"%s"}}}\n' \
	"$(printf 't7114:t7114' | base64)" >"$STORE/auth/config.json"
python3 -c '
import ssl, sys
der = open(sys.argv[1], "rb").read()
open(sys.argv[2], "w").write(ssl.DER_cert_to_PEM_cert(der))
' "$FIXTURES/cert.der" "$STORE/certs-1/registry-ca.pem"
chmod 0644 "$STORE/auth/config.json" "$STORE/certs-1/registry-ca.pem"
ln -s certs-1 "$STORE/certs"
ln -s ../../../usr/local/share/shirudo-t7114/auth/config.json \
	"$LINKS/auth.json"
ln -s "$STORE/certs/registry-ca.pem" "$LINKS/ca.pem"
ln -s ca.pem "$LINKS/current-ca.pem"
ln -s "$STORE/auth/config.json" "$LINKS/auth-nobody.json"
chown -h "$NOBODY:$NOBODY" "$LINKS/auth-nobody.json"
ln -s "$STORE/certs/registry-ca.pem" "$LINKS/ca-nobody.pem"
chown -h "$NOBODY:$NOBODY" "$LINKS/ca-nobody.pem"
ln -s ../auth/config.json "$STORE/open/config.json"
ln -s "$STORE/open/config.json" "$LINKS/auth-open.json"

tree_registry_start "$REGISTRY" "$WORK"
cp "$TREE_STATE_FILE" "$WORK/state"

test_expect_success 'a dry run syncs without an auth file or a CA' '
	sync_with "$WORK/absent.json" "" &&
	[ "$(report_field dry_run <"$WORK/report.json")" = True ] &&
	[ "$(requests)" -gt 0 ] &&
	cmp -s "$TREE_STATE_FILE" "$WORK/state"
'

test_expect_success 'links root owns lead it to the auth file and the CA' '
	before=$(requests) &&
	sync_with "$LINKS/auth.json" "$LINKS/current-ca.pem" &&
	[ "$(report_field dry_run <"$WORK/report.json")" = True ] &&
	[ "$(requests)" -gt "$before" ] &&
	cmp -s "$TREE_STATE_FILE" "$WORK/state"
'

test_expect_success 'an auth file through a link nobody owns is refused' '
	before=$(requests) &&
	! sync_with "$LINKS/auth-nobody.json" "$LINKS/ca.pem" &&
	refused_for "$LINKS/auth-nobody.json: link $LINKS/auth-nobody.json, owner $NOBODY" &&
	grep -qxF "bpm tree sync: Operation not permitted" "$WORK/err" &&
	[ "$(requests)" = "$before" ]
'

test_expect_success 'so is a CA certificate through a link nobody owns' '
	before=$(requests) &&
	! sync_with "$LINKS/auth.json" "$LINKS/ca-nobody.pem" &&
	refused_for "$LINKS/ca-nobody.pem: link $LINKS/ca-nobody.pem, owner $NOBODY" &&
	grep -qF "BPM_OCI_CA_FILE is not a readable certificate" "$WORK/err" &&
	[ "$(requests)" = "$before" ]
'

test_expect_success 'and an auth file through a directory others can write' '
	before=$(requests) &&
	! sync_with "$LINKS/auth-open.json" "$LINKS/ca.pem" &&
	refused_for "$LINKS/auth-open.json: directory $STORE/open, owner 0, mode 0777" &&
	[ "$(requests)" = "$before" ]
'

test_done
