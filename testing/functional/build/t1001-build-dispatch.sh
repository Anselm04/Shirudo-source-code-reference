#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/../.."
. ./test-lib.sh

SHIRUDO=../shirudo
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

write_helper()
{
	path="$1"
	cat >"$path" <<'EOF'
#!/bin/sh
printf '%s\n' "$0" >"$BUILD_DISPATCH_LOG"
printf '%s\n' "$*" >>"$BUILD_DISPATCH_LOG"
EOF
	chmod +x "$path"
}

printf 'int main(void) { return 0; }\n' >"$WORK/input.bpf.c"
mkdir "$WORK/path-bin"
write_helper "$WORK/explicit-helper"
write_helper "$WORK/path-bin/shirudo-build"

test_expect_success 'shirudo build honors SHIRUDO_BUILD' '
	BUILD_DISPATCH_LOG="$WORK/explicit.log" \
		SHIRUDO_BUILD="$WORK/explicit-helper" \
		PATH="$WORK/path-bin:$PATH" \
		$SHIRUDO build "$WORK/input.bpf.c" -o "$WORK/explicit.upatch" &&
	grep -Fqx "$WORK/explicit-helper" "$WORK/explicit.log" &&
	grep -Fqx "$WORK/input.bpf.c -o $WORK/explicit.upatch" \
		"$WORK/explicit.log"
'

test_expect_success 'shirudo build falls back to shirudo-build on PATH' '
	if [ -x /usr/local/libexec/shirudo/shirudo-build ]; then
		:
	else
		BUILD_DISPATCH_LOG="$WORK/path.log" \
			env -u SHIRUDO_BUILD PATH="$WORK/path-bin" \
			$SHIRUDO build "$WORK/input.bpf.c" \
				-o "$WORK/path.upatch" &&
			grep -Fqx "$WORK/path-bin/shirudo-build" "$WORK/path.log" &&
			grep -Fqx "$WORK/input.bpf.c -o $WORK/path.upatch" \
				"$WORK/path.log"
	fi
'

test_expect_success 'shirudo build reports an unavailable helper' '
	! BUILD_DISPATCH_LOG="$WORK/missing.log" \
		env -u SHIRUDO_BUILD PATH="$WORK/empty-bin" \
		$SHIRUDO build "$WORK/input.bpf.c" \
		>"$WORK/missing.out" 2>&1 &&
	grep -q "exec shirudo-build" "$WORK/missing.out"
'

test_done
