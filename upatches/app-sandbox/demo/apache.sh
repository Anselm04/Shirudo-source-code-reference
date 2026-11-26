#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# usage: apache.sh install <archive> | start | stop | remove
#
# Runs the Apache of build.sh on a target, as root, in a chroot under
# /var/lib/app-sandbox-demo, serving https://127.0.0.1:8443. install
# unpacks the archive and links the server's binary at /usr/sbin/apache2,
# the path the package labels: a hard link is the same inode, so the
# label the load sets there is on the file the chroot executes.

set -eu

root=/var/lib/app-sandbox-demo
pidfile=/run/app-sandbox-demo.pid

usage()
{
	echo "usage: $0 install <archive> | start | stop | remove" >&2
	exit 2
}

stop()
{
	[ -s "$pidfile" ] || return 0
	kill "$(cat "$pidfile")" 2>/dev/null || true
	rm -f "$pidfile"
	sleep 1
}

unmount()
{
	for dir in proc dev tmp run; do
		umount -l "$root/$dir" 2>/dev/null || true
	done
}

[ $# -ge 1 ] || usage
case $1 in
install)
	[ $# -eq 2 ] || usage
	rm -rf "$root"
	mkdir -p "$root"
	tar -xf "$2" -C "$root" --exclude='dev/*'
	ln "$root/usr/sbin/apache2" /usr/sbin/apache2
	;;
start)
	stop
	unmount
	mount -t tmpfs tmpfs "$root/run"
	mount -t tmpfs tmpfs "$root/tmp"
	chmod 1777 "$root/tmp"
	mount -t proc proc "$root/proc"
	mount --bind /dev "$root/dev"
	# In a session of its own: Apache signals its process group when
	# it stops.
	setsid chroot "$root" /usr/local/bin/apache2-foreground \
		>/var/log/app-sandbox-demo.log 2>&1 &
	echo $! >"$pidfile"
	for _ in $(seq 50); do
		curl -s -k -o /dev/null https://127.0.0.1:8443/index.php &&
			exit 0
		sleep 0.2
	done
	echo "$0: Apache does not answer, see /var/log/app-sandbox-demo.log" >&2
	exit 1
	;;
stop)
	stop
	unmount
	;;
remove)
	stop
	unmount
	rm -f /usr/sbin/apache2
	rm -rf "$root"
	;;
*)
	usage
	;;
esac
