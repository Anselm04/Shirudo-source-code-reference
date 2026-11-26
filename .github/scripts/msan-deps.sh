#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Build the libraries the MemorySanitizer suite links, each instrumented:
# MemorySanitizer takes what code it did not instrument writes as never
# written, so a library left as the distribution ships it makes every read
# of its output a report. LuaJIT is left out, its interpreter being
# assembly, and with it the decoder tests. The libraries go to
# MSAN_PREFIX, /tmp/shirudo-msan by default, and a copy to MSAN_CACHE,
# build/msan-deps, which a later run copies back instead of building.

set -eu

ZLIB_VERSION=1.4
ZLIB_SHA256=02dd159783677a749c04adbdd02b55b8a2bcc7e054f51b76b549199a916ad584
OPENSSL_VERSION=3.5.9
OPENSSL_SHA256=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a
ELFUTILS_VERSION=0.197
ELFUTILS_SHA256=1fdf525f22dcf796d99a99ba3ea00a1f7b1ae5421bc62e8443a708920b99b904
CURL_VERSION=8.18.0
CURL_SHA256=40df79166e74aa20149365e11ee4c798a46ad57c34e4f68fd13100e2c9a91946
TSS_VERSION=4.2.0

CC=${CC:-clang-23}
prefix=${MSAN_PREFIX:-/tmp/shirudo-msan}
cache=${MSAN_CACHE:-$(cd "$(dirname "$0")/../.." && pwd)/build/msan-deps}
work=${MSAN_WORK:-/tmp/msan-src}
jobs=$(nproc)

if [ -s "$cache/lib/libcrypto.so" ]; then
	rm -rf "$prefix"
	cp -a "$cache" "$prefix"
	exit 0
fi

msan="-fsanitize=memory -fsanitize-memory-track-origins=2 -fno-omit-frame-pointer -g -O1"
export CC
export CFLAGS="$msan"
export LDFLAGS="-fsanitize=memory -L$prefix/lib -Wl,-rpath,$prefix/lib"
export CPPFLAGS="-I$prefix/include"
export PKG_CONFIG_PATH="$prefix/lib/pkgconfig"

fetch() {
	url=$1 sum=$2
	file="$work/${url##*/}"
	[ -f "$file" ] || curl -fsSL --retry 3 -o "$file" "$url"
	printf '%s  %s\n' "$sum" "$file" | sha256sum -c --quiet
	tar -C "$work" -xf "$file"
}

rm -rf "$prefix" "$cache"
mkdir -p "$work" "$prefix"

fetch "https://github.com/madler/zlib/releases/download/v$ZLIB_VERSION/zlib-$ZLIB_VERSION.tar.gz" \
	"$ZLIB_SHA256"
(cd "$work/zlib-$ZLIB_VERSION" &&
	./configure --prefix="$prefix" &&
	make -j"$jobs" && make install)

# No assembly, which the sanitizer cannot see into either.
fetch "https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/openssl-$OPENSSL_VERSION.tar.gz" \
	"$OPENSSL_SHA256"
(cd "$work/openssl-$OPENSSL_VERSION" &&
	CFLAGS='' LDFLAGS='' CPPFLAGS='' ./Configure linux-x86_64-clang \
		--prefix="$prefix" --openssldir=/etc/ssl --libdir=lib \
		enable-msan no-asm no-docs no-tests \
		-fsanitize-memory-track-origins=2 -Wl,-rpath,"$prefix/lib" &&
	make -j"$jobs" && make install_sw)

# libelf alone, the part libbpf links.
fetch "https://sourceware.org/elfutils/ftp/$ELFUTILS_VERSION/elfutils-$ELFUTILS_VERSION.tar.bz2" \
	"$ELFUTILS_SHA256"
(cd "$work/elfutils-$ELFUTILS_VERSION" &&
	./configure --prefix="$prefix" --enable-sanitize-memory \
		--disable-debuginfod --disable-libdebuginfod --without-bzlib \
		--without-lzma --without-zstd &&
	make -j"$jobs" -C lib && make -j"$jobs" -C libelf &&
	make -C libelf install && make -C config install-pkgconfigDATA)

fetch "https://curl.se/download/curl-$CURL_VERSION.tar.xz" "$CURL_SHA256"
(cd "$work/curl-$CURL_VERSION" &&
	./configure --prefix="$prefix" --with-openssl="$prefix" \
		--with-zlib="$prefix" \
		--with-ca-bundle=/etc/ssl/certs/ca-certificates.crt \
		--with-ca-path=/etc/ssl/certs \
		--without-libpsl --without-brotli --without-zstd \
		--without-nghttp2 --without-nghttp3 --without-ngtcp2 \
		--without-libidn2 --without-librtmp --without-libssh2 \
		--without-libssh --without-libgsasl \
		--disable-ldap --disable-ldaps --disable-rtsp --disable-dict \
		--disable-telnet --disable-tftp --disable-pop3 --disable-imap \
		--disable-smtp --disable-gopher --disable-mqtt --disable-smb \
		--disable-ftp --disable-file --disable-manual --disable-docs &&
	make -j"$jobs" && make install)

[ -d "$work/tpm2-tss-$TSS_VERSION" ] ||
	git clone --quiet --depth 1 --branch "$TSS_VERSION" \
		https://github.com/tpm2-software/tpm2-tss.git \
		"$work/tpm2-tss-$TSS_VERSION"
(cd "$work/tpm2-tss-$TSS_VERSION" && ./bootstrap &&
	./configure --prefix="$prefix" --libdir="$prefix/lib" \
		--disable-defaultflags --disable-fapi --disable-policy \
		--disable-doxygen-doc \
		--disable-tcti-i2c-ftdi --disable-tcti-spi-ftdi \
		--disable-tcti-spi-ltt2go --disable-tcti-libtpms \
		--disable-tcti-pcap &&
	make -j"$jobs" && make install)

mkdir -p "$(dirname "$cache")"
cp -a "$prefix" "$cache"
