# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Apache with mod_ssl and mod_php, as the Docker "official image" of PHP
# builds it on Debian: the web server the sandboxes of app-sandbox are
# shown around. The digest pins what was run: PHP 8.4, Apache 2.4,
# Debian 13, the prefork MPM.
FROM php:8.4-apache@sha256:884f64b47174de2c0e813270fe7b24a18605729fcebe201302d98c38805530d0

# A certificate for the demo alone, made when the image is built.
RUN openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
		-nodes -keyout /etc/ssl/private/demo.key \
		-out /etc/ssl/certs/demo.pem -subj /CN=localhost -days 3650 \
	&& a2enmod ssl >/dev/null \
	&& a2dissite 000-default >/dev/null

COPY demo.conf /etc/apache2/sites-enabled/demo.conf
COPY htdocs/ /var/www/html/
RUN mkdir /var/www/html/uploads \
	&& echo data >/var/www/html/uploads/data.txt \
	&& chown -R www-data: /var/www/html/uploads
