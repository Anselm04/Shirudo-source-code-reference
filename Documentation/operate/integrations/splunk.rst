..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: How-to
:audience: Operators, SecOps

Export to Splunk
================

Index the keepalives and map snapshots of your targets in Splunk,
through the OpenTelemetry Collector's Splunk HEC exporter, which sends to
Splunk's HTTP Event Collector.

This is a do-it-yourself example to get started from, not an
integration that shirudo ships or maintains. Adapt retention, access
control and sizing to your deployment.

Before you begin
----------------

- Targets that export to a collector, as
  :doc:`/operate/run/telemetry` describes, with the collector's ``otlp``
  receiver set up there.
- The OpenTelemetry Collector Contrib distribution, ``otelcol-contrib``,
  built with Go 1.24 or later. The contrib distribution includes the
  Splunk HEC exporter; Go 1.24 offers the hybrid key exchange the
  targets require.
- An HTTP Event Collector token, an events index for the log records and,
  if a decoder emits metrics, a metrics index.

Set up the exporter
-------------------

#. Add one exporter per index and the pipelines to the collector's
   configuration, next to the ``otlp`` receiver:

   .. code-block:: yaml

      exporters:
        splunk_hec/logs:
          token: ${env:SPLUNK_HEC_TOKEN}
          endpoint: https://<splunk-host>:8088/services/collector
          source: shirudo
          sourcetype: shirudo
          index: shirudo
          tls:
            ca_file: /etc/otelcol/splunk-ca.pem
        splunk_hec/metrics:
          token: ${env:SPLUNK_HEC_TOKEN}
          endpoint: https://<splunk-host>:8088/services/collector
          source: shirudo
          sourcetype: shirudo
          index: shirudo_metrics
          tls:
            ca_file: /etc/otelcol/splunk-ca.pem

      service:
        pipelines:
          logs:
            receivers: [otlp]
            exporters: [splunk_hec/logs]
          metrics:
            receivers: [otlp]
            exporters: [splunk_hec/metrics]

   ``SPLUNK_HEC_TOKEN`` comes from the collector's environment, and
   ``ca_file`` names the CA that signed the HEC endpoint's certificate.
   The exporter takes each event's host from the ``host.name`` resource
   attribute, so every event carries the name of the target that sent
   it. The record's body becomes the event, and its attributes become
   indexed fields under their own names, next to ``otel.log.name`` for
   the event name. A keepalive's body is a string, the JSON object the
   target's TPM quoted, so the event is that text, and the searches
   below take the keys they need out of it with ``rex``;
   :doc:`/reference/cli/status` lists the keys.

#. Restart the collector.

Check the data
--------------

#. Search for the events of one target:

   .. code-block:: text

      index=shirudo sourcetype=shirudo host=<target>

   A target sends a keepalive every minute, so each target shows up
   within a minute or two of the restart.

#. List when each target last reported:

   .. code-block:: text

      index=shirudo sourcetype=shirudo
      | stats latest(_time) AS last_seen BY host
      | sort last_seen

   A target at the top whose ``last_seen`` falls behind has stopped
   sending.

Alert on the data
-----------------

Each search below returns one row for every target that needs a look.
Save each one as an alert that runs every few minutes and triggers when
the number of results is greater than zero.
:doc:`/operate/run/telemetry` explains each signal under what to alert
on.

#. Find targets that stopped sending. Ten minutes covers several
   keepalive intervals and a tree sync of a few minutes, which holds the
   config operation lock that a keepalive waits for; a target whose tree
   syncs run for longer needs a longer threshold:

   .. code-block:: text

      | tstats latest(_time) AS last_seen
          WHERE index=shirudo sourcetype=shirudo earliest=-1d BY host
      | where last_seen < relative_time(now(), "-10m")

   A target silent for longer than a day drops out of the search.

#. Find targets that reported a verdict other than ``ok`` in the last
   five minutes:

   .. code-block:: text

      index=shirudo sourcetype=shirudo otel.log.name=shirudo.keepalive earliest=-5m
      | rex "\"verdict\":\"(?<verdict>[^\"]+)\""
      | where verdict != "ok"
      | stats count AS reports BY host, verdict

#. Find targets whose guards refused operations in the last ten
   minutes:

   .. code-block:: text

      index=shirudo sourcetype=shirudo otel.log.name=shirudo.keepalive earliest=-10m
      | rex "\"boot_id\":\"(?<boot_id>[^\"]+)\""
      | rex "\"tamper\":(?<tamper>\[[^\]]*\]|null)"
      | stats dc(tamper) AS counts BY host, boot_id
      | where counts > 1

   ``tamper`` lists every counter since boot. The counters only grow
   within a boot and start at zero at the next, so more than one list in
   the keepalives of one ``boot_id`` means a counter rose, and a reboot
   in the window reports nothing. ``integrity`` lists the integrity
   counters the same way; the query with ``integrity`` in place of
   ``tamper`` finds targets that refused a change to their running
   kernel.

Next steps
----------

- :doc:`/reference/formats/otlp` for every field a target sends
- :doc:`/upatches/write/decoders` to turn a map into log records or
  metrics
- :doc:`/concepts/background/siem-export` for how the records reach a
  backend and what to build on them
