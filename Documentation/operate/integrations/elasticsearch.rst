..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: How-to
:audience: Operators, SecOps

Export to Elasticsearch
=======================

Index the keepalives, map snapshots and decoder metrics of your targets
in Elasticsearch, through the OpenTelemetry Collector's Elasticsearch
exporter, and alert on them from Kibana or Elastic Security.

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
  Elasticsearch exporter; Go 1.24 offers the hybrid key exchange the
  targets require.
- Elasticsearch 9.4 or later, whose ES|QL has the ``LAST`` function
  that the query of the last verdict uses, and Kibana.

The exporter's log and metric support is beta.

Set up the exporter
-------------------

#. In Kibana's Dev Tools console, create an API key that may only write
   to the data streams the exporter uses:

   .. code-block:: text

      POST /_security/api_key
      {
        "name": "shirudo-otel",
        "role_descriptors": {
          "shirudo-otel": {
            "indices": [
              {
                "names": ["logs-*.otel-*", "metrics-*.otel-*"],
                "privileges": ["auto_configure", "create_doc"]
              }
            ]
          }
        }
      }

   Keep the ``encoded`` value of the answer for the collector.

#. Add the exporter and the pipelines to the collector's configuration,
   next to the ``otlp`` receiver:

   .. code-block:: yaml

      exporters:
        elasticsearch:
          endpoint: https://<elasticsearch-host>:9200
          api_key: ${env:ELASTICSEARCH_API_KEY}
          tls:
            ca_file: /etc/otelcol/elasticsearch-ca.pem

      service:
        pipelines:
          logs:
            receivers: [otlp]
            exporters: [elasticsearch]
          metrics:
            receivers: [otlp]
            exporters: [elasticsearch]

   ``ELASTICSEARCH_API_KEY`` holds the encoded key and comes from the
   collector's environment, and ``ca_file`` names the CA that signed the
   Elasticsearch certificate.

#. Restart the collector.

The exporter writes in its default ``otel`` mapping mode: log records go
to the data stream ``logs-generic.otel-default`` and metrics to
``metrics-generic.otel-default``. A document keeps the OTLP layout, with
the attributes under ``attributes``, the resource attributes under
``resource.attributes``, a string body under ``body.text`` and a
structured body under ``body.structured``. Elasticsearch's OpenTelemetry
templates also offer each attribute under its own name, so ``host.name``
works in queries.

A keepalive's body is a string, the JSON object the target's TPM quoted,
so it lands in ``body.text``. The queries below take the keys they need
out of it with ``GROK``; :doc:`/reference/cli/status` lists the keys,
which always come in the same order.

Check the data
--------------

#. In Discover, switch to ES|QL and list the latest keepalives:

   .. code-block:: text

      FROM logs-generic.otel-default
      | WHERE event_name == "shirudo.keepalive"
      | GROK body.text "\"verdict\":\"%{DATA:verdict}\""
      | SORT @timestamp DESC
      | KEEP @timestamp, host.name, verdict, body.text
      | LIMIT 10

   A target sends a keepalive every minute, so each target shows up
   within a minute or two of the restart.

#. Show the last verdict of every target and when it last reported:

   .. code-block:: text

      FROM logs-generic.otel-default
      | WHERE event_name == "shirudo.keepalive"
      | GROK body.text "\"verdict\":\"%{DATA:verdict}\""
      | STATS verdict = LAST(verdict, @timestamp),
              last_seen = MAX(@timestamp) BY host.name
      | SORT last_seen

#. Read the map snapshots of one upatch:

   .. code-block:: text

      FROM logs-generic.otel-default
      | WHERE shirudo.upatch.name == "<upatch>"
      | KEEP @timestamp, host.name, shirudo.map.name, body.structured

   ``body.structured`` holds what the map's decoder returned, or the
   map's entries when the upatch ships no decoder. ES|QL returns it
   whole and cannot select a field inside it. A decoder that emits
   metrics writes to ``metrics-generic.otel-default``, with one field
   per metric.

Alert on the data
-----------------

Each query below returns one row for every target that needs a look.
In Kibana, create an Elasticsearch query rule for each, with ES|QL as
the query type, ``@timestamp`` as the time field and a time window at
least as long as the query's; the rule alerts when the query returns
rows. In Elastic Security, use the query in a detection rule of type
ES|QL instead. :doc:`/operate/run/telemetry` explains each signal under
what to alert on.

#. Find targets that stopped sending keepalives. Ten minutes covers
   several keepalive intervals and a tree sync of a few minutes, which
   holds the config operation lock that a keepalive waits for; a target
   whose tree syncs run for longer needs a longer threshold:

   .. code-block:: text

      FROM logs-generic.otel-default
      | WHERE event_name == "shirudo.keepalive" AND @timestamp > NOW() - 1 day
      | STATS last_seen = MAX(@timestamp) BY host.name
      | WHERE last_seen < NOW() - 10 minutes

   A target silent for longer than a day drops out of the query.

#. Find targets that reported a verdict other than ``ok`` in the last
   five minutes:

   .. code-block:: text

      FROM logs-generic.otel-default
      | WHERE event_name == "shirudo.keepalive" AND @timestamp > NOW() - 5 minutes
      | GROK body.text "\"verdict\":\"%{DATA:verdict}\""
      | WHERE verdict != "ok"
      | STATS reports = COUNT(*) BY host.name, verdict

#. Find targets whose guards refused operations in the last ten
   minutes:

   .. code-block:: text

      FROM logs-generic.otel-default
      | WHERE event_name == "shirudo.keepalive" AND @timestamp > NOW() - 10 minutes
      | GROK body.text "\"boot_id\":\"%{DATA:boot_id}\""
      | GROK body.text "\"tamper\":%{DATA:tamper},\"integrity\""
      | STATS counts = COUNT_DISTINCT(tamper) BY host.name, boot_id
      | WHERE counts > 1

   ``tamper`` lists every counter since boot. The counters only grow
   within a boot and start at zero at the next, so more than one list in
   the keepalives of one ``boot_id`` means a counter rose, and a reboot
   in the window reports nothing. ``integrity`` lists the integrity
   counters the same way; the query with
   ``"\"integrity\":%{DATA:integrity},\"tree_id\""`` finds targets that
   refused a change to their running kernel.

Next steps
----------

- :doc:`/reference/formats/otlp` for every field a target sends
- :doc:`/upatches/write/decoders` to turn a map into log records or
  metrics
- :doc:`/concepts/background/siem-export` for how the records reach a
  backend and what to build on them
