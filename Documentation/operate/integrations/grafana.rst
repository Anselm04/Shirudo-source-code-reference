..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: How-to
:audience: Operators, SecOps

Export to Grafana
=================

Show the keepalives, map snapshots and decoder metrics of your targets in
Grafana, with the log records in Loki and the metrics in Prometheus. Both
accept OTLP directly, so the collector forwards to them with its
``otlphttp`` exporter.

This is a do-it-yourself example to get started from, not an
integration that shirudo ships or maintains. Adapt retention, access
control and sizing to your deployment.

Before you begin
----------------

- Targets that export to a collector, as
  :doc:`/operate/run/telemetry` describes, with the collector's ``otlp``
  receiver set up there.
- An OpenTelemetry Collector built with Go 1.24 or later, which offers
  the hybrid key exchange the targets require.
- Loki 3 or later, which stores OTLP attributes as structured metadata.
- Prometheus 3 or later, for the metrics that decoders emit.
- Grafana with Loki and Prometheus as data sources.

Set up Loki and Prometheus
--------------------------

#. In Loki's configuration, keep structured metadata on, raise the
   size limit of a log line and make the target's host name a label:

   .. code-block:: yaml

      limits_config:
        allow_structured_metadata: true
        max_line_size: 4MB
        otlp_config:
          resource_attributes:
            attributes_config:
              - action: index_label
                attributes:
                  - host.name

   Loki 3 enables structured metadata by default; an older configuration
   may turn it off. A keepalive is about a kilobyte, but a map snapshot
   can exceed Loki's default limit of 256 KB; Loki then refuses it and
   the collector drops it. 4 MB is the largest request a target sends,
   ``map_export.otlp_max_bytes`` by default, so every record fits.
   Without the label, every target writes to the one stream
   ``{service_name="shirudo"}`` and shares its rate limit.

#. Start Prometheus with ``--web.enable-otlp-receiver``, and in
   ``prometheus.yml`` promote the target's host name to a label and accept
   samples that arrive late:

   .. code-block:: yaml

      otlp:
        promote_resource_attributes:
          - host.name
      storage:
        tsdb:
          out_of_order_time_window: 30m

Set up the collector
--------------------

#. Add the exporters and the pipelines to the collector's configuration,
   next to the ``otlp`` receiver:

   .. code-block:: yaml

      exporters:
        otlphttp/loki:
          endpoint: https://<loki-host>/otlp
        otlphttp/prometheus:
          endpoint: https://<prometheus-host>/api/v1/otlp

      service:
        pipelines:
          logs:
            receivers: [otlp]
            exporters: [otlphttp/loki]
          metrics:
            receivers: [otlp]
            exporters: [otlphttp/prometheus]

   The exporter appends ``/v1/logs`` and ``/v1/metrics`` to each
   endpoint.

#. Restart the collector.

Check the data
--------------

#. In Grafana's Explore view with the Loki data source, list the
   keepalives that do not report ``ok``:

   .. code-block:: text

      {service_name="shirudo"} |= `"schema":"shirudo.keepalive/1"` | json verdict="verdict" | verdict != "ok"

   Loki turns ``service.name`` and ``host.name`` into the labels
   ``service_name`` and ``host_name`` and stores the other attributes as
   structured metadata, with dots turned into underscores. A
   keepalive's body is a string, the JSON object the target's TPM
   quoted, and becomes the log line: the line filter keeps the
   keepalives and ``json`` takes keys out of them.
   :doc:`/reference/cli/status` lists the keys.

#. List the keepalives of one target:

   .. code-block:: text

      {service_name="shirudo", host_name="<target>"} |= `"schema":"shirudo.keepalive/1"`

#. Read the map snapshots of one upatch:

   .. code-block:: text

      {service_name="shirudo"} | shirudo_upatch_name = "<upatch>"

#. With the Prometheus data source, select the metrics of one target:

   .. code-block:: text

      {host_name="<target>"}

   Which metrics exist depends on the decoders of the loaded upatches.

Alert on the data
-----------------

Alert on the keepalives with rules that Loki's ruler evaluates. Each
expression returns one series for every target that needs a look.
:doc:`/operate/run/telemetry` explains each signal under what to alert
on.

#. Put the rules in a file in the ruler's rule directory, under the
   tenant's name, ``fake`` when Loki runs without authentication:

   .. code-block:: yaml

      groups:
        - name: shirudo
          rules:
            - alert: ShirudoTargetSilent
              expr: |
                sum by (host_name) (count_over_time({service_name="shirudo"} |= `"schema":"shirudo.keepalive/1"` [1d]))
                unless
                sum by (host_name) (count_over_time({service_name="shirudo"} |= `"schema":"shirudo.keepalive/1"` [10m]))
            - alert: ShirudoTargetNotOk
              expr: |
                sum by (host_name) (count_over_time({service_name="shirudo"} |= `"schema":"shirudo.keepalive/1"` | json verdict="verdict" | verdict != "ok" [5m])) > 0
            - alert: ShirudoTamperAttempts
              expr: |
                count by (host_name, boot_id) (
                  sum by (host_name, boot_id, tamper) (
                    count_over_time({service_name="shirudo"} |= `"schema":"shirudo.keepalive/1"` | json boot_id="boot_id" | regexp `"tamper":(?P<tamper>\[[^\]]*\]|null)` [10m])
                  )
                ) > 1

   ``ShirudoTargetSilent`` fires for a target that sent keepalives in
   the last day but none in the last ten minutes, which covers several
   keepalive intervals and a tree sync of a few minutes, which holds the
   config operation lock that a keepalive waits for; a target whose tree
   syncs run for longer needs a longer window. A target silent for longer than a day drops out of
   the rule. ``ShirudoTargetNotOk`` fires for a verdict other than
   ``ok`` in the last five minutes. ``ShirudoTamperAttempts`` counts the
   different lists of counters, ``tamper``, in the keepalives of one
   boot in ten minutes. The counters only grow within a boot and start
   at zero at the next, so more than one list means a counter rose, and
   a reboot in the window gives no alert. ``integrity`` lists the
   integrity counters the same way; the rule with ``integrity`` in place
   of ``tamper`` alerts on a refused change to the running kernel.

#. Point the ruler at the directory and at your Alertmanager in Loki's
   configuration:

   .. code-block:: yaml

      ruler:
        storage:
          type: local
          local:
            directory: /etc/loki/rules
        rule_path: /var/lib/loki/rules-temp
        alertmanager_url: http://<alertmanager-host>:9093

#. Restart Loki and list the alerts:

   .. code-block:: console

      $ curl -s http://<loki-host>:3100/prometheus/api/v1/alerts

The same expressions work as queries of Grafana-managed alert rules
with the Loki data source.

Next steps
----------

- :doc:`/reference/formats/otlp` for every field a target sends
- :doc:`/upatches/write/decoders` to turn a map into log records or
  metrics
- :doc:`clickhouse` to keep the records for longer analysis
- :doc:`/concepts/background/siem-export` for how the records reach a
  backend and what to build on them
