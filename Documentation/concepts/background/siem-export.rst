..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Explanation
:audience: Operators, SecOps

SIEM export
===========

A target reports its own state and what its upatches observe as
OpenTelemetry records, which :doc:`opentelemetry` explains. This page
follows those records from the target into a SIEM or another backend,
shows where their fields land, and explains which detections they
support and why each one is built as it is.

What a SIEM does
----------------

A security information and event management system, a SIEM, collects
events from many sources into one store: hosts, network devices,
identity providers and applications. It maps them to common fields so
that one search spans every source, keeps them for investigation and
compliance, and runs rules that correlate events and raise alerts.
Splunk and Elastic Security are SIEMs.

Other backends cover part of that. A log store such as Loki keeps and
searches records, a database such as ClickHouse analyzes them in SQL,
and Grafana charts and alerts on both. The same records serve each of
them; what differs is the query language and what the backend charges
for or limits.

From target to backend
----------------------

A target pushes OTLP over HTTP with JSON bodies, through TLS 1.3 with a
hybrid post-quantum key exchange, and nothing else. A SIEM has an
ingest interface of its own, such as Splunk's HTTP Event Collector or
Elasticsearch's bulk API. An OpenTelemetry Collector sits between them.
It accepts the targets' requests, speaks the backend's protocol over
ordinary TLS, batches and retries, and holds the backend's credentials,
so a target carries only what it needs to reach the collector.

The target keeps no spool. A map export that fails loses what the map
collected in that interval, and a keepalive that fails leaves a gap
until the next one. The collector's sending queue is the only buffer on
the way. A collector can also filter or rewrite records before export,
but it must leave a keepalive's body as it arrived: its quote covers
those exact bytes.

Where the fields land
---------------------

Every record carries the resource attribute ``host.name``, which names
the target. The event name tells a keepalive, ``shirudo.keepalive``,
from a map snapshot, ``shirudo.bpf.map.snapshot``. A map snapshot's
attributes name its upatch and map, and its body holds what the map's
decoder returned. A keepalive's body is a string, the compact JSON
status record that the target's TPM quoted, with the verdict, the
conditions and the tamper counters among its keys
(:doc:`/reference/cli/status`). Its one attribute is the quote.

Each exporter keeps the body in its own way, and each backend reads the
keys of a keepalive out of it with a function of its own:

.. list-table::
   :header-rows: 1
   :widths: 19 27 29 25

   * - Backend
     - Target
     - Verdict
     - Body
   * - ClickHouse
     - ``ResourceAttributes['host.name']``
     - ``JSONExtractString(Body, 'verdict')``
     - ``Body``, as JSON text
   * - Elasticsearch
     - ``host.name``
     - ``GROK`` on ``body.text``
     - ``body.text`` for a keepalive, ``body.structured`` for a snapshot
   * - Loki
     - Label ``host_name``
     - The ``json`` parser on the log line
     - Log line
   * - Splunk
     - ``host``
     - ``rex`` on the event
     - Event

Loki makes ``host_name`` a label only when configured to, as
:doc:`/operate/integrations/grafana` shows. The keys of a keepalive
always come in the same order and its body is about a kilobyte, so a
pattern finds a key in it as reliably as a JSON parser does.

What to detect
--------------

Three detections cover the keepalive, and
:doc:`/operate/integrations/index` gives each of them for every backend.

A target that goes silent is the first. A target that is down, a timer
that was stopped, a network that fails and an attacker who stopped the
export look the same from the backend: nothing arrives. A rule cannot
match an event that does not exist, so the query compares the last
keepalive of every target it knows against the current time. It knows
the targets that reported within a longer window, such as a day, so a
target silent for longer drops out of the alert. A
keepalive runs a minute after the previous run ends and may wait up to
30 seconds for the config operation lock. A tree sync holds that lock
for as long as it runs, and a keepalive that cannot take it sends
nothing, so ten minutes without one spans several missed intervals and
a sync of a few minutes. A target whose syncs take longer needs a longer
window.

A verdict other than ``ok`` is the second. The keepalive's severity
follows the verdict, ``WARN`` or ``ERROR``, so a rule on severity
catches the same records.

A rise of a tamper counter is the third. The body's ``tamper`` lists
every counter of the guards' refusals since boot, so a change means
something on the target tried an operation the guards refused. The
counters start at zero each boot. A rule that compared any two
keepalives of a target would fire on every reboot, so the examples
compare only the keepalives of one ``boot_id``, within which the
counters only grow.

Map snapshots carry what upatches observe, such as the programs that
``kernel-obs`` saw run. Their fields depend on the upatch's decoder, so
rules on them are written per upatch. The host name and the time of a
record join it to events from other sources.

Volume
------

A keepalive's body is about a kilobyte, and with its quote and resource
attributes a record is about two. At one keepalive a minute that adds up
to a few megabytes a day for each target. Map snapshots are what a SIEM
priced or capped by ingested volume, or a backend that limits the size
of a record or the rate of a stream, has to size for: their volume
depends on the loaded upatches and their decoders.

Limits
------

Telemetry is the target's own account of itself. A keepalive's quote
shows that its body is unchanged since the target's attestation key
signed it, but not that the key lives in a genuine TPM, and root on a
target can stop the keepalive or have the TPM quote a body that reports
``ok`` with no refusals. Map snapshots are not signed at all. A SIEM
alert on a keepalive tells you where to look. The silence alert catches
a target whose export was stopped, but not one whose root sends forged
keepalives instead.

Evidence of what a target runs is the TPM-signed record that ``shirudo
attest`` produces and ``shirudo attest verify`` checks on the operator
host, described in :doc:`/operate/run/attest`.

Related
-------

- :doc:`opentelemetry` for the records and the protocol
- :doc:`/operate/run/telemetry` to set up export on a target
- :doc:`/operate/integrations/index` for the backend examples
- :doc:`/reference/formats/otlp` for every field a target sends
