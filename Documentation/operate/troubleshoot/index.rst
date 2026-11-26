..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

Troubleshoot
============

Find the cause of a failure from its message, respond to a target that
reports ``tampered``, and report a bug with what the developers need to
reproduce it.

Start on the target with ``shirudo status``. It is the target's own
report on its enforcement, its ``.bpf`` and ``.dm-verity`` keyrings, its
measurement register, its signed config and the upatches it runs, summed
up in one verdict. It still runs when most other commands refuse. A
``tampered`` verdict is an incident, see
:doc:`/operate/troubleshoot/incident-tampered`. :ref:`status-verdicts`
says what each other verdict means and what to do about it, and
:doc:`/operate/run/read-status` explains the whole report.

.. toctree::
   :titlesonly:

   troubleshooting
   incident-tampered
   bug-report
