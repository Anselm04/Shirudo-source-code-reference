..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

Deploy
======

Bring a target from a built kernel to an enforcing first boot. The
deployment checklist lists every step, boot integration puts shirudo
into the initrd of a signed unified kernel image, and the last page
checks ``init`` after every boot.

.. toctree::
   :titlesonly:

   deployment-checklist
   boot-integration
   initialize
