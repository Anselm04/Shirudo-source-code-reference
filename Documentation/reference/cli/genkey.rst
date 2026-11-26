..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators

shirudo genkey
==============

Generate an ML-DSA-87 private key and a self-signed X.509 certificate for
signing upatches.

Runs on: operator host, without the image gate; refused on a target
where shirudo enforces. Requires: write access to the keys directory.
Changes measured state: no.

Usage
-----

.. code-block:: none

   shirudo genkey [--force | -f] [--keys-dir <dir> | --keys-dir=<dir>]

Description
-----------

#. ``genkey`` selects the keys directory: ``--keys-dir``, else
   ``$SHIRUDO_KEYS_DIR``, else ``/var/lib/shirudo/keys``.
#. It creates the directory with mode 0700 when it is missing.
#. Run as a user other than root with the default directory, it requires
   every component of the path to be owned by root or that user and not
   writable by group or others, and the directory itself to be owned by
   that user.
#. Without ``--force``, it refuses when ``signing_key.pem`` or
   ``cert.der`` exists in the directory.
#. It generates an ML-DSA-87 key and writes:

   - ``<dir>/signing_key.pem``: the private key, PEM, mode 0600
   - ``<dir>/cert.der``: a self-signed X.509 certificate, DER, mode 0600,
     subject and issuer ``CN=shirudo``, valid from its creation and
     without an expiration date (``notAfter`` ``99991231235959Z``, the
     value RFC 5280 gives a certificate without one)

#. It logs ``genkey: created shirudo ML-DSA-87 signing material at
   <dir>`` at audit priority.

With ``--force``, ``genkey`` writes the new pair as ``*.new``, keeps the
old key as ``signing_key.pem.old`` until both new files are in place,
then removes the old key. A failure between the two renames puts the old
key back.

The signing commands read a key only when it is a regular file with mode
0600. Pass the same ``--keys-dir`` to :doc:`build`, :doc:`keys`
``vouch``, :doc:`bpm` ``build`` and ``tree append``, and :doc:`image`
``build``. ``bpm push`` ignores ``SHIRUDO_KEYS_DIR`` and signs only with
an explicit ``--keys-dir`` or ``--index-key`` and ``--index-cert``.

.. warning::

   ``--force`` deletes the old private key. A target that trusts only the
   old certificate refuses everything the new key signs, and nothing can
   sign for the old certificate any more. Generate the new pair in
   another directory and vouch for it with the old key first, as
   :doc:`/operate/maintain/keys` describes.

Options
-------

.. list-table::
   :header-rows: 1
   :widths: 22 12 26 40

   * - Option
     - Argument
     - Default
     - Description
   * - ``--force``, ``-f``
     - none
     - off
     - Replace an existing key and certificate.
   * - ``--keys-dir``
     - ``<dir>``, as the next argument or after ``=``
     - ``$SHIRUDO_KEYS_DIR``, else ``/var/lib/shirudo/keys``
     - Directory to write the pair to.

Exit status
-----------

.. list-table::
   :header-rows: 1
   :widths: 15 85

   * - Status
     - Meaning
   * - 0
     - The pair was written.
   * - 1
     - The pair exists and ``--force`` was not given, the directory is
       unsafe or not writable, generating or writing failed, or shirudo
       enforces on this host.
   * - 2
     - A usage error: an unknown option, an option given twice,
       ``--keys-dir`` without a value or with an empty one, or an
       argument.

Files and environment
---------------------

- ``<dir>/signing_key.pem``, ``<dir>/cert.der``, and during ``--force``
  ``<dir>/signing_key.pem.new``, ``<dir>/cert.der.new`` and
  ``<dir>/signing_key.pem.old``
- ``SHIRUDO_KEYS_DIR``: the default directory

Examples
--------

Create a key pair in a directory the operator owns:

.. code-block:: console

   operator$ shirudo genkey --keys-dir ~/shirudo-keys

Related
-------

- :doc:`keys`
- :doc:`/operate/maintain/keys`
- :doc:`/security/cryptography`
