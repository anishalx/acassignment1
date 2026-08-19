"""TR-4 -- Associated Data (AAD) Test.

    OWNER: MEMBER 2 -- NOT YET WRITTEN

Assignment text
---------------

    "Modify the associated data of a protected record and demonstrate that the
    receiver rejects the record."

    Both AEAD configurations, separately (Section 6).

Start here: what *is* the AAD in this subsystem?
------------------------------------------------

Read ``RecordHeader.aad()`` in ``srp/header.py`` before writing anything.  The
choice of what goes in the AAD is a design decision with consequences, and this
test file is where those consequences get demonstrated.  Every field the AAD
covers is a field the attacker cannot silently rewrite; anything left out is a
field they can.

What this file has to establish
-------------------------------

*   Rewriting an authenticated header field is rejected with
    ``RejectReason.AUTH_FAILED``, while the ciphertext and tag stay byte-identical
    -- that is what makes it an AAD test rather than a ciphertext test.
*   Cover the fields individually, because each is a different *semantic*
    attack rather than a repeat of the same one.  For each, say in the report
    what the attacker would gain if it succeeded:
        - ``record_type``   (make a DATA record look like a CLOSE)
        - ``flags``         (forge or strip END_OF_STREAM)
        - ``stream_id``     (re-route a record to another stream)
        - ``session_id``    (move a record into another key epoch)
        - ``suite_id``      (claim the other AEAD configuration)
        - ``payload_len``   (lie about the length)
        - ``nonce_prefix``  (this one has a second effect -- work out what)
        - ``seq``           (see TR-5)
*   A sweep over every bit of the header, so the claim covers the whole AAD and
    not just the fields you thought to name.
*   Some of these are caught by framing validation *before* the AEAD runs.
    That is fine, but note which, and be clear that the AAD is the mechanism
    that makes the guarantee hold in general.
*   Round-trip property: parsing a header and re-serialising it must be the
    identity, for arbitrary bytes.  If it were not, an attacker could find two
    encodings of the same header, and the AAD would stop being canonical.
*   The AAD is authenticated but **not** encrypted -- it is readable on the
    wire.  Demonstrate both halves of that, and explain why the header must be
    readable at all.
*   Also test with the receiver *unpinned* (``pin_session=False``), so the
    session-id rejection is coming from the AAD and not merely from the
    receiver's session check.

Fixtures available (see ``conftest.py``): ``channel``, ``actor``,
``suite_name``, ``small_policy``, ``payloads``.
"""

import pytest

pytest.skip(
    "TR-4 tests are Member 2's deliverable and have not been written yet "
    "(see HANDOFF.md). Delete this skip when you add tests.",
    allow_module_level=True,
)
