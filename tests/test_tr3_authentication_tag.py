"""TR-3 -- Authentication Tag Test.

    OWNER: MEMBER 2 -- NOT YET WRITTEN

Assignment text
---------------

    "Modify the authentication tag of a protected record and demonstrate that
    the receiver rejects the record."

    Both AEAD configurations, separately (Section 6).

What this file has to establish
-------------------------------

*   Any modification to the 16-byte tag causes rejection with
    ``RejectReason.AUTH_FAILED``, with the ciphertext and header left untouched
    so that the tag is demonstrably the only thing that changed.
*   The result does not depend on which bit: a sweep over all 128 tag bit
    positions is cheap and makes the claim exhaustive rather than anecdotal.
*   Degenerate tags are not special -- an all-zero tag, or a random one, is
    rejected like any other.  Random guessing is worth a test with a comment
    stating the actual success probability.
*   A truncated tag is rejected.  Short tags are a real historical weakness in
    GCM; note where in the pipeline the truncated frame is caught, and whether
    that is before or after the AEAD.
*   A valid tag taken from a *different* record does not authenticate this one.
    Work out which part of the design makes that true.

Fixtures available (see ``conftest.py``): ``channel``, ``actor``,
``suite_name``, ``payloads``.  Useful constants: ``TAG_LEN``, ``HEADER_LEN``
from ``srp``.
"""

import pytest

pytest.skip(
    "TR-3 tests are Member 2's deliverable and have not been written yet "
    "(see HANDOFF.md). Delete this skip when you add tests.",
    allow_module_level=True,
)
