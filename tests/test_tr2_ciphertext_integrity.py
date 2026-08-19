"""TR-2 -- Ciphertext Integrity Test.

    OWNER: MEMBER 2 -- NOT YET WRITTEN

Assignment text
---------------

    "Modify the ciphertext of a protected record and demonstrate that the
    receiver detects the modification and rejects the record."

    Section 6: every Testing Requirement shall be demonstrated separately using
    both supported AEAD configurations.  The ``suite_name`` fixture in
    ``conftest.py`` parametrises every test over both, so writing a test that
    takes ``channel`` or ``suite_name`` gives you that for free -- do not
    hard-code a suite.

What this file has to establish
-------------------------------

*   A modification the attacker makes to the ciphertext body is detected, and
    the record is rejected with ``RejectReason.AUTH_FAILED``.
*   The modification is *minimal*.  Handing the receiver random garbage proves
    only that the parser works.  Start from a genuine record produced by the
    real sender and change as little as possible -- a single bit is the strong
    version of the claim, and ``MaliciousActor.flip_ciphertext_bit`` exists for
    exactly that.
*   The result does not depend on *which* bit.  A sweep over every bit position
    in a small record turns "we tried one and it failed" into "no single-bit
    edit is accepted", which is a much better sentence for the report.
*   No plaintext escapes.  A rejected verdict must carry none.
*   Length-changing edits (truncation, extension) are rejected too.
*   Recovery: after the attacks, a genuine record is still accepted, so the
    receiver rejects the forgery rather than wedging itself.

Before you write it, read the ordering note in ``Receiver.receive``
--------------------------------------------------------------------

There is a subtlety that decides how these tests must be structured.  If the
attacker modifies a record the receiver has **already accepted** and re-sends
it, replay detection may reject it before the tag is ever checked -- so the
record is rejected, but not for the reason TR-2 is about.  To demonstrate
*authentication* failure specifically, the actor has to intercept the record
**in flight**: modify it and deliver only the modified copy.  Work out why, and
say so in the report -- it is also the more realistic attacker model.

Fixtures available (see ``conftest.py``): ``channel``, ``actor``,
``suite_name``, ``payloads``.
"""

import pytest

pytest.skip(
    "TR-2 tests are Member 2's deliverable and have not been written yet "
    "(see HANDOFF.md). Delete this skip when you add tests.",
    allow_module_level=True,
)
