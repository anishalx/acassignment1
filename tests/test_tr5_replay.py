"""TR-5 -- Replay Test.

    OWNER: MEMBER 2 -- NOT YET WRITTEN

Assignment text
---------------

    "Capture a valid protected record and re-deliver it to the receiver.
    Demonstrate that the replayed record is detected and handled according to
    the replay handling strategy."

    Both AEAD configurations, separately (Section 6).

The point this file has to make
-------------------------------

A replayed record is **byte-identical** to a genuine one, so its tag verifies
perfectly.  The AEAD cannot help here at all -- that is precisely why FR-8 asks
for a separate mechanism.  Show that explicitly: verify that the replayed bytes
really would authenticate, and that the rejection therefore comes from the
replay logic and not from a coincidentally-broken tag.

What this file has to establish
-------------------------------

*   A record accepted once is rejected on re-delivery, with
    ``RejectReason.REPLAY_DETECTED``, and no plaintext is released.
*   Repeated replays stay rejected -- the state does not decay.
*   Legitimate out-of-order delivery within the tolerance is *accepted*.
    Section 3.2 puts ordering out of scope, so a design that rejected all
    reordering would be broken, not strict.  A duplicate of an out-of-order
    record must still be caught.
*   Records too old to classify are rejected (``RejectReason.STALE_RECORD``),
    and the boundary is where the documented strategy says it is.  Use
    ``small_policy`` so the boundary is reachable in a short test.
*   Renumbering a captured record to slip past the replay check fails --
    and work out which of the two independent mechanisms catches it first.
*   **The state-poisoning attack.**  This is the most important test in the
    file.  A forged record carrying an enormous sequence number must not be
    able to move the receiver's replay state, or a single unauthenticated
    packet becomes a permanent denial of service.  Show that a genuine record
    is still accepted afterwards.
*   Scoping: a record replayed onto a different stream, or into a different
    session, is rejected; and separate streams keep independent state.
*   Volume: run ~10,000 genuine records and assert **zero** false replay
    positives.  This pairs with TR-7 and is what makes the strategy credible
    rather than merely conservative.
*   Render the replay state (``WindowSnapshot.describe()``) in at least one
    test so the report can show the mechanism working, not just its verdict.

Fixtures available (see ``conftest.py``): ``channel``, ``actor``,
``suite_name``, ``small_policy``.
"""

import pytest

pytest.skip(
    "TR-5 tests are Member 2's deliverable and have not been written yet "
    "(see HANDOFF.md). Delete this skip when you add tests.",
    allow_module_level=True,
)
