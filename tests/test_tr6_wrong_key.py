"""TR-6 -- Wrong-Key Test.

    OWNER: MEMBER 2 -- NOT YET WRITTEN

Assignment text
---------------

    "Attempt to recover a protected record using an incorrect key and
    demonstrate that recovery fails safely."

    Both AEAD configurations, separately (Section 6).

"Fails safely" is the part being tested
---------------------------------------

Not just "fails".  The receiver must reject the record cleanly, release no
plaintext, raise no exception out of ``receive``, and remain usable afterwards.
A wrong key is the everyday case of a key-management error as much as it is an
attack, so the failure has to be orderly.

What this file has to establish
-------------------------------

*   A genuine record, handed to a receiver holding a different key, is rejected
    with ``RejectReason.AUTH_FAILED`` and ``verdict.plaintext is None``.
*   The same record *is* accepted by a receiver holding the correct key --
    without this control the test proves nothing about the key.
*   It is not one unlucky record: every record in a run fails under the wrong
    key.
*   A key differing in a **single bit** is still the wrong key.  Sweep several
    bit positions; this is the test that says something about the primitive
    rather than about the plumbing.
*   All-zero and all-ones keys are not special-cased anywhere.
*   An attacker who forges a structurally perfect record under a key they chose
    is rejected (``MaliciousActor.forge_with_wrong_key``).  Reproduce
    everything observable -- session id, stream, sequence number, nonce prefix
    -- so the only difference is the key.
*   Key length is validated at construction, and that is a
    ``ConfigurationError`` (a local programming error), *not* a verdict.  Be
    clear in the report about why those two failure kinds are reported
    differently.
*   Recovery works again once the correct key is used, on the same receiver
    state.

Fixtures available (see ``conftest.py``): ``channel``, ``actor``,
``suite_name``.  You will likely want your own fixture that builds a
sender/receiver pair over deliberately mismatched keys.
"""

import pytest

pytest.skip(
    "TR-6 tests are Member 2's deliverable and have not been written yet "
    "(see HANDOFF.md). Delete this skip when you add tests.",
    allow_module_level=True,
)
