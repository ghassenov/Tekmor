"""Trust levels as integrity labels.

The six levels of `docs/technical-doc.md` Part I form a lattice:

    SYSTEM_POLICY > AUTHENTICATED_USER > TRUSTED_INTERNAL >
    UNTRUSTED_INTERNAL > UNTRUSTED_EXTERNAL > ADVERSARY_CONTROLLED

Read as Biba integrity labels: the integrity of anything influenced by several inputs is
the *minimum* integrity of those inputs. The enum is ordered so that the usual
comparison operators are the lattice order and `min()` is the meet.

Taint propagation through memory and tool-output fields is Phase 2; this module is only
the lattice itself.
"""

from collections.abc import Iterable
from enum import IntEnum


class TrustLevel(IntEnum):
    """Integrity of a source. Higher is more trusted; the order is the lattice order."""

    ADVERSARY_CONTROLLED = 0
    UNTRUSTED_EXTERNAL = 1
    UNTRUSTED_INTERNAL = 2
    TRUSTED_INTERNAL = 3
    AUTHENTICATED_USER = 4
    SYSTEM_POLICY = 5


def least_trusted(levels: Iterable[TrustLevel]) -> TrustLevel:
    """Meet of the lattice: the integrity of something influenced by all of `levels`.

    No levels means nothing is known about the influences. Unknown provenance must not
    read as trusted, so the meet of the empty set is the bottom of the lattice rather
    than the top.
    """
    return min(levels, default=TrustLevel.ADVERSARY_CONTROLLED)
