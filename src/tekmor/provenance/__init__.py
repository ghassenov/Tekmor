"""Tekmor provenance component: the trust lattice.

Taint propagation through memory and tool-output fields is Phase 2; see src/CLAUDE.md.
"""

from tekmor.provenance.trust import TrustLevel, least_trusted

__all__ = ["TrustLevel", "least_trusted"]
