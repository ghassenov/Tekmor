"""Tekmor provenance component: the trust lattice.

Taint propagation through memory and tool-output fields is Phase 2; see src/CLAUDE.md.
"""

from tekmor.provenance.trust import Source, TrustLevel, least_trusted

__all__ = ["Source", "TrustLevel", "least_trusted"]
