"""Tekmor provenance component: the trust lattice and the labelled source.

Taint propagation through memory and tool-output fields is the remaining Phase 2 piece;
until it lands, sources are declared by whatever produced the observation. See
src/CLAUDE.md.
"""

from tekmor.provenance.trust import Source, TrustLevel, least_trusted

__all__ = ["Source", "TrustLevel", "least_trusted"]
