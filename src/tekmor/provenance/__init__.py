"""Tekmor provenance component: the trust lattice, labelled sources, and taint.

See src/CLAUDE.md.
"""

from tekmor.provenance.taint import USER_REQUEST, TaintTracker
from tekmor.provenance.trust import Source, TrustLevel, least_trusted

__all__ = ["USER_REQUEST", "Source", "TaintTracker", "TrustLevel", "least_trusted"]
