"""Tool sets per domain.

`docs/technical-doc.md` Part I names three domains (enterprise productivity, a financial
sandbox with a prepare → confirm → execute lifecycle, and a SOC). Only the enterprise
one exists: it is enough to exercise the read-untrusted → act-outbound shape the
provenance gate is about, and the other two are written when there are scenarios that
need them.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tekmor.simulator.world import Tool, World


def _read_document(world: World, args: Mapping[str, Any]) -> str:
    return world.documents[str(args["id"])]


def _read_secret(world: World, args: Mapping[str, Any]) -> str:
    return world.canaries[str(args["name"])]


def _send_email(world: World, args: Mapping[str, Any]) -> str:
    world.sent.append(dict(args))
    return f"sent to {args.get('to', '?')}"


def _draft_email(world: World, args: Mapping[str, Any]) -> str:
    """The lower-capability variant of `send_email`; the Phase 2 rewriter targets it."""
    world.drafts.append(dict(args))
    return "draft saved"


ENTERPRISE = (
    Tool("read_document", _read_document),
    Tool("read_secret", _read_secret),
    Tool("send_email", _send_email, outbound=True),
    Tool("draft_email", _draft_email),
)

DOMAINS: Mapping[str, tuple[Tool, ...]] = {"enterprise": ENTERPRISE}
