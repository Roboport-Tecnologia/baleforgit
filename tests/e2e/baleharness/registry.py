"""Phase grouping + within-group ordering."""

from __future__ import annotations

import random


PHASE_GROUPS_ORDER = ["g1", "g2-head", "g2-tail", "g3"]


def order_within_group(phases: list[str], order: str, rng: random.Random) -> list[str]:
    if order == "forward":
        return list(phases)
    if order == "reverse":
        return list(reversed(phases))
    if order == "random":
        out = list(phases)
        rng.shuffle(out)
        return out
    raise ValueError(f"unknown order: {order!r}")
