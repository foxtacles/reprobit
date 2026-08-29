"""Shared failures for closed classic semantic proofs."""

from __future__ import annotations


class ClassicSemanticError(ValueError):
    """Current-run evidence cannot establish semantic ancestry."""
