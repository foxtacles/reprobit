"""Verification-report labels and compact numeric formatting."""

from __future__ import annotations

from fractions import Fraction

from reprobit.costs import CostClass, FunctionCost


def yes_no(value: bool) -> str:
    return "yes" if value else "no"


def human_label(value: str) -> str:
    return value.replace("_", " ").replace("-", " ").strip().title()


def cost_class_label(value: CostClass) -> str:
    return {
        CostClass.STATE_CARRIER: "State carrier",
        CostClass.GENERATED_SUPPLIER: "Generated supplier",
        CostClass.LINK_ORDERING: "Link ordering",
        CostClass.EQUAL_BODY_DONOR: "Equal-body donor",
        CostClass.STRUCTURAL_DONOR: "Structural donor",
        CostClass.CROSS_TU_OR_OVERLAY: "Cross-TU or overlay",
        CostClass.SEMANTIC_REWRITE: "Semantic rewrite",
        CostClass.BINARY_SURGERY: "Binary surgery",
        CostClass.ORACLE_INSTALL: "Oracle install",
    }[value]


def format_bytes(value: int) -> str:
    units = ("bytes", "KiB", "MiB", "GiB")
    amount = float(value)
    unit = units[0]
    for candidate in units:
        unit = candidate
        if amount < 1024 or candidate == units[-1]:
            break
        amount /= 1024
    if unit == "bytes":
        return f"{value:,} bytes"
    return f"{amount:,.1f} {unit}"


def format_seconds(value: float) -> str:
    if value < 0.01:
        return f"{value * 1000:.1f} ms"
    if value < 60:
        return f"{value:.2f} s"
    minutes, seconds = divmod(value, 60)
    return f"{int(minutes)}m {seconds:.1f}s"


def format_fraction(value: Fraction) -> str:
    if value.denominator == 1:
        return f"{value.numerator:,}"
    return f"{value.numerator:,}/{value.denominator:,}"


def function_total(item: FunctionCost) -> Fraction:
    return Fraction(item.direct_cost) + item.allocated_shared_cost.as_fraction()


def readable_function(value: str) -> str:
    """Return a compact display hint without claiming to fully demangle MSVC names."""

    if value.startswith("??0"):
        owner = value[3:].split("@", 1)[0]
        return f"{owner} constructor" if owner else "Constructor"
    if value.startswith("??1"):
        owner = value[3:].split("@", 1)[0]
        return f"{owner} destructor" if owner else "Destructor"
    if value.startswith("?"):
        pieces = value[1:].split("@")
        if len(pieces) > 1 and pieces[0] and pieces[1]:
            return f"{pieces[1]}.{pieces[0].lstrip('?')}"
        if pieces and pieces[0]:
            return pieces[0].lstrip("?")
    return value if len(value) <= 56 else f"{value[:53]}…"


__all__ = [
    "cost_class_label",
    "format_bytes",
    "format_fraction",
    "format_seconds",
    "function_total",
    "human_label",
    "readable_function",
    "yes_no",
]
