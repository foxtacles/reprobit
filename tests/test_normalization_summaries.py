from __future__ import annotations

import pytest
from pydantic import ValidationError

from reprobit.execution import EngineError, NormalizationCategoryAttestation
from reprobit.model import ByteRange
from reprobit.report import NormalizationCategorySummary

_INVALID_RANGE_SUMMARIES = (
    pytest.param(1, 0, (), 0, "changed-byte and range counts disagree", id="bytes-without-ranges"),
    pytest.param(
        0,
        1,
        (ByteRange(offset=4, length=1),),
        0,
        "changed-byte and range counts disagree",
        id="ranges-without-bytes",
    ),
    pytest.param(
        1,
        1,
        (ByteRange(offset=4, length=2),),
        0,
        "range summary exceeds changed bytes",
        id="preview-exceeds-bytes",
    ),
    pytest.param(
        2,
        1,
        (ByteRange(offset=4, length=1),),
        0,
        "ranges do not exhaust changed bytes",
        id="complete-preview-understates-bytes",
    ),
    pytest.param(
        1,
        2,
        (ByteRange(offset=4, length=1),),
        1,
        "range summary exceeds changed bytes",
        id="omitted-range-has-no-byte",
    ),
)


@pytest.mark.parametrize(
    ("changed_bytes", "changed_range_count", "changed_ranges", "omitted", "message"),
    _INVALID_RANGE_SUMMARIES,
)
def test_runtime_normalization_rejects_inconsistent_range_accounting(
    changed_bytes: int,
    changed_range_count: int,
    changed_ranges: tuple[ByteRange, ...],
    omitted: int,
    message: str,
) -> None:
    with pytest.raises(EngineError, match=message):
        NormalizationCategoryAttestation(
            category="test.category",
            normalized_bytes=16,
            changed_bytes=changed_bytes,
            changed_range_count=changed_range_count,
            changed_ranges=changed_ranges,
            omitted_changed_ranges=omitted,
        )


@pytest.mark.parametrize(
    ("changed_bytes", "changed_range_count", "changed_ranges", "omitted", "message"),
    _INVALID_RANGE_SUMMARIES,
)
def test_report_normalization_rejects_inconsistent_range_accounting(
    changed_bytes: int,
    changed_range_count: int,
    changed_ranges: tuple[ByteRange, ...],
    omitted: int,
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        NormalizationCategorySummary(
            category="test.category",
            normalized_bytes=16,
            changed_bytes=changed_bytes,
            changed_range_count=changed_range_count,
            changed_ranges=changed_ranges,
            omitted_changed_ranges=omitted,
        )


def test_normalization_range_preview_can_omit_accounted_bytes() -> None:
    changed_ranges = (ByteRange(offset=4, length=1),)
    summaries = (
        NormalizationCategoryAttestation(
            category="test.category",
            normalized_bytes=16,
            changed_bytes=4,
            changed_range_count=2,
            changed_ranges=changed_ranges,
            omitted_changed_ranges=1,
        ),
        NormalizationCategorySummary(
            category="test.category",
            normalized_bytes=16,
            changed_bytes=4,
            changed_range_count=2,
            changed_ranges=changed_ranges,
            omitted_changed_ranges=1,
        ),
    )

    assert all(summary.changed_bytes == 4 for summary in summaries)
