from __future__ import annotations

from reprobit.artifacts import digest_bytes
from reprobit.classic.source_regeneration import (
    _ClassicRegenerationContext,
    _parameter_map,
    _refresh_source_identities,
)


class _Reader:
    def __init__(self, files: dict[str, bytes]) -> None:
        self._files = files

    def read(self, relative: str, *, wanted_by: str) -> bytes:
        return self._files[relative]


def _context(files: dict[str, bytes], documents: dict[str, object]) -> _ClassicRegenerationContext:
    return _ClassicRegenerationContext(
        documents=documents,
        plan_relative="reprobit/build-plan.json",
        reader=_Reader(files),
        error_type=ValueError,
    )


def _document(identity: dict[str, object]) -> dict[str, object]:
    return {
        "source": "src/unit.cpp",
        "interventions": [
            {
                "id": "fn_test",
                "parameters": [
                    {"name": "same_function_source_identity", "value": identity},
                ],
            }
        ],
    }


def test_identity_repins_when_its_file_was_refreshed() -> None:
    old_clean = digest_bytes(b"old clean bytes")
    new_clean_bytes = b"new clean bytes"
    identity = {
        "clean_source_sha256": old_clean,
        "effective_source_sha256": digest_bytes(b"old effective bytes"),
        "function_range_sha256": "untouched",
    }
    document = _document(identity)
    context = _context({"src/unit.cpp": new_clean_bytes}, {"unit.json": document})
    context.stale_paths["src/unit.cpp"] = old_clean
    context.effective_by_path["src/unit.cpp"] = digest_bytes(b"new effective bytes")

    _refresh_source_identities(context)

    updated = _parameter_map(document["interventions"][0])["same_function_source_identity"]
    assert updated["clean_source_sha256"] == digest_bytes(new_clean_bytes)
    assert updated["effective_source_sha256"] == digest_bytes(b"new effective bytes")
    assert updated["function_range_sha256"] == "untouched"
    assert {change.location for change in context.changes} == {
        "fn_test same_function_source_identity.clean_source_sha256",
        "fn_test same_function_source_identity.effective_source_sha256",
    }


def test_identity_for_unchanged_file_is_left_alone() -> None:
    identity = {
        "clean_source_sha256": digest_bytes(b"stable clean"),
        "effective_source_sha256": digest_bytes(b"stable effective"),
    }
    document = _document(identity)
    context = _context({}, {"unit.json": document})
    context.stale_paths["src/other.cpp"] = digest_bytes(b"other old clean")

    _refresh_source_identities(context)

    unchanged = _parameter_map(document["interventions"][0])["same_function_source_identity"]
    assert unchanged == identity
    assert context.changes == []
