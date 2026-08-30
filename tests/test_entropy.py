from __future__ import annotations

import pytest

from reprobit.entropy import generate_extern_run, generate_forward_run


def test_entropy_prefixes_are_ascii_cpp_identifier_stems() -> None:
    assert generate_forward_run("Spare", 2, 1) == "class Spare0;\nclass Spare1;\n"
    assert generate_extern_run("g_spare", 2, 1) == ("extern int g_spare0;\nextern int g_spare1;\n")

    for prefix in ("café", "Ωmega", "bad-name", "_reserved"):
        with pytest.raises(ValueError, match="identifier stem"):
            generate_forward_run(prefix, 1, 1)
        with pytest.raises(ValueError, match="identifier stem"):
            generate_extern_run(prefix, 1, 1)
