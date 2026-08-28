from __future__ import annotations

import hashlib
import re
from pathlib import Path

# Content identities of downstream-project tokens that previously leaked into
# the reusable validator.  Hashes keep the regression test itself free of the
# identities it prohibits.
_FORBIDDEN_TOKEN_DIGESTS = frozenset(
    {
        "d937f01b7daf50dce79eca93e56b0f39341ca132b22e8fcde17d54240fda769b",
        "9ba4945ddd14997fc68e1a6ede9f15f4e558e0f95b753d60d91a30ea4e93aca6",
        "a23880d50b3df164cdda2b4260a36ffa33890bd5d5f9abc42bde0bae0c1aeb25",
        "69c8b1df7c5acff6cb42fb79882ed2279d3aef786123299e6bdf619b47ddba5d",
        "9f9270101c01c10c311b9895749b23d114b5c93bb3efeb8e21f75802e33a7908",
        "524a4d869567d3dd7add1e89a03b6c9c55092d6e2edcc163fb532d6dcdd86514",
        "6f3175ef4e2ced9f6b7febeb49e0103c6e41478af1e7a31202d61c36b1aebcec",
        "d166ee4ce18147eb4c37cbea728ac389fe6c6f9636ef28f9369f10c3fa9a67bd",
        "d294677fe15ee3e70a1b39d974c4f5802b08314237aa1bc4361d96c85ab1e337",
        "5e13b72e07d10b61e99cd45489024189af7973ecd02395809e209398026a7b31",
    }
)
_FORBIDDEN_FOUR_CHARACTER_PREFIX_DIGESTS = frozenset(
    {"69c8b1df7c5acff6cb42fb79882ed2279d3aef786123299e6bdf619b47ddba5d"}
)
_TEXT_ROOTS = ("src", "tests", "docs", "schemas")
_TOKEN = re.compile(r"[A-Za-z][A-Za-z0-9_]*")


def _digest(value: str) -> str:
    return hashlib.sha256(value.casefold().encode("ascii")).hexdigest()


def test_reusable_repository_contains_no_downstream_project_identity() -> None:
    root = Path(__file__).resolve().parents[1]
    leaks: list[str] = []
    for relative_root in _TEXT_ROOTS:
        for path in sorted((root / relative_root).rglob("*")):
            if not path.is_file() or path.suffix in {".pyc", ".png", ".zip"}:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            for line_number, line in enumerate(text.splitlines(), 1):
                for match in _TOKEN.finditer(line):
                    token = match.group(0)
                    folded = token.casefold()
                    if _digest(folded) in _FORBIDDEN_TOKEN_DIGESTS or (
                        len(folded) >= 4
                        and _digest(folded[:4])
                        in _FORBIDDEN_FOUR_CHARACTER_PREFIX_DIGESTS
                    ):
                        leaks.append(f"{path.relative_to(root)}:{line_number}:{token}")
    assert not leaks, "downstream project identities leaked into reusable code:\n" + "\n".join(
        leaks
    )
