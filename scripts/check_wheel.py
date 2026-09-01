"""Check that an installed ReproBit wheel carries every non-Python asset.

CI runs this after ``pip install --force-reinstall dist/*.whl`` so the imports
below resolve to the installed distribution, not the source tree.  The source
tree is only consulted to enumerate what the wheel must contain.
"""

from __future__ import annotations

from importlib.metadata import distribution
from pathlib import Path

from reprobit.assets import runtime_asset_path
from reprobit.cmake import cmake_module_path

ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    cmake_module = cmake_module_path() / "ReproBit.cmake"
    runtime_proxy = runtime_asset_path("ReproBitPathProxy.sh")
    for path in (cmake_module, runtime_proxy):
        if not path.is_file():
            raise SystemExit(f"wheel omitted {path}")
    installed = distribution("reprobit")
    files = {str(item) for item in installed.files or ()}
    license_root = f"reprobit-{installed.version}.dist-info/licenses"
    required = {
        "reprobit/py.typed",
        f"{license_root}/LICENSE",
        f"{license_root}/NOTICE",
    }
    for directory in ("cmake", "runtime", "schemas"):
        required.update(
            f"share/reprobit/{path.relative_to(ROOT).as_posix()}"
            for path in (ROOT / directory).rglob("*")
            if path.is_file()
        )
    if missing := sorted(required - files):
        raise SystemExit(f"wheel omitted {missing}")


if __name__ == "__main__":
    main()
