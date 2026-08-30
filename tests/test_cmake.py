from __future__ import annotations

import os
import shutil
import subprocess
from hashlib import sha256
from pathlib import Path

import pytest

import reprobit.cmake as cmake_support
from reprobit.cmake import CMakeExportPlan, cmake_module_path


def test_installed_module_lookup_ignores_unrelated_cmake_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    site_packages = tmp_path / "site-packages"
    package = site_packages / "reprobit"
    package.mkdir(parents=True)
    fake_module = package / "cmake.py"
    fake_module.touch()
    unrelated = tmp_path / "cmake"
    unrelated.mkdir()
    (unrelated / "ReproBit.cmake").write_text("unrelated", encoding="utf-8")
    installed = site_packages / "share" / "reprobit" / "cmake"
    installed.mkdir(parents=True)
    (installed / "ReproBit.cmake").write_text("packaged", encoding="utf-8")
    monkeypatch.setattr(cmake_support, "__file__", str(fake_module))

    assert cmake_support.cmake_module_path() == installed


@pytest.mark.skipif(shutil.which("cmake") is None, reason="CMake is not installed")
@pytest.mark.skipif(os.name != "posix", reason="CMake integration fixture requires POSIX")
def test_cmake_module_serializes_targets_and_all_admission_fields(tmp_path: Path) -> None:
    source = tmp_path / "source"
    build = tmp_path / "build"
    source.mkdir()
    (source / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    module = (cmake_module_path() / "ReproBit.cmake").as_posix()
    (source / "CMakeLists.txt").write_text(
        f"""cmake_minimum_required(VERSION 3.20)
project(plan_fixture C)
include(\"{module}\")
add_executable(app main.c)
reprobit_register_target(TARGET app ARTIFACT_ID app.image)
reprobit_add_link_admission(
  ID admit.object
  TARGET app
  ARTIFACT_ID generated.object
  OBJECT_PATH R:/build/generated.obj
  BEFORE runtime.lib
  EXPECTED_SYMBOL _entry
)
reprobit_write_plan(OUTPUT \"${{CMAKE_BINARY_DIR}}/reprobit-plan.json\")
""",
        encoding="utf-8",
    )

    completed = subprocess.run(
        ["cmake", "-S", str(source), "-B", str(build)],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    assert completed.returncode == 0, completed.stdout
    plan = CMakeExportPlan.read(build / "reprobit-plan.json")

    assert plan.targets[0].name == "app"
    assert plan.targets[0].artifact_id == "app.image"
    assert Path(plan.targets[0].output).name == "app"
    admission = plan.link_admissions[0]
    assert admission.object_path == "R:/build/generated.obj"
    assert admission.before == "runtime.lib"
    assert admission.expected_symbol == "_entry"


@pytest.mark.skipif(shutil.which("cmake") is None, reason="CMake is not installed")
@pytest.mark.skipif(os.name != "posix", reason="CMake integration fixture requires POSIX")
def test_cmake_module_applies_checked_source_and_link_seats(tmp_path: Path) -> None:
    source = tmp_path / "source"
    build = tmp_path / "build"
    source.mkdir()
    (source / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    (source / "tail.c").write_text("int tail(void) { return 1; }\n", encoding="utf-8")
    generated = b"int generated(void) { return 2; }\n"
    (source / "generated.c").write_bytes(generated)
    module = (cmake_module_path() / "ReproBit.cmake").as_posix()
    (source / "CMakeLists.txt").write_text(
        f"""cmake_minimum_required(VERSION 3.20)
project(graph_fixture C)
include("{module}")
add_executable(app main.c tail.c)
target_link_libraries(app PRIVATE alpha beta)
reprobit_insert_generated_source(
  TARGET app SOURCE generated.c INDEX 1 AFTER main.c BEFORE tail.c
  LANGUAGE C SHA256 {sha256(generated).hexdigest()} SIZE {len(generated)}
)
reprobit_insert_link_item(
  TARGET app ITEM gamma INDEX 1 AFTER alpha BEFORE beta
)
get_target_property(final_sources app SOURCES)
get_target_property(final_links app LINK_LIBRARIES)
file(WRITE "${{CMAKE_BINARY_DIR}}/graph.txt"
  "sources=${{final_sources}}\nlinks=${{final_links}}\n")
""",
        encoding="utf-8",
    )

    completed = subprocess.run(
        ["cmake", "-S", str(source), "-B", str(build)],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    assert completed.returncode == 0, completed.stdout
    state = (build / "graph.txt").read_text(encoding="utf-8")
    assert "main.c;" in state
    assert "/generated.c;tail.c" in state
    assert "links=alpha;gamma;beta" in state
