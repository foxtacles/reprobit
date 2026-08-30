from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from reprobit import msvc42_provision as provisioner


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.parametrize(
    ("relative", "authority"),
    provisioner._PROVISIONED_TRANSPORT_FILES.items(),
)
def test_packaged_transport_assets_match_fixed_authority(
    relative: str,
    authority: provisioner.FileAuthority,
) -> None:
    source = provisioner._transport_asset(relative, authority)

    assert source.stat().st_size == authority.size
    assert _sha256(source) == authority.sha256
    assert b"Permission to use, copy, modify" in source.read_bytes()


def test_missing_packaged_transport_is_a_provision_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing(_name: str) -> Path:
        raise FileNotFoundError("simulated missing wheel asset")

    monkeypatch.setattr(provisioner, "runtime_asset_directory", missing)

    with pytest.raises(provisioner.ProvisionError, match="missing wheel asset"):
        provisioner._transport_asset("wine/x86/cl", provisioner._TRANSPORT_FILES["wine/x86/cl"])


def test_transport_install_is_exact_regular_and_non_overwriting(tmp_path: Path) -> None:
    provisioner._install_transport_assets(tmp_path)

    for relative, authority in provisioner._PROVISIONED_TRANSPORT_FILES.items():
        installed = tmp_path.joinpath(*relative.split("/"))
        assert installed.is_file()
        assert not installed.is_symlink()
        assert installed.stat().st_size == authority.size
        assert _sha256(installed) == authority.sha256
        if os.name == "posix":
            assert os.access(installed, os.X_OK)

    with pytest.raises(provisioner.ProvisionError, match="already exists"):
        provisioner._install_transport_assets(tmp_path)


def test_complete_verification_requires_cross_host_transport(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(provisioner, "_FILES", {})
    monkeypatch.setattr(provisioner, "_TREES", {})

    with pytest.raises(provisioner.ProvisionError, match="absent or redirected"):
        provisioner.verify_msvc42(tmp_path)

    provisioner._install_transport_assets(tmp_path)
    provisioner.verify_msvc42(tmp_path)


def test_complete_verification_rejects_transport_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(provisioner, "_FILES", {})
    monkeypatch.setattr(provisioner, "_TREES", {})
    provisioner._install_transport_assets(tmp_path)
    transport = tmp_path / "wine" / "x86" / "wine-msvc.sh"
    transport.write_bytes(transport.read_bytes() + b"\n")

    with pytest.raises(provisioner.ProvisionError, match="file authority differs"):
        provisioner.verify_msvc42(tmp_path)


def test_cmake_frontend_verification_is_exact_and_finite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payloads = {
        "bin/NMAKE.EXE": b"nmake",
        "bin/NMAKE.ERR": b"messages",
    }
    authorities = {
        relative: provisioner.FileAuthority(len(payload), hashlib.sha256(payload).hexdigest())
        for relative, payload in payloads.items()
    }
    monkeypatch.setattr(provisioner, "_CMAKE_FRONTEND_FILES", authorities)
    for relative, payload in payloads.items():
        path = tmp_path.joinpath(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)

    provisioner.verify_msvc42_cmake_frontend(tmp_path)
    (tmp_path / "bin/NMAKE.ERR").write_bytes(b"changed")
    with pytest.raises(provisioner.ProvisionError, match="file authority differs"):
        provisioner.verify_msvc42_cmake_frontend(tmp_path)


@pytest.mark.skipif(os.name != "posix", reason="portable symlink creation")
def test_provision_rejects_redirected_destination(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    redirected = tmp_path / "redirected"
    redirected.symlink_to(real, target_is_directory=True)

    with pytest.raises(provisioner.ProvisionError, match="redirected path"):
        provisioner.provision_msvc42(redirected)


def test_existing_exact_destination_reports_progress_and_returns_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    messages: list[str] = []
    monkeypatch.setattr(provisioner, "verify_msvc42", lambda _root: None)

    result = provisioner.provision_msvc42(tmp_path, progress=messages.append)

    assert result == tmp_path.resolve(strict=True)
    assert messages == [
        f"verifying existing destination {tmp_path.resolve(strict=True)}",
        "existing toolchain is exact; no download needed",
    ]
