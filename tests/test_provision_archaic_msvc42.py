from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from scripts import provision_archaic_msvc42 as provisioner


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
        provisioner.verify(tmp_path)

    provisioner._install_transport_assets(tmp_path)
    provisioner.verify(tmp_path)


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
        provisioner.verify(tmp_path)


@pytest.mark.skipif(os.name != "posix", reason="portable symlink creation")
def test_provision_rejects_redirected_destination(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    redirected = tmp_path / "redirected"
    redirected.symlink_to(real, target_is_directory=True)

    with pytest.raises(provisioner.ProvisionError, match="redirected path"):
        provisioner.provision(redirected)
