"""CLI helper tests. No test in this suite ever touches the network."""

from f5audit.cli import _load_resume_data
from f5audit.collector import RawStore


def test_load_resume_data_ignores_missing_or_empty_dir(tmp_path):
    assert _load_resume_data(None) is None
    assert _load_resume_data(str(tmp_path / "does-not-exist")) is None
    empty = tmp_path / "empty"
    empty.mkdir()
    assert _load_resume_data(str(empty)) is None


def test_load_resume_data_reuses_existing_cache(tmp_path, capsys):
    store = RawStore(str(tmp_path))
    store.save("sys_version", "/mgmt/tm/sys/version", {"x": 1})

    resume = _load_resume_data(str(tmp_path))

    assert resume is not None
    assert resume.datasets["sys_version"] == {"x": 1}
    assert "Resuming collection" in capsys.readouterr().out
