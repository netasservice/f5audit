"""Collector tests: raw cache roundtrip, 403/404 handling. No network."""

import pytest

from f5audit.client import F5APIError, F5ClientError
from f5audit.collector import Collector, RawStore, load_from_raw
from tests.conftest import build_collection, load_fixture


class FakeClient:
    """Stands in for F5ReadOnlyClient; serves canned responses per path."""

    page_size = 100
    _host = "192.0.2.1"

    def __init__(self, responses):
        # responses: {path: data} or {path: F5APIError instance}
        self.responses = responses
        self.requested = []

    def _serve(self, path):
        self.requested.append(path)
        result = self.responses.get(path)
        if isinstance(result, F5APIError):
            raise result
        return result

    def get(self, path, params=None):
        data = self._serve(path)
        if data is None:
            raise F5APIError(404, path)
        return data

    def get_collection(self, path, params=None):
        data = self._serve(path)
        if data is None:
            raise F5APIError(404, path)
        return data


def minimal_responses():
    return {
        "/mgmt/tm/sys/version": load_fixture("sys_version.json"),
        "/mgmt/tm/sys/failover": load_fixture("sys_failover_active.json"),
        "/mgmt/tm/sys/clock": {},
        "/mgmt/tm/cm/device": load_fixture("cm_device.json"),
        "/mgmt/tm/auth/partition": load_fixture("auth_partition.json"),
        "/mgmt/tm/ltm/node": load_fixture("nodes.json"),
        "/mgmt/tm/ltm/pool": [load_fixture("pools.json")[0]],
        "/mgmt/tm/ltm/virtual": [],
        "/mgmt/tm/ltm/rule": [],
        "/mgmt/tm/ltm/policy": [],
        "/mgmt/tm/ltm/pool/~Common~pool-web/members": load_fixture("pool_members_pool-web.json"),
        "/mgmt/tm/ltm/pool/~Common~pool-web/members/stats": load_fixture(
            "pool_member_stats_pool-web.json"
        ),
        "/mgmt/tm/ltm/monitor/http": load_fixture("monitors_http.json"),
        "/mgmt/tm/ltm/virtual/stats": {},
        "/mgmt/tm/ltm/pool/stats": {},
        "/mgmt/tm/ltm/node/stats": {},
    }


def test_collect_gathers_expected_datasets():
    collector = Collector(FakeClient(minimal_responses()))
    data = collector.collect()

    assert data.meta["aborted"] is None
    assert data.get("sys_version")
    assert data.get("ltm_node@Common")
    assert data.get("ltm_pool_members@/Common/pool-web")
    # Unprovisioned monitor types (404) are skipped silently.
    assert "ltm_monitor_mysql@Common" not in data.datasets
    assert "/mgmt/tm/ltm/monitor/mysql" not in data.meta["missing_endpoints"]
    assert data.get("ltm_monitor_http@Common")


def test_collect_records_403_as_denied():
    responses = minimal_responses()
    responses["/mgmt/tm/ltm/rule"] = F5APIError(403, "/mgmt/tm/ltm/rule")
    collector = Collector(FakeClient(responses))
    data = collector.collect()

    denied = data.meta["denied"]
    assert any(
        entry["endpoint"] == "/mgmt/tm/ltm/rule" and entry["partition"] == "Common"
        for entry in denied
    )
    assert data.meta["aborted"] is None


def test_collect_aborts_cleanly_on_connection_failure():
    responses = minimal_responses()

    class DyingClient(FakeClient):
        def get_collection(self, path, params=None):
            if path == "/mgmt/tm/ltm/virtual":
                raise F5ClientError("GET failed after 3 attempts: Timeout")
            return super().get_collection(path, params)

    collector = Collector(DyingClient(responses))
    data = collector.collect()

    assert "Timeout" in data.meta["aborted"]
    # Earlier datasets were kept.
    assert data.get("sys_version")
    assert data.get("ltm_node@Common")


def test_raw_store_roundtrip(tmp_path):
    original = build_collection()
    store = RawStore(str(tmp_path))
    for key, dataset in original.datasets.items():
        store.save(key, f"/mgmt/fake/{key}", dataset)
    store.save_meta(original.meta)

    loaded = load_from_raw(str(tmp_path))

    assert loaded.datasets == original.datasets
    assert loaded.meta == original.meta


def test_raw_files_carry_timestamp(tmp_path):
    store = RawStore(str(tmp_path))
    store.save("sys_version", "/mgmt/tm/sys/version", {"x": 1})
    import json

    files = list(tmp_path.glob("*.json"))
    assert len(files) == 1
    payload = json.loads(files[0].read_text())
    assert payload["collected_at"]  # enables the future compare subcommand
    assert payload["path"] == "/mgmt/tm/sys/version"


def test_load_from_raw_empty_dir_errors(tmp_path):
    with pytest.raises(F5ClientError):
        load_from_raw(str(tmp_path))
