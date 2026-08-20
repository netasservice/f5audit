"""Client tests: structural read-only guarantees, pagination, re-login.

None of these tests open a socket: the requests session is mocked.
"""

import inspect
from pathlib import Path
from unittest.mock import MagicMock

import pytest

import f5audit.client as client_module
from f5audit.client import F5APIError, F5ReadOnlyClient, LOGIN_PATH

PACKAGE_DIR = Path(client_module.__file__).parent


def make_response(status_code=200, json_data=None):
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = json_data if json_data is not None else {}
    return response


def make_client(**kwargs):
    kwargs.setdefault("delay", 0)
    client = F5ReadOnlyClient("192.0.2.1", "auditor", "secret", **kwargs)
    client._session = MagicMock()
    return client


def authed_client(**kwargs):
    client = make_client(**kwargs)
    client._token = "fake-token"
    return client


# ---------------------------------------------------------------------------
# Structural read-only guarantees (spec section 2)
# ---------------------------------------------------------------------------

def test_client_exposes_no_write_methods():
    for verb in ("post", "put", "patch", "delete", "request"):
        assert not hasattr(F5ReadOnlyClient, verb), (
            f"F5ReadOnlyClient must not expose a '{verb}' method"
        )


def test_only_write_call_is_the_login_post():
    source = inspect.getsource(client_module)
    assert ".put(" not in source
    assert ".patch(" not in source
    assert ".delete(" not in source
    assert source.count(".post(") == 1, "exactly one POST (the login) allowed"
    login_source = inspect.getsource(F5ReadOnlyClient.login)
    assert ".post(" in login_source, "the single POST must live in login()"
    # And the login target is the hardcoded constant, not a parameter.
    assert "LOGIN_PATH" in login_source
    assert LOGIN_PATH == "/mgmt/shared/authn/login"


def test_no_util_bash_anywhere_in_the_package():
    for path in PACKAGE_DIR.glob("*.py"):
        source = path.read_text(encoding="utf-8")
        assert "util/bash" not in source, f"forbidden endpoint referenced in {path.name}"
        assert "tm/util" not in source, f"forbidden endpoint referenced in {path.name}"


# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------

def test_get_collection_paginates_with_top_and_skip():
    client = authed_client(page_size=2)
    pages = [
        make_response(200, {"items": [{"name": "a"}, {"name": "b"}]}),
        make_response(200, {"items": [{"name": "c"}]}),
    ]
    client._session.get.side_effect = pages

    items = client.get_collection("/mgmt/tm/ltm/pool")

    assert [item["name"] for item in items] == ["a", "b", "c"]
    calls = client._session.get.call_args_list
    assert len(calls) == 2
    assert calls[0].kwargs["params"] == {"$top": 2, "$skip": 0}
    assert calls[1].kwargs["params"] == {"$top": 2, "$skip": 2}


def test_get_collection_single_short_page():
    client = authed_client(page_size=100)
    client._session.get.return_value = make_response(200, {"items": [{"name": "a"}]})
    assert len(client.get_collection("/mgmt/tm/ltm/node")) == 1
    assert client._session.get.call_count == 1


# ---------------------------------------------------------------------------
# Auth behavior
# ---------------------------------------------------------------------------

def test_relogin_once_on_401_mid_collection():
    client = authed_client()
    client._session.post.return_value = make_response(
        200, {"token": {"token": "new-token"}}
    )
    client._session.get.side_effect = [
        make_response(401),
        make_response(200, {"items": []}),
    ]

    result = client.get("/mgmt/tm/ltm/pool")

    assert result == {"items": []}
    assert client._session.post.call_count == 1
    assert client._session.post.call_args.args[0].endswith(LOGIN_PATH)
    assert client._token == "new-token"


def test_second_401_after_relogin_raises():
    client = authed_client()
    client._session.post.return_value = make_response(
        200, {"token": {"token": "new-token"}}
    )
    client._session.get.side_effect = [make_response(401), make_response(401)]

    with pytest.raises(F5APIError) as excinfo:
        client.get("/mgmt/tm/ltm/pool")
    assert excinfo.value.status_code == 401


def test_login_404_falls_back_to_basic_auth():
    client = make_client()
    client._session.post.return_value = make_response(404)
    client.login()
    assert client._auth_mode == "basic"
    assert client._session.auth == ("auditor", "secret")

    client._session.get.return_value = make_response(200, {"items": []})
    assert client.get("/mgmt/tm/ltm/pool") == {"items": []}
    # Basic mode must not attempt another login POST on GETs.
    assert client._session.post.call_count == 1


def test_non_success_status_raises_api_error_with_path():
    client = authed_client()
    client._session.get.return_value = make_response(403)
    with pytest.raises(F5APIError) as excinfo:
        client.get("/mgmt/tm/ltm/rule")
    assert excinfo.value.status_code == 403
    assert excinfo.value.path == "/mgmt/tm/ltm/rule"
