"""Read-only iControl REST client.

Safety contract (see project spec, section 2):
- The only public request method is ``get``. There are no public
  ``post``/``patch``/``put``/``delete`` methods on this class.
- The single internal write is the token login, hardcoded to
  ``LOGIN_PATH`` and not redirectable to any other route.
- No explicit logout: deleting the token would be a write. Tokens
  expire on their own (~20 minutes, BIG-IP default).
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

import requests

# The ONLY endpoint this tool is ever allowed to write to.
LOGIN_PATH = "/mgmt/shared/authn/login"

DEFAULT_TIMEOUT = 30
MAX_RETRIES = 2  # retries after the initial attempt
BACKOFF_BASE_SECONDS = 1.0

logger = logging.getLogger("f5audit.client")


class F5ClientError(Exception):
    """Connection-level or protocol-level failure talking to the BIG-IP."""


class F5AuthError(F5ClientError):
    """Authentication failed (bad credentials or REST access disabled)."""


class F5APIError(F5ClientError):
    """A GET returned a non-success HTTP status."""

    def __init__(self, status_code: int, path: str, message: str = ""):
        self.status_code = status_code
        self.path = path
        detail = message or f"HTTP {status_code} on GET {path}"
        super().__init__(detail)


class F5ReadOnlyClient:
    """HTTP client restricted to GET requests against a BIG-IP.

    Auth modes:
    - token (default): POST to LOGIN_PATH once, then X-F5-Auth-Token header.
    - basic: automatic fallback when the login endpoint returns 404
      (BIG-IP <= 11.5 without token auth).
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        *,
        verify_tls: bool = True,
        login_provider: str = "tmos",
        timeout: int = DEFAULT_TIMEOUT,
        delay: float = 0.1,
        page_size: int = 100,
    ):
        self._host = host
        self._username = username
        self._password = password
        self._login_provider = login_provider
        self._timeout = timeout
        self._delay = delay
        self.page_size = page_size
        self._token: Optional[str] = None
        self._auth_mode = "token"  # or "basic" after 404 fallback
        self._session = requests.Session()
        self._session.verify = verify_tls

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def login(self) -> None:
        """Obtain an auth token. Falls back to HTTP Basic on 404.

        This is the only method in the entire codebase that performs a
        non-GET request, and the target path is a module constant.
        """
        url = f"https://{self._host}{LOGIN_PATH}"
        body = {
            "username": self._username,
            "password": self._password,
            "loginProviderName": self._login_provider,
        }
        try:
            response = self._session.post(url, json=body, timeout=self._timeout)
        except requests.exceptions.SSLError as exc:
            raise F5ClientError(
                "TLS certificate verification failed. If the management "
                "interface uses a self-signed certificate, re-run with "
                "--insecure (understanding the risk)."
            ) from exc
        except requests.RequestException as exc:
            raise F5ClientError(
                f"Could not reach https://{self._host}: {exc.__class__.__name__}. "
                "Check network/firewall access to the management interface (443)."
            ) from exc

        if response.status_code == 200:
            try:
                self._token = response.json()["token"]["token"]
            except (ValueError, KeyError) as exc:
                raise F5ClientError(
                    "Login succeeded but the token response was malformed."
                ) from exc
            self._session.headers["X-F5-Auth-Token"] = self._token
            logger.debug("Token auth established (token %s...)", self._token[:6])
        elif response.status_code == 404:
            # Old BIG-IP (<= 11.5) without token auth: fall back to Basic.
            logger.warning(
                "Token login endpoint not found (404); this looks like an old "
                "BIG-IP version. Falling back to HTTP Basic Auth for GETs."
            )
            self._auth_mode = "basic"
            self._session.auth = (self._username, self._password)
        elif response.status_code == 401:
            raise F5AuthError(
                "Login rejected (401). Check the credentials and that the "
                "account has iControl REST access enabled (an Auditor/RO "
                "role still needs REST access granted)."
            )
        else:
            raise F5AuthError(
                f"Unexpected status {response.status_code} from login endpoint."
            )

    def _ensure_authenticated(self) -> None:
        if self._auth_mode == "token" and self._token is None:
            self.login()

    # ------------------------------------------------------------------
    # Read-only requests
    # ------------------------------------------------------------------

    def get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """GET a single resource and return the parsed JSON body.

        Retries up to MAX_RETRIES times with exponential backoff on
        timeouts / connection errors / 5xx. On a 401 mid-collection
        (expired token) it re-logins once, transparently.
        """
        self._ensure_authenticated()
        url = f"https://{self._host}{path}"
        relogin_done = False
        attempt = 0
        while True:
            if self._delay:
                time.sleep(self._delay)
            try:
                response = self._session.get(url, params=params, timeout=self._timeout)
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as exc:
                if attempt < MAX_RETRIES:
                    wait = BACKOFF_BASE_SECONDS * (2 ** attempt)
                    logger.warning(
                        "GET %s failed (%s), retrying in %.1fs",
                        path, exc.__class__.__name__, wait,
                    )
                    time.sleep(wait)
                    attempt += 1
                    continue
                raise F5ClientError(
                    f"GET {path} failed after {MAX_RETRIES + 1} attempts: "
                    f"{exc.__class__.__name__}"
                ) from exc

            if response.status_code == 200:
                try:
                    return response.json()
                except ValueError as exc:
                    raise F5APIError(
                        200, path, f"Malformed JSON in response from {path}"
                    ) from exc

            if response.status_code == 401 and self._auth_mode == "token" and not relogin_done:
                # Token likely expired mid-collection: one transparent re-login.
                logger.info("Got 401 on %s; re-authenticating once.", path)
                self._token = None
                self.login()
                relogin_done = True
                continue

            if response.status_code >= 500 and attempt < MAX_RETRIES:
                wait = BACKOFF_BASE_SECONDS * (2 ** attempt)
                logger.warning(
                    "GET %s returned %d, retrying in %.1fs",
                    path, response.status_code, wait,
                )
                time.sleep(wait)
                attempt += 1
                continue

            raise F5APIError(response.status_code, path)

    def get_collection(
        self, path: str, params: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """GET a collection with $top/$skip pagination; returns merged items."""
        items: List[Dict[str, Any]] = []
        skip = 0
        while True:
            page_params = dict(params or {})
            page_params["$top"] = self.page_size
            page_params["$skip"] = skip
            data = self.get(path, params=page_params)
            page_items = data.get("items", [])
            items.extend(page_items)
            if len(page_items) < self.page_size:
                break
            skip += self.page_size
        return items
