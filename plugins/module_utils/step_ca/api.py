# -*- coding: utf-8 -*-
# (c) 2026, Bodo Schulz <bodo@boone-schulz.de>

"""
Thin HTTPS client for the step-ca Admin API.

Wraps a :class:`requests.Session` configured to verify TLS against the
local root CA and to attach a freshly minted admin token to every
request.

Three quirks of step-ca's Admin API are encoded here so that the
calling modules don't have to know about them:

* **No ``Bearer`` prefix.** Despite RFC 6750, step-ca expects the raw
  JWT in the ``Authorization`` header. Adding ``Bearer `` causes step-ca
  to feed the prefix into its base64 decoder and fail with a misleading
  "invalid character" error. ``step-cli`` itself sends the token raw —
  we mirror that behaviour.

* **Per-request audience.** step-ca compares the JWT's ``aud`` claim
  verbatim against the request URL. A token minted with audience
  ``<ca_url>/admin`` will not validate on ``<ca_url>/admin/provisioners``.
  We therefore generate a new token for every request, with the
  audience set to the exact target URL.

* **Lazy token cost.** Token generation involves a 600_000-iteration
  PBKDF2 (decrypting the JWK on first use) and a ``/1.0/sign`` round-trip
  (issuing the ephemeral admin cert). Both are amortised inside
  :class:`AdminTokenBuilder` and remain cheap on subsequent calls within
  the same client instance.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from urllib.parse import urljoin

from ansible_collections.bodsch.certs.plugins.module_utils.step_ca.admin_token import (
    AdminTokenBuilder,
)
from ansible_collections.bodsch.certs.plugins.module_utils.step_ca.exceptions import (
    StepCAAPIError,
)

try:
    import requests

    HAS_REQUESTS = True
    REQUESTS_IMPORT_ERROR = None
except ImportError as exc:
    HAS_REQUESTS = False
    REQUESTS_IMPORT_ERROR = exc


class StepCAClient:
    """
    HTTP client for step-ca's Admin API (``/admin/*``).

    A single instance is intended to live for the duration of a single
    Ansible module run. Reusing the instance across multiple API calls
    is encouraged — the underlying :class:`AdminTokenBuilder` caches the
    expensive crypto state (decrypted JWK, ephemeral admin cert) so that
    only the first call pays the full cost.

    Example:

        client = StepCAClient(
            ca_url="https://ca.lab.local:9000",
            ca_root="/opt/step-ca/.step/certs/root_ca.crt",
            admin_provisioner="admin",
            admin_subject="step",
            admin_password=b"super-secret",
        )

        provisioners = client.get("/admin/provisioners")["provisioners"]

    :param ca_url:            Base URL of the step-ca instance, including
                              scheme and port. Trailing slash is stripped.
    :param ca_root:           Filesystem path to the root CA certificate.
                              Used both as the requests TLS bundle and,
                              indirectly, for the JWT ``sha`` claim.
    :param admin_provisioner: Name of the JWK admin provisioner used to
                              authenticate. Defaults to ``admin``.
    :param admin_subject:     Subject registered on step-ca as a super
                              admin. Defaults to ``step``.
    :param admin_password:    Bytes or str — the password protecting the
                              JWK provisioner key.
    :param timeout:           Per-request timeout in seconds.

    :raises StepCAAPIError: if the ``requests`` package is not installed.
    """

    def __init__(
        self,
        ca_url,
        ca_root,
        admin_provisioner,
        admin_subject,
        admin_password,
        timeout=15,
    ):
        if not HAS_REQUESTS:
            raise StepCAAPIError(
                "Python module 'requests' is required for the step-ca API client."
            )

        self._ca_url = ca_url.rstrip("/")
        self._timeout = timeout

        self._token_builder = AdminTokenBuilder(
            ca_url=self._ca_url,
            ca_root_path=ca_root,
            provisioner_name=admin_provisioner,
            admin_subject=admin_subject,
            password=admin_password,
        )

        self._session = requests.Session()
        self._session.verify = ca_root

    # -------------------------------------------------------------- public API

    def get(self, path, params=None):
        """
        Issue a ``GET`` request against the admin API.

        :param path:   API path, with or without leading slash. Joined
                       to the base URL via :func:`urllib.parse.urljoin`.
        :param params: Optional dict of query parameters.
        :returns:      Parsed JSON response (dict) or ``{}`` for empty
                       responses.
        :raises StepCAAPIError: on non-2xx responses or transport errors.
        """
        return self._request("GET", path, params=params)

    def post(self, path, payload):
        """
        Issue a ``POST`` request with a JSON-encoded body.

        :param path:    API path.
        :param payload: Dict to be JSON-encoded as the request body.
        :returns:       Parsed JSON response (dict) or ``{}``.
        :raises StepCAAPIError: on non-2xx responses or transport errors.
        """
        return self._request("POST", path, json_body=payload)

    def put(self, path, payload):
        """
        Issue a ``PUT`` request with a JSON-encoded body.

        :param path:    API path.
        :param payload: Dict to be JSON-encoded as the request body.
        :returns:       Parsed JSON response (dict) or ``{}``.
        :raises StepCAAPIError: on non-2xx responses or transport errors.
        """
        return self._request("PUT", path, json_body=payload)

    def delete(self, path):
        """
        Issue a ``DELETE`` request.

        :param path:    API path.
        :returns:       Parsed JSON response (dict) or ``{}``.
        :raises StepCAAPIError: on non-2xx responses or transport errors.
        """
        return self._request("DELETE", path)

    # ----------------------------------------------------------------- private

    def _request(self, method, path, params=None, json_body=None):
        """
        Internal request dispatcher.

        Mints a fresh admin token with audience set to the exact target
        URL, attaches it as the raw ``Authorization`` header value (no
        ``Bearer`` prefix — see module docstring), then performs the
        request and decodes the response.

        Empty bodies and ``204 No Content`` responses are normalised to
        ``{}`` so callers can always treat the return as a dict.
        """
        url = urljoin(self._ca_url + "/", path.lstrip("/"))

        # step-ca expects the raw token in the Authorization header, NOT prefixed
        # with "Bearer " (despite RFC 6750). step-cli also sends it raw — see
        # captured request via local mock server.
        headers = {
            "Authorization": self._build_token(audience=url),
            "Accept": "application/json",
        }
        if json_body is not None:
            headers["Content-Type"] = "application/json"

        try:
            resp = self._session.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                json=json_body,
                timeout=self._timeout,
            )
        except requests.RequestException as exc:
            raise StepCAAPIError(f"HTTP request to {url} failed: {exc}") from exc

        if resp.status_code == 204 or not resp.content:
            return {}

        try:
            data = resp.json()
        except ValueError:
            data = {"raw": resp.text}

        if resp.status_code >= 400:
            raise StepCAAPIError(
                f"step-ca API error {resp.status_code} on {method} {path}: "
                f"{data.get('message') or data.get('detail') or data}",
                status_code=resp.status_code,
                payload=data,
            )

        return data

    def _build_token(self, audience):
        """Mint a fresh admin token with the given audience URL."""
        return self._token_builder.build(audience=audience)
