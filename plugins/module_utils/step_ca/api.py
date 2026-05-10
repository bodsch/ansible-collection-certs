# -*- coding: utf-8 -*-
# (c) 2026, Bodo Schulz <bodo@boone-schulz.de>

"""
Thin HTTPS client for the step-ca Admin API.

Wraps a `requests.Session` configured to verify against the local root CA
certificate and to attach the admin JWT as a Bearer token on each request.
The admin JWT is regenerated on every call (it is short-lived and cheap to
sign once the JWK is cached in AdminTokenBuilder).
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
    HTTP client for the step-ca Admin API (`/admin/*`).

    Typical usage:

        client = StepCAClient(
            ca_url="https://localhost:9000",
            ca_root="/opt/step/.step/certs/root_ca.crt",
            ca_config="/opt/step/.step/config/ca.json",
            admin_provisioner="admin",
            admin_subject="step",
            admin_password=b"super-secret",
        )

        provisioners = client.get("/admin/provisioners")["provisioners"]
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
        """ """
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
        return self._request("GET", path, params=params)

    def post(self, path, payload):
        return self._request("POST", path, json_body=payload)

    def put(self, path, payload):
        return self._request("PUT", path, json_body=payload)

    def delete(self, path):
        return self._request("DELETE", path)

    # ----------------------------------------------------------------- private

    def _request(self, method, path, params=None, json_body=None):
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
        return self._token_builder.build(audience=audience)
