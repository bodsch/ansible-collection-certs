#!/usr/bin/python3
# -*- coding: utf-8 -*-

# (c) 2026, Bodo Schulz <bodo@boone-schulz.de>

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import os
from urllib.parse import urlparse

import requests
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.bodsch.certs.plugins.module_utils.step_ca.api import (
    StepCAClient,
)
from ansible_collections.bodsch.certs.plugins.module_utils.step_ca.exceptions import (
    StepCAAPIError,
    StepCAError,
)

DOCUMENTATION = r"""
---
module: step_ca_info
version_added: "1.5.0"
short_description: Read-only facts about a step-ca instance
author:
  - "Bodo Schulz (@bodsch) <bodo@boone-schulz.de>"
description:
  - Gathers facts from a running step-ca instance for use in subsequent tasks.
  - Supports both public endpoints (health, version, roots, provisioners) and
    admin endpoints (admin-side provisioners, admins, authority policy).
  - Public-only invocations do not require C(api.admin_password_file). Admin
    facts can only be requested when the password file is provided.
  - The module never modifies anything on the CA.
options:
  api:
    description: Connection parameters for the step-ca API.
    type: dict
    required: true
    suboptions:
      ca_url:
        description: Base URL of the step-ca instance.
        type: str
        required: true
      ca_root:
        description: Path to the root CA certificate used for TLS verification.
        type: path
        required: true
      admin_provisioner:
        description: JWK admin provisioner name. Only used for admin facts.
        type: str
        default: admin
      admin_subject:
        description: Admin subject. Only used for admin facts.
        type: str
        default: step
      admin_password_file:
        description:
          - Path to the admin provisioner password file.
          - Required if any admin-scope key is requested in I(gather).
        type: path
  gather:
    description:
      - Names of the facts to fetch.
      - Public-scope keys C(health), C(version), C(roots), C(provisioners).
      - Admin-scope keys C(admin_provisioners), C(admins), C(policy).
    type: list
    elements: str
    choices:
      - health
      - version
      - roots
      - provisioners
      - admin_provisioners
      - admins
      - policy
    required: true
notes:
  - Result keys are exactly the names requested via I(gather). Unrequested
    keys are not present in the result.
"""

EXAMPLES = r"""
- name: Quick health + version check (no admin auth)
  bodsch.certs.step_ca_info:
    api:
      ca_url: https://localhost:9000
      ca_root: /opt/step-ca/.step/certs/root_ca.crt
    gather: [health, version]
  register: _ca

- name: Full inventory (admin auth required)
  bodsch.certs.step_ca_info:
    api: "{{ step_ca_admin_connection }}"
    gather:
      - health
      - version
      - roots
      - provisioners
      - admin_provisioners
      - admins
      - policy
  register: _ca

- name: Assert that a specific provisioner exists
  ansible.builtin.assert:
    that:
      - "'acme-dns' in (_ca.admin_provisioners | map(attribute='name') | list)"
"""

RETURN = r"""
health:
  description: Server health status string.
  type: str
  returned: when health was gathered
version:
  description: Server version object as returned by /version.
  type: dict
  returned: when version was gathered
roots:
  description: Root CA certificates in PEM form.
  type: list
  elements: str
  returned: when roots was gathered
provisioners:
  description:
    - Public provisioner list as returned by /provisioners.
    - Includes encrypted JWK material for JWK-type provisioners.
  type: list
  elements: dict
  returned: when provisioners was gathered
admin_provisioners:
  description: Admin-side provisioner list (with policies, details, claims).
  type: list
  elements: dict
  returned: when admin_provisioners was gathered
admins:
  description: Registered admin users.
  type: list
  elements: dict
  returned: when admins was gathered
policy:
  description: Authority-wide policy, or null if none is configured.
  type: dict
  returned: when policy was gathered
"""


_PAGE_LIMIT = 100

# Keys that require admin authentication.
_ADMIN_KEYS = frozenset({"admin_provisioners", "admins", "policy"})


class StepCAInfo:
    """Gather facts from a step-ca instance.

    Two transport paths:
      * Public endpoints — direct requests against ca_url with TLS verify
        against ca_root. No JWT, no provisioner key handling.
      * Admin endpoints — full StepCAClient including the AdminTokenBuilder
        chain (provisioner JWK lookup, ephemeral cert, x5c JWT).
    """

    def __init__(self, module):
        self.module = module
        self.gather = list(
            dict.fromkeys(module.params["gather"] or [])
        )  # dedupe, keep order

        api = module.params["api"]
        self._ca_url = api["ca_url"].rstrip("/")
        self._ca_root = api["ca_root"]
        self._admin_password_file = api.get("admin_password_file")
        self._admin_provisioner_name = api.get("admin_provisioner") or "admin"
        self._admin_subject = api.get("admin_subject") or "step"

        self._validate_inputs()

        # Admin client is built lazily — only when an admin key is gathered.
        self._admin_client = None

    # ------------------------------------------------------------------ public

    def run(self):
        result = dict(changed=False)
        for key in self.gather:
            result[key] = self._fetch(key)
        return result

    # ------------------------------------------------------------- validation

    def _validate_inputs(self):
        host = urlparse(self._ca_url).hostname or ""
        if host in ("0.0.0.0", "::", ""):
            self.module.fail_json(
                msg=f"ca_url '{self._ca_url}' uses a bind address ('{host}'), "
                "not a connect address."
            )

        if not os.path.exists(self._ca_root):
            self.module.fail_json(msg=f"ca_root does not exist: {self._ca_root}")

        admin_keys_requested = set(self.gather) & _ADMIN_KEYS
        if admin_keys_requested and not self._admin_password_file:
            self.module.fail_json(
                msg=f"gather keys {sorted(admin_keys_requested)} require admin "
                "authentication. Set api.admin_password_file."
            )
        if admin_keys_requested and not os.path.exists(self._admin_password_file):
            self.module.fail_json(
                msg=f"Admin password file does not exist: {self._admin_password_file}"
            )

    # --------------------------------------------------------------- dispatch

    def _fetch(self, key):
        try:
            handler = getattr(self, f"_fetch_{key}")
        except AttributeError:
            self.module.fail_json(msg=f"Unsupported gather key: {key!r}")
        return handler()

    # ---------------------------------------------------------- public scope

    def _fetch_health(self):
        data = self._public_get("/health")
        return data.get("status") if isinstance(data, dict) else data

    def _fetch_version(self):
        return self._public_get("/version")

    def _fetch_roots(self):
        """
        /roots returns a list of root CA crts. Some versions wrap them in
        a `crts` key, some return a top-level list. Normalise to PEM list.
        """
        data = self._public_get("/roots")
        items = (
            data
            if isinstance(data, list)
            else (data.get("crts") or data.get("certs") or [])
        )
        out = []
        for item in items:
            if isinstance(item, str):
                out.append(item)
            elif isinstance(item, dict):
                pem = item.get("crt") or item.get("certificate") or item.get("pem")
                if pem:
                    out.append(pem)
        return out

    def _fetch_provisioners(self):
        return list(self._paginate_public("/provisioners", "provisioners"))

    # ----------------------------------------------------------- admin scope

    def _fetch_admin_provisioners(self):
        return list(self._paginate_admin("/admin/provisioners", "provisioners"))

    def _fetch_admins(self):
        # return list(self._paginate_admin("/admin/admins", "admins"))
        admins = list(self._paginate_admin("/admin/admins", "admins"))
        for adm in admins:
            t = adm.get("type")
            if isinstance(t, int):
                adm["type"] = {1: "ADMIN", 2: "SUPER_ADMIN"}.get(t, t)
        return admins

    def _fetch_policy(self):
        try:
            return self._admin().get("/admin/policy")
        except StepCAAPIError as exc:
            if exc.status_code == 404:
                return None
            raise

    # -------------------------------------------------------------- transport

    def _public_get(self, path, params=None):
        url = f"{self._ca_url}{path}"
        try:
            resp = requests.get(url, params=params, verify=self._ca_root, timeout=15)
            resp.raise_for_status()
        except requests.RequestException as exc:
            self.module.fail_json(msg=f"GET {url} failed: {exc}")
        try:
            return resp.json()
        except ValueError:
            return resp.text

    def _paginate_public(self, path, key):
        cursor = ""
        while True:
            params = {"limit": _PAGE_LIMIT}
            if cursor:
                params["cursor"] = cursor
            data = self._public_get(path, params=params)
            for item in self._extract_list(data, key):
                yield item
            cursor = (data.get("nextCursor") if isinstance(data, dict) else "") or ""
            if not cursor:
                break

    def _paginate_admin(self, path, key):
        client = self._admin()
        cursor = ""
        while True:
            params = {"limit": _PAGE_LIMIT}
            if cursor:
                params["cursor"] = cursor
            try:
                data = client.get(path, params=params)
            except StepCAAPIError as exc:
                self.module.fail_json(msg=f"GET {path} failed: {exc}")
            for item in self._extract_list(data, key):
                yield item
            cursor = (data.get("nextCursor") if isinstance(data, dict) else "") or ""
            if not cursor:
                break

    @staticmethod
    def _extract_list(payload, key):
        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            value = payload.get(key)
            if isinstance(value, list):
                return value
        return []

    def _admin(self):
        if self._admin_client is not None:
            return self._admin_client
        with open(self._admin_password_file, "rb") as f:
            password = f.read().rstrip(b"\r\n")
        self._admin_client = StepCAClient(
            ca_url=self._ca_url,
            ca_root=self._ca_root,
            admin_provisioner=self._admin_provisioner_name,
            admin_subject=self._admin_subject,
            admin_password=password,
        )
        return self._admin_client


def main():
    module = AnsibleModule(
        argument_spec=dict(
            api=dict(
                type="dict",
                required=True,
                options=dict(
                    ca_url=dict(type="str", required=True),
                    ca_root=dict(type="path", required=True),
                    admin_provisioner=dict(type="str", default="admin"),
                    admin_subject=dict(type="str", default="step"),
                    admin_password_file=dict(type="path", no_log=True),
                ),
            ),
            gather=dict(
                type="list",
                elements="str",
                required=True,
                choices=[
                    "health",
                    "version",
                    "roots",
                    "provisioners",
                    "admin_provisioners",
                    "admins",
                    "policy",
                ],
            ),
        ),
        supports_check_mode=True,
    )

    try:
        result = StepCAInfo(module).run()
    except StepCAError as exc:
        module.fail_json(msg=str(exc))
    except Exception as exc:  # noqa: BLE001
        module.fail_json(msg=f"Unhandled error: {exc}")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
