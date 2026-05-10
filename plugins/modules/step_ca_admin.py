#!/usr/bin/python3
# -*- coding: utf-8 -*-

# (c) 2026, Bodo Schulz <bodo@boone-schulz.de>

"""
Idempotent management of step-ca admin users via the Admin API.

step-ca's ``/admin/admins`` endpoint accepts the provisioner name on
``POST`` but reports membership via ``provisioner_id`` (UUID) on ``GET``.
This module bridges the two by resolving the name to its UUID once per
invocation and using that UUID as the idempotency match criterion.

Field-name oddity: the linkedca enum ``Admin_Type`` is serialised as an
integer on this endpoint (``ADMIN=1``, ``SUPER_ADMIN=2``), unlike the
provisioner endpoints which use protojson and accept enum strings. The
module exposes a string-based interface and translates internally.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import os
from urllib.parse import urlparse

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
module: step_ca_admin
version_added: "1.2.0"
short_description: Manage step-ca admin users via the Admin API
author:
  - "Bodo Schulz (@bodsch) <bodo@boone-schulz.de>"

description:
  - Creates, updates and removes admin users on a running step-ca instance.
  - Identifies an admin by the tuple C((subject, provisioner)). step-ca
    allows multiple admins with the same subject as long as they belong
    to different provisioners — this module mirrors that semantics.
  - The admin's role can be changed in place via PATCH; the link to a
    provisioner is fixed at creation time.
  - Communicates exclusively over the step-ca Admin HTTPS API.
options:
  state:
    description: Desired state of the admin.
    type: str
    choices: [present, absent]
    default: present
  api:
    description: Connection parameters for the step-ca Admin API.
    type: dict
    required: true
    suboptions:
      ca_url:
        type: str
        required: true
      ca_root:
        type: path
        required: true
      admin_provisioner:
        type: str
        default: admin
      admin_subject:
        type: str
        default: step
      admin_password_file:
        type: path
        required: true
  subject:
    description: Subject (username) of the admin.
    type: str
    required: true
  provisioner:
    description:
      - Name of the provisioner the admin is linked to.
      - Required when C(state=present). For C(state=absent) it disambiguates
        between admins with identical subjects on different provisioners.
    type: str
  type:
    description:
      - Admin role.
      - C(SUPER_ADMIN) can manage other admins; C(ADMIN) cannot.
    type: str
    choices: [ADMIN, SUPER_ADMIN]
    default: ADMIN
notes:
  - Removing the last C(SUPER_ADMIN) is rejected by step-ca itself.
  - Removing the admin used by this module's own connection (the
    C(api.admin_subject)) is allowed but will lock you out — the next
    Ansible run will fail to authenticate. Take care.
"""

EXAMPLES = r"""
- name: Ensure a regular admin exists
  bodsch.certs.step_ca_admin:
    state: present
    subject: alice@example.com
    provisioner: admin
    type: ADMIN
    api: "{{ step_ca_admin_connection }}"

- name: Promote alice to super-admin (PATCH role)
  bodsch.certs.step_ca_admin:
    state: present
    subject: alice@example.com
    provisioner: admin
    type: SUPER_ADMIN
    api: "{{ step_ca_admin_connection }}"

- name: Remove the legacy admin
  bodsch.certs.step_ca_admin:
    state: absent
    subject: legacy@example.com
    provisioner: admin
    api: "{{ step_ca_admin_connection }}"
"""

RETURN = r"""
changed:
  description: True if the admin was created, updated or removed.
  type: bool
  returned: always
admin:
  description: The admin object as returned by the server.
  type: dict
  returned: when state=present
"""


#: Page size used when paginating ``/admin/admins``.
_PAGE_LIMIT = 100

#: Module-facing string ↔ wire-format integer for ``linkedca.Admin_Type``.
_ADMIN_TYPE_TO_INT = {
    "ADMIN": 1,
    "SUPER_ADMIN": 2,
}

_ADMIN_TYPE_FROM_INT = {v: k for k, v in _ADMIN_TYPE_TO_INT.items()}


def _normalize_admin_type(value):
    """
    Normalise a server-supplied admin type to its string name.

    step-ca currently returns the enum integer (e.g. ``1``), but
    different versions or response formats might return the string.
    Both are folded to the canonical string ``"ADMIN"`` /
    ``"SUPER_ADMIN"`` for comparison; an unknown integer or empty
    value collapses to the empty string.
    """
    if isinstance(value, int):
        return _ADMIN_TYPE_FROM_INT.get(value, "")
    if isinstance(value, str):
        return value.upper()
    return ""


class StepCAAdmin:
    """
    Idempotent management of step-ca admin users.

    The /admin/admins endpoint:
      * GET  /admin/admins                  — paginated list
      * GET  /admin/admins/{id}             — by server-internal UUID
      * POST /admin/admins                  — create
      * PATCH /admin/admins/{id}            — update (only `type` is mutable)
      * DELETE /admin/admins/{id}           — remove

    There is no "get by subject" endpoint, so we list and filter client-side.

    Identity model
        An admin is identified by ``(subject, provisioner)``. Provisioner
        is given by name on input but compared by UUID, since the list
        endpoint reports admins under ``provisioner_id``. The mapping
        name → UUID is fetched on demand and cached on the instance.

    Mutable fields
        Only ``type`` (the role). Changing the provisioner of an existing
        admin is not supported — that would require delete + recreate
        which the module declines to perform implicitly.
    """

    def __init__(self, module):
        """
        :param module: The :class:`AnsibleModule` instance.
        """
        self.module = module
        # self.module.log("StepCAAdmin::__init__()")

        self.state = module.params["state"]
        self.subject = module.params["subject"]
        self.provisioner = module.params.get("provisioner")
        self.type = module.params["type"]

        if self.state == "present" and not self.provisioner:
            module.fail_json(
                msg="parameter 'provisioner' is required when state=present"
            )

        self.client = self._build_client(module.params["api"])
        self._provisioner_id = None  # resolved on demand

    def run(self):
        """
        Locate a matching admin and apply the requested state.

        :returns: Result dict suitable for ``module.exit_json``.
        """
        # self.module.log("StepCAAdmin::run()")

        existing = self._find_existing()
        if self.state == "absent":
            return self._ensure_absent(existing)
        return self._ensure_present(existing)

    # ------------------------------------------------------------------ logic

    def _ensure_present(self, existing):
        """
        Create the admin if missing, PATCH its role if mismatched, no-op
        if already in the desired state.

        :param existing: Either ``None`` or the matched admin dict from
            :meth:`_find_existing`.
        :returns: Dict with ``changed`` and ``admin``.
        """
        # self.module.log(f"StepCAAdmin::_ensure_present(existing: {existing})")
        type_int = _ADMIN_TYPE_TO_INT[self.type]

        if existing is None:
            payload = {
                "subject": self.subject,
                "provisioner": self.provisioner,
                "type": type_int,
            }
            if self.module.check_mode:
                return dict(changed=True, admin=payload)
            try:
                created = self.client.post("/admin/admins", payload)
            except StepCAAPIError as exc:
                self.module.fail_json(msg=f"Failed to create admin: {exc}")
            return dict(changed=True, admin=created)

        if _normalize_admin_type(existing.get("type")) == self.type:
            return dict(changed=False, admin=existing)

        if self.module.check_mode:
            merged = dict(existing)
            merged["type"] = self.type
            return dict(changed=True, admin=merged)

        admin_id = existing.get("id")
        if not admin_id:
            self.module.fail_json(
                msg=f"Cannot update admin: server response missing 'id' ({existing!r})"
            )

        try:
            updated = self.client.patch(
                f"/admin/admins/{admin_id}",
                {"type": type_int},
            )
        except StepCAAPIError as exc:
            self.module.fail_json(msg=f"Failed to update admin role: {exc}")
        return dict(changed=True, admin=updated)

    def _ensure_absent(self, existing):
        """
        Remove the admin if it exists, no-op otherwise.

        :param existing: Either ``None`` or the matched admin dict.
        :returns: Dict with ``changed``.
        """
        # self.module.log(f"StepCAAdmin::_ensure_absent(existing: {existing})")

        if existing is None:
            return dict(changed=False)

        if self.module.check_mode:
            return dict(changed=True)

        admin_id = existing.get("id")
        if not admin_id:
            self.module.fail_json(
                msg=f"Cannot delete admin: server response missing 'id' ({existing!r})"
            )

        try:
            self.client.delete(f"/admin/admins/{admin_id}")
        except StepCAAPIError as exc:
            self.module.fail_json(msg=f"Failed to delete admin: {exc}")
        return dict(changed=True)

    # --------------------------------------------------------------- discover

    def _find_existing(self):
        """
        Return the unique existing admin matching subject (and, if
        :attr:`provisioner` is set, the resolved provisioner UUID), or
        ``None``.

        Multiple matches without a provisioner constraint is treated as
        a hard error — the module refuses to guess.

        Both ``provisionerId`` (camelCase, protojson) and
        ``provisioner_id`` (snake_case, gojson) are accepted on inbound
        records since step-ca's responses are inconsistent across
        endpoints.
        """
        # self.module.log("StepCAAdmin::_find_existing()")

        target_prov_id = self._resolve_provisioner_id()

        matches = []
        cursor = ""
        while True:
            params = {"limit": _PAGE_LIMIT}
            if cursor:
                params["cursor"] = cursor
            try:
                data = self.client.get("/admin/admins", params=params)
            except StepCAAPIError as exc:
                self.module.fail_json(msg=f"Failed to list admins: {exc}")

            for adm in self._extract_list(data):
                if adm.get("subject") != self.subject:
                    continue

                adm_prov_id = adm.get("provisionerId") or adm.get("provisioner_id")
                if target_prov_id is None or adm_prov_id == target_prov_id:
                    matches.append(adm)

            cursor = data.get("nextCursor") or ""
            if not cursor:
                break

        if len(matches) > 1:
            self.module.fail_json(
                msg=f"Ambiguous: {len(matches)} admins match subject="
                f"'{self.subject}'. Specify 'provisioner' to disambiguate."
            )

        return matches[0] if matches else None

    @staticmethod
    def _extract_list(payload):
        """
        Unwrap a list response that may be either a bare list or a dict
        wrapping the list under ``admins`` or ``data``.
        """
        if isinstance(payload, list):
            return payload
        for key in ("admins", "data"):
            if isinstance(payload.get(key), list):
                return payload[key]
        return []

    def _resolve_provisioner_id(self):
        """
        Resolve the provisioner *name* to its server-side UUID.

        The /admin/admins responses link admins via `provisionerId` (UUID),
        while the create payload accepts the provisioner *name* — we therefore
        have to translate one to the other for idempotent matching.

        The lookup hits ``/admin/provisioners/{name}`` exactly once per
        module run; the result is cached on the instance.
        """
        # self.module.log("StepCAAdmin::_resolve_provisioner_id()")

        if self._provisioner_id is not None:
            return self._provisioner_id
        if not self.provisioner:
            return None
        try:
            prov = self.client.get(f"/admin/provisioners/{self.provisioner}")
        except StepCAAPIError as exc:
            if exc.status_code == 404:
                self.module.fail_json(
                    msg=f"Provisioner '{self.provisioner}' does not exist"
                )
            raise
        pid = prov.get("id")
        if not pid:
            self.module.fail_json(
                msg=f"Provisioner '{self.provisioner}' response missing 'id'"
            )
        self._provisioner_id = pid
        return pid

    # ------------------------------------------------------------- api setup

    def _build_client(self, api_params):
        """
        Construct a :class:`StepCAClient` from the module's I(api) dict.

        Validates the URL and password file before any network I/O so
        configuration mistakes surface as clean fail_json messages
        rather than mid-flow stack traces.
        """
        # self.module.log(f"StepCAAdmin::_build_client(api_params: {api_params})")

        ca_url = api_params["ca_url"]
        host = urlparse(ca_url).hostname or ""
        if host in ("0.0.0.0", "::", ""):
            self.module.fail_json(
                msg=f"ca_url '{ca_url}' uses a bind address ('{host}'), not a "
                "connect address."
            )

        password_file = api_params["admin_password_file"]
        if not os.path.exists(password_file):
            self.module.fail_json(
                msg=f"Admin password file does not exist: {password_file}"
            )
        with open(password_file, "rb") as f:
            password = f.read().rstrip(b"\r\n")

        return StepCAClient(
            ca_url=ca_url,
            ca_root=api_params["ca_root"],
            admin_provisioner=api_params.get("admin_provisioner", "admin"),
            admin_subject=api_params.get("admin_subject", "step"),
            admin_password=password,
        )


def main():
    """Module entry point. Wires :class:`AnsibleModule` to :class:`StepCAAdmin`."""
    module = AnsibleModule(
        argument_spec=dict(
            state=dict(type="str", choices=["present", "absent"], default="present"),
            api=dict(
                type="dict",
                required=True,
                options=dict(
                    ca_url=dict(type="str", required=True),
                    ca_root=dict(type="path", required=True),
                    admin_provisioner=dict(type="str", default="admin"),
                    admin_subject=dict(type="str", default="step"),
                    admin_password_file=dict(type="path", required=True, no_log=True),
                ),
            ),
            subject=dict(type="str", required=True),
            provisioner=dict(type="str"),
            type=dict(type="str", choices=["ADMIN", "SUPER_ADMIN"], default="ADMIN"),
        ),
        supports_check_mode=True,
        required_if=[
            ("state", "present", ["provisioner"]),
        ],
    )

    try:
        result = StepCAAdmin(module).run()
    except StepCAError as exc:
        module.fail_json(msg=str(exc))
    except Exception as exc:  # noqa: BLE001
        module.fail_json(msg=f"Unhandled error: {exc}")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
