#!/usr/bin/python3
# -*- coding: utf-8 -*-

# (c) 2026, Bodo Schulz <bodo@boone-schulz.de>

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json
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
module: step_ca_policy
version_added: "1.3.0"
short_description: Manage X.509 / SSH issuance policies on step-ca
author:
  - "Bodo Schulz (@bodsch) <bodo@boone-schulz.de>"
description:
  - Manages issuance policies on a running step-ca instance.
  - Policies restrict which subject identifiers (DNS names, IPs, emails, URIs,
    Common Names, principals) a CA or provisioner may sign.
  - Policies can be applied at two scopes:
      C(authority) — the CA-wide default that applies to every provisioner
      that does not carry its own policy;
      C(provisioner) — overrides the authority-wide default for one provisioner.
  - Per-account ACME policies (Certificate Manager only) are not supported.
  - Communicates exclusively over the step-ca Admin HTTPS API.
options:
  state:
    description:
      - C(present) ensures the policy matches the C(policy) parameter.
      - C(absent) removes the policy entirely. The CA or provisioner then
        falls back to its respective default (no restriction at authority
        level, authority policy at provisioner level).
    type: str
    choices: [present, absent]
    default: present
  scope:
    description: Which policy to manage.
    type: str
    choices: [authority, provisioner]
    required: true
  provisioner:
    description: Provisioner name. Required when C(scope=provisioner).
    type: str
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
  policy:
    description:
      - The policy specification. Required when C(state=present).
      - Top-level keys are C(x509) and C(ssh). The schema mirrors step-ca's
        policy format with snake_case top-level keys translated to the
        protojson camelCase wire format internally.
      - Within C(x509.allow) / C(x509.deny) the recognised sublists are
        C(dns), C(ips), C(emails), C(uris), C(common_names), C(principals).
      - C(x509.allow_wildcard_names) is a separate boolean.
      - Within C(ssh.host.allow|deny) and C(ssh.user.allow|deny) the
        sublists are C(dns), C(ips), C(emails), C(principals) — applicable
        ones depend on the ssh certificate type.
      - Empty / unset lists are equivalent to "no rule of that kind".
    type: dict
notes:
  - Per-provisioner policies are stored inside the provisioner object on
    the server. Setting them via this module updates the provisioner
    record. Do not use the deprecated C(policy) pass-through of the
    C(step_ca_provisioner) module in the same role; this module is the
    canonical place.
"""

EXAMPLES = r"""
- name: CA-wide default — only allow lab DNS names and the lab subnet
  bodsch.certs.step_ca_policy:
    scope: authority
    state: present
    policy:
      x509:
        allow:
          dns: ["*.lab.local", "lab.local"]
          ips: ["10.42.0.0/16"]
        allow_wildcard_names: true
    api: "{{ step_ca_admin_connection }}"

- name: Tighter scope for the dns-only provisioner
  bodsch.certs.step_ca_policy:
    scope: provisioner
    provisioner: acme-dns
    state: present
    policy:
      x509:
        allow:
          dns: ["*.svc.lab.local"]
        deny:
          dns: ["admin.svc.lab.local"]
    api: "{{ step_ca_admin_connection }}"

- name: Drop the authority-wide policy (back to "no restriction")
  bodsch.certs.step_ca_policy:
    scope: authority
    state: absent
    api: "{{ step_ca_admin_connection }}"

- name: Drop policy on a specific provisioner (falls back to authority policy)
  bodsch.certs.step_ca_policy:
    scope: provisioner
    provisioner: acme-dns
    state: absent
    api: "{{ step_ca_admin_connection }}"
"""

RETURN = r"""
changed:
  description: True if the policy was created, updated or removed.
  type: bool
  returned: always
policy:
  description: The policy object as it stands on the server after the operation
    (in the protojson wire format — camelCase keys).
  type: dict
  returned: when state=present
"""


# --------------------------------------------------------------- translation

# x509 allow/deny block
_X509_KEY_MAP = {
    "dns": "dns",
    "ips": "ips",
    "emails": "emails",
    "uris": "uris",
    "common_names": "commonNames",
    "principals": "principals",
}

# ssh allow/deny block (intersection of host/user; per-type filtering happens
# on step-ca's side — invalid combos like ssh.user.dns are simply ignored)
_SSH_KEY_MAP = {
    "dns": "dns",
    "ips": "ips",
    "emails": "emails",
    "principals": "principals",
}


def _translate_block(block, key_map):
    """Translate one allow/deny block from snake_case to protojson camelCase."""
    out = {}
    for src, dst in key_map.items():
        value = block.get(src)
        if value:  # drops None, [], ""
            out[dst] = list(value)
    return out


def _translate_x509(x509):
    out = {}
    for direction in ("allow", "deny"):
        block = x509.get(direction)
        if block:
            translated = _translate_block(block, _X509_KEY_MAP)
            if translated:
                out[direction] = translated
    if "allow_wildcard_names" in x509 and x509["allow_wildcard_names"] is not None:
        out["allowWildcardNames"] = bool(x509["allow_wildcard_names"])
    return out


def _translate_ssh(ssh):
    out = {}
    for cert_type in ("host", "user"):
        cert_block = ssh.get(cert_type)
        if not cert_block:
            continue
        translated_cert = {}
        for direction in ("allow", "deny"):
            inner = cert_block.get(direction)
            if inner:
                translated_inner = _translate_block(inner, _SSH_KEY_MAP)
                if translated_inner:
                    translated_cert[direction] = translated_inner
        if translated_cert:
            out[cert_type] = translated_cert
    return out


def translate_policy(user_policy):
    """Translate the user-facing snake_case policy dict to step-ca's wire format."""
    out = {}
    if not user_policy:
        return out

    x509 = user_policy.get("x509")
    if x509:
        translated = _translate_x509(x509)
        if translated:
            out["x509"] = translated

    ssh = user_policy.get("ssh")
    if ssh:
        translated = _translate_ssh(ssh)
        if translated:
            out["ssh"] = translated

    return out


# --------------------------------------------------------------- comparison


def _normalize_for_compare(value):
    """
    Drop fields that protojson would also omit (False, "", 0, [], {}).

    Sort string lists for order-insensitive comparison — DNS/IP/email lists
    are semantically sets, so step-ca may return them in different order
    after persisting.
    """
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            nv = _normalize_for_compare(v)
            if nv in (None, False, "", 0):
                continue
            if isinstance(nv, (list, dict)) and len(nv) == 0:
                continue
            out[k] = nv
        return out
    if isinstance(value, list):
        normalized = [_normalize_for_compare(x) for x in value]
        try:
            return sorted(normalized)
        except TypeError:
            return normalized
    return value


def policies_equal(a, b):
    return _normalize_for_compare(a) == _normalize_for_compare(b)


# ---------------------------------------------------------------- main class


class StepCAPolicy:
    """Manage authority-wide or provisioner-scoped issuance policies."""

    def __init__(self, module):
        self.module = module
        # self.module.log("StepCAPolicy::__init__()")

        self.scope = module.params["scope"]
        self.state = module.params["state"]
        self.provisioner = module.params.get("provisioner")
        self.policy_input = module.params.get("policy") or {}

        if self.scope == "provisioner":
            self.module.fail_json(
                msg="Per-provisioner policies are not supported in standalone "
                "step-ca (the API responds with 'disabled in standalone'). "
                "Only authority-wide policies are available — use scope=authority."
            )

        if self.state == "present" and not self.policy_input:
            module.fail_json(msg="parameter 'policy' is required when state=present")

        self.client = self._build_client(module.params["api"])

    def run(self):
        """ """
        # self.module.log("StepCAPolicy::run()")

        if self.scope == "authority":
            return self._run_authority()
        return self._run_provisioner()

    # -------------------------------------------------------- authority scope

    def _run_authority(self):
        """ """
        # self.module.log("StepCAPolicy::_run_authority()")

        existing = self._get_authority_policy()
        desired = (
            translate_policy(self.policy_input) if self.state == "present" else None
        )

        if self.state == "absent":
            if existing is None:
                return dict(changed=False)
            if self.module.check_mode:
                return dict(changed=True)
            self.client.delete("/admin/policy")  # <-- war /admin/authority/policy
            return dict(changed=True)

        if existing is not None and policies_equal(existing, desired):
            return dict(changed=False, policy=existing)

        if self.module.check_mode:
            return dict(changed=True, policy=desired)

        if existing is None:
            result = self.client.post("/admin/policy", desired)  # <-- /admin/policy
        else:
            result = self.client.put("/admin/policy", desired)  # <-- /admin/policy
        return dict(changed=True, policy=result or desired)

    def _get_authority_policy(self):
        """ """
        # self.module.log("StepCAPolicy::_get_authority_policy()")

        try:
            data = self.client.get("/admin/policy")  # <-- /admin/policy
        except StepCAAPIError as exc:
            if exc.status_code == 404:
                return None
            raise
        if isinstance(data, dict) and set(data.keys()) <= {"x509", "ssh"}:
            return data if data else None
        for key in ("policy", "authorityPolicy"):
            if isinstance(data.get(key), dict):
                return data[key]
        return data or None

    # ----------------------------------------------------- provisioner scope

    def _run_provisioner(self):
        """ """
        # self.module.log("StepCAPolicy::_run_provisioner()")

        existing_prov = self._get_provisioner()
        if existing_prov is None:
            self.module.fail_json(
                msg=f"Provisioner '{self.provisioner}' does not exist"
            )

        existing_policy = existing_prov.get("policy")

        if self.state == "absent":
            if not existing_policy:
                return dict(changed=False)
            if self.module.check_mode:
                return dict(changed=True)
            merged = dict(existing_prov)
            merged.pop("policy", None)

            self.client.put(f"/admin/provisioners/{self.provisioner}", merged)
            return dict(changed=True)

        desired = translate_policy(self.policy_input)
        if existing_policy and policies_equal(existing_policy, desired):
            return dict(changed=False, policy=existing_policy)

        if self.module.check_mode:
            return dict(changed=True, policy=desired)

        merged = dict(existing_prov)
        merged["policy"] = desired

        result = self.client.put(f"/admin/provisioners/{self.provisioner}", merged)
        return dict(changed=True, policy=(result or {}).get("policy", desired))

    def _get_provisioner(self):
        """ """
        # self.module.log("StepCAPolicy::_get_provisioner()")

        try:
            return self.client.get(f"/admin/provisioners/{self.provisioner}")
        except StepCAAPIError as exc:
            if exc.status_code == 404:
                return None
            raise

    # ------------------------------------------------------------- api setup

    def _build_client(self, api_params):
        """ """
        self.module.log(f"StepCAPolicy::_build_client(api_params: {api_params})")

        ca_url = api_params["ca_url"]
        host = urlparse(ca_url).hostname or ""
        if host in ("0.0.0.0", "::", ""):
            self.module.fail_json(
                msg=f"ca_url '{ca_url}' uses a bind address ('{host}'), not a "
                "connect address. Use a hostname listed in the CA's DNS SANs."
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
    module = AnsibleModule(
        argument_spec=dict(
            state=dict(type="str", choices=["present", "absent"], default="present"),
            scope=dict(
                type="str", choices=["authority"], default="authority", required=False
            ),
            provisioner=dict(type="str"),
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
            policy=dict(type="dict"),
        ),
        supports_check_mode=True,
        required_if=[
            ("scope", "provisioner", ["provisioner"]),
            ("state", "present", ["policy"]),
        ],
    )

    try:
        result = StepCAPolicy(module).run()
    except StepCAError as exc:
        module.fail_json(msg=str(exc))
    except Exception as exc:  # noqa: BLE001
        module.fail_json(msg=f"Unhandled error: {exc}")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
