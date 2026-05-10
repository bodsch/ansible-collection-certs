#!/usr/bin/python3
# -*- coding: utf-8 -*-

# (c) 2026, Bodo Schulz <bodo@boone-schulz.de>

"""
Idempotent management of step-ca's authority-wide issuance policy.

Per-provisioner and per-ACME-account policies are listed in step-ca's
proto schema but their endpoints respond with "disabled in standalone"
on open-source step-ca — they require Smallstep Certificate Manager.
This module therefore restricts itself to authority scope.

The user-facing schema uses snake_case top-level keys (closer to
Ansible conventions); the module translates them to the camelCase
shape step-ca's protojson handlers expect on the wire.
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
module: step_ca_policy
version_added: "1.2.0"
short_description: Manage the authority-wide X.509 / SSH issuance policy on step-ca
author:
  - "Bodo Schulz (@bodsch) <bodo@boone-schulz.de>"
description:
  - Manages the authority-wide issuance policy on a running step-ca instance.
  - Policies restrict which subject identifiers (DNS names, IPs, emails, URIs,
    Common Names, principals) the CA may sign.
  - Per-provisioner and per-ACME-account policies are gated behind Smallstep
    Certificate Manager (the corresponding endpoints respond with
    "disabled in standalone" on open-source step-ca) and are therefore
    not exposed by this module.
  - Communicates exclusively over the step-ca Admin HTTPS API.
options:
  state:
    description:
      - C(present) ensures the authority policy matches the C(policy)
        parameter.
      - C(absent) removes the authority policy entirely; the CA falls
        back to "no restriction".
    type: str
    choices: [present, absent]
    default: present
  scope:
    description:
      - Scope of the policy. Currently fixed to C(authority); included
        for forward compatibility with future Certificate-Manager-only
        scopes.
    type: str
    choices: [authority]
    default: authority
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
  - step-ca rejects a policy update that would lock out the admin
    subject this module is using to authenticate (default C(step)).
    Make sure the admin subject is in C(x509.allow.dns) when shipping
    a restrictive policy.
"""

EXAMPLES = r"""
- name: CA-wide default — only allow lab DNS names and the lab subnet
  bodsch.certs.step_ca_policy:
    scope: authority
    state: present
    policy:
      x509:
        allow:
          # Include the admin subject ('step') here to avoid the lock-out check.
          dns: ["*.lab.local", "lab.local", "step"]
          ips: ["10.42.0.0/16"]
        allow_wildcard_names: true
    api: "{{ step_ca_admin_connection }}"

- name: Drop the authority-wide policy (back to "no restriction")
  bodsch.certs.step_ca_policy:
    scope: authority
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

#: Snake_case key → camelCase wire-format key for x509 allow/deny blocks.
_X509_KEY_MAP = {
    "dns": "dns",
    "ips": "ips",
    "emails": "emails",
    "uris": "uris",
    "common_names": "commonNames",
    "principals": "principals",
}

#: Snake_case key → camelCase wire-format key for ssh allow/deny blocks.
#: Per-type filtering happens on step-ca's side — invalid combos like
#: ``ssh.user.dns`` are simply ignored by the server.
_SSH_KEY_MAP = {
    "dns": "dns",
    "ips": "ips",
    "emails": "emails",
    "principals": "principals",
}


def _translate_block(block, key_map):
    """
    Translate one allow/deny block from snake_case to protojson camelCase.

    Empty values (``None``, ``[]``, ``""``) are dropped — they would be
    semantically equivalent to "no rule" and step-ca prefers them absent
    so that idempotent comparison against the server's response works.
    """
    out = {}
    for src, dst in key_map.items():
        value = block.get(src)
        if value:  # drops None, [], ""
            out[dst] = list(value)
    return out


def _translate_x509(x509):
    """Translate the user's ``x509`` policy block to wire format."""
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
    """Translate the user's ``ssh`` policy block to wire format."""
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
    """
    Translate the user-facing snake_case policy dict to step-ca's wire format.

    :param user_policy: Dict as supplied by the module user. May be
        ``None`` or empty, in which case an empty dict is returned.
    :returns: Dict in the protojson wire shape, ready to be POST/PUT.
    """
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
    """
    Compare two policies for semantic equality.

    Differences in default-value omission and unsorted lists do not
    register as a change — see :func:`_normalize_for_compare`.
    """
    return _normalize_for_compare(a) == _normalize_for_compare(b)


# ---------------------------------------------------------------- main class


class StepCAPolicy:
    """
    Manage the authority-wide issuance policy on step-ca.

    Operates on the ``/admin/policy`` endpoint:

      * ``GET /admin/policy``    — current policy or 404.
      * ``POST /admin/policy``   — create when none exists.
      * ``PUT /admin/policy``    — update.
      * ``DELETE /admin/policy`` — remove.

    Provisioner-scope code paths exist below in :meth:`_run_provisioner` /
    :meth:`_get_provisioner` but are unreachable in the current
    implementation — :meth:`__init__` rejects ``scope=provisioner``
    outright because the corresponding step-ca endpoint is gated behind
    Certificate Manager. They are kept for the day this collection
    grows hosted-mode support.

    Lock-out protection
        step-ca refuses a policy update that would exclude the admin
        subject this module authenticates as (default ``step``). The
        rejection comes back as a 4xx — there is no in-module check, we
        rely on the server's safety net.
    """

    def __init__(self, module):
        """
        :param module: The :class:`AnsibleModule` instance.

        Rejects ``scope=provisioner`` early with a clear message,
        before any network I/O. (The argument spec already restricts
        the choice to ``authority``, but the check stays for the day
        the choice list is widened.)
        """
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
        """
        Dispatch to the scope-appropriate handler.

        Currently always lands in :meth:`_run_authority` since the
        :meth:`__init__` guard rejects any other scope.
        """
        # self.module.log("StepCAPolicy::run()")

        if self.scope == "authority":
            return self._run_authority()
        return self._run_provisioner()

    # -------------------------------------------------------- authority scope

    def _run_authority(self):
        """
        Reconcile the authority-wide policy.

        Flow:
          * If state=absent: DELETE if a policy exists, else no-op.
          * If state=present: GET the current policy, compare against the
            translated user input, then POST (create) or PUT (update)
            only if they differ.
        """
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
            self.client.delete("/admin/policy")
            return dict(changed=True)

        if existing is not None and policies_equal(existing, desired):
            return dict(changed=False, policy=existing)

        if self.module.check_mode:
            return dict(changed=True, policy=desired)

        if existing is None:
            result = self.client.post("/admin/policy", desired)
        else:
            result = self.client.put("/admin/policy", desired)
        return dict(changed=True, policy=result or desired)

    def _get_authority_policy(self):
        """
        Fetch the current authority policy or return ``None``.

        Tolerates two response shapes step-ca has been seen to use:
        a bare policy dict (top-level ``x509`` / ``ssh`` keys) and a
        wrapped form (``policy`` or ``authorityPolicy`` envelope).
        404 is treated as "no policy configured".
        """
        # self.module.log("StepCAPolicy::_get_authority_policy()")

        try:
            data = self.client.get("/admin/policy")
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
    #
    # The methods below are currently unreachable — :meth:`__init__` rejects
    # ``scope=provisioner`` because the underlying step-ca endpoint is gated
    # behind Certificate Manager. Kept for the day this collection grows
    # hosted-mode support.

    def _run_provisioner(self):
        """
        Reconcile a per-provisioner policy by GET-then-PUT'ing the whole
        provisioner record with the policy field replaced.

        **Currently unreachable** — see class docstring.
        """
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
        """
        Fetch a provisioner's full record by name, or return ``None``
        on 404.

        **Currently unreachable** — see class docstring.
        """
        # self.module.log("StepCAPolicy::_get_provisioner()")

        try:
            return self.client.get(f"/admin/provisioners/{self.provisioner}")
        except StepCAAPIError as exc:
            if exc.status_code == 404:
                return None
            raise

    # ------------------------------------------------------------- api setup

    def _build_client(self, api_params):
        """
        Construct a :class:`StepCAClient` from the I(api) sub-options.

        Validates the URL and password file before any network I/O so
        config mistakes surface as clean fail_json messages rather than
        mid-flow stack traces.
        """
        # self.module.log(f"StepCAPolicy::_build_client(api_params: {api_params})")

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
    """Module entry point. Wires :class:`AnsibleModule` to :class:`StepCAPolicy`."""
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
