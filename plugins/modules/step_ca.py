#!/usr/bin/python3
# -*- coding: utf-8 -*-

# (c) 2022-2026, Bodo Schulz <bodo@boone-schulz.de>

"""
Bootstrap module for a local smallstep step-ca authority.

Scope:
    * One-time bootstrap of the CA PKI via step-cli (step ca init).
    * Idempotent updates to authority claims in ca.json.

Out of scope (use dedicated modules):
    * Provisioner management              -> bodsch.certs.step_ca_provisioner
    * Admin user management               -> bodsch.certs.step_ca_admin
    * x509/ssh policies                   -> bodsch.certs.step_ca_policy

Rationale:
    The CA PKI cannot be created via the Admin API because the API only
    exists once step-ca is running. Therefore the bootstrap step still
    shells out to step-cli. Everything that happens at runtime (provisioner
    CRUD, policies, EAB keys) is handled via dedicated API-based modules.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json
import os
import shutil

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.bodsch.core.plugins.module_utils.checksum import Checksum

DOCUMENTATION = r"""
---
module: step_ca
version_added: "1.0.0"
short_description: Bootstrap a local smallstep step-ca authority
author:
  - "Bodo Schulz (@bodsch) <bodo@boone-schulz.de>"
description:
  - Initializes a standalone step-ca PKI under the given home directory using C(step-cli).
  - Optionally updates the C(authority.claims) section of C(ca.json) idempotently.
  - Provisioner management has been removed from this module — use C(step_ca_provisioner) instead.
requirements:
  - step-cli
  - step-ca
options:
  state:
    description: Desired state.
    type: str
    choices: [init]
    default: init
  force:
    description:
      - If C(true), wipe the existing C(.step) directory under I(home) before initializing.
      - Destroys all CA keys and configuration. Use with care.
    type: bool
    default: false
  home:
    description: Base directory for the CA runtime environment. C(.step) is created below it.
    type: path
    required: true
  name:
    description: Human-readable name of the new PKI. Required for first-time init.
    type: str
  listen:
    description: Address/port the CA listens on. Written into C(ca.json) by step-cli.
    type: dict
    default: {address: "127.0.0.1", port: 9000}
    suboptions:
      address:
        description: Bind address.
        type: str
        default: "127.0.0.1"
      port:
        description: TCP port.
        type: int
        default: 9000
  password_file:
    description:
      - Filename (relative to I(home)) holding the password used to encrypt the
        root, intermediate and provisioner keys. Used both as C(--password-file)
        and C(--provisioner-password-file).
    type: str
    default: password
  dns:
    description: DNS names / IP addresses for the CA endpoint, passed as C(--dns).
    type: list
    elements: str
    default: []
  admin_subject:
    description:
      - Subject used by step-ca for the bootstrap super-admin (C(--admin-subject)).
      - Persisting this value is important — the Admin API uses it as the C(sub) claim
        when generating admin tokens. The downstream API modules need to know it.
    type: str
    default: step
  admin_provisioner:
    description: Name of the JWK admin provisioner created during init (C(--provisioner)).
    type: str
    default: admin
  config:
    description:
      - Authority claims to merge into C(authority.claims) in C(ca.json).
      - Differences against the existing claims trigger a file rewrite (changed=true).
    type: dict
    default: {}
notes:
  - This module does not support check mode.
  - Provisioner management is no longer handled here. Use the C(step_ca_provisioner) module.
"""

EXAMPLES = r"""
- name: Bootstrap a local CA
  bodsch.certs.step_ca:
    state: init
    home: /opt/step
    name: "Local Lab CA"
    password_file: .step.password
    listen:
      address: 0.0.0.0
      port: 9000
    dns:
      - ca.lab.local
      - localhost

- name: Tune authority claims (idempotent)
  bodsch.certs.step_ca:
    state: init
    home: /opt/step
    name: "Local Lab CA"
    config:
      tls_duration:
        default: 48h
        min: 5m
        max: 168h
      ssh_durations:
        host: {default: 48h, min: 5m, max: 168h}
        user: {default: 48h, min: 5m, max: 168h}
      disable_renewal: false
      allow_renewal_after_expiry: false
"""

RETURN = r"""
changed:
  description: True if the PKI was created or claims were updated.
  type: bool
  returned: always
msg:
  description: Human-readable status.
  type: str
  returned: sometimes
result:
  description: Trimmed stdout of step-cli when invoked.
  type: str
  returned: when init was executed
cmd:
  description: Argv used to invoke step-cli.
  type: list
  elements: str
  returned: when init was executed
"""


# Mapping of nested config keys to step-ca claim names.
# Kept as a flat declarative table to avoid 25 lines of if/elif.
_CLAIM_MAP = (
    # (config_path, claim_name)
    (("tls_duration", "default"), "defaultTLSCertDuration"),
    (("tls_duration", "min"), "minTLSCertDuration"),
    (("tls_duration", "max"), "maxTLSCertDuration"),
    (("ssh_durations", "host", "default"), "defaultHostSSHCertDuration"),
    (("ssh_durations", "host", "min"), "minHostSSHCertDuration"),
    (("ssh_durations", "host", "max"), "maxHostSSHCertDuration"),
    (("ssh_durations", "user", "default"), "defaultUserSSHCertDuration"),
    (("ssh_durations", "user", "min"), "minUserSSHCertDuration"),
    (("ssh_durations", "user", "max"), "maxUserSSHCertDuration"),
    (("disable_renewal",), "disableRenewal"),
    (("allow_renewal_after_expiry",), "allowRenewalAfterExpiry"),
)


class StepCA:
    """Bootstrap and configure the authority claims of a step-ca instance."""

    def __init__(self, module):
        self.module = module
        self.module.log("StepCA::__init__()")

        self.state = module.params["state"]
        self.force = module.params["force"]
        self.step_home = module.params["home"]
        self.step_name = module.params["name"]
        self.step_password_file = module.params["password_file"]
        self.step_dns = module.params["dns"] or []
        self.step_config = module.params["config"] or {}
        self.admin_subject = module.params["admin_subject"]
        self.admin_provisioner = module.params["admin_provisioner"]
        self.remote_management = module.params["remote_management"]

        listen = module.params["listen"] or {}
        self.listen_address = listen.get("address", "127.0.0.1")
        self.listen_port = int(listen.get("port", 9000))

        self._step = module.get_bin_path("step-cli", required=True)
        self.step_root_cert = os.path.join(
            self.step_home, ".step", "certs", "root_ca.crt"
        )
        self.step_config_file = os.path.join(
            self.step_home, ".step", "config", "ca.json"
        )

        self.checksum = Checksum(module)

    # ----------------------------------------------------------------- public

    def run(self):
        if self.force:
            self._clean()

        if self.state != "init":
            self.module.fail_json(msg=f"Unsupported state: {self.state}")

        result = self._init_ca()
        if result.get("failed"):
            return result

        return self._update_authority_claims(result)

    # ---------------------------------------------------------------- private

    def _clean(self):
        path = os.path.join(self.step_home, ".step")
        if os.path.exists(path):
            shutil.rmtree(path)

    def _init_ca(self):
        if os.path.exists(self.step_root_cert) and os.path.exists(
            self.step_config_file
        ):
            return dict(failed=False, changed=False, msg="CA is already created.")

        if not self.step_name:
            self.module.fail_json(msg="'name' is required for first-time init")

        pwd_file = os.path.join(self.step_home, self.step_password_file)
        if not os.path.exists(pwd_file):
            self.module.fail_json(msg=f"Password file does not exist: {pwd_file}")

        args = [
            self._step,
            "ca",
            "init",
            "--name",
            self.step_name,
            "--address",
            f"{self.listen_address}:{self.listen_port}",
            "--provisioner",
            self.admin_provisioner,
            "--password-file",
            pwd_file,
            "--provisioner-password-file",
            pwd_file,
            "--deployment-type",
            "standalone",
        ]

        # --admin-subject is only valid together with --remote-management
        if self.remote_management:
            args.append("--remote-management")
            args.extend(["--admin-subject", self.admin_subject])

        for dns in self.step_dns:
            args.extend(["--dns", dns])

        rc, out, err = self.module.run_command(args, check_rc=False)

        if rc != 0:
            return dict(
                failed=True,
                changed=False,
                cmd=args,
                msg="step ca init failed",
                stderr=err,
                stdout=out,
            )

        return dict(
            failed=False, changed=True, cmd=args, result=out.rstrip(), stdout=out
        )

    def _init_ca_OLD(self):
        if os.path.exists(self.step_root_cert) and os.path.exists(
            self.step_config_file
        ):
            return dict(failed=False, changed=False, msg="CA is already created.")

        if not self.step_name:
            self.module.fail_json(msg="'name' is required for first-time init")

        pwd_file = os.path.join(self.step_home, self.step_password_file)
        if not os.path.exists(pwd_file):
            self.module.fail_json(msg=f"Password file does not exist: {pwd_file}")

        args = [
            self._step,
            "ca",
            "init",
            "--name",
            self.step_name,
            "--address",
            f"{self.listen_address}:{self.listen_port}",
            "--provisioner",
            self.admin_provisioner,
            "--admin-subject",
            self.admin_subject,
            "--password-file",
            pwd_file,
            "--provisioner-password-file",
            pwd_file,
            "--deployment-type",
            "standalone",
        ]
        for dns in self.step_dns:
            args.extend(["--dns", dns])

        rc, out, err = self.module.run_command(args, check_rc=False)

        if rc != 0:
            return dict(
                failed=True,
                changed=False,
                cmd=args,
                msg="step ca init failed",
                stderr=err,
                stdout=out,
            )

        return dict(
            failed=False, changed=True, cmd=args, result=out.rstrip(), stdout=out
        )

    def _update_authority_claims(self, result):
        desired = self._build_desired_claims()
        if not desired:
            return result

        if not os.path.exists(self.step_config_file):
            self.module.fail_json(
                msg=f"ca.json not found after init: {self.step_config_file}"
            )

        with open(self.step_config_file, "r", encoding="utf-8") as f:
            ca_data = json.load(f)

        current = ca_data.get("authority", {}).get("claims", {}) or {}

        if self.checksum.checksum(current) == self.checksum.checksum(desired):
            return result

        ca_data.setdefault("authority", {})["claims"] = desired

        with open(self.step_config_file, "w", encoding="utf-8") as f:
            json.dump(ca_data, f, ensure_ascii=False, indent=2)

        result["changed"] = True
        return result

    def _build_desired_claims(self):
        """Translate nested module config dict to flat step-ca claims dict."""
        claims = {}
        for path, claim_name in _CLAIM_MAP:
            value = self._dig(self.step_config, path)
            if value is not None:
                claims[claim_name] = value
        return claims

    @staticmethod
    def _dig(data, path):
        cur = data
        for key in path:
            if not isinstance(cur, dict):
                return None
            cur = cur.get(key)
            if cur is None:
                return None
        return cur


def main():
    module = AnsibleModule(
        argument_spec=dict(
            state=dict(type="str", choices=["init"], default="init"),
            force=dict(type="bool", default=False),
            home=dict(type="path", required=True),
            name=dict(type="str"),
            listen=dict(
                type="dict",
                default={"address": "127.0.0.1", "port": 9000},
                options=dict(
                    address=dict(type="str", default="127.0.0.1"),
                    port=dict(type="int", default=9000),
                ),
            ),
            password_file=dict(type="str", default="password", no_log=False),
            dns=dict(type="list", elements="str", default=[]),
            admin_subject=dict(type="str", default="step"),
            admin_provisioner=dict(type="str", default="admin"),
            remote_management=dict(type="bool", default=True),
            config=dict(type="dict", default={}),
        ),
        supports_check_mode=False,
    )

    try:
        result = StepCA(module).run()
    except Exception as exc:  # noqa: BLE001
        module.fail_json(msg=f"Unhandled error: {exc}")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
