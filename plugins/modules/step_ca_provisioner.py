#!/usr/bin/python3
# -*- coding: utf-8 -*-

# (c) 2026, Bodo Schulz <bodo@boone-schulz.de>

"""
Idempotent management of step-ca provisioners via the Admin API.

Currently supports the C(ACME) provisioner type. The wire format mirrors
the linkedca protobuf schema serialised via protojson:

  * The provisioner-type discriminator is the outer ``type`` field.
  * Type-specific fields go into ``details.<TYPE>`` — for ACME, that is
    ``details.ACME``, with the inner key being the protobuf oneof field
    name (no separate ``data`` wrapper, no inner ``type`` discriminator).
  * Enum-style fields (``challenges``, ``attestationFormats``) use the
    protobuf enum names (e.g. ``HTTP_01``), not the ACME spec strings.
  * Provisioner ``claims`` are nested under a ``durations`` block per
    certificate kind, distinct from the flat field names that
    ``authority.claims`` in ``ca.json`` uses.

Idempotency is non-trivial because step-ca's responses omit default
values (``false`` / ``""`` / empty list / empty dict). The :meth:`_diff`
helper treats "missing on server" as "equal to default in desired" so
that wiring through the same dict on a second run produces no PUT.
"""

from __future__ import absolute_import, division, print_function

import json
import os

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.bodsch.certs.plugins.module_utils.step_ca.api import (
    StepCAClient,
)
from ansible_collections.bodsch.certs.plugins.module_utils.step_ca.exceptions import (
    StepCAError,
)

DOCUMENTATION = r"""
---
module: step_ca_provisioner
version_added: "1.2.0"
short_description: Manage step-ca provisioners via the Admin API
author:
  - "Bodo Schulz (@bodsch) <bodo@boone-schulz.de>"
description:
  - Creates, updates and removes provisioners on a running step-ca instance.
  - Communicates exclusively over the step-ca Admin HTTPS API; no shell-out to step-cli.
  - Currently supports the C(ACME) provisioner type. Other types (OIDC, JWK, X5C) will be added.
options:
  state:
    description: Desired state of the provisioner.
    type: str
    choices: [present, absent]
    default: present
  api:
    description: Connection parameters for the step-ca Admin API.
    type: dict
    required: true
    suboptions:
      ca_url:
        description: Base URL of the step-ca instance, including scheme and port.
        type: str
        required: true
      ca_root:
        description: Path to the root CA certificate used for TLS verification.
        type: path
        required: true
      admin_provisioner:
        description: Name of the JWK admin provisioner used to authenticate.
        type: str
        default: admin
      admin_subject:
        description: Subject ("admin username") registered in step-ca for this admin.
        type: str
        default: step
      admin_password_file:
        description: Path to the file containing the admin provisioner password.
        type: path
        required: true
  name:
    description: Name of the provisioner.
    type: str
    required: true
  type:
    description: Provisioner type. Only C(ACME) is currently supported.
    type: str
    choices: [ACME]
    default: ACME
  force_cn:
    description: Require/force the Common Name to be present in the SAN list (ACME).
    type: bool
    default: false
  require_eab:
    description:
      - Require External Account Binding for ACME registrations.
      - Note that issuing/managing EAB credentials is gated behind Smallstep
        Certificate Manager. Setting this to C(true) on standalone step-ca
        produces a configurable provisioner that no client can register
        with — the matching admin endpoints respond with HTTP 501.
    type: bool
    default: false
  challenges:
    description:
      - Allowed ACME challenge types.
      - Use any combination of C(http-01), C(dns-01), C(tls-alpn-01), C(device-attest-01).
    type: list
    elements: str
    default: [http-01, dns-01, tls-alpn-01]
  attestation_formats:
    description: Allowed attestation formats for C(device-attest-01).
    type: list
    elements: str
    default: []
  claims:
    description:
      - Per-provisioner overrides for certificate-duration claims.
      - Top-level keys (all optional) follow snake_case for the user-facing
        API and are translated internally to the protojson wire format.
      - C(tls_duration) — dict with C(default) / C(min) / C(max), e.g.
        C({default: 24h, min: 5m, max: 720h}).
      - C(ssh_user_duration) — same shape, applies to ssh user certs.
      - C(ssh_host_duration) — same shape, applies to ssh host certs.
      - C(disable_renewal) — bool.
      - C(allow_renewal_after_expiry) — bool.
      - C(disable_smallstep_extensions) — bool.
      - Unknown top-level keys cause the module to fail rather than
        producing a payload step-ca would reject with a cryptic error.
    type: dict
    default: {}
  policy:
    description:
      - Optional x509/ssh policy attached to the provisioner.
      - Per-provisioner policies are gated behind Smallstep Certificate
        Manager — the corresponding endpoint responds with
        "disabled in standalone" on open-source step-ca.
      - Prefer the dedicated C(step_ca_policy) module with
        C(scope=authority) for issuance restrictions.
    type: dict
"""

EXAMPLES = r"""
- name: Ensure default ACME provisioner exists
  bodsch.certs.step_ca_provisioner:
    state: present
    name: acme
    type: ACME
    challenges: [http-01, dns-01, tls-alpn-01]
    api: "{{ step_ca_admin_connection }}"

- name: ACME provisioner with EAB and tighter durations
  bodsch.certs.step_ca_provisioner:
    state: present
    name: acme-eab
    type: ACME
    require_eab: true
    challenges: [dns-01]
    claims:
      tls_duration:
        default: 24h
        max: 168h
    api: "{{ step_ca_admin_connection }}"

- name: Remove a provisioner
  bodsch.certs.step_ca_provisioner:
    state: absent
    name: legacy-acme
    api: "{{ step_ca_admin_connection }}"
"""

RETURN = r"""
changed:
  description: True if the provisioner was created, updated or deleted.
  type: bool
  returned: always
provisioner:
  description: The provisioner object as returned by the Admin API after the operation.
  type: dict
  returned: when state=present
diff:
  description: Differences between the desired and existing provisioner (debug aid).
  type: dict
  returned: when changes were applied
"""


#: ACME challenge spec strings → linkedca enum value names. The wire
#: format requires the enum names (e.g. ``HTTP_01``); we expose the
#: spec strings (``http-01``) on the module interface for readability.
_ACME_CHALLENGE_MAP = {
    "http-01": "HTTP_01",
    "dns-01": "DNS_01",
    "tls-alpn-01": "TLS_ALPN_01",
    "device-attest-01": "DEVICE_ATTEST_01",
}

#: Attestation format strings → linkedca enum value names.
_ACME_ATTESTATION_MAP = {
    "apple": "APPLE",
    "step": "STEP",
    "tpm": "TPM",
}


class StepCAProvisioner:
    """
    Idempotent management of step-ca provisioners.

    Strategy:
      1. Fetch existing provisioner by name.
      2. Build desired payload from module params.
      3. Compare normalised payloads (only fields we manage).
      4. Create / update / delete as needed.

    Supported types
        Only ``ACME`` for now. Other types (``OIDC``, ``JWK``, ``X5C``)
        require dedicated detail builders and will be added as needed.

    Wire format
        See the module-level docstring for the protojson quirks the
        builders accommodate (oneof discriminator on field name, no
        ``data`` wrapper, enum names rather than spec strings).
    """

    # Mapping of module-param names to API field names for the ACME details
    # block. Kept explicit (rather than auto-camelCase) for clarity.

    def __init__(self, module):
        """
        :param module: The :class:`AnsibleModule` instance.
        """
        self.module = module
        # self.module.log("StepCAProvisioner::__init__()")

        self.state = module.params["state"]
        self.name = module.params["name"]
        self.type = module.params["type"].upper()

        api_params = module.params["api"]
        self.client = self._build_client(api_params)

    # ----------------------------------------------------------------- public

    def run(self):
        """
        Apply the requested state.

        :returns: Result dict for ``module.exit_json``.
        """
        # self.module.log("StepCAProvisioner::run()")

        existing = self._fetch_existing()

        if self.state == "absent":
            return self._ensure_absent(existing)

        return self._ensure_present(existing)

    # ----------------------------------------------------------------- private

    def _build_client(self, api_params):
        """
        Construct a :class:`StepCAClient` from the I(api) sub-options.

        Validates the URL (rejects bind-only addresses that would fail
        as TLS hostname mismatches) and the password file before any
        network I/O so config mistakes surface as clean fail_json
        messages rather than mid-flow stack traces.
        """
        # self.module.log(f"StepCAProvisioner::_build_client(api_params: {api_params})")

        from urllib.parse import urlparse

        ca_url = api_params["ca_url"]
        host = urlparse(ca_url).hostname or ""
        if host in ("0.0.0.0", "::", ""):
            self.module.fail_json(
                msg=f"ca_url '{ca_url}' uses a bind address ('{host}'), not a "
                "connect address. Use a hostname listed in the CA's DNS "
                "SANs (e.g. 'localhost' or your CA's FQDN)."
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

    def _fetch_existing(self):
        """
        Fetch the named provisioner from the server, or return ``None``
        if it does not exist.

        Translates a 404 into ``None`` rather than raising, so callers
        can use the absence/presence as a state signal.
        """
        # self.module.log("StepCAProvisioner::_fetch_existing()")

        try:
            data = self.client.get(f"/admin/provisioners/{self.name}")
        except StepCAError as exc:
            # 404 surfaces as StepCAAPIError with status_code=404
            status = getattr(exc, "status_code", None)
            if status == 404:
                return None
            self.module.fail_json(msg=f"Failed to fetch provisioner: {exc}")
        return data

    def _build_desired(self):
        """
        Build the linkedca-shaped provisioner payload step-ca expects on
        /admin/provisioners. The Admin API uses protojson, so:

          * The provisioner-type discriminator is the outer `type` field.
          * Type-specific fields go into details.<TYPE> (no inner discriminator).
          * Enum-style fields (challenges, attestationFormats) use the
            protobuf enum names (e.g. "HTTP_01"), not the ACME spec strings.
          * Provisioner claims use a nested durations schema, not the flat
            field names from authority.claims in ca.json.
        """
        payload = {
            "type": self.type,
            "name": self.name,
        }

        claims = self._build_claims()
        if claims:
            payload["claims"] = claims

        policy = self.module.params.get("policy")
        if policy:
            payload["policy"] = policy

        if self.type == "ACME":
            payload["details"] = self._build_acme_details()
        else:
            self.module.fail_json(msg=f"Unsupported provisioner type: {self.type}")

        return payload

    def _build_claims(self):
        """
        Translate the user-friendly claims dict into the linkedca proto schema.

        User input (intuitive, mirrors authority.claims style):

            claims:
              tls_duration:  {default: 24h, min: 5m, max: 720h}
              ssh_user_duration: {default: 16h, min: 5m, max: 168h}
              ssh_host_duration: {default: 24h, min: 5m, max: 720h}
              disable_renewal: false
              allow_renewal_after_expiry: true
              disable_smallstep_extensions: false

        Wire format (linkedca.Claims):

            {
              "x509": {"durations": {"default": "24h", "min": "5m", "max": "720h"}},
              "ssh":  {"userDurations": {...}, "hostDurations": {...}},
              "disableRenewal": false,
              ...
            }
        """
        raw = self.module.params.get("claims") or {}
        if not raw:
            return None

        out = {}

        tls = raw.get("tls_duration") or {}
        if tls:
            out["x509"] = {"durations": self._duration_block(tls)}

        ssh_user = raw.get("ssh_user_duration") or {}
        ssh_host = raw.get("ssh_host_duration") or {}
        if ssh_user or ssh_host:
            ssh_block = {}
            if ssh_user:
                ssh_block["userDurations"] = self._duration_block(ssh_user)
            if ssh_host:
                ssh_block["hostDurations"] = self._duration_block(ssh_host)
            out["ssh"] = ssh_block

        for src, dst in (
            ("disable_renewal", "disableRenewal"),
            ("allow_renewal_after_expiry", "allowRenewalAfterExpiry"),
            ("disable_smallstep_extensions", "disableSmallstepExtensions"),
        ):
            if src in raw:
                out[dst] = bool(raw[src])

        # Reject leftover keys so users notice typos instead of silently
        # producing a payload step-ca would reject with a cryptic line:col error.
        KNOWN = {
            "tls_duration",
            "ssh_user_duration",
            "ssh_host_duration",
            "disable_renewal",
            "allow_renewal_after_expiry",
            "disable_smallstep_extensions",
        }
        unknown = set(raw) - KNOWN
        if unknown:
            self.module.fail_json(
                msg=f"Unknown claims keys: {sorted(unknown)}. "
                f"Valid: {sorted(KNOWN)}"
            )

        return out or None

    @staticmethod
    def _duration_block(d):
        """Map {default,min,max} dict to a linkedca Duration proto block."""
        block = {}
        if d.get("default") is not None:
            block["default"] = str(d["default"])
        if d.get("min") is not None:
            block["min"] = str(d["min"])
        if d.get("max") is not None:
            block["max"] = str(d["max"])
        return block

    def _build_acme_details(self):
        """
        Build the ACME-specific block of the provisioner payload.

        Schema mirrors linkedca.ProvisionerDetails serialised via protojson:
        the oneof discriminator 'ACME' is the field name itself — no inner
        'type' key, no 'data' wrapper. Field names use protojson defaults
        (lowerCamelCase from the proto definition):

            ACMEProvisioner.force_cn          -> "forceCn"
            ACMEProvisioner.require_eab       -> "requireEab"
            ACMEProvisioner.challenges        -> "challenges"
            ACMEProvisioner.attestation_*     -> "attestationFormats" / "attestationRoots"
        """
        # self.module.log("StepCAProvisioner::_build_acme_details()")

        inner = {
            "forceCn": bool(self.module.params.get("force_cn")),
            "requireEab": bool(self.module.params.get("require_eab")),
        }

        challenges = self.module.params.get("challenges") or []
        if challenges:
            try:
                inner["challenges"] = [_ACME_CHALLENGE_MAP[c] for c in challenges]
            except KeyError as exc:
                self.module.fail_json(
                    msg=f"Unknown ACME challenge: {exc}. "
                    f"Valid: {sorted(_ACME_CHALLENGE_MAP)}"
                )

        formats = self.module.params.get("attestation_formats") or []
        if formats:
            try:
                inner["attestationFormats"] = [
                    _ACME_ATTESTATION_MAP[f] for f in formats
                ]
            except KeyError as exc:
                self.module.fail_json(
                    msg=f"Unknown attestation format: {exc}. "
                    f"Valid: {sorted(_ACME_ATTESTATION_MAP)}"
                )

        return {"ACME": inner}

    def _ensure_present(self, existing):
        """
        Create the provisioner if missing, PUT a merged record if any
        managed field differs, no-op otherwise.

        Update path: the existing record is merged with the desired
        payload (server-supplied metadata such as ``id`` /
        ``createdAt`` is preserved), then PUT back to the server.

        :param existing: ``None`` or the dict returned by
            :meth:`_fetch_existing`.
        """
        # self.module.log(f"StepCAProvisioner::_ensure_present(existing: {existing})")

        desired = self._build_desired()

        if existing is None:
            self.module.log(f"  -> POST payload: {json.dumps(desired)}")

            if self.module.check_mode:
                return dict(changed=True, provisioner=desired)
            created = self.client.post("/admin/provisioners", desired)
            return dict(changed=True, provisioner=created)

        diff = self._diff(existing, desired)
        if not diff:
            return dict(changed=False, provisioner=existing)

        self.module.log(f"  -> PUT diff: {diff}")

        if self.module.check_mode:
            return dict(changed=True, provisioner=desired, diff=diff)

        merged = dict(existing)
        merged.update(desired)
        updated = self.client.put(f"/admin/provisioners/{self.name}", merged)
        return dict(changed=True, provisioner=updated, diff=diff)

    def _ensure_absent(self, existing):
        """
        Delete the provisioner if present, no-op otherwise.
        """
        # self.module.log(f"StepCAProvisioner::_ensure_absent(existing: {existing})")

        if existing is None:
            return dict(changed=False)
        if self.module.check_mode:
            return dict(changed=True)
        self.client.delete(f"/admin/provisioners/{self.name}")
        return dict(changed=True)

    @staticmethod
    def _diff(existing, desired):
        """
        Recursive diff between desired (module input) and existing (server response).

        Handles three idempotency quirks of step-ca's protojson serialisation:

        1. Default values (False, "", 0, [], {}) are *omitted* in responses.
           'Missing on server' therefore equals 'default in desired'.

        2. Lists representing sets — challenges, attestationFormats —
           can come back in arbitrary order. Compared as sets.

        3. Server adds metadata fields (id, authorityId, createdAt, deletedAt)
           that we don't manage. Only fields present in `desired` are compared.
        """
        UNORDERED_LISTS = {"challenges", "attestationFormats"}

        def is_default(value):
            if value in (False, "", 0, None):
                return True
            if isinstance(value, (list, dict, tuple)) and len(value) == 0:
                return True
            return False

        def equal(have, want, key=None):
            if have is None and is_default(want):
                return True
            if isinstance(want, dict):
                have = have or {}
                if not isinstance(have, dict):
                    return False
                return all(equal(have.get(k), v, key=k) for k, v in want.items())
            if key in UNORDERED_LISTS and isinstance(want, list):
                return set(want) == set(have or [])
            return have == want

        diff = {}
        for key, want in desired.items():
            have = existing.get(key)
            if not equal(have, want, key=key):
                diff[key] = {"before": have, "after": want}
        return diff


def main():
    """Module entry point. Wires :class:`AnsibleModule` to :class:`StepCAProvisioner`."""
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
            name=dict(type="str", required=True),
            type=dict(type="str", choices=["ACME"], default="ACME"),
            force_cn=dict(type="bool", default=False),
            require_eab=dict(type="bool", default=False),
            challenges=dict(
                type="list",
                elements="str",
                default=["http-01", "dns-01", "tls-alpn-01"],
            ),
            attestation_formats=dict(type="list", elements="str", default=[]),
            claims=dict(type="dict", default={}),
            policy=dict(type="dict"),
        ),
        supports_check_mode=True,
    )

    try:
        result = StepCAProvisioner(module).run()
    except StepCAError as exc:
        module.fail_json(msg=str(exc))
    except Exception as exc:  # noqa: BLE001
        module.fail_json(msg=f"Unhandled error: {exc}")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
