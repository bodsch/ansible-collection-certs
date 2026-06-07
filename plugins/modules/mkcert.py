#!/usr/bin/python3
# -*- coding: utf-8 -*-

# (c) 2022-2026, Bodo Schulz <bodo@boone-schulz.de>
# Apache-2.0 (see LICENSE or https://opensource.org/license/apache-2-0/)
# SPDX-License-Identifier: Apache-2.0

"""
Manage a local mkcert certificate authority and the certificates issued by it.

Scope:
    * Bootstrap the local CA via ``mkcert -install`` (idempotent).
    * Validate the existing CA root certificate and re-create it when it
      has expired.
    * Issue one leaf certificate per entry in I(certificates), each into
      its own subdirectory below I(config_directory).

The module shells out to the ``mkcert`` binary because there is no API.
CA and certificate locations are pinned via the ``$CAROOT`` environment
variable so the module is fully self-contained and does not depend on the
per-user default locations mkcert would otherwise pick.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import os
import shutil
from datetime import datetime, timezone

from ansible.module_utils.basic import AnsibleModule

try:
    from cryptography import x509

    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


DOCUMENTATION = r"""
---
module: mkcert
version_added: "1.0.0"
short_description: Bootstrap a local mkcert CA and issue certificates
author:
  - "Bodo Schulz (@bodsch) <bodo@boone-schulz.de>"

description:
  - Runs C(mkcert -install) to create (and trust) a local certificate authority.
  - Verifies the validity of the existing CA root certificate and re-creates the CA
    when it has expired (or is about to expire within I(renew_remaining_days)).
  - Issues one leaf certificate per entry in I(certificates). Each certificate is
    written into its own subdirectory C(<config_directory>/<domain>).
  - Re-issues a certificate when it is missing, expired, or no longer covers exactly
    the requested names (subjectAltName).
requirements:
  - mkcert
  - python cryptography library
options:
  force:
    description:
      - If C(true), wipe all issued certificates and the CA below I(config_directory)
        before re-creating them. Destructive — use with care.
    type: bool
    default: false
  config_directory:
    description:
      - Base directory holding the CA subdirectory and one subdirectory per issued
        certificate.
    type: path
    required: true
  ca_directory:
    description:
      - Directory used as C($CAROOT) for mkcert, i.e. where C(rootCA.pem) and
        C(rootCA-key.pem) are stored.
      - Defaults to C(<config_directory>/CA).
    type: path
  renew_remaining_days:
    description:
      - Re-create the CA when fewer than this many days of validity remain.
      - C(0) renews the CA only once it has actually expired.
    type: int
    default: 0
  certificates:
    description:
      - List of certificates to manage. Each item is issued into its own
        subdirectory C(<config_directory>/<domain>).
    type: list
    elements: dict
    default: []
    suboptions:
      domain:
        description: Name of the certificate; also used as the subdirectory name.
        type: str
        required: true
      state:
        description: Whether the certificate should be present or absent.
        type: str
        choices: [present, absent]
        default: present
      certificates:
        description:
          - Names (DNS names / wildcards / IPs) the certificate should be valid for,
            passed verbatim to C(mkcert). Defaults to a single entry equal to I(domain).
        type: list
        elements: str
        default: []
  owner:
    description: Owner applied to created directories and files (optional).
    type: str
  group:
    description: Group applied to created directories and files (optional).
    type: str
notes:
  - This module does not support check mode.
"""

EXAMPLES = r"""
- name: Bootstrap CA and issue certificates
  bodsch.certs.mkcert:
    config_directory: /etc/mkcert
    certificates:
      - domain: example.org
        state: present
        certificates:
          - example.org
          - "*.example.org"
      - domain: foo.bar
        state: absent
        certificates:
          - "*.foo.bar"

- name: Re-create everything from scratch
  bodsch.certs.mkcert:
    config_directory: /etc/mkcert
    force: true
    certificates:
      - domain: example.org
        certificates:
          - "*.example.org"
"""

RETURN = r"""
changed:
  description: True if the CA or any certificate was created, renewed or removed.
  type: bool
  returned: always
ca:
  description: Information about the managed CA.
  type: dict
  returned: always
  sample:
    path: /etc/mkcert/CA
    root_cert: /etc/mkcert/CA/rootCA.pem
    not_after: "2035-06-07T10:00:00+00:00"
    changed: false
certificates:
  description: One entry per managed certificate, including the on-disk paths.
  type: list
  elements: dict
  returned: always
  sample:
    - domain: example.org
      state: present
      path: /etc/mkcert/example.org
      cert_file: /etc/mkcert/example.org/example.org.pem
      key_file: /etc/mkcert/example.org/example.org-key.pem
      names: ["example.org", "*.example.org"]
      changed: true
certificate_paths:
  description: Flat list of the directories of all present certificates.
  type: list
  elements: str
  returned: always
"""


class MkCert:
    """
    Bootstrap a local mkcert CA and issue the configured leaf certificates.

    Three-phase :meth:`run`:

    1. **Force phase** — if I(force), remove all issued certificates and the
       CA below I(config_directory).
    2. **CA phase** — ensure a valid CA exists. Run ``mkcert -install`` when
       the root certificate is missing, and re-create it when it has expired
       (or expires within I(renew_remaining_days)).
    3. **Certificate phase** — reconcile each entry in I(certificates):
       (re-)issue present certificates that are missing, expired or whose SAN
       no longer matches the requested names, and remove absent ones.
    """

    ROOT_CERT = "rootCA.pem"

    def __init__(self, module):
        """
        :param module: The :class:`AnsibleModule` instance providing
            parameters and reporting facilities.
        """
        self.module = module
        self.module.log("MkCert::__init__()")

        self.force = module.params["force"]
        self.config_directory = module.params["config_directory"]
        self.renew_remaining_days = module.params["renew_remaining_days"]
        self.certificates = module.params["certificates"] or []
        self.owner = module.params["owner"]
        self.group = module.params["group"]

        self.ca_directory = module.params["ca_directory"] or os.path.join(
            self.config_directory, "CA"
        )
        self.root_cert = os.path.join(self.ca_directory, self.ROOT_CERT)

        self._mkcert = module.get_bin_path("mkcert", required=True)

    # ----------------------------------------------------------------- public

    def run(self):
        """
        Execute the force / CA / certificate pipeline.

        :returns: Result dict suitable for ``module.exit_json``.
        """
        result = dict(changed=False, ca={}, certificates=[], certificate_paths=[])

        if self.force:
            self._clean()
            result["changed"] = True

        ca_info = self._ensure_ca()
        result["ca"] = ca_info
        if ca_info.get("failed"):
            result["failed"] = True
            result["msg"] = ca_info.get("msg", "CA bootstrap failed")
            return result
        if ca_info.get("changed"):
            result["changed"] = True

        for entry in self.certificates:
            cert_result = self._reconcile_certificate(entry)
            result["certificates"].append(cert_result)
            if cert_result.get("failed"):
                result["failed"] = True
                result["msg"] = cert_result.get("msg", "certificate creation failed")
                return result
            if cert_result.get("changed"):
                result["changed"] = True
            if cert_result.get("state") == "present":
                result["certificate_paths"].append(cert_result["path"])

        return result

    # ---------------------------------------------------------------- private

    def _clean(self):
        """
        Remove the CA and every issued certificate below I(config_directory).

        Destructive — wipes the CA keys/certificate and all per-domain
        subdirectories. Only invoked when I(force) is true.
        """
        if os.path.isdir(self.ca_directory):
            shutil.rmtree(self.ca_directory)

        for entry in self.certificates:
            domain = entry.get("domain")
            if not domain:
                continue
            path = os.path.join(self.config_directory, domain)
            if os.path.isdir(path):
                shutil.rmtree(path)

    def _ensure_ca(self):
        """
        Ensure a valid CA root certificate exists, creating or renewing it.

        :returns: Dict describing the CA. Contains ``failed`` on error.
        """
        info = dict(
            path=self.ca_directory,
            root_cert=self.root_cert,
            changed=False,
        )

        renew = False
        if os.path.exists(self.root_cert):
            not_after, expired = self._certificate_validity(self.root_cert)
            info["not_after"] = not_after
            if expired:
                self.module.log("mkcert CA expired, re-creating")
                renew = True
            else:
                return info

        if renew and os.path.isdir(self.ca_directory):
            # Drop the stale CA so mkcert -install regenerates it.
            shutil.rmtree(self.ca_directory)

        self._makedirs(self.ca_directory)

        rc, out, err = self._mkcert_run(["-install"])
        if rc != 0 or not os.path.exists(self.root_cert):
            info["failed"] = True
            info["msg"] = "mkcert -install failed"
            info["stdout"] = out
            info["stderr"] = err
            return info

        self._apply_ownership(self.ca_directory, recursive=True)

        not_after, _ = self._certificate_validity(self.root_cert)
        info["not_after"] = not_after
        info["changed"] = True
        return info

    def _reconcile_certificate(self, entry):
        """
        Reconcile a single certificate entry.

        :param entry: One item from I(certificates).
        :returns: Result dict for this certificate.
        """
        domain = entry["domain"]
        cert_state = entry.get("state", "present")
        names = entry.get("certificates") or [domain]

        cert_dir = os.path.join(self.config_directory, domain)
        cert_file = os.path.join(cert_dir, f"{domain}.pem")
        key_file = os.path.join(cert_dir, f"{domain}-key.pem")

        result = dict(
            domain=domain,
            state=cert_state,
            path=cert_dir,
            cert_file=cert_file,
            key_file=key_file,
            names=names,
            changed=False,
        )

        if cert_state == "absent":
            if os.path.isdir(cert_dir):
                shutil.rmtree(cert_dir)
                result["changed"] = True
                result["msg"] = "removed"
            return result

        if not self._certificate_needs_update(cert_file, names):
            result["msg"] = "up-to-date"
            return result

        self._makedirs(cert_dir)

        args = ["-cert-file", cert_file, "-key-file", key_file] + list(names)
        rc, out, err = self._mkcert_run(args)
        if rc != 0 or not os.path.exists(cert_file):
            result["failed"] = True
            result["msg"] = f"mkcert failed for {domain}"
            result["stdout"] = out
            result["stderr"] = err
            return result

        self._apply_ownership(cert_dir, recursive=True)
        result["changed"] = True
        result["msg"] = "created"
        return result

    # ----------------------------------------------------------------- helpers

    def _certificate_needs_update(self, cert_file, names):
        """
        Decide whether a leaf certificate has to be (re-)issued.

        Re-issues when the file is missing, expired (within
        I(renew_remaining_days)), or its subjectAltName set no longer matches
        the requested names exactly.

        :param cert_file: Path to the certificate PEM file.
        :param names: Requested names for the certificate.
        :returns: ``True`` if the certificate must be re-created.
        """
        if not os.path.exists(cert_file):
            return True

        not_after, expired = self._certificate_validity(cert_file)
        if expired:
            return True

        current = self._subject_alt_names(cert_file)
        return current != set(names)

    def _certificate_validity(self, cert_file):
        """
        Read a certificate's expiry.

        :param cert_file: Path to a PEM certificate.
        :returns: Tuple ``(not_after_iso, expired)``. ``expired`` is ``True``
            when fewer than I(renew_remaining_days) days of validity remain.
        """
        cert = self._load_cert(cert_file)
        not_after = getattr(cert, "not_valid_after_utc", None)
        if not_after is None:
            not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

        remaining = (not_after - datetime.now(timezone.utc)).total_seconds()
        expired = remaining <= self.renew_remaining_days * 86400
        return not_after.isoformat(), expired

    def _subject_alt_names(self, cert_file):
        """
        Extract the set of subjectAltName DNS and IP entries from a cert.

        :param cert_file: Path to a PEM certificate.
        :returns: Set of name strings (matching what was passed to mkcert).
        """
        cert = self._load_cert(cert_file)
        names = set()
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        except x509.ExtensionNotFound:
            return names

        names.update(ext.value.get_values_for_type(x509.DNSName))
        names.update(str(ip) for ip in ext.value.get_values_for_type(x509.IPAddress))
        return names

    @staticmethod
    def _load_cert(cert_file):
        """Load a PEM x509 certificate from disk."""
        with open(cert_file, "rb") as fh:
            return x509.load_pem_x509_certificate(fh.read())

    def _mkcert_run(self, args):
        """
        Invoke the mkcert binary with C($CAROOT) pinned to I(ca_directory).

        :param args: Arguments following the binary path.
        :returns: ``(rc, stdout, stderr)``.
        """
        cmd = [self._mkcert] + args
        rc, out, err = self.module.run_command(
            cmd,
            check_rc=False,
            environ_update={"CAROOT": self.ca_directory},
        )
        if rc != 0:
            self.module.log(msg=f"mkcert {' '.join(args)} -> rc={rc}, err={err}")
        return rc, out, err

    def _makedirs(self, path):
        """Create I(path) (and parents) if missing and apply ownership."""
        if not os.path.isdir(path):
            os.makedirs(path, exist_ok=True)
            self._apply_ownership(path)

    def _apply_ownership(self, path, recursive=False):
        """
        Apply I(owner)/I(group) to I(path) when configured.

        :param path: File or directory to chown.
        :param recursive: Also chown the directory's contents.
        """
        if not self.owner and not self.group:
            return

        targets = [path]
        if recursive and os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                targets.extend(os.path.join(root, d) for d in dirs)
                targets.extend(os.path.join(root, f) for f in files)

        for target in targets:
            try:
                shutil.chown(target, user=self.owner, group=self.group)
            except (LookupError, PermissionError, OSError) as exc:
                self.module.warn(f"could not chown {target}: {exc}")


def main():
    """Module entry point. Wires :class:`AnsibleModule` to :class:`MkCert`."""

    arguments = dict(
        force=dict(type="bool", default=False),
        config_directory=dict(type="path", required=True),
        ca_directory=dict(type="path"),
        renew_remaining_days=dict(type="int", default=0),
        certificates=dict(
            type="list",
            elements="dict",
            default=[],
            options=dict(
                domain=dict(type="str", required=True),
                state=dict(
                    type="str",
                    choices=["present", "absent"],
                    default="present",
                ),
                certificates=dict(type="list", elements="str", default=[]),
            ),
        ),
        owner=dict(type="str"),
        group=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=arguments,
        supports_check_mode=False,
    )

    if not HAS_CRYPTOGRAPHY:
        module.fail_json(msg="The 'cryptography' Python library is required.")

    try:
        result = MkCert(module).run()
    except Exception as exc:  # noqa: BLE001
        module.fail_json(msg=f"Unhandled error: {exc}")

    if result.get("failed"):
        module.fail_json(**result)

    module.exit_json(**result)


if __name__ == "__main__":
    main()
