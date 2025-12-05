#!/usr/bin/python3
# -*- coding: utf-8 -*-

# (c) 2021-2024, Bodo Schulz <bodo@boone-schulz.de>
# GNU General Public License version 3 (see LICENSE or https://opensource.org/license/gpl-3-0)
# SPDX-License-Identifier: GPL-3.0

from __future__ import absolute_import, division, print_function

import os

from ansible.module_utils.basic import AnsibleModule

# ---------------------------------------------------------------------------------------

DOCUMENTATION = r"""
---
module: domain_certs
author:
  - "Bodo 'bodsch' Schulz (@bodsch) <bodo@boone-schulz.de>"
version_added: "1.0.0"

short_description: Check presence of certificate files created by Let's Encrypt certbot

description:
  - Check whether certificate files issued by Let's Encrypt certbot exist for a list of domains.
  - The module does not create or renew certificates; it only inspects the filesystem.

options:
  path:
    description:
      - Base directory where certificate directories for each domain are stored.
      - Typically this is the C(/etc/letsencrypt/live) directory.
    required: true
    type: path

  file:
    description:
      - File name to test for inside each domain directory.
      - Common examples are C(fullchain.pem), C(cert.pem), or C(privkey.pem).
    required: true
    type: str

  certificates:
    description:
      - List of certificates to verify.
      - Each item describes a primary domain and optional subdomains which share the same certificate.
    required: true
    type: list
    elements: dict
    suboptions:
      domain:
        description:
          - Primary domain name.
          - This is used as the directory name below C(path) (for example C(/etc/letsencrypt/live/example.com)).
        required: true
        type: str
      subdomains:
        description:
          - Optional list or string of additional names which belong to the same certificate.
          - Currently this field is not evaluated by the module but is accepted for structural consistency.
        required: false
        type: raw
"""

EXAMPLES = r"""
- name: Ensure that domain certificates are present
  domain_certs:
    path: /etc/letsencrypt/live
    file: fullchain.pem
    certificates:
      - domain: foo.bar
        subdomains: www.foo.bar
  register: domain_certificates_exists

- name: Check multiple domains for a specific certificate file
  domain_certs:
    path: /etc/letsencrypt/live
    file: cert.pem
    certificates:
      - domain: example.com
        subdomains:
          - www.example.com
          - api.example.com
      - domain: example.org
  register: cert_status

- name: Fail if any certificate is missing
  domain_certs:
    path: /etc/letsencrypt/live
    file: fullchain.pem
    certificates:
      - domain: example.net
      - domain: example.io
  register: cert_check

- name: Assert that all certificates exist
  ansible.builtin.assert:
    that:
      - cert_check.certificate_miss | length == 0
    fail_msg: "Some certificates are missing: {{ cert_check.certificate_miss | join(', ') }}"
"""

RETURN = r"""
changed:
  description:
    - Indicates whether the module has changed anything.
    - This module only performs checks and will always return C(false) with the current implementation.
  type: bool
  returned: always
  sample: false

failed:
  description:
    - Indicates whether the module execution has failed.
  type: bool
  returned: always
  sample: false

certificate_present:
  description:
    - List of domains for which the specified certificate file exists at the expected location.
    - The expected location is C(<path>/<domain>/<file>).
  type: list
  elements: str
  returned: always
  sample:
    - example.com
    - example.org

certificate_miss:
  description:
    - List of domains for which the specified certificate file does not exist at the expected location.
    - The expected location is C(<path>/<domain>/<file>).
  type: list
  elements: str
  returned: always
  sample:
    - missing.example.net
"""

# ---------------------------------------------------------------------------------------


class DomainCerts(object):
    """ """

    def __init__(self, module):
        """ """
        self.module = module

        self.path = module.params.get("path")
        self.file = module.params.get("file")
        self.certificates = module.params.get("certificates")

    def run(self):
        """ """
        present = []
        misses = []

        for cert in self.certificates:
            # self.module.log(msg=f"   - cert: {cert}")
            domain = cert.get("domain", None)

            if domain:
                if os.path.exists(os.path.join(self.path, domain, self.file)):
                    present.append(domain)
                else:
                    misses.append(domain)
            else:
                self.module.log(msg=f"ERROR: missing name in {cert}")
                pass

        return dict(
            changed=False,
            failed=False,
            certificate_present=present,
            certificate_miss=misses,
        )


def main():
    specs = dict(
        path=dict(required=True, type="str"),
        file=dict(required=True, type="str"),
        certificates=dict(required=True, type="list"),
    )

    module = AnsibleModule(
        argument_spec=specs,
        supports_check_mode=True,
    )

    p = DomainCerts(module)
    result = p.run()

    module.exit_json(**result)


if __name__ == "__main__":
    main()
