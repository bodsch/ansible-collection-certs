#!/usr/bin/python3
# -*- coding: utf-8 -*-

# (c) 2021, Bodo Schulz <bodo@boone-schulz.de>
# BSD 2-clause (see LICENSE or https://opensource.org/licenses/BSD-2-Clause)

from __future__ import absolute_import, division, print_function

import os
# import json
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from ansible.module_utils.basic import AnsibleModule

# ---------------------------------------------------------------------------------------

DOCUMENTATION = """
---
module: certbot
author: "Bodo 'bodsch' Schulz (@bodsch) <bodo@boone-schulz.de>"
version_added: 1.0.0

short_description: creates a certificate with letsentcrypt certbot

description:
    - creates a new certificate with letsentcrypt certbot

options:
  state:
    description:
      - (C(certonly))
    default: certonly
    required: true

  webroot_path:
    description:
      -
    required: true
    type: str

  rsa_key_size:
    description:
      -
    default: 4096
    type: int

  domains:
    description:
      -
    required: true
    type: list

  certbot_base_directory:
    description:
      -
    default: /etc/letsencrypt
    required: false

  email:
    description:
      -
    required: true
    type: str

  quiet:
    description:
      -
    default: false
    required: false
    type: bool

  test_cert:
    description:
      -
    default: false
    required: false
    type: bool

  dry_run:
    description:
      -
    default: false
    required: false
    type: bool

  auto_expand:
    description:
      -
    default: false
    required: false
    type: bool

  arguments:
    description:
      -
    required: false
    type: list
"""

EXAMPLES = """
- name: create certificate with certbot certonly
  certbot:
    state: certonly
    arguments:
      - --test-cert
      - --dry-run
    webroot_path: /var/www/certbot
    rsa_key_size: 4096
    domains:
      - domain: foo.bar
        subdomains: www.foo.bar
    certbot_base_directory: /etc/letsencrypt
    email: pki@test.com
  register: create_certificates

- name: create test certificate with certbot
  certbot:
    state: certonly
    dry_run: true
    test_cert: true
    webroot_path: /var/www/certbot
    rsa_key_size: 4096
    domains:
      - domain: foo.bar
        subdomains: www.foo.bar
    certbot_base_directory: /etc/letsencrypt
    email: pki@test.com
  register: create_certificates

- name: create test certificate with certbot and extend the existing certificate
  certbot:
    state: certonly
    dry_run: true
    test_cert: true
    auto_expand: true
    webroot_path: /var/www/certbot
    rsa_key_size: 4096
    domains:
      - domain: foo.bar
        subdomains:
          - www.foo.bar
          - stage.foo.bar
    certbot_base_directory: /etc/letsencrypt
    email: pki@test.com
  register: create_certificates

"""

RETURN = """
"""

# ---------------------------------------------------------------------------------------


class DomainCerts(object):
    """
    """

    def __init__(self, module):
        """
        """
        self.module = module

        self.state = module.params.get("state")
        self.webroot_path = module.params.get("webroot_path")
        self.rsa_key_size = module.params.get("rsa_key_size")
        self.domains = module.params.get("domains")
        self.certbot_base_directory = module.params.get("certbot_base_directory")
        self.email = module.params.get("email")
        self.quiet = module.params.get("quiet")
        self.test_cert = module.params.get("test_cert")
        self.dry_run = module.params.get("dry_run")
        self.auto_expand = module.params.get("auto_expand")
        self.arguments = module.params.get("arguments")

        self._certbot = module.get_bin_path('certbot', True)

    def run(self):
        """
        """
        _failed = True
        _changed = False

        """
        certbot certonly \
          {{ multi_certbot_staging_args | join(' ') }} \
          --webroot \
          --webroot-path {{ multi_certbot_www_directory }} \
          --rsa-key-size {{ multi_certbot_rsa_key_size }} \
          --domain {{ multi_certbot_full_domain_list }} \
          --cert-path {{ multi_certbot_conf_directory }}/live/{{ item }} \
          --non-interactive \
          --agree-tos \
          --expand \
          --email {{ multi_certbot_email }}
    """
        result_msgs = {}

        base_args = []
        base_args.append(self._certbot)
        base_args.append(self.state)
        base_args.append("--rsa-key-size")
        base_args.append(str(self.rsa_key_size))
        if self.quiet:
            base_args.append("--quiet")
        base_args.append("--non-interactive")
        base_args.append("--agree-tos")
        base_args.append("--email")
        base_args.append(self.email)

        if self.webroot_path and len(self.webroot_path) > 0:
            base_args.append("--webroot")
            base_args.append("--webroot-path")
            base_args.append(self.webroot_path)

        if self.test_cert:
            base_args.append("--test-cert")

        if self.dry_run:
            base_args.append("--dry-run")

        if len(self.arguments) > 0:
            for arg in self.arguments:
                base_args.append(arg)

        for domain in self.domains:
            args = []
            # expand = False

            domain_name = domain.get("domain")
            domain_list = self.__cert_list(domain)

            # self.module.log(msg=f"   domain : {domain_name}")
            # self.module.log(msg=f"     - domains {domain_list}")

            cert_path = os.path.join(self.certbot_base_directory, "live", domain_name)
            current_certificates = self._current_certificates(cert_path)

            # self.module.log(msg=f"     - current  {current_certificates}")
            # self.module.log(msg=f"     - wanted   {domain_list}")

            if len(current_certificates) != 0:
                if len(domain_list) > len(current_certificates):
                    self.module.log(msg=f"The certificate for '{domain_name}' must be expand.")
                    # domain_diff = list(set(domain_list) - set(current_certificates))
                    # expand = True

                elif len(domain_list) < len(current_certificates):
                    self.module.log(msg=f"The certificate for '{domain_name}' should be revoked and renewed.")
                    # domain_diff = list(set(current_certificates) - set(domain_list))

                elif len(domain_list) == len(current_certificates):
                    # self.module.log(msg=f"   certificate are in sync.")
                    # domain_diff = []
                    pass

            # self.module.log(msg=f"     - diff     {domain_diff}")

            if not os.path.exists(cert_path):
                """
                    certificat not exists
                """
                self.module.log(msg=f"Create a new certificate for '{domain_name}'")

                # result_msgs[domain_name] = {}
                # self.module.log(msg=f"        run certbot")
                args = base_args.copy()
                args.append("--cert-path")
                args.append(cert_path)

                for d in domain_list:
                    args.append("--domain")
                    args.append(d)

            # else:
            #     """
            #         certificat not exists
            #     """
            #     if expand:
            #         args.append("--expand")

            # self.module.log(msg=f" - base_args {base_args}")
            # self.module.log(msg=f" - args      {args}")

            # ---------------------------------------------------------------------
            # rc, out, err = self.__exec(args, check=False)
            rc = 2
            out = "testing"
            err = "testing"

            # self.module.log(msg=f"  rc : '{rc}'")
            # self.module.log(msg=f"  out: '{out}'")
            # self.module.log(msg=f"  err: '{err}'")

            if rc == 0:
                self.module.log(msg=f"     out: '{out}'")
                _failed = False
                _changed = True
                result_msgs[domain_name] = dict(
                    rc=rc,
                    cmd=" ".join(args),
                    failed=False,
                    changed=True
                )

            else:
                self.module.log(msg=f"     err: '{err}'")
                result_msgs[domain_name] = dict(
                    rc=rc,
                    cmd=" ".join(args),
                    stderr=err,
                    stdout=out,
                    failed=True,
                    changed=False
                )
            # ---------------------------------------------------------------------

        error_count = len(
            {k for k, v in result_msgs.items() if v.get("failed", False)}
        )

        if error_count != 0:
            _failed = True
        else:
            _failed = False

        self.module.log(msg=f" = {result_msgs}")

        return dict(
            failed=_failed,
            changed=_changed,
            errors=error_count,
            result=result_msgs
        )

    def __cert_list(self, domain_data):
        """
        """
        # self.module.log(msg=f"__cert_list({domain_data}")

        domain_name = domain_data.get("domain")
        domain_list = domain_data.get("subdomains", [])

        if isinstance(domain_list, list) and len(domain_list) > 0:
            domains = domain_list
            domains.insert(0, domain_name)
        elif domain_list is None:
            domains = []
            domains.append(domain_name)
        elif isinstance(domain_list, str):
            domains = []
            domains.append(domain_name)
            domains.append(domain_list)
        else:
            domains = []
            domains.append(domain_name)

        domains = sorted(domains)
        domains = list(set(domains))

        return domains

    def _current_certificates(self, domain_path):
        """
            current_certificates() {
              echo "current certificates"
              certbot certificates
            }
        """
        domains = []
        alt_names = []

        for currentpath, dirs, files in os.walk(domain_path, topdown=True):
            for file in files:
                if file == "fullchain.pem":
                    f = os.path.join(currentpath, file)

                    # self.module.log(msg=f"  - file: {f}")

                    with open(f, 'br') as cert_content:
                        cert_data = cert_content.read()
                        cert_decoded = x509.load_pem_x509_certificate(cert_data, default_backend())

                        subject = cert_decoded.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value.lower()

                        SubjectAlternativeName = cert_decoded.extensions.get_extension_for_oid(x509.extensions.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                        if SubjectAlternativeName:
                            alt_names = SubjectAlternativeName.value.get_values_for_type(x509.extensions.DNSName)

                        # self.module.log(msg=f"  - subject  : {subject}")
                        # self.module.log(msg=f"  - alt names: {alt_names}")
                        domains = alt_names

                        if subject not in alt_names:
                            domains += subject

        domains = sorted(domains)
        domains = list(set(domains))

        return domains

    def __exec(self, args, check=True):
        """
        """
        rc, out, err = self.module.run_command(args, check_rc=check)
        # self.module.log(msg=f"  rc : '{rc}'")
        # self.module.log(msg=f"  out: '{out}'")
        # self.module.log(msg=f"  err: '{err}'")
        return rc, out, err


# ===========================================
# Module execution.


def main():

    specs = dict(
        state=dict(
            default="certonly",
            choices=["certonly"]
        ),
        webroot_path=dict(
            required=True,
            type="str"
        ),
        rsa_key_size=dict(
            type="int",
            default=4096
        ),
        domains=dict(
            required=True,
            type="list"
        ),
        certbot_base_directory=dict(
            required=False,
            type="str",
            default="/etc/letsencrypt"
        ),
        email=dict(
            required=True,
            type="str"
        ),
        quiet=dict(
            required=False,
            type="bool",
            default=False
        ),
        test_cert=dict(
            required=False,
            type="bool",
            default=False
        ),
        dry_run=dict(
            required=False,
            type="bool",
            default=False
        ),
        auto_expand=dict(
            required=False,
            type="bool",
            default=False
        ),
        arguments=dict(
            required=False,
            default=[],
            type=list
        )
    )

    module = AnsibleModule(

        argument_spec=specs,
        supports_check_mode=True,
    )
    p = DomainCerts(module)
    result = p.run()

    # module.log(msg="= result: {}".format(result))
    module.exit_json(**result)


if __name__ == '__main__':
    main()
