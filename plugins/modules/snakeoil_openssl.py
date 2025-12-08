#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2021-2023, Bodo Schulz <bodo@boone-schulz.de>
# Apache-2.0 (see LICENSE or https://opensource.org/license/apache-2-0/)
# SPDX-License-Identifier: Apache-2.0

from __future__ import absolute_import, print_function

import os
import re

from ansible.module_utils.basic import AnsibleModule

# ---------------------------------------------------------------------------------------

DOCUMENTATION = r"""
---
module: snakeoil_openssl
version_added: "1.0.0"
short_description: Create snakeoil certificates and DH parameters with OpenSSL
author:
  - "Bodo Schulz (@bodsch) <bodo@boone-schulz.de>"

description:
  - Uses the C(openssl) command line tool to generate simple self-signed "snakeoil" certificates and Diffie-Hellman parameters.
  - Supports creation of a private key and CSR, a self-signed certificate including a combined PEM file, DH parameter generation,
    and inspection of an existing DH parameter file size.

requirements:
  - openssl

options:
  state:
    description:
      - Action to perform.
      - C(csr) creates a new private key and certificate signing request (CSR) for the given domain.
      - C(crt) creates a self-signed certificate from an existing CSR and key and writes a combined C(.pem) file.
      - C(dhparam) generates a new Diffie-Hellman parameter file.
      - C(dhparam_size) inspects the size of an existing Diffie-Hellman parameter file.
    type: str
    required: true
    choices:
      - csr
      - crt
      - dhparam
      - dhparam_size
  directory:
    description:
      - Base directory containing the per-domain subdirectory.
      - The module expects all files to reside in C(<directory>/<domain>).
      - The directory must exist; it is not created automatically.
    type: path
    required: true
  domain:
    description:
      - Domain (subdirectory) for which to create or read the files.
      - All generated files are placed under C(<directory>/<domain>).
      - The subdirectory must exist; it is not created automatically.
    type: path
    required: true
  dhparam:
    description:
      - Size in bits of the Diffie-Hellman parameters when I(state=dhparam).
      - Passed directly as the last argument to C(openssl dhparam).
    type: int
    default: 2048
  cert_life_time:
    description:
      - Lifetime in days of the self-signed certificate when I(state=crt).
      - Passed as C(-days) to C(openssl x509).
    type: int
    default: 10
  openssl_config:
    description:
      - Path to an OpenSSL configuration file.
      - Required for I(state=csr) and I(state=crt).
      - For I(state=crt) it must provide a C([req_ext]) section referenced via C(-extensions req_ext).
    type: str

notes:
  - This module does not support check mode.
  - The module is not idempotent; repeated runs with the same parameters for I(state=csr), I(state=crt) or I(state=dhparam)
    will recreate keys, certificates or DH parameters.
"""

EXAMPLES = r"""
- name: Create CSR and private key for example.org
  bodsch.core.snakeoil_openssl:
    state: csr
    directory: /etc/ssl/snakeoil
    domain: example.org
    openssl_config: /etc/ssl/snakeoil/example.org/openssl.cnf

- name: Create self-signed certificate and combined PEM for example.org
  bodsch.core.snakeoil_openssl:
    state: crt
    directory: /etc/ssl/snakeoil
    domain: example.org
    cert_life_time: 365
    openssl_config: /etc/ssl/snakeoil/example.org/openssl.cnf

- name: Generate 4096-bit DH parameters
  bodsch.core.snakeoil_openssl:
    state: dhparam
    directory: /etc/ssl/snakeoil
    domain: example.org
    dhparam: 4096

- name: Read DH parameter size
  bodsch.core.snakeoil_openssl:
    state: dhparam_size
    directory: /etc/ssl/snakeoil
    domain: example.org
  register: dh_size

- name: Fail if DH parameters are too small
  ansible.builtin.fail:
    msg: "DH params too small ({{ dh_size.size }} bits)"
  when:
    - dh_size.size | int < 2048
"""

RETURN = r"""
changed:
  description:
    - Indicates if any files were created or modified.
    - For I(state=csr), I(state=crt) and I(state=dhparam) the value is C(true) on success.
    - For I(state=dhparam_size) the value is always C(false).
  returned: always
  type: bool

failed:
  description:
    - Indicates whether the module failed to complete the requested action.
  returned: always
  type: bool

msg:
  description:
    - Human-readable status message, for example C("success") or an error description such as a missing directory.
  returned: sometimes
  type: str

size:
  description:
    - Size of the DH parameters in bits when I(state=dhparam_size).
    - Returns C(0) if the DH parameter file is missing or cannot be read.
  returned: when I(state=dhparam_size)
  type: int
"""

# ---------------------------------------------------------------------------------------


class SnakeoilOpenssl(object):
    """ """

    module = None

    def __init__(self, module):
        """
        Initialize all needed Variables
        """
        self.module = module

        self._openssl = module.get_bin_path("openssl", True)
        self.state = module.params.get("state")
        self.directory = module.params.get("directory")
        self.domain = module.params.get("domain")
        self.dhparam = module.params.get("dhparam")
        self.cert_life_time = module.params.get("cert_life_time")
        self.openssl_config = module.params.get("openssl_config")

    def run(self):
        """ """
        result = dict(failed=True, changed=False, msg="failed")

        # base_directory = os.path.join(self.directory, self.domain)
        #
        # if not os.path.isdir(base_directory):
        #     return dict(
        #         failed=True,
        #         changed=False,
        #         msg=f"missing directory {base_directory}"
        #     )
        #
        # os.chdir(base_directory)

        error, msg = self._base_directory()

        if error:
            return dict(failed=True, changed=False, msg=msg)

        _ssl_args = []

        csr_file = os.path.join(self.directory, self.domain, f"{self.domain}.csr")
        crt_file = os.path.join(self.directory, self.domain, f"{self.domain}.crt")
        pem_file = os.path.join(self.directory, self.domain, f"{self.domain}.pem")
        key_file = os.path.join(self.directory, self.domain, f"{self.domain}.key")
        dh_file = os.path.join(self.directory, self.domain, "dh.pem")

        if self.state == "csr":
            _ssl_args.append(self._openssl)
            _ssl_args.append("req")
            _ssl_args.append("-new")
            _ssl_args.append("-sha512")
            _ssl_args.append("-nodes")
            _ssl_args.append("-out")
            _ssl_args.append(csr_file)
            _ssl_args.append("-newkey")
            _ssl_args.append("rsa:4096")
            _ssl_args.append("-keyout")
            _ssl_args.append(key_file)
            _ssl_args.append("-config")
            _ssl_args.append(self.openssl_config)

            # error, msg = self._base_directory()
            #
            # if error:
            #     return dict(failed=True, changed=False, msg=msg)

            rc, out, err = self._exec(_ssl_args)

            result = dict(failed=False, changed=True, msg="success")

        if self.state == "crt":
            _ssl_args.append(self._openssl)
            _ssl_args.append("x509")
            _ssl_args.append("-req")
            _ssl_args.append("-in")
            _ssl_args.append(csr_file)
            _ssl_args.append("-out")
            _ssl_args.append(crt_file)
            _ssl_args.append("-signkey")
            _ssl_args.append(key_file)
            _ssl_args.append("-extfile")
            _ssl_args.append(self.openssl_config)
            _ssl_args.append("-extensions")
            _ssl_args.append("req_ext")
            _ssl_args.append("-days")
            _ssl_args.append(str(self.cert_life_time))

            # error, msg = self._base_directory()
            #
            # if error:
            #     return dict(failed=True, changed=False, msg=msg)

            rc, out, err = self._exec(_ssl_args)

            # cat {{ domain }}.crt {{ domain }}.key >> {{ domain }}.pem
            if rc == 0:
                filenames = [crt_file, key_file]
                with open(pem_file, "w") as outfile:
                    for fname in filenames:
                        with open(fname) as infile:
                            outfile.write(infile.read())

            result = dict(failed=False, changed=True, msg="success")

        if self.state == "dhparam":
            _ssl_args.append(self._openssl)
            _ssl_args.append("dhparam")
            _ssl_args.append("-5")
            _ssl_args.append("-out")
            _ssl_args.append(dh_file)
            _ssl_args.append(str(self.dhparam))

            # error, msg = self._base_directory()
            #
            # if error:
            #     return dict(failed=True, changed=False, msg=msg)

            rc, out, err = self._exec(_ssl_args)

            result = dict(failed=False, changed=True, msg="success")

        if self.state == "dhparam_size":
            _ssl_args.append(self._openssl)
            _ssl_args.append("dhparam")
            _ssl_args.append("-in")
            _ssl_args.append(dh_file)
            _ssl_args.append("-text")

            # error, msg = self._base_directory()
            #
            # if error:
            #     return dict(failed=False, changed=False, size=int(0))

            rc, out, err = self._exec(_ssl_args)

            if rc == 0:
                """ """
                output_string = 0
                pattern = re.compile(r".*DH Parameters: \((?P<size>\d+) bit\).*")

                result = re.search(pattern, out)
                if result:
                    output_string = result.group("size")

            result = dict(failed=False, changed=False, size=int(output_string))

        return result

    def _base_directory(self):
        """ """
        error = False
        msg = ""

        base_directory = os.path.join(self.directory, self.domain)

        if os.path.isdir(base_directory):
            os.chdir(base_directory)
        else:
            error = True
            msg = f"missing directory {base_directory}"

        return (error, msg)

    def _exec(self, args):
        """ """
        rc, out, err = self.module.run_command(args, check_rc=True)
        # self.module.log(msg=f"  rc : '{rc}'")
        if rc != 0:
            self.module.log(msg=f"  out: '{str(out)}'")
            self.module.log(msg=f"  err: '{str(err)}'")

        return (rc, out, err)


# ===========================================
# Module execution.
#


def main():
    """ """
    args = dict(
        state=dict(required=True, choose=["crt", "csr", "dhparam" "dhparam_size"]),
        directory=dict(required=True, type="path"),
        domain=dict(required=True, type="path"),
        dhparam=dict(default=2048, type="int"),
        cert_life_time=dict(default=10, type="int"),
        openssl_config=dict(required=False, type="str"),
        # openssl_params=dict(required=True, type="path"),
    )

    module = AnsibleModule(
        argument_spec=args,
        supports_check_mode=False,
    )

    openssl = SnakeoilOpenssl(module)
    result = openssl.run()

    # module.log(msg=f"= result : '{result}'")

    module.exit_json(**result)


# import module snippets
if __name__ == "__main__":
    main()
