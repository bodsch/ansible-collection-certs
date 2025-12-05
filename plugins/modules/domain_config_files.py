#!/usr/bin/python3
# -*- coding: utf-8 -*-

# (c) 2021-2024, Bodo Schulz <bodo@boone-schulz.de>
# GNU General Public License version 3 (see LICENSE or https://opensource.org/license/gpl-3-0)
# SPDX-License-Identifier: GPL-3.0

from __future__ import absolute_import, division, print_function

import os
import shutil

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.bodsch.core.plugins.module_utils.checksum import Checksum
from ansible_collections.bodsch.core.plugins.module_utils.directory import (
    create_directory,
)
from ansible_collections.bodsch.core.plugins.module_utils.module_results import results

# ---------------------------------------------------------------------------------------

DOCUMENTATION = r"""
---
module: domain_config_files
version_added: "1.0.0"
author:
  - "Bodo 'bodsch' Schulz (@bodsch) <bodo@boone-schulz.de>"
short_description: Manage YAML configuration files with domain lists
description:
  - Generate simple YAML configuration files containing lists of domains and subdomains.
  - One configuration file per primary domain is created in the given directory.
options:
  path:
    description:
      - Directory in which the domain configuration files will be created.
      - One file per domain with the name C(<domain>.yml) is written in this directory.
    type: path
    required: true
  certificates:
    description:
      - List of domain definitions for which configuration files should be generated.
    type: list
    elements: dict
    required: true
    suboptions:
      domain:
        description:
          - Primary domain name.
          - Used as the filename C(<domain>.yml) and as the first entry in the YAML C(domains) list.
        type: str
        required: true
      subdomains:
        description:
          - Additional domains to include in the configuration.
          - Can be a list of strings, a single string, or C(null).
          - When omitted or C(null), only the primary domain is written.
        type: raw
notes:
  - Existing configuration files are only overwritten when the rendered content changes.
  - When a configuration file for a domain does not yet exist, it will be created.
"""

EXAMPLES = r"""
- name: Create domain configuration files for multiple domains
  bodsch.core.domain_config_files:
    path: /etc/certbot/domains.d
    certificates:
      - domain: example.com
        subdomains:
          - www.example.com
          - api.example.com
      - domain: example.org
        subdomains: null

- name: Create configuration for a single domain with one extra name
  bodsch.core.domain_config_files:
    path: /etc/certbot/domains.d
    certificates:
      - domain: example.net
        subdomains: www.example.net

- name: Only primary domains without subdomains
  bodsch.core.domain_config_files:
    path: /etc/certbot/domains.d
    certificates:
      - domain: foo.example.com
      - domain: bar.example.com
"""

RETURN = r"""
---
changed:
  description: Whether any configuration file was created or modified.
  type: bool
  returned: always
failed:
  description: Whether the module execution failed.
  type: bool
  returned: always
state:
  description:
    - List of per-domain result dictionaries.
    - Each item has a single key with the domain name mapped to its result.
  returned: always
  type: list
  elements: dict
  sample:
    - example.com:
        changed: true
        msg: The configuration was successfully written.
    - example.org:
        changed: false
        msg: The configuration has not been changed.
"""

# ---------------------------------------------------------------------------------------


class DomainConfigs(object):
    """ """

    def __init__(self, module):
        """ """
        self.module = module

        self.certificates = module.params.get("certificates")
        self.base_directory = module.params.get("path")
        self.mode = module.params.get("mode")

        pid = os.getpid()
        self.tmp_directory = os.path.join("/run/.ansible", f"certbot.{str(pid)}")

    def run(self):
        """ """
        result_state = []

        create_directory(directory=self.tmp_directory, mode="0750")
        checksum = Checksum(self.module)

        for cert in self.certificates:
            res = {}
            domains = []
            domain = cert.get("domain", None)
            subdomain_list = cert.get("subdomains", [])

            if subdomain_list is None:
                domains.append(domain)
            elif isinstance(subdomain_list, list) and len(subdomain_list) > 0:
                domains = subdomain_list
                domains.insert(0, domain)
            elif isinstance(subdomain_list, str):
                domains.append(domain)
                domains.append(subdomain_list)
            else:
                domains.append(domain)

            file_name = os.path.join(self.base_directory, f"{domain}.yml")
            tmp_file = os.path.join(self.tmp_directory, f"{domain}.yml")

            self.__write_file(domains, tmp_file)

            new_checksum = checksum.checksum_from_file(tmp_file)
            old_checksum = checksum.checksum_from_file(file_name)
            changed = not (new_checksum == old_checksum)
            # new_file = False

            # self.module.log(f" tmp_file      : {tmp_file}")
            # self.module.log(f" config_file   : {file_name}")
            # self.module.log(f" changed       : {changed}")
            # self.module.log(f" new_checksum  : {new_checksum}")
            # self.module.log(f" old_checksum  : {old_checksum}")

            if changed:
                # shutil.copyfile(tmp_file, file_name)

                if os.path.exists(f"{tmp_file}"):
                    shutil.copyfile(f"{tmp_file}", f"{file_name}")

                res[domain] = dict(
                    changed=True, msg="The configuration was successfully written."
                )
            elif not changed and old_checksum is None:
                # shutil.copyfile(tmp_file, file_name)

                if os.path.exists(f"{tmp_file}"):
                    shutil.copyfile(f"{tmp_file}", f"{file_name}")

                res[domain] = dict(
                    changed=True, msg="The configuration was successfully created."
                )

            else:
                res[domain] = dict(
                    changed=False, msg="The configuration has not been changed."
                )

            result_state.append(res)

        _state, _changed, _failed, state, changed, failed = results(
            self.module, result_state
        )

        result = dict(changed=_changed, failed=failed, state=result_state)

        shutil.rmtree(self.tmp_directory)

        return result

    def __yaml_template(self, domain_list):
        """
        generate data from dictionary
        """
        tpl = """---
# generated by ansible

domains:
{%- for i in item %}
  - {{ i }}
{%- endfor %}

"""
        from jinja2 import Template

        tm = Template(tpl)
        d = tm.render(item=domain_list)

        return d

    def __write_file(self, domains, data_file):
        """ """
        data = self.__yaml_template(domains)
        with open(f"{data_file}", "w") as f:
            f.write(data)


def main():

    specs = dict(
        certificates=dict(required=True, type="list"),
        path=dict(required=True, type="str"),
    )

    module = AnsibleModule(
        argument_spec=specs,
        supports_check_mode=True,
    )

    p = DomainConfigs(module)
    result = p.run()

    # module.log(msg=f"= result: {result}")
    module.exit_json(**result)


if __name__ == "__main__":
    main()
