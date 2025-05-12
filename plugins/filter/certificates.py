# python 3 headers, required if submitting to Ansible
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible.parsing.yaml.objects import AnsibleUnicode
from ansible.utils.display import Display

display = Display()


class FilterModule(object):
    """
    """

    def filters(self):
        return {
            'check_certificates': self.certificates,
            'domain_list': self.domain_list,
            'flatten_domain_list': self.flatten_domain_list,
        }

    def certificates(self, data=None):
        """
        """
        display.v(f" data: ({type(data)}) {data}")

        result = []
        r = data.get('results', [])

        display.v(f" results: ({type(r)}) {r}")

        for k in r:
            item = k.get('item', {})

            if item:
                name = item.get('domain', None)
                exists = k.get('stat', {}).get('exists', False)

                if not exists:
                    result.append(name)
        display.v(f" = result {result}")
        return result

    def domain_list(selfself, data, domain):
        """
        """
        domains = []
        domain_list = []

        for d in data:
            name = d.get("domain")
            domain_list = []
            if name == domain:
                domain_list = d.get("subdomains", [])
                break

        if isinstance(domain_list, list) and len(domain_list) > 0:
            domains = domain_list
            domains.insert(0, domain)
        elif domain_list is None:
            domains = []
            domains.append(domain)
        elif isinstance(domain_list, AnsibleUnicode) or isinstance(domain_list, str):
            domains = []
            domains.append(domain)
            domains.append(domain_list)
        else:
            domains = []
            domains.append(domain)

        return domains

    def flatten_domain_list(selfself, data, with_subdomains=False):
        """
        """
        domains = []

        for d in data:
            name = d.get("domain")
            domains.append(name)

            if with_subdomains:
                domain_list = d.get("subdomains", [])

                if domain_list is None:
                    pass
                elif isinstance(domain_list, list) and len(domain_list) > 0:
                    # add list to other list
                    domains.extend(domain_list)
                elif isinstance(domain_list, AnsibleUnicode) or isinstance(domain_list, str):
                    domains.append(domain_list)
                else:
                    pass

        return domains
