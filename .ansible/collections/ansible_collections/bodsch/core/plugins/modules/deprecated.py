#!/usr/bin/python

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type
from ansible.module_utils.basic import AnsibleModule

# https://stackoverflow.com/a/73422966


class Deprecated():
    def __init__(self, module):
        """
        """
        self.module = module
        self. msg = module.params.get("msg")

    def run(self):
        """
        """
        return dict(
            changed=False,
            msg="\n".join(self.msg)
        )


def main():
    """
    """
    module = AnsibleModule(
        argument_spec=dict(
            msg=dict(
                type='list',
                required=True
            )
        ),
        supports_check_mode=True,
    )

    o = Deprecated(module)
    result = o.run()

    module.log(msg=f"= result: {result}")

    module.exit_json(**result)


if __name__ == '__main__':
    main()
