# python 3 headers, required if submitting to Ansible

from __future__ import (absolute_import, print_function)
__metaclass__ = type

from ansible.utils.display import Display

display = Display()


class FilterModule(object):
    """
        Ansible file jinja2 tests
    """

    def filters(self):
        return {
            'pip_requirements': self.pip_requirements,
        }

    def pip_requirements(self, data):
        """
        """
        result = []

        if isinstance(data, list):
            for entry in data:
                display.v(f"  - {entry}")
                name = entry.get("name")
                compare_direction = entry.get("compare_direction", None)
                version = entry.get("version", None)
                versions = entry.get("versions", [])
                url = entry.get("url", None)

                if isinstance(version, str):
                    if compare_direction:
                        version = f"{compare_direction} {version}"
                    else:
                        version = f"== {version}"

                    result.append(f"{name} {version}")

                elif isinstance(versions, list) and len(versions) > 0:
                    versions = ", ".join(versions)
                    result.append(f"{name} {versions}")

                elif isinstance(url, str):
                    result.append(f"{name} @ {url}")

                else:
                    result.append(name)

        return result
