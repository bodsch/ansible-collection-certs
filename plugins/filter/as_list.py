# (c) 2026, Bodo Schulz <bodo@boone-schulz.de>

"""
Filter plugin: as_list.

Normalises a scalar-or-list input to a list, so a YAML key that accepts
either a single string or a list of strings can be consumed uniformly
in downstream code:

    "systemctl reload nginx"          -> ["systemctl reload nginx"]
    ["a", "b"]                        -> ["a", "b"]
    None                              -> []
    ""                                -> []
"""




def as_list(value):
    """Return ``value`` as a list."""
    if value is None or value == "":
        return []
    if isinstance(value, (list, tuple)):
        return [item for item in value if item not in (None, "")]
    return [value]


class FilterModule:
    """Ansible filter plugin entry."""

    def filters(self):
        return {
            "as_list": as_list,
        }
