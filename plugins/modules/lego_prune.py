#!/usr/bin/python3
# -*- coding: utf-8 -*-

# (c) 2026, Bodo Schulz <bodo@boone-schulz.de>

"""
Prune unmanaged files from a lego configuration directory.

Replaces the two-task "find + loop file: state=absent" pattern with a
single module invocation. Avoids per-iteration Ansible overhead and
makes the operation atomic from the playbook's point of view.

Used by the C(bodsch.certs.lego) role to clean up
C(/etc/lego/issuers.d/) and C(/etc/lego/domains.d/) after the user
removes an issuer or domain from the role variables.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import glob
import os

from ansible.module_utils.basic import AnsibleModule


DOCUMENTATION = r"""
---
module: lego_prune
version_added: "1.0.0"
short_description: Remove files in a directory that are not in a keep-list
author:
  - "Bodo Schulz (@bodsch) <bodo@boone-schulz.de>"
description:
  - Scans I(path) for files matching I(pattern) and removes any whose
    basename (with I(suffix) stripped) is not present in I(keep).
  - Designed for the C(bodsch.certs.lego) role to prune stale issuer
    and domain configuration files after the user removes entries
    from C(lego_issuers) or C(lego_tls_certificates), but generic
    enough for similar declarative-cleanup needs.
  - Idempotent: nothing is removed if the directory does not exist
    or all files are listed in I(keep).
options:
  path:
    description: Directory to scan.
    type: path
    required: true
  pattern:
    description:
      - Glob pattern relative to I(path). Defaults to C(*) (every file).
    type: str
    default: "*"
  keep:
    description:
      - List of basenames (after stripping I(suffix)) that must stay.
        Anything else matching I(pattern) is deleted.
    type: list
    elements: str
    required: true
  suffix:
    description:
      - Optional suffix stripped from the file's basename before
        comparison with I(keep). Example: with C(suffix='.yml'), a
        file C(foo.yml) is considered as C(foo) for the keep-check.
    type: str
    default: ""
notes:
  - Subdirectories are not traversed; only files directly in I(path).
  - Supports check mode.
"""

EXAMPLES = r"""
- name: prune stale issuer files
  bodsch.certs.lego_prune:
    path: /etc/lego/issuers.d
    pattern: "*.yml"
    suffix: ".yml"
    keep: "{{ lego_issuers | map(attribute='name') | list }}"
  register: _pruned

- name: prune stale domain files
  bodsch.certs.lego_prune:
    path: /etc/lego/domains.d
    pattern: "*.yml"
    suffix: ".yml"
    keep: "{{ lego_tls_certificates | map(attribute='domain') | list }}"
"""

RETURN = r"""
changed:
  description: True if at least one file was removed.
  type: bool
  returned: always
removed:
  description: Basenames (with suffix) of files that were deleted.
  type: list
  elements: str
  returned: always
kept:
  description: Basenames (with suffix) of files that matched I(keep) and stayed.
  type: list
  elements: str
  returned: always
"""


def run_module():
    """Module entry: scan, diff against keep-list, delete."""
    module = AnsibleModule(
        argument_spec=dict(
            path=dict(type="path", required=True),
            pattern=dict(type="str", default="*"),
            keep=dict(type="list", elements="str", required=True),
            suffix=dict(type="str", default=""),
        ),
        supports_check_mode=True,
    )

    path = module.params["path"]
    pattern = module.params["pattern"]
    keep = set(module.params["keep"] or [])
    suffix = module.params["suffix"] or ""

    result = dict(changed=False, removed=[], kept=[])

    if not os.path.isdir(path):
        # Nothing to prune. Not an error — the directory may not exist yet.
        module.exit_json(**result)

    matches = glob.glob(os.path.join(path, pattern))
    files = [m for m in matches if os.path.isfile(m)]

    for filepath in files:
        basename = os.path.basename(filepath)
        stem = basename[: -len(suffix)] if suffix and basename.endswith(suffix) else basename

        if stem in keep:
            result["kept"].append(basename)
            continue

        result["removed"].append(basename)
        if not module.check_mode:
            try:
                os.unlink(filepath)
            except OSError as exc:
                module.fail_json(
                    msg=f"Failed to remove {filepath}: {exc}",
                    **result,
                )

    result["changed"] = bool(result["removed"])
    module.exit_json(**result)


def main():
    """CLI entry point."""
    run_module()


if __name__ == "__main__":
    main()
