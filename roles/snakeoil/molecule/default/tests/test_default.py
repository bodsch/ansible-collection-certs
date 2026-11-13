# coding: utf-8
from __future__ import annotations, unicode_literals

import json

from helper.molecule import get_vars, infra_hosts

testinfra_hosts = infra_hosts(host_name="all")


# --- tests -----------------------------------------------------------------


def test_directories(host, get_vars):
    """ """
    wanted_domain = get_vars.get("snakeoil_domain", None)

    dirs = ["/etc/ssl/{0}"]

    for directory in dirs:
        d = host.file(directory.format(wanted_domain))
        assert d.is_directory
