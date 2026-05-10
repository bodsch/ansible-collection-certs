# coding: utf-8
from __future__ import annotations, unicode_literals

import pytest
from helper.molecule import get_vars, infra_hosts, local_facts

testinfra_hosts = infra_hosts(host_name="all")

# --- tests -----------------------------------------------------------------

# _facts = local_facts(host=host, fact="step_ca")


def test_directories(host, get_vars):
    """ """
    wanted_domain = get_vars.get("snakeoil_domain", None)

    dirs = ["/opt/step-ca", "/var/log/step-ca"]

    for directory in dirs:
        d = host.file(directory.format(wanted_domain))
        assert d.is_directory


def test_files(host, get_vars):
    """ """
    wanted_domain = get_vars.get("snakeoil_domain", None)

    files = [
        "/etc/default/step-ca",
        "/usr/bin/step-ca",
        "/usr/lib/systemd/system/step-ca.service",
    ]

    for file in files:
        f = host.file(file.format(wanted_domain))
        assert f.exists
