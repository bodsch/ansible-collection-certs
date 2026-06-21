# coding: utf-8
from __future__ import annotations, unicode_literals

import os

import pytest
import testinfra.utils.ansible_runner
from helper.molecule import get_vars, infra_hosts, local_facts

testinfra_hosts = infra_hosts(host_name="instance")

# --- tests -----------------------------------------------------------------


def test_directories(host, get_vars):
    """ """
    dirs = ["/usr/local/opt/lego"]

    for directory in dirs:
        d = host.file(directory)
        assert d.is_directory


def test_files(host, get_vars):
    """ """
    files = [
        "/usr/bin/lego",
    ]

    for f in files:
        f = host.file(f)
        assert f.exists


def test_version(host, get_vars):
    """ """
    distribution = host.system_info.distribution
    release = host.system_info.release

    print(f"distribution: {distribution}")
    print(f"release     : {release}")

    _facts = local_facts(host=host, fact="lego")

    version = _facts.get("version")

    install_dir = get_vars.get("lego_install_path")

    if "latest" in install_dir:
        install_dir = install_dir.replace("latest", version)

    files = []
    files.append("/usr/bin/lego")

    if install_dir:
        files.append(f"{install_dir}/lego")

    print(files)

    for _file in files:
        f = host.file(_file)
        assert f.is_file


def test_user(host, get_vars):
    """ """
    user = get_vars.get("lego_system_user", "lego")
    group = get_vars.get("lego_system_group", "lego")

    assert host.group(group).exists
    assert host.user(user).exists
    assert group in host.user(user).groups
    assert host.user(user).home == "/nonexistent"
