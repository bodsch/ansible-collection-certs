from __future__ import annotations, unicode_literals

import os

import pytest
import testinfra.utils.ansible_runner
from helper.molecule import get_vars, infra_hosts, local_facts

testinfra_hosts = infra_hosts(host_name="instance")

# --- tests -----------------------------------------------------------------


def test_directories(host, get_vars):
    """ """
    dirs = ["/usr/local/opt/mkcert"]

    for directory in dirs:
        d = host.file(directory)
        assert d.is_directory


def test_files(host, get_vars):
    """ """
    files = [
        "/usr/bin/mkcert",
    ]

    for f in files:
        f = host.file(f)
        assert f.exists


def test_version(host, get_vars):
    """ """
    distribution = host.system_info.distribution
    release = host.system_info.release
    version = local_facts(host=host, fact="mkcert").get("version")

    print(f"distribution: {distribution}")
    print(f"release     : {release}")
    print(f"version     : {version}")

    install_dir = get_vars.get("mkcert_install_path")

    if "latest" in install_dir:
        install_dir = install_dir.replace("latest", version)

    files = []
    files.append("/usr/bin/mkcert")

    if install_dir:
        files.append(f"{install_dir}/mkcert")

    print(files)

    for _file in files:
        f = host.file(_file)
        assert f.is_file


def test_user(host, get_vars):
    """ """
    user = get_vars.get("mkcert_system_user", {})
    owner = user.get("owner", "mkcert")
    group = user.get("group", "mkcert")

    assert host.group(group).exists
    assert host.user(owner).exists
    assert group in host.user(owner).groups
    assert host.user(owner).home == "/nonexistent"
