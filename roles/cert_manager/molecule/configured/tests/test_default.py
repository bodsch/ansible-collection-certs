# coding: utf-8
from __future__ import annotations, unicode_literals

import json

from helper.molecule import get_vars, infra_hosts

testinfra_hosts = infra_hosts(host_name="all")


# --- tests -----------------------------------------------------------------


def test_lego_binary(host, get_vars):
    """the lego role has to provide the binary"""
    binary = get_vars.get("cert_manager_lego_binary", "/usr/bin/lego")
    assert host.file(binary).exists


def test_directories(host, get_vars):
    for key in ("config_dir", "issuers_dir", "domains_dir", "state_dir"):
        d = host.file(get_vars.get(f"cert_manager_{key}"))
        assert d.is_directory


def test_files(host, get_vars):
    script = get_vars.get("cert_manager_script", "/usr/bin/cert-manager.py")
    config_dir = get_vars.get("cert_manager_config_dir", "/etc/cert-manager")

    f = host.file(script)
    assert f.is_file
    assert f.mode == 0o750

    f = host.file(f"{config_dir}/renew.yml")
    assert f.is_file
    assert f.mode == 0o640

    assert not host.file("/bin/lego-renew.py").exists


def test_issuer_and_domain_files(host, get_vars):
    issuers_dir = get_vars.get("cert_manager_issuers_dir")
    domains_dir = get_vars.get("cert_manager_domains_dir")

    for issuer in get_vars.get("cert_manager_issuers", []):
        assert host.file(f"{issuers_dir}/{issuer['name']}.yml").is_file

    for cert in get_vars.get("cert_manager_certificates", []):
        name = cert["domain"].replace("*", "_")
        assert host.file(f"{domains_dir}/{name}.yml").is_file


def test_list(host, get_vars):
    script = get_vars.get("cert_manager_script", "/usr/bin/cert-manager.py")
    cmd = host.run(f"{script} --list --json")
    assert cmd.rc == 0

    listed = {row["domain"] for row in json.loads(cmd.stdout)}
    expected = {c["domain"] for c in get_vars.get("cert_manager_certificates", [])}

    print(f"listed  : {listed}")
    print(f"expected: {expected}")

    assert listed == expected


def test_timer(host, get_vars):
    if host.system_info.type != "linux" or not host.file("/run/systemd/system").exists:
        return

    systemd_service = "/usr/lib/systemd/system/cert-manager.timer"
    systemd_timer = "/usr/lib/systemd/system/cert-manager.service"

    enabled_systemd_timer = "/etc/systemd/system/timers.target.wants/cert-manager.timer"

    assert host.file(systemd_service).is_file
    assert host.file(systemd_timer).is_file

    assert not host.file(enabled_systemd_timer).is_file
