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
        "/usr/bin/step-cli",
        "/usr/lib/systemd/system/step-ca.service",
        "/opt/step-ca/.step/config/ca.json",
        "/opt/step-ca/.step/config/defaults.json",
        "/opt/step-ca/.step/secrets/intermediate_ca_key",
        "/opt/step-ca/.step/secrets/root_ca_key",
    ]

    for file in files:
        f = host.file(file.format(wanted_domain))
        assert f.exists


def test_open_port(host, get_vars):
    for i in host.socket.get_listening_sockets():
        print(i)

    service = host.socket("tcp://0.0.0.0:9000")
    assert service.is_listening


def test_cert(host, get_vars):
    """ """
    wanted_alt_names = get_vars.get("snakeoil_alt_names", [])
    wanted_domain = get_vars.get("snakeoil_domain", None)
    # print(" - {} -> {}".format(wanted_domain, wanted_alt_names))
    if len(wanted_alt_names) > 0:
        """ """
        cert_file_name = os.path.join(
            get_vars.get("snakeoil_local_tmp_directory"),
            wanted_domain,
            f"{wanted_domain}.pem",
        )

        if os.path.exists(cert_file_name):
            try:
                cert_dict = ssl._ssl._test_decode_cert(cert_file_name)
            except Exception as e:
                assert "Error decoding certificate: {0:}".format(e)
            else:
                # get all alternative names
                alt_names = cert_dict.get("subjectAltName")
                # convert tuple to dict
                alt_names = dict(map(reversed, alt_names))
                # print(f"found in certificate: {alt_names}")
                # seperate values
                alt_dns = [k for k, v in alt_names.items() if v == "DNS"]
                alt_ips = [k for k, v in alt_names.items() if v == "IP Address"]
                # print(f"DNS: {alt_dns}")
                # print(f"IP : {alt_ips}")
                for n in wanted_alt_names:
                    dns = n.get("dns", [])
                    ip = n.get("ip", [])
                    # assert for all DNS entries
                    for d in dns:
                        assert d in alt_dns
                    # assert for all IP entries
                    for i in ip:
                        assert i in alt_ips
        else:
            assert False, f"file {cert_file_name} is not present on ansible controller"
