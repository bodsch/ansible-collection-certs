# coding: utf-8
from __future__ import annotations, unicode_literals

import json
import os
import ssl

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


def test_files(host, get_vars):
    """ """
    wanted_domain = get_vars.get("snakeoil_domain", None)

    files = [
        "/etc/ssl/{0}/dh.pem",
        "/etc/ssl/{0}/{0}.conf",
        "/etc/ssl/{0}/{0}.crt",
        "/etc/ssl/{0}/{0}.csr",
        "/etc/ssl/{0}/{0}.key",
        "/etc/ssl/{0}/{0}.pem",
    ]

    for file in files:
        f = host.file(file.format(wanted_domain))
        assert f.exists


def test_cert(host, get_vars):
    """ """
    wanted_alt_names = get_vars.get("snakeoil_alt_names", [])
    wanted_domain = get_vars.get("snakeoil_domain", None)
    print(f" - {wanted_domain} -> {wanted_alt_names}")

    if len(wanted_alt_names) > 0:
        """ """
        cert_file_name = os.path.join(
            get_vars.get("snakeoil_local_tmp_directory"),
            wanted_domain,
            f"{wanted_domain}.pem",
        )

        print(cert_file_name)

        if os.path.exists(cert_file_name):
            try:
                cert_dict = ssl._ssl._test_decode_cert(cert_file_name)
            except Exception as e:
                assert f"Error decoding certificate: {e:}"
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
