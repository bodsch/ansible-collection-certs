
from ansible.parsing.dataloader import DataLoader
from ansible.template import Templar
import pytest
import os
import testinfra.utils.ansible_runner

import pprint
pp = pprint.PrettyPrinter()

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('instance')


def base_directory():
    cwd = os.getcwd()

    if ('group_vars' in os.listdir(cwd)):
        directory = "../.."
        molecule_directory = "."
    else:
        directory = "."
        molecule_directory = "molecule/{}".format(
            os.environ.get('MOLECULE_SCENARIO_NAME'))

    return directory, molecule_directory


def read_ansible_yaml(file_name, role_name):
    ext_arr = ["yml", "yaml"]

    read_file = None

    for e in ext_arr:
        test_file = "{}.{}".format(file_name, e)
        if os.path.isfile(test_file):
            read_file = test_file
            break

    return "file={} name={}".format(read_file, role_name)


@pytest.fixture()
def get_vars(host):
    """
        parse ansible variables
        - defaults/main.yml
        - vars/main.yml
        - vars/${DISTRIBUTION}.yaml
        - molecule/${MOLECULE_SCENARIO_NAME}/group_vars/all/vars.yml
    """
    base_dir, molecule_dir = base_directory()
    distribution = host.system_info.distribution

    if distribution in ['debian', 'ubuntu']:
        os = "debian"
    elif distribution in ['centos', 'redhat', 'ol']:
        os = "redhat"
    elif distribution in ['arch']:
        os = "archlinux"

    print(" -> {} / {}".format(distribution, os))

    file_defaults = read_ansible_yaml("{}/defaults/main".format(base_dir), "role_defaults")
    file_vars = read_ansible_yaml("{}/vars/main".format(base_dir), "role_vars")
    file_distibution = read_ansible_yaml("{}/vars/{}".format(base_dir, os), "role_distibution")
    file_molecule = read_ansible_yaml("{}/group_vars/all/vars".format(base_dir), "test_vars")
    # file_host_molecule = read_ansible_yaml("{}/host_vars/{}/vars".format(base_dir, HOST), "host_vars")

    defaults_vars = host.ansible("include_vars", file_defaults).get("ansible_facts").get("role_defaults")
    vars_vars = host.ansible("include_vars", file_vars).get("ansible_facts").get("role_vars")
    distibution_vars = host.ansible("include_vars", file_distibution).get("ansible_facts").get("role_distibution")
    molecule_vars = host.ansible("include_vars", file_molecule).get("ansible_facts").get("test_vars")
    # host_vars          = host.ansible("include_vars", file_host_molecule).get("ansible_facts").get("host_vars")

    ansible_vars = defaults_vars
    ansible_vars.update(vars_vars)
    ansible_vars.update(distibution_vars)
    ansible_vars.update(molecule_vars)
    # ansible_vars.update(host_vars)

    templar = Templar(loader=DataLoader(), variables=ansible_vars)
    result = templar.template(ansible_vars, fail_on_undefined=False)

    return result


def test_package(host, get_vars):
    p = host.package("certbot")
    assert p.is_installed


@pytest.mark.parametrize("dirs", [
    "/etc/certbot",
    "/etc/certbot/domains",
    "/etc/letsencrypt",
    "/var/www/certbot",
    "/etc/systemd/system/certbot.service.d"
])
def test_directories(host, dirs):
    d = host.file(dirs)
    assert d.is_directory
    assert d.exists


@pytest.mark.parametrize("files", [
    "/etc/certbot/renew.yml",
    "/etc/certbot/domains/boone-schulz.lan.yml",
    "/etc/certbot/domains/haus-der-schmerzen.lan.yml",
    "/etc/certbot/domains/zweit-hirn.lan.yml",
    "/etc/systemd/system/certbot.service.d/overwrite.conf"
])
def test_files(host, files):
    f = host.file(files)
    assert f.exists
    assert f.is_file


# def test_user(host):
#     assert host.group("www-data").exists
#     assert host.user("www-data").exists
#     assert "www-data" in host.user("www-data").groups
#     assert host.user("www-data").home == "/var/www"
#
#
# def test_service(host, get_vars):
#     service = host.service("nginx")
#     assert service.is_enabled
#     assert service.is_running
#
#
# def test_open_port(host, get_vars):
#     for i in host.socket.get_listening_sockets():
#         print(i)
#
#     bind_address = "0.0.0.0"
#     bind_port = "80"
#
#     service = host.socket("tcp://{0}:{1}".format(bind_address, bind_port))
#     assert service.is_listening
