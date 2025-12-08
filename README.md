# Ansible Collection - bodsch.certs

Documentation for the collection.



## supported Operating systems

Tested on

* ArchLinux
* Debian based
    - Debian 10 / 11 / 12 / 13
    - Ubuntu 20.04 / 22.04 / 24.04

> **RedHat-based systems are no longer officially supported! May work, but does not have to.**


## Requirements & Dependencies

- python module: dateutil

```bash
apt-get install -y python3-dateutil


pacman -S python-dateutil
```

## Included content


### Roles

| Role                                                                       | Build State | Description |
|:---------------------------------------------------------------------------| :---------: | :----       |
| [bodsch.certs.snakeoil](./roles/snakeoil/README.md)                        | [![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/bodsch/ansible-collection-certs/snakeoil.yml?branch=main)][snakeoil] | build a simple snakeoil certificate for a test environment. |
| [bodsch.certs.step_ca](./roles/step_ca/README.md)                          | [![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/bodsch/ansible-collection-certs/step_ca.yml?branch=main)][step_ca]   | install and configure `step_ca`. |
| [bodsch.certs.certbot](./roles/certbot/README.md)                          | [![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/bodsch/ansible-collection-certs/certbot.yml?branch=main)][certbot]   | certbot role for multiple ACME certificates. |

[snakeoil]: https://github.com/bodsch/ansible-collection-certs/actions/workflows/snakeoil.yml
[step_ca]: https://github.com/bodsch/ansible-collection-certs/actions/workflows/step_ca.yml
[certbot]: https://github.com/bodsch/ansible-collection-certs/actions/workflows/certbot.yml

### Modules

| Name                      | Description |
|:--------------------------|:----|
| [bodsch.certs.certbot](./plugins/modules/certbot.py)                         | Creates a certificate using Let's Encrypt Certbot |
| [bodsch.certs.domain_certs](./plugins/modules/domain_certs.py)               | Check presence of certificate files created by Let's Encrypt certbot |
| [bodsch.certs.domain_config_files](./plugins/modules/domain_config_files.py) | Manage YAML configuration files with domain lists |
| [bodsch.certs.snakeoil_date](./plugins/modules/snakeoil_date.py)             | Read expiration date of a snakeoil certificate |
| [bodsch.certs.snakeoil_openssl](./plugins/modules/snakeoil_openssl.py)       | Create snakeoil certificates and DH parameters with OpenSSL |
| [bodsch.certs.step_ca](./plugins/modules/step_ca.py)                         | Manage a local smallstep step-ca authority |


## Contribution

Please read [Contribution](CONTRIBUTING.md)

## Development,  Branches (Git Tags)

The `master` Branch is my *Working Horse* includes the "latest, hot shit" and can be complete broken!

If you want to use something stable, please use a [Tagged Version](https://github.com/bodsch/ansible-collection-certs/tags)!


## Author

- Bodo Schulz

## License

[Apache](LICENSE)

**FREE SOFTWARE, HELL YEAH!**
