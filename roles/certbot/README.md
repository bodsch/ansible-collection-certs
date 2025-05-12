# ansible rolle `multi-certbot`

certbot role for multiple ACME certificates


[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/bodsch/ansible-multidomain-certbot/main.yml?branch=main)][ci]
[![GitHub issues](https://img.shields.io/github/issues/bodsch/ansible-multidomain-certbot)][issues]
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/bodsch/ansible-multidomain-certbot)][releases]
[![Ansible Downloads](https://img.shields.io/ansible/role/d/bodsch/multidomain_certbot?logo=ansible)][galaxy]

[ci]: https://github.com/bodsch/ansible-multidomain-certbot/actions
[issues]: https://github.com/bodsch/ansible-multidomain-certbot/issues?q=is%3Aopen+is%3Aissue
[releases]: https://github.com/bodsch/ansible-multidomain-certbot/releases
[galaxy]: https://galaxy.ansible.com/ui/standalone/roles/bodsch/multidomain_certbot/

## Requirements & Dependencies

Ansible Collections

- [bodsch.core](https://github.com/bodsch/ansible-collection-core)

```bash
ansible-galaxy collection install bodsch.core
```
or
```bash
ansible-galaxy collection install --requirements-file collections.yml
```

## tested operating systems

* ArchLinux
* Debian based
    - Debian 11 / 12
    - Ubuntu 22.04


## usage

```yaml
multi_certbot_config:
  conf_directory: /etc/letsencrypt
  www_directory: /var/www/certbot
  well_known_directory: /var/www/certbot/.well-known/acme-challenge
  rsa_key_size: 4096
  email: pki@test.com
  expire_days_limit: 20

multi_certbot_tls_certificates: []


multi_certbot_notification:
  enabled: false
  smtp:
    server_name: localhost      # smtp.example.com
    port: 25                    # 587
    auth:
      username: ""              #
      password: ""              #
  sender: ""                    # backup@example.com
  recipient: ""                 # admin@foo.bar

multi_certbot_test_cert: true
multi_certbot_dry_run: true
multi_certbot_auto_expand: false

multi_certbot_systemd: {}
#  use_timer: true
#  service_name:
#    timer: certbot.timer
#    service: certbot.service

multi_certbot_staging_args: []
#  - --test-cert
#  - --dry-run

multi_certbot_restart_services: []
#  - service: nginx
```

### `multi_certbot_tls_certificates`

```yaml
multi_certbot_tls_certificates:
  - domain: foo.bar
    subdomains:
  - domain: bar.foo
    subdomains: www.bar.foo
  - domain: test.com
    subdomains:
      - www.test.com
      - www1.test.com
      - www2.test.com
```

## certificate renew

Alle vorliegenden Zertifikate werden über das Script `/usr/local/bin/certbot-renew.py` erneuert.

Diese werden ausschließlich via *webroot* erneuert!  
Um das zu gewährleisten wird die Erreichbarkeit der Domain geprüft.  
Hierzu wird eine temporäre zufällige Datei im Verzeichniss `multi_certbot_well_known_directory` erstellt und diese
anschließend über abgefragt.

Desweiteren wird geprüft, ob sämtliche konfigurierte Domains im Zertifikat verfügbar sind.

Ist dies nicht der Fall, wird das Zertifikat automatisch erweitert.


## Contribution

Please read [Contribution](CONTRIBUTING.md)

## Development,  Branches (Git Tags)

The `master` Branch is my *Working Horse* includes the "latest, hot shit" and can be complete broken!

If you want to use something stable, please use a [Tagged Version](https://github.com/bodsch/ansible-multidomain-certbot/tags)!

## Author

- Bodo Schulz

## License

[Apache](LICENSE)

**FREE SOFTWARE, HELL YEAH!**
