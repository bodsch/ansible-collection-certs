# ansible rolle `multi-certbot`

certbot role for multiple ACME certificates

## tested operating systems

* ArchLinux
* Debian based
    - Debian 11 / 12
    - Ubuntu 22.04


## usage

```yaml
certbot_config:
  conf_directory: /etc/letsencrypt
  www_directory: /var/www/certbot
  well_known_directory: /var/www/certbot/.well-known/acme-challenge
  rsa_key_size: 4096
  email: pki@test.com
  expire_days_limit: 20

certbot_tls_certificates: []


certbot_notification:
  enabled: false
  smtp:
    server_name: localhost      # smtp.example.com
    port: 25                    # 587
    auth:
      username: ""              #
      password: ""              #
  sender: ""                    # backup@example.com
  recipient: ""                 # admin@foo.bar

certbot_test_cert: true
certbot_dry_run: true
certbot_auto_expand: false

certbot_systemd: {}
#  use_timer: true
#  service_name:
#    timer: certbot.timer
#    service: certbot.service

certbot_staging_args: []
#  - --test-cert
#  - --dry-run

certbot_restart_services: []
#  - service: nginx
```

### `certbot_tls_certificates`

```yaml
certbot_tls_certificates:
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
Hierzu wird eine temporäre zufällige Datei im Verzeichniss `certbot_well_known_directory` erstellt und diese
anschließend über abgefragt.

Desweiteren wird geprüft, ob sämtliche konfigurierte Domains im Zertifikat verfügbar sind.

Ist dies nicht der Fall, wird das Zertifikat automatisch erweitert.

## Author

- Bodo Schulz

## License

[Apache](LICENSE)

**FREE SOFTWARE, HELL YEAH!**
