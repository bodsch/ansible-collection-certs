# Ansible role `bodsch.certs.cert_renew`

Manages multiple ACME certificates with `lego-multi-renew.py`, run by a
systemd timer or by cron. The [lego](https://go-acme.github.io/lego/) binary
itself is installed by the `bodsch.certs.lego` role.

* http-01 (webroot or standalone) and dns-01 (any lego DNS provider)
* several issuers: Let's Encrypt, ZeroSSL (EAB), step-ca (private trust anchor), ...
* renewal by expiry threshold **and** on SAN changes (expand / shrink)
* http-01 pre-checks: DNS resolution and `.well-known/acme-challenge` reachability
* install of cert/key/chain with owner and mode, optional certbot-like `live/` layout
* per-certificate hooks, service reload/restart after changes, e-mail report

## Tested operating systems

* ArchLinux
* Debian based

## Usage

```yaml
- hosts: webservers
  roles:
    - role: bodsch.certs.lego          # installs the lego binary
    - role: bodsch.certs.cert_renew    # script, configuration, timer
```

### Variables

```yaml
cert_renew_script: /usr/local/bin/lego-multi-renew.py
cert_renew_lego_binary: /usr/bin/lego

cert_renew_days: 30
cert_renew_key_type: ec256            # rsa2048|rsa3072|rsa4096|rsa8192|ec256|ec384
cert_renew_default_issuer: letsencrypt
cert_renew_live_dir: ""               # e.g. /etc/letsencrypt/live

cert_renew_checks:                    # only for http-01
  dns: true
  well_known: true                    # only in webroot mode
  on_unreachable: drop                # drop | fail | ignore
  timeout: 5

cert_renew_dns_resolver: []           # resolvers for the DNS pre-check

cert_renew_restarts:                  # after any changed certificate
  - service: nginx
    action: reload                    # reload | restart

cert_renew_notification:
  enabled: true
  events: [changed, failed]           # or [always]
  sender: lego@example.com
  recipient: admin@example.com
  smtp:
    server_name: smtp.example.com
    port: 587
    tls: starttls                     # starttls | ssl | none
    auth:
      username: ""
      password: ""

cert_renew_timer:
  enabled: true
  type: systemd                       # systemd | cron (cron is always used without systemd)
  on_calendar: "*-*-* 02:58:00"
  randomized_delay: 1h
  cron:
    minute: "58"
    hour: "2"
    weekday: "*"
```

### Issuers

```yaml
cert_renew_issuers:
  - name: letsencrypt
    server: https://acme-v02.api.letsencrypt.org/directory
    email: pki@example.com
    challenge:
      type: http
      webroot: /var/www/certbot       # webroot mode, or
      # port: 80                      # standalone mode (lego binds the port itself)

  - name: letsencrypt-dns
    server: https://acme-v02.api.letsencrypt.org/directory
    email: pki@example.com
    challenge:
      type: dns
      provider: hetzner               # see `lego dnshelp`
      env:
        HETZNER_API_KEY: "{{ vault_hetzner_api_key }}"
      # env_file: /etc/lego/hetzner.env
      # resolvers: ["9.9.9.9:53"]
      # propagation: {disable_ans: true, rns: false, wait: 30s}

  - name: step-ca-lab
    server: https://ca.lab.local:9000/acme/acme/directory
    email: lego@lab.local
    ca_certificate: /etc/ssl/lab-root.crt
    # preferred_chain: "ISRG Root X1"
    # eab: {kid: "...", hmac_key: "..."}
    challenge:
      type: dns
      provider: pdns
      env:
        PDNS_API_URL: http://dns.lab.local:8081
        PDNS_API_KEY: "{{ vault_pdns_api_key }}"
```

### Certificates

```yaml
cert_renew_certificates:
  - domain: example.com
    subdomains:
      - www.example.com
    # issuer: letsencrypt             # optional with cert_renew_default_issuer
    install:                          # optional
      cert: /etc/nginx/tls/example.com/fullchain.pem
      key: /etc/nginx/tls/example.com/privkey.pem
      ca: /etc/nginx/tls/example.com/chain.pem
      # leaf: ...                     # leaf certificate only
      # combined: ...                 # key + fullchain (haproxy)
      owner: root
      group: www-data
      cert_mode: "0644"
      key_mode: "0640"
    post_hook: systemctl reload nginx

  - domain: "*.example.org"           # wildcards need dns-01
    subdomains: example.org
    issuer: letsencrypt
    key_type: rsa4096
    challenge:                        # merged over the issuer's challenge
      type: dns
      provider: hetzner
      env:
        HETZNER_API_KEY: "{{ vault_hetzner_api_key }}"
    restarts:
      - postfix
```

Hooks:

| key            | runs                                                         |
|----------------|--------------------------------------------------------------|
| `pre_hook`     | before lego is called                                        |
| `cleanup_hook` | after every lego call, successful or not                     |
| `post_hook`    | after a new certificate has been installed                   |

Hooks get `LEGO_RENEW_DOMAIN`, `LEGO_RENEW_DOMAINS`, `LEGO_RENEW_ACTION`,
`LEGO_RENEW_CERT_PATH`, `LEGO_RENEW_KEY_PATH` and `LEGO_RENEW_ISSUER_PATH`
in their environment.

## Files

| path                                  | content                                   |
|---------------------------------------|-------------------------------------------|
| `/etc/lego/renew.yml`                 | script configuration                      |
| `/etc/lego/issuers.d/<name>.yml`      | one file per issuer                       |
| `/etc/lego/domains.d/<domain>.yml`    | one file per certificate (`*` → `_`)       |
| `/var/lib/lego/certificates/`         | lego account and certificate store        |
| `/var/log/lego-renew.log`             | log file                                  |

## Command line

```bash
lego-multi-renew.py --preflight                 # binary, dirs, issuers, domain definitions
lego-multi-renew.py --list [--json]             # certificate state
lego-multi-renew.py --dry-run                   # checks + planned lego calls, no changes
lego-multi-renew.py --domain example.com        # only this certificate (repeatable)
lego-multi-renew.py --domain example.com --force
lego-multi-renew.py --force-restarts --no-notify --verbose --log-level DEBUG
```

Exit codes: `0` ok, `1` a certificate, hook or restart failed, `2` configuration
or pre-flight error.

## Migration from the `lego` role (before the split)

| old                     | new                         |
|-------------------------|-----------------------------|
| `lego_issuers`          | `cert_renew_issuers`        |
| `lego_tls_certificates` | `cert_renew_certificates`   |
| `lego_config_dir`       | `cert_renew_config_dir`     |
| `lego_issuers_dir`      | `cert_renew_issuers_dir`    |
| `lego_domains_dir`      | `cert_renew_domains_dir`    |
| `lego_state_dir`        | `cert_renew_state_dir`      |
| `lego_renew_days`       | `cert_renew_days`           |
| `lego_renew_key_type`   | `cert_renew_key_type`       |
| `lego_renew_lock_file`  | `cert_renew_lock_file`      |

The paths below `/etc/lego` and `/var/lib/lego` stay the same, so existing
accounts and certificates are reused. `/bin/lego-renew.py` is removed.

## Migration from certbot

* Set `cert_renew_live_dir: /etc/letsencrypt/live` so existing webserver
  configurations keep their paths (`cert.pem`, `chain.pem`, `fullchain.pem`,
  `privkey.pem`).
* Point the http-01 issuer `webroot` at the old `certbot_config.www_directory`.
* Domain files in the certbot format (`domains: [a, b]`) are read as well.
* lego keeps its own account and store, so every certificate is issued once
  more on the first run.
