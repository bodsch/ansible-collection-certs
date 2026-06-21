

/usr/local/opt/lego/4.25.0/lego --accept-tos --email lego@lab.local --server https://ca.lab.local:9000/acme/acme/directory --path /var/lib/lego --key-type ec256 --dns pdns -d lab.local -d www.lab.local -d api.lab.local run


lego dnshelp -c pdns
lego dnshelp -c netcup

2026-06-21 05:55:20 DEBUG   effective config: {'lego_binary': '/usr/local/opt/lego/4.25.0/lego', 'state_dir': '/var/lib/lego', 'issuers_dir': '/etc/lego/issuers.d', 'domains_dir': '/etc/lego/domains.d', 'renewal_days': 30, 'key_type': 'ec256', 'lock_file': '/run/lego-renew.lock'}
2026-06-21 05:55:20 INFO    === lab.local (issuer=step-ca-lab) ===
2026-06-21 05:55:20 DEBUG   mode=run not_after_before=None
2026-06-21 05:55:20 INFO    [dry-run] would exec: /usr/local/opt/lego/4.25.0/lego --accept-tos --email lego@lab.local --server https://ca.lab.local:9000/acme/acme/directory --path /var/lib/lego --key-type ec256 --dns pdns -d lab.local -d www.lab.local -d api.lab.local run
2026-06-21 05:55:20 INFO    === mail.lab.local (issuer=step-ca-lab) ===
2026-06-21 05:55:20 DEBUG   mode=run not_after_before=None
2026-06-21 05:55:20 INFO    [dry-run] would exec: /usr/local/opt/lego/4.25.0/lego --accept-tos --email lego@lab.local --server https://ca.lab.local:9000/acme/acme/directory --path /var/lib/lego --key-type ec256 --dns pdns -d mail.lab.local run
2026-06-21 05:55:20 INFO    summary: skipped=2


2026-06-21 05:56:26 DEBUG   effective config: {'lego_binary': '/usr/local/opt/lego/4.25.0/lego', 'state_dir': '/var/lib/lego', 'issuers_dir': '/etc/lego/issuers.d', 'domains_dir': '/etc/lego/domains.d', 'renewal_days': 30, 'key_type': 'ec256', 'lock_file': '/run/lego-renew.lock'}
2026-06-21 05:56:26 INFO    === lab.local (issuer=step-ca-lab) ===
2026-06-21 05:56:26 DEBUG   mode=run not_after_before=None
2026-06-21 05:56:26 INFO    === mail.lab.local (issuer=step-ca-lab) ===
2026-06-21 05:56:26 DEBUG   mode=run not_after_before=None
2026-06-21 05:56:26 INFO    summary: failed=2
2026-06-21 05:56:26 ERROR   failures: lab.local, mail.lab.local

root@instance:/# /usr/local/opt/lego/4.25.0/lego --accept-tos --email lego@lab.local --server https://ca.lab.local:9000/acme/acme/directory  --path /var/lib/lego --key-type ec256 --dns pdns -d lab.local -d www.lab.local -d api.lab.local run
2026/06/21 05:57:35 Could not create client: get directory at 'https://ca.lab.local:9000/acme/acme/directory': Get "https://ca.lab.local:9000/acme/acme/directory": GET https://ca.lab.local:9000/acme/acme/directory giving up after 1 attempt(s): Get "https://ca.lab.local:9000/acme/acme/directory": tls: failed to verify certificate: x509: certificate signed by unknown authority
