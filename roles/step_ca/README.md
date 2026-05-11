# ansible role `bodsch.certs.step_ca`

Ansible Role to install and manage teh [smallstep](https://smallstep.com/docs/platform/) Service.

## tested operating systems

* ArchLinux
* Debian based
    - Debian 12 / 13
    - Ubuntu 22.04 / 24.04


## usage

```yaml
step_ca_packages:
  - step-cli
  - step-ca

step_ca_system:
  owner: step-ca
  group: step-ca
  home: /opt/step-ca

step_ca_service:
  state: started
  enabled: true

step_ca_force: false

step_ca_support_acme: false

# e.g. 'cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 64 | head -n 1'
step_ca_init_password: ""

step_ca_admins: []
#   - subject: alice@example.com
#     provisioner: admin
#     type: ADMIN
#   - subject: bob@example.com
#     provisioner: admin
#     type: SUPER_ADMIN

step_ca_authority:
  name: "Local Lab CA"
  listen:
    address: 0.0.0.0
    port: 9000
  dns: []
  #   - ca.lab.local        # erster Eintrag = primärer Hostname für API-Zugriff
  #   - localhost           # Fallback für lokalen Zugriff vom CA-Host
  provisioners: []
  #   - name: acme
  #     type: ACME
  #     challenges: [http-01, dns-01, tls-alpn-01]
  # 
  #   - name: acme-dns
  #     type: ACME
  #     require_eab: false       # im OS step-ca nicht nutzbar
  #     challenges: [dns-01]
  #     claims:
  #       tls_duration:
  #         default: 720h
  #         max: 2160h
  #       disable_renewal: false
  #       allow_renewal_after_expiry: false

step_ca_admin_connection:
  ca_url: "https://localhost:{{ step_ca_authority.listen.port }}"
  ca_root: "{{ step_ca_system.home }}/.step/certs/root_ca.crt"
  admin_provisioner: admin
  admin_subject: step
  admin_password_file: "{{ step_ca_system.home }}/.step.password"

step_ca_authority_policy: {}
#  x509:
#    allow:
#      dns: ["*.lab.local", "lab.local", "step"]   # 'step' wegen Lock-Out-Schutz
#      ips: ["10.42.0.0/16"]
#    allow_wildcard_names: true
```


## Author

- Bodo Schulz

## License

[Apache](LICENSE)

**FREE SOFTWARE, HELL YEAH!**
