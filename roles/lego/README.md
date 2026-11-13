# Ansible role `bodsch.certs.lego`

Installs the [lego](https://go-acme.github.io/lego/) ACME client binary
(download from GitHub releases, versioned install below
`/usr/local/opt/lego/<version>`, link to `/usr/bin/lego`).

Issuing and renewing certificates is done by the
[`bodsch.certs.cert_renew`](../cert_renew/README.md) role.

## Tested operating systems

* ArchLinux
* Debian based

## Usage

```yaml
- hosts: webservers
  roles:
    - role: bodsch.certs.lego
    - role: bodsch.certs.cert_renew
```

### Variables

```yaml
lego_version: 4.25.0                  # or "latest"

# download on the target host instead of the controller
lego_direct_download: false

lego_system_user: lego
lego_system_group: lego

# override parts of the release information (download url, file, binary)
lego_release: {}
```
