# Ansible Role: `bodsch.certs.step_ca`

Installs and manages a standalone [smallstep step-ca][smallstep] PKI.

Covers the entire lifecycle: package installation, one-time PKI bootstrap,
service supervision via systemd, and ongoing management of authority claims,
ACME provisioners, the authority-wide issuance policy and admin users — all
through the step-ca Admin HTTPS API (no shell-out to `step-cli` at runtime).

[smallstep]: https://smallstep.com/docs/platform/

## Tested Operating Systems

* Arch Linux
* Debian 12, 13
* Ubuntu 22.04, 24.04

## Requirements

### Controller

* Ansible >= 2.15
* `community.crypto` (for the optional fingerprint helpers)

### Managed host

* Python >= 3.9
* `cryptography >= 41`
* `requests >= 2.28`
* `step-cli` (used only during bootstrap)
* `step-ca` (the daemon itself)

The Python dependencies are installed automatically; the step packages come
from the distribution's repository or from the upstream `.deb` / `pacman`
package, as listed in `step_ca_packages`.

## Limitations

These step-ca features are gated behind Smallstep Certificate Manager and
respond with HTTP 501 on open-source step-ca — the role acknowledges them
but cannot manage them:

* ACME External Account Binding (EAB)
* Per-provisioner policies
* Per-account ACME policies

For issuance restriction in standalone mode, use the **authority-wide
policy** (see `step_ca_authority_policy` below) and/or multiple provisioners
with narrow scopes.

## Role Variables

### `step_ca_packages`

Distribution packages that provide the `step-cli` and `step-ca` binaries.

```yaml
step_ca_packages:
  - step-cli
  - step-ca
```

### `step_ca_system`

System account and on-disk layout for the CA.

```yaml
step_ca_system:
  owner: step-ca           # POSIX user the daemon runs as
  group: step-ca           # POSIX group
  home: /opt/step-ca       # base directory; CA state lives under {home}/.step
```

### `step_ca_service`

Desired state of the `step-ca` systemd unit.

```yaml
step_ca_service:
  state: started
  enabled: true
```

### `step_ca_force`

If `true`, the bootstrap step wipes the existing `.step` directory before
re-initialising. **Destroys all CA keys and configuration** — only useful for
disposable lab installs.

```yaml
step_ca_force: false
```

### `step_ca_init_password`

Password used to encrypt the root, intermediate and provisioner private
keys during bootstrap. Required. Pass via Ansible Vault in any real setup.

A throwaway generator for lab use:

```bash
cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 64 | head -n 1
```

The password is written to `{step_ca_system.home}/.step.password` (mode
`0600`, owned by `step_ca_system.owner`).

### `step_ca_authority`

Bootstrap parameters and runtime configuration of the authority itself.

```yaml
step_ca_authority:
  name: "Local Lab CA"           # human-readable PKI name (required at first bootstrap)
  listen:
    address: 0.0.0.0             # bind address (use 0.0.0.0 to expose, 127.0.0.1 for local-only)
    port: 9000
  dns:                           # DNS names / IPs the API certificate is valid for
    - ca.lab.local
    - localhost
  config: {}                     # optional: authority claims, see below
  provisioners: []               # ACME provisioners, see below
```

#### `step_ca_authority.config` — authority claims

Optional. Sets the global certificate-duration defaults written to
`authority.claims` in `ca.json`. Idempotent on every run.

```yaml
step_ca_authority:
  config:
    tls_duration:
      default: 48h
      min: 5m
      max: 168h
    ssh_durations:
      host: {default: 48h, min: 5m, max: 168h}
      user: {default: 8h,  min: 5m, max: 24h}
    disable_renewal: false
    allow_renewal_after_expiry: false
```

#### `step_ca_authority.provisioners` — ACME provisioners

List of ACME provisioners. Managed by the `step_ca_provisioner` module on
every run — created, updated or left alone based on diff.

Each entry:

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | str | — | Provisioner name. Required. |
| `type` | str | `ACME` | Provisioner type. Currently only `ACME` is supported. |
| `state` | str | `present` | `present` or `absent`. |
| `challenges` | list | `[http-01, dns-01, tls-alpn-01]` | Allowed ACME challenge types. |
| `attestation_formats` | list | `[]` | Allowed attestation formats for `device-attest-01`. |
| `force_cn` | bool | `false` | Require the Common Name to appear in the SAN list. |
| `require_eab` | bool | `false` | Require External Account Binding. **Not usable on open-source step-ca** — see Limitations. |
| `claims` | dict | `{}` | Per-provisioner duration overrides; same shape as `authority.config`. |

Example:

```yaml
step_ca_authority:
  provisioners:
    - name: acme
      type: ACME
      challenges: [http-01, dns-01, tls-alpn-01]

    - name: acme-dns
      type: ACME
      challenges: [dns-01]
      claims:
        tls_duration:
          default: 720h
          max: 2160h
        disable_renewal: false
        allow_renewal_after_expiry: false
```

### `step_ca_authority_policy`

Authority-wide issuance policy. Restricts which subject identifiers
(DNS names, IPs, emails, etc.) the CA may sign across all provisioners
without an own policy. Empty `{}` means "no restriction".

> **Important — lock-out protection**: step-ca refuses any policy update
> that would exclude the admin subject the role uses to authenticate
> (default `step`). Always include the admin subject in `x509.allow.dns`
> when shipping a restrictive policy.

```yaml
step_ca_authority_policy:
  x509:
    allow:
      dns: ["*.lab.local", "lab.local", "step"]   # 'step' = admin subject; do not forget
      ips: ["10.42.0.0/16"]
    deny:
      dns: ["admin.lab.local"]
    allow_wildcard_names: true
  ssh:
    host:
      allow:
        dns: ["*.lab.local"]
```

Recognised sublists inside `x509.allow` / `x509.deny`:
`dns`, `ips`, `emails`, `uris`, `common_names`, `principals`.

Recognised sublists inside `ssh.{host,user}.{allow,deny}`:
`dns`, `ips`, `emails`, `principals`.

### `step_ca_admins`

Additional admin users beyond the bootstrap admin. Managed via the Admin
API on every run.

```yaml
step_ca_admins:
  - subject: alice@example.com
    provisioner: admin                # JWK provisioner the admin authenticates with
    type: ADMIN                       # ADMIN | SUPER_ADMIN
  - subject: bob@example.com
    provisioner: admin
    type: SUPER_ADMIN
```

Notes:

* The `(subject, provisioner)` pair is the identity key — step-ca allows
  the same subject under different provisioners.
* Removing the last `SUPER_ADMIN` is rejected by step-ca itself.
* Removing the admin the role uses for authentication locks the next run
  out. Don't do that.

### `step_ca_admin_connection`

Shared connection block used by all API-based modules in the role.
Derived from the other variables and rarely needs to be changed.

```yaml
step_ca_admin_connection:
  ca_url: "https://localhost:{{ step_ca_authority.listen.port }}"
  ca_root: "{{ step_ca_system.home }}/.step/certs/root_ca.crt"
  admin_provisioner: admin
  admin_subject: step
  admin_password_file: "{{ step_ca_system.home }}/.step.password"
```

The `ca_url` must use a hostname listed in the CA's DNS SANs (commonly
`localhost`) — `0.0.0.0` would fail with a TLS hostname mismatch even
when step-ca is bound to it.

### `step_ca_support_acme`

Legacy/feature flag (currently unused by the runtime tasks). Keep
`false` unless you specifically wire it up.

```yaml
step_ca_support_acme: false
```

## Task Flow

The role applies tasks in this order; the sequence is deliberate and
should not be reshuffled:

1. **System prep** — install packages, create user and directories,
   write the bootstrap password file.
2. **Bootstrap** — `step ca init` (the only step that still uses
   `step-cli`); idempotent against an already-initialised PKI.
3. **Service start** — bring up the systemd unit and wait until the
   `/health` endpoint responds.
4. **Authority policy** — applied **before** provisioners so that
   issuance restrictions are in effect for the first request the new
   provisioners might serve.
5. **Provisioners** — created, updated or removed via the Admin API.
6. **Admins** — additional admin users via the Admin API.
7. **Smoke check** — `step_ca_info` confirms the resulting state.

Between steps 2 and 3 the role flushes handlers and waits a second
time on `/health` to absorb any service restart triggered by config
changes.

## Example Playbook

```yaml
- hosts: ca
  become: true
  vars:
    step_ca_init_password: !vault |
      $ANSIBLE_VAULT;1.1;AES256
      6438393138...

    step_ca_authority:
      name: "Local Lab CA"
      listen: {address: 0.0.0.0, port: 9000}
      dns: [ca.lab.local, localhost]
      config:
        tls_duration: {default: 48h, min: 5m, max: 168h}
      provisioners:
        - {name: acme,     type: ACME, challenges: [http-01, dns-01, tls-alpn-01]}
        - {name: acme-dns, type: ACME, challenges: [dns-01]}

    step_ca_authority_policy:
      x509:
        allow:
          dns: ["*.lab.local", "lab.local", "step"]
          ips: ["10.42.0.0/16"]
        allow_wildcard_names: true

    step_ca_admins:
      - {subject: alice@example.com, provisioner: admin, type: ADMIN}
      - {subject: ops@example.com,   provisioner: admin, type: SUPER_ADMIN}

  roles:
    - role: bodsch.certs.step_ca
```

## Related Modules

This role uses the following modules from `bodsch.certs`:

| Module | Purpose |
| --- | --- |
| `step_ca` | One-time bootstrap and authority claims |
| `step_ca_provisioner` | ACME provisioner CRUD |
| `step_ca_policy` | Authority-wide policy CRUD |
| `step_ca_admin` | Admin user CRUD |
| `step_ca_info` | Read-only facts |

See the collection-level README for module-by-module details.

## Author

- Bodo Schulz

## License

[Apache](LICENSE)

**FREE SOFTWARE, HELL YEAH!**
