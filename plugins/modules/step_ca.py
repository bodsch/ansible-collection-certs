#!/usr/bin/python3
# -*- coding: utf-8 -*-

# (c) 2022, Bodo Schulz <bodo@boone-schulz.de>

from __future__ import absolute_import, division, print_function

import json
import os
import shutil

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.bodsch.core.plugins.module_utils.checksum import Checksum

# ---------------------------------------------------------------------------------------

DOCUMENTATION = r"""
---
module: step_ca
version_added: "1.0.0"
short_description: Manage a local smallstep step-ca authority
author:
  - "Bodo Schulz (@bodsch) <bodo@boone-schulz.de>"
description:
  - Initialize and configure a local C(step-ca) Certificate Authority using the C(step-cli) tool.
  - Creates a standalone CA PKI under the given home directory and optionally adjusts authority claims in C(ca.json).
  - Optionally ensures an ACME provisioner exists for use with clients like C(certbot).
requirements:
  - step-cli
  - step-ca
options:
  state:
    description:
      - Desired state of the CA.
      - With C(init) the CA PKI is created if missing and authority claims may be updated.
      - C(add-acme-provisioner) is reserved for future use and currently behaves as a no-op.
    type: str
    choices:
      - init
      - add-acme-provisioner
    default: init
  force:
    description:
      - If C(true), remove the existing C(.step) directory under I(home) before initializing the CA.
      - Use with care, as this will destroy existing CA keys and configuration.
    type: bool
    default: false
  home:
    description:
      - Base directory for the CA runtime environment.
      - The C(.step) directory will be created below this path and used for certificates, keys and configuration.
    type: path
    required: true
  name:
    description:
      - Human-readable name of the new PKI.
      - Passed as C(--name) to C(step ca init).
      - Required when initializing a new CA.
    type: str
  password_file:
    description:
      - File name (relative to I(home)) containing the password to encrypt the root, intermediate and provisioner keys.
      - The file is passed as C(--password-file) and C(--provisioner-password-file) to C(step ca init).
    type: str
    default: password
  dns:
    description:
      - DNS names or IP addresses for the CA endpoint.
      - Each entry is passed as a separate C(--dns) argument to C(step ca init).
    type: list
    elements: str
    default: []
  with_provisioners:
    description:
      - Optional list used as a flag to add additional provisioners after CA initialization.
      - If this list is non-empty, the module will ensure an ACME provisioner exists by calling
        C(step ca provisioner add acme --type ACME --root <root_ca.crt>) when the CA is initialized.
    type: list
    elements: str
    default: []
  config:
    description:
      - Authority claim configuration that will be merged into the C(authority.claims) section of C(ca.json).
      - Used to tune certificate durations, SSH certificate durations and renewal behavior.
      - If existing claims differ from the requested ones, the configuration file is updated.
    type: dict
    default: {}
    suboptions:
      tls_duration:
        description:
          - Default and boundary durations for TLS certificates.
        type: dict
        suboptions:
          default:
            description:
              - Default TLS certificate validity duration.
            type: str
          min:
            description:
              - Minimum TLS certificate validity duration.
            type: str
          max:
            description:
              - Maximum TLS certificate validity duration.
            type: str
      ssh_durations:
        description:
          - Default and boundary durations for SSH host and user certificates.
        type: dict
        suboptions:
          host:
            description:
              - SSH host certificate durations.
            type: dict
            suboptions:
              default:
                description:
                  - Default SSH host certificate validity duration.
                type: str
              min:
                description:
                  - Minimum SSH host certificate validity duration.
                type: str
              max:
                description:
                  - Maximum SSH host certificate validity duration.
                type: str
          user:
            description:
              - SSH user certificate durations.
            type: dict
            suboptions:
              default:
                description:
                  - Default SSH user certificate validity duration.
                type: str
              min:
                description:
                  - Minimum SSH user certificate validity duration.
                type: str
              max:
                description:
                  - Maximum SSH user certificate validity duration.
                type: str
      disable_renewal:
        description:
          - If C(true), disables certificate renewal in the authority claims.
        type: bool
      allow_renewal_after_expiry:
        description:
          - If C(true), allows certificate renewal after expiry in the authority claims.
        type: bool
notes:
  - This module does not support check mode.
"""

EXAMPLES = r"""
- name: Initialize standalone step-ca in /opt/step
  bodsch.core.step_ca:
    state: init
    home: /opt/step
    name: "My Local CA"
    password_file: password
    dns:
      - localhost

- name: Initialize step-ca and ensure ACME provisioner exists
  bodsch.core.step_ca:
    state: init
    home: /opt/step
    name: "My Local CA"
    password_file: password
    dns:
      - localhost
      - ca.example.com
    with_provisioners:
      - acme
  register: _step_ca_init

- name: Tune authority claims for TLS and SSH certificate durations
  bodsch.core.step_ca:
    state: init
    home: /opt/step
    name: "My Local CA"
    config:
      tls_duration:
        default: 24h
        min: 1h
        max: 720h
      ssh_durations:
        host:
          default: 24h
          min: 1h
          max: 720h
        user:
          default: 16h
          min: 1h
          max: 168h
      disable_renewal: false
      allow_renewal_after_expiry: true

- name: Re-run initialization to update claims only (idempotent)
  bodsch.core.step_ca:
    state: init
    home: /opt/step
    name: "My Local CA"
    config:
      tls_duration:
        default: 48h
"""

RETURN = r"""
changed:
  description:
    - Indicates if the CA PKI was created, the ACME provisioner was added or the authority claims were updated.
  returned: always
  type: bool

failed:
  description:
    - Indicates if the module execution failed.
  returned: always
  type: bool

msg:
  description:
    - Human readable status message from the module.
    - For example C("CA is already created.") when initialization is skipped
      or C("acme provisioner already created.") when the provisioner exists.
  returned: sometimes
  type: str

result:
  description:
    - Raw textual result from the underlying C(step-cli) command.
    - Contains the trimmed standard output of C(step ca init) or C(step ca provisioner add acme).
  returned: when C(step-cli) is executed
  type: str

stdout:
  description:
    - Standard output from the C(step-cli) command used to initialize the CA.
  returned: when C(step ca init) is executed and succeeds
  type: str

stderr:
  description:
    - Standard error output from the C(step-cli) command.
  returned: when C(step ca init) fails
  type: str

cmd:
  description:
    - Full command list used to invoke C(step-cli).
  returned: when C(step-cli) is executed
  type: list
  elements: str
"""

# ---------------------------------------------------------------------------------------


class StepCA:
    """ """

    module = None

    def __init__(self, module):
        """ """
        self.module = module

        self.state = module.params.get("state")
        self.force = module.params.get("force", False)
        self.step_home = module.params.get("home", None)
        self.step_name = module.params.get("name", None)
        self.step_password_file = module.params.get("password_file", None)
        self.step_dns = module.params.get("dns", [])
        self.step_provisioners = module.params.get("with_provisioners")
        self.step_config = module.params.get("config")

        self._step = module.get_bin_path("step-cli", True)
        self.step_root_cert = os.path.join(
            self.step_home, ".step", "certs", "root_ca.crt"
        )
        self.step_config_file = os.path.join(
            self.step_home, ".step", "config", "ca.json"
        )

    def run(self):
        """ """
        result = dict(
            failed=False,
            changed=False,
        )

        self.checksum = Checksum(self.module)

        if self.force:
            self.cleanFiles()

        if self.state == "init":
            result = self.initCA()

            if not result.get("failed"):
                if len(self.step_provisioners) > 0:
                    self.addProvisioner()

                result = self.updateAuthorityClaims(result)

        return result

    def cleanFiles(self):
        """ """
        path = os.path.join(self.step_home, ".step")
        if os.path.exists(path):
            shutil.rmtree(path)

    def initCA(self):
        """
            --name "My Local CA" \
            --dns "localhost" \
            --address ":9000" \
            --provisioner "admin" \
            --provisioner-password-file  ~/ca.password   \
            --password-file ~/ca.password   \
            --deployment-type "standalone"
        """
        result = dict()

        pwd_file = os.path.join(self.step_home, self.step_password_file)

        if os.path.exists(self.step_root_cert) and os.path.exists(
            self.step_config_file
        ):
            return dict(failed=False, changed=False, msg="CA is already created.")

        args = []
        args.append(self._step)
        args.append("ca")
        args.append("init")
        args.append("--name")
        args.append(self.step_name)
        args.append("--address")
        args.append(":9000")
        for dns in self.step_dns:
            args.append("--dns")
            args.append(dns)
        args.append("--provisioner")
        args.append("admin")
        args.append("--provisioner-password-file")
        args.append(pwd_file)
        args.append("--password-file")
        args.append(pwd_file)
        args.append("--deployment-type")
        args.append("standalone")

        self.module.log(msg=f"  args : '{args}'")

        rc, out, err = self._exec(args)

        result["result"] = f"{out.rstrip()}"

        if rc == 0:
            result["changed"] = True
            result["stdout"] = out
            result["cmd"] = args
        else:
            result["failed"] = True
            result["stderr"] = err
            result["cmd"] = args

        return result

    def updateAuthorityClaims(self, result):
        """ """
        self.module.log(msg=f"updateAuthorityClaims({result})")
        self.module.log(msg=f"  - {self.step_config_file}")

        current_claims = dict()
        needed_claims = dict()
        claims = dict()

        hashed_current = None
        hashed_needed = None

        if len(self.step_config) > 0:

            tls_duration = self.step_config.get("tls_duration", {})
            tls_duration_default = tls_duration.get("default", None)
            tls_duration_min = tls_duration.get("min", None)
            tls_duration_max = tls_duration.get("max", None)

            ssh_durations = self.step_config.get("ssh_durations", {})
            ssh_duration_host = ssh_durations.get("host", {})
            ssh_duration_user = ssh_durations.get("user", {})

            ssh_duration_host_default = ssh_duration_host.get("default", None)
            ssh_duration_host_min = ssh_duration_host.get("min", None)
            ssh_duration_host_max = ssh_duration_host.get("max", None)

            ssh_duration_user_default = ssh_duration_user.get("default", None)
            ssh_duration_user_min = ssh_duration_user.get("min", None)
            ssh_duration_user_max = ssh_duration_user.get("max", None)

            disable_renewal = self.step_config.get("disable_renewal", None)
            allow_renewal_after_expiry = self.step_config.get(
                "allow_renewal_after_expiry", None
            )

            if tls_duration_default:
                claims["defaultTLSCertDuration"] = tls_duration_default
            if tls_duration_default:
                claims["minTLSCertDuration"] = tls_duration_min
            if tls_duration_default:
                claims["maxTLSCertDuration"] = tls_duration_max

            if ssh_duration_host_default:
                claims["defaultHostSSHCertDuration"] = ssh_duration_host_default
            if ssh_duration_host_min:
                claims["minHostSSHCertDuration"] = ssh_duration_host_min
            if ssh_duration_host_max:
                claims["maxHostSSHCertDuration"] = ssh_duration_host_max

            if ssh_duration_user_default:
                claims["defaultUserSSHCertDuration"] = ssh_duration_user_default
            if ssh_duration_user_min:
                claims["minUserSSHCertDuration"] = ssh_duration_user_min
            if ssh_duration_user_max:
                claims["maxUserSSHCertDuration"] = ssh_duration_user_max

            if disable_renewal is not None:
                claims["disableRenewal"] = disable_renewal

            if allow_renewal_after_expiry is not None:
                claims["allowRenewalAfterExpiry"] = allow_renewal_after_expiry

            needed_claims.update({"claims": claims})

            self.module.log(msg=f"  - {needed_claims}")

        if os.path.exists(self.step_config_file):

            with open(self.step_config_file, "r") as f:
                ca_data = json.load(f)

                current_claims = ca_data.get("authority", {}).get("claims", {})

        if isinstance(current_claims, dict):
            hashed_current = self.checksum.checksum(current_claims)

        if isinstance(needed_claims, dict):
            hashed_needed = self.checksum.checksum(needed_claims.get("claims"))

        if isinstance(current_claims, dict) and isinstance(needed_claims, dict):
            if hashed_current or hashed_needed:

                self.module.log(msg=f"  current_claims : '{current_claims}'")
                self.module.log(msg=f"  needed_claims  : '{needed_claims}'")

                self.module.log(msg=f"  hashed_current : '{hashed_current}'")
                self.module.log(msg=f"  hashed_needed  : '{hashed_needed}'")

                if hashed_current == hashed_needed:
                    return result

                ca_data["authority"].update(needed_claims)

                with open(self.step_config_file, "w", encoding="utf-8") as f:
                    json.dump(ca_data, f, ensure_ascii=False, indent=2)

                result["changed"] = True

        return result

    def addProvisioner(self):
        """
            step ca provisioner add acme \
                --type ACME \
                --root /opt/step/.step/certs/root_ca.crt
        """
        result = dict(
            failed=False,
            changed=False,
        )

        args = []

        if os.path.exists(self.step_root_cert) and os.path.exists(
            self.step_config_file
        ):

            with open(self.step_config_file, "r") as f:
                ca_data = json.load(f)

                provisioners = ca_data.get("authority", {}).get("provisioners", [])
                types = [x.get("type").lower() for x in provisioners]

                if "acme" in types:
                    return dict(
                        failed=False,
                        changed=False,
                        msg="acme provisioner already created.",
                    )

            args.append(self._step)
            args.append("ca")
            args.append("provisioner")
            args.append("add")
            args.append("acme")
            args.append("--type")
            args.append("ACME")
            args.append("--root")
            args.append(self.step_root_cert)

        self.module.log(msg=f"  args : '{args}'")

        rc, out, _ = self._exec(args)

        result["result"] = f"{out.rstrip()}"

        if rc == 0:
            result["changed"] = True
        else:
            result["failed"] = True

        return result

    def _exec(self, commands):
        """ """
        # self.module.log(msg=f"  commands: '{commands}'")
        rc, out, err = self.module.run_command(commands, check_rc=False)

        self.module.log(msg=f"  rc : '{rc}'")
        if int(rc) != 0:
            self.module.log(msg=f"  out: '{out}'")
            self.module.log(msg=f"  err: '{err}'")
            for line in err.splitlines():
                self.module.log(msg=f"   {line}")

        return (rc, out, err)


def main():

    args = dict(
        state=dict(default="init", choices=["init", "add-acme-provisioner"]),
        force=dict(required=False, default=False, type="bool"),
        home=dict(required=True, type="str"),
        name=dict(required=False, type="str"),
        password_file=dict(required=False, default="password", type="str"),
        dns=dict(required=False, type="list"),
        with_provisioners=dict(required=False, type="list", default=[]),
        config=dict(required=False, type="dict", default={}),
    )

    module = AnsibleModule(
        argument_spec=args,
        supports_check_mode=False,
    )

    e = StepCA(module)
    result = e.run()

    module.log(msg=f"= result: {result}")

    module.exit_json(**result)


# import module snippets
if __name__ == "__main__":
    main()


"""
$ step ca init --help
NAME
      step ca init -- initialize the CA PKI

USAGE
      step ca init [--root=file] [--key=file]
      [--key-password-file=file] [--pki] [--ssh] [--helm]
      [--deployment-type=name] [--name=name] [--dns=dns]
      [--address=address] [--provisioner=name]
      [--admin-subject=string] [--provisioner-password-file=file]
      [--password-file=file] [--ra=type] [--kms=type]
      [--with-ca-url=url] [--no-db] [--remote-management]
      [--acme] [--context=name] [--profile=name]
      [--authority=name]

DESCRIPTION
      step ca init command initializes a public key infrastructure (PKI) to
      be used by the Certificate Authority.

OPTIONS
      --root=file
          The path of an existing PEM file to be used as the root
          certificate authority.

      --key=file
          The path of an existing key file of the root certificate
          authority.

      --key-password-file=file
          The path to the file containing the password to decrypt the
          existing root certificate key.

      --pki
          Generate only the PKI without the CA configuration.

      --ssh
          Create keys to sign SSH certificates.

      --helm
          Generates a Helm values YAML to be used with step-certificates chart.

      --deployment-type=name
          The name of the deployment type to use. Options are:

            standalone
              An instance of step-ca that does not connect to any cloud services. You
              manage authority keys and configuration yourself.
              Choose standalone if you'd like to run step-ca yourself and do not want
              cloud services or commercial support.

            linked
              An instance of step-ca with locally managed keys that connects to your
              Certificate Manager account for provisioner management, alerting,
              reporting, revocation, and other managed services.
              Choose linked if you'd like cloud services and support, but need to
              control your authority's signing keys.

            hosted
              A highly available, fully-managed instance of step-ca run by smallstep
              just for you.
              Choose hosted if you'd like cloud services and support.

          More information and pricing at: https://u.step.sm/cm

      --name=name
          The name of the new PKI.

      --dns=name
          The DNS name or IP address of the new CA. Use the '--dns' flag
          multiple times to configure multiple DNS names.

      --address=address
          The address that the new CA will listen at.

      --provisioner=name
          The name of the first provisioner.

      --password-file=file
          The path to the file containing the password to encrypt the keys.

      --provisioner-password-file=file
          The path to the file containing the password to encrypt the
          provisioner key.

      --with-ca-url=URI
          URI of the Step Certificate Authority to write in defaults.json

      --ra=type
          The registration authority type to use. Currently "StepCAS" and
          "CloudCAS" are supported.

      --kms=type
          The key manager service type to use to manage keys. Options are:

            azurekms
              Use Azure Key Vault to manage X.509 and SSH keys. The key URIs have
              the following format azurekms:name=key-name;vault=vault-name.

      --kms-root=URI
          The kms URI used to generate the root certificate key. Examples
          are:

            azurekms
              azurekms:name=my-root-key;vault=my-vault

      --kms-intermediate=URI
          The kms URI used to generate the intermediate certificate key.
          Examples are:

            azurekms
              azurekms:name=my-intermediate-key;vault=my-vault

      --kms-ssh-host=URI
          The kms URI used to generate the key used to sign SSH host
          certificates. Examples are:

            azurekms
              azurekms:name=my-host-key;vault=my-vault

      --kms-ssh-user=URI
          The kms URI used to generate the key used to sign SSH user
          certificates. Examples are:

            azurekms
              azurekms:name=my-user-key;vault=my-vault

      --issuer=url
          The registration authority issuer url to use.

          If StepCAS is used, this flag should be the URL of the CA to connect
          to, e.g https://ca.smallstep.com:9000

          If CloudCAS is used, this flag should be the resource name of the
          intermediate certificate to use. This has the format
          'projects/*/locations/*/caPools/*/certificateAuthorities/*'.

      --issuer-fingerprint=fingerprint
          The root certificate fingerprint of the issuer CA. This flag is
          supported in "StepCAS", and it should be the result of running:

              $ step certificate fingerprint root_ca.crt
              4fe5f5ef09e95c803fdcb80b8cf511e2a885eb86f3ce74e3e90e62fa3faf1531

      --issuer-provisioner=name
          The name of an existing provisioner in the issuer CA. This flag is
          supported in "StepCAS".

      --credentials-file=file
          The registration authority credentials file to use.

          If CloudCAS is used, this flag should be the path to a service account
          key. It can also be set using the 'GOOGLE_APPLICATION_CREDENTIALS=path'
          environment variable or the default service account in an instance in
          Google Cloud.

      --no-db
          Generate a CA configuration without the DB stanza. No persistence
          layer.

      --context=name
          The name of the context for the new authority.

      --remote-management
          Enable Remote Management. Defaults to false.

      --acme
          Create a default ACME provisioner. Defaults to false.

      --admin-subject=subject, --admin-name=subject
          The admin subject to use for generating admin credentials.

      --profile=name
          The name that will serve as the profile name for the context.

      --authority=name
          The name that will serve as the authority name for the context.
"""


"""
step ca init \
  --name "My Local CA" \
  --dns "localhost" \
  --address ":9000" \
  --provisioner "admin" \
> --provisioner-password-file  ~/ca.password   \
> --password-file ~/ca.password   \
> --deployment-type "standalone"

Generating root certificate... done!
Generating intermediate certificate... done!

✔ Root certificate: /root/.step/certs/root_ca.crt
✔ Root private key: /root/.step/secrets/root_ca_key
✔ Root fingerprint: d4e002e3fb4d38fbd63ada58ad2a96b8ccec5e8306fadd3c481619f8e28f093d
✔ Intermediate certificate: /root/.step/certs/intermediate_ca.crt
✔ Intermediate private key: /root/.step/secrets/intermediate_ca_key
✔ Database folder: /root/.step/db
✔ Default configuration: /root/.step/config/defaults.json
✔ Certificate Authority configuration: /root/.step/config/ca.json

Your PKI is ready to go. To generate certificates for individual services see 'step help ca'.

FEEDBACK 😍 🍻
  The step utility is not instrumented for usage statistics. It does not phone
  home. But your feedback is extremely valuable. Any information you can provide
  regarding how you’re using `step` helps. Please send us a sentence or two,
  good or bad at feedback@smallstep.com or join GitHub Discussions
  https://github.com/smallstep/certificates/discussions and our Discord
  https://u.step.sm/discord.

"""

"""
step ca certificate www.matrix.lan www.crt www.key --provisioner "admin"
--provisioner-password-file /opt/step/.step/password -ca-url https://localhost:9000
--root /opt/step/.step/certs/root_ca.crt
"""

"""
step ca provisioner add acme \
  --type ACME

certbot certonly \
  --standalone \
  --server https://localhost:9000/acme/acme/directory \
  -d www.matrix.lan \
  --email admin@matrix.lan \
  --agree-tos \
  --no-eff-email
"""
