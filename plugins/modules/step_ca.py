#!/usr/bin/python3
# -*- coding: utf-8 -*-

# (c) 2022, Bodo Schulz <bodo@boone-schulz.de>

from __future__ import absolute_import, division, print_function
import os
import shutil
import json

from ansible.module_utils.basic import AnsibleModule

# ---------------------------------------------------------------------------------------

DOCUMENTATION = r"""
---
module: step_ca
version_added: 2.7.0
author: "Bodo Schulz (@bodsch) <bodo@boone-schulz.de>"

short_description: use step-ca

description:
    - TBD

options: TBD

"""

EXAMPLES = r"""

"""

RETURN = r"""

"""

# ---------------------------------------------------------------------------------------

class StepCA():
    """
    """
    module = None

    def __init__(self, module):
        """
        """
        self.module = module

        self.state = module.params.get("state")
        self.force = module.params.get("force", False)
        self.step_home = module.params.get("home", False)
        self.step_name = module.params.get("name", False)
        self.step_password_file = module.params.get("password_file", False)
        self.step_dns = module.params.get("dns", False)

        self._step = module.get_bin_path('step-cli', True)

    def run(self):
        """
        """
        result = dict(
            failed=False,
            changed=False,
        )

        if self.force:
            self.cleanFiles()

        if self.state == "init":
            result = self.initCA()

        if self.state == "add-acme-provisioner":
            result = self.addProvisioner()

        return result

    def cleanFiles(self):
        """
        """
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
        result = dict(
            failed=False,
            changed=False,
        )

        pwd_file = os.path.join(self.step_home, self.step_password_file)
        root_cert = os.path.join(self.step_home, ".step", "certs", "root_ca.crt")
        config_file = os.path.join(self.step_home, ".step", "config", "ca.json")

        if os.path.exists(root_cert) and os.path.exists(config_file):
            return dict(
                failed=False,
                changed=False,
                msg="cae already created."
            )

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

        rc, out = self._exec(args)

        result['result'] = f"{out.rstrip()}"

        if rc == 0:
            result['changed'] = True
        else:
            result['failed'] = True

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

        root_cert = os.path.join(self.step_home, ".step", "certs", "root_ca.crt")
        config_file = os.path.join(self.step_home, ".step", "config", "ca.json")

        args = []

        if os.path.exists(root_cert) and os.path.exists(config_file):

            with open(config_file, "r") as f:
                ca_data = json.load(f)

                provisioners = ca_data.get("authority", {}).get("provisioners", [])
                self.module.log(msg=f"  provisioners : '{provisioners}'")
                types = [x.get("type").lower() for x in provisioners]

                if "acme" in types:
                    return dict(
                        failed=False,
                        changed=False,
                        msg="acme provisioner already created."
                    )

            args.append(self._step)
            args.append("ca")
            args.append("provisioner")
            args.append("add")
            args.append("acme")
            args.append("--type")
            args.append("ACME")
            args.append("--root")
            args.append(root_cert)

        self.module.log(msg=f"  args : '{args}'")

        rc, out = self._exec(args)

        result['result'] = f"{out.rstrip()}"

        if rc == 0:
            result['changed'] = True
        else:
            result['failed'] = True

        return result

    def _exec(self, commands):
        """
        """
        # self.module.log(msg=f"  commands: '{commands}'")
        rc, out, err = self.module.run_command(commands, check_rc=False)

        self.module.log(msg=f"  rc : '{rc}'")
        if int(rc) != 0:
            self.module.log(msg=f"  out: '{out}'")
            self.module.log(msg=f"  err: '{err}'")

        return rc, out


def main():

    args = dict(
        state=dict(
            default="init",
            choices=[
                "init",
                "add-acme-provisioner"
            ]
        ),
        force=dict(
            required=False,
            default=False,
            type='bool'
        ),
        home=dict(
            required=True,
            type="str"
        ),
        name=dict(
            required=False,
            type="str"
        ),
        password_file=dict(
            required=False,
            default="password",
            type="str"
        ),
        dns=dict(
            required=False,
            type="list"
        ),

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
if __name__ == '__main__':
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
step ca certificate www.matrix.lan www.crt www.key --provisioner "admin" --provisioner-password-file /opt/step/.step/password -ca-url https://localhost:9000 --root /opt/step/.step/certs/root_ca.crt
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
