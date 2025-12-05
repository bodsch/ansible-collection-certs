#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2021-2022, Bodo Schulz <bodo@boone-schulz.de>
# BSD 2-clause (see LICENSE or https://opensource.org/licenses/BSD-2-Clause)

from __future__ import absolute_import, print_function

import os
import re
from datetime import datetime
from enum import Enum

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.bodsch.core.plugins.module_utils.crypto_utils import (
    CertificateInfoRetrieval,
    get_relative_time_option,
)

# ---------------------------------------------------------------------------------------

DOCUMENTATION = r"""
---
module: snakeoil_date
version_added: "1.0.0"
short_description: Read expiration date of a snakeoil certificate
author:
  - "Bodo Schulz (@bodsch) <bodo@boone-schulz.de>"

description:
  - Reads the expiration date of a self-signed "snakeoil" certificate and calculates the remaining days until it expires.
  - The module expects the certificate to be stored as C(<snakeoil_directory>/<snakeoil_domain>/<snakeoil_domain>.pem).
  - The expiration date can be formatted using an arbitrary C(strftime) pattern.

requirements:
  - python "cryptography" library (indirectly via C(bodsch.core.crypto_utils))

options:
  snakeoil_directory:
    description:
      - Base directory containing the per-domain subdirectory with the snakeoil certificate.
      - The module does not create the directory; it must already exist.
    type: path
    required: true
  snakeoil_domain:
    description:
      - Domain (subdirectory) for which the certificate should be checked.
      - The certificate is expected at C(<snakeoil_directory>/<snakeoil_domain>/<snakeoil_domain>.pem).
    type: path
    required: true
  pattern:
    description:
      - Datetime format pattern used to format the certificate expiration date.
      - Must be a valid C(strftime) pattern.
      - The default output is an ISO-like timestamp without timezone.
    type: str
    default: "%Y-%m-%dT%H:%M:%S"

notes:
  - This module does not support check mode.
  - If the certificate file does not exist or the date cannot be parsed, C(expire_date) is set to C("none") and C(diff_days) to C(0).
"""

EXAMPLES = r"""
- name: Read expiration date of snakeoil certificate for example.org
  bodsch.core.snakeoil_date:
    snakeoil_directory: /etc/ssl/snakeoil
    snakeoil_domain: example.org
  register: snakeoil_expiry

- name: Fail if certificate will expire within the next 14 days
  ansible.builtin.fail:
    msg: "Snakeoil certificate for example.org expires in {{ snakeoil_expiry.diff_days }} days (on {{ snakeoil_expiry.expire_date }})"
  when:
    - snakeoil_expiry.diff_days | int <= 14

- name: Read expiration date with custom format
  bodsch.core.snakeoil_date:
    snakeoil_directory: /etc/ssl/snakeoil
    snakeoil_domain: example.org
    pattern: "%Y-%m-%d %H:%M:%S"
  register: snakeoil_expiry_formatted
"""

RETURN = r"""
changed:
  description:
    - Indicates if the module changed anything.
    - Always C(false), as the module is read-only.
  returned: always
  type: bool

failed:
  description:
    - Indicates whether the module execution failed.
  returned: always
  type: bool

expire_date:
  description:
    - Certificate expiration date formatted using I(pattern).
    - C("none") if the certificate file is missing or the expiration date could not be determined.
  returned: always
  type: str

diff_days:
  description:
    - Difference in whole days between the certificate expiration date and the current time.
    - Positive value means the certificate expires in the future, negative value means it is already expired.
    - C(0) if the certificate could not be read or parsed.
  returned: always
  type: int
"""

# ---------------------------------------------------------------------------------------


class Month(Enum):
    Jan = "01"
    Feb = "02"
    Mar = "03"
    Apr = "04"
    May = "05"
    Jun = "06"
    Jul = "07"
    Aug = "08"
    Sep = "09"
    Oct = "10"
    Nov = "11"
    Dec = "12"


class SnakeoilDate(object):
    """
    Main Class
    """

    module = None

    def __init__(self, module):
        """
        Initialize all needed Variables
        """
        self.module = module

        self.openssl_bin = module.get_bin_path("openssl", True)
        self.snakeoil_directory = module.params.get("snakeoil_directory")
        self.snakeoil_domain = module.params.get("snakeoil_domain")
        self.pattern = module.params.get("pattern")

        self.use_openssl = False

        # import locale
        # self.module.log(msg=f"  - language: '{locale.getdefaultlocale()}'")

    def run(self):
        """ """
        result = dict(failed=False, changed=False, expire_date="none", diff_days=0)

        certificate = os.path.join(
            self.snakeoil_directory, self.snakeoil_domain, self.snakeoil_domain + ".pem"
        )

        if os.path.isfile(certificate):

            if self.use_openssl:
                date_not_after = self._exec_openssl(certificate)
            else:
                date_not_after = self._crypto(certificate)

            if date_not_after:
                result = self.calculate_diff(date_not_after)

        return result

    def _exec_openssl(self, certificate):
        """ """
        result = None

        _ssl_args = []
        _ssl_args.append(self.openssl_bin)
        _ssl_args.append("x509")
        _ssl_args.append("-enddate")
        _ssl_args.append("-noout")
        _ssl_args.append("-in")
        _ssl_args.append(certificate)

        rc, out, err = self._exec(_ssl_args)

        # %b - Month as locale’s abbreviated name.                   (Jan, Feb, …, Dec (en_US))
        #                                                            (Jan, Feb, …, Dez (de_DE))
        # %m - month as a zero padded decimal number                 (01, 02)
        # %d - Day of the month as a zero-padded decimal number.     (01, 02, …, 31)
        # %H - Hour (24-hour clock) as a zero-padded decimal number. (00, 01, …, 23)
        # %M - Minute as a zero-padded decimal number.               (00, 01, …, 59)
        # %S - Second as a zero-padded decimal number.               (00, 01, …, 59)
        # %Y - Year with century as a decimal number.                (0001, 0002, …, 2013, 2014, …, 9998, 9999)
        # datetime_format = '%b %d %H:%M:%S %Y'

        # now = datetime.now()
        # self.module.log(msg=f"  - local date: '{now.strftime(datetime_format)}'")

        if rc == 0:
            date_not_after = out.rstrip("\n")
            # reorg date string (see https://github.com/bodsch/ansible-snakeoil/issues/4)
            pattern = re.compile(
                r".*=(?P<month>.{3}) (?P<day>\d+) (?P<hour>\d+):(?P<minute>\d+):(?P<second>\d{2}) (?P<year>\d{4}) GMT$"
            )
            date_pattern = re.search(pattern, date_not_after)

            self.module.log(msg=f"  - date_pattern: '{date_pattern}'")

            if date_pattern:
                """ """
                # convert month name to month as a zero padded decimal number
                month = Month[date_pattern.group("month")].value
                # our new timeformat: 2022-10-24 09:31:51
                # datetime_format = "%Y-%m-%d %H:%M:%S"
                _pattern = [
                    f"{date_pattern.group('year')}-{month}-{date_pattern.group('day')}",
                    f"{date_pattern.group('hour')}:{date_pattern.group('minute')}:{date_pattern.group('second')}",
                ]
                date_not_after = " ".join(_pattern)

            if self.validate_datetime(date_not_after):
                """
                # datetime are valid
                """
                result = date_not_after

        return result

    def _crypto(self, certificate):
        """ """
        result = None
        data = None

        try:
            with open(certificate, "rb") as f:
                data = f.read()
        except (IOError, OSError) as e:
            msg = f"Error while reading pem file from disk: {e}"
            self.module.log(msg)
            self.module.fail_json(msg)

        if data:

            # if CertificateInfoRetrieval:
            #     self.module.log("  ->  CertificateInfoRetrieval")
            #     cert_info = CertificateInfoRetrieval(module=self.module, content=data)
            #     info = cert_info.get_info(prefer_one_fingerprint=False)
            # else:
            #     self.module.log("  ->  get_certificate_info")
            #     info = get_certificate_info(
            #         module=self.module, backend="cryptography", content=data
            #     )

            cert_info = CertificateInfoRetrieval(module=self.module, content=data)
            info = cert_info.get_info(prefer_one_fingerprint=False)

            # self.module.log(msg=f"  - info: '{info}'")
            # self.module.log(msg=f"  - date_not_before: '{info.get('not_before')}'")
            # self.module.log(msg=f"  - date_not_after : '{info.get('not_after')}'")
            # self.module.log(msg=f"  - expired        : '{info.get('expired')}'")

            # date_not_before = get_relative_time_option(
            #     info.get("not_before"), input_name="not_before"
            # )
            date_not_after = get_relative_time_option(
                info.get("not_after"), input_name="not_after"
            )

            # self.module.log(msg=f"  - date_not_before: '{date_not_before}'")
            # self.module.log(msg=f"  - date_not_after : '{date_not_after}'")

            if self.validate_datetime(str(date_not_after)):
                result = date_not_after

        return result

    def calculate_diff(self, date_not_after, datetime_format="%Y-%m-%d %H:%M:%S"):
        """ """
        result = dict(failed=False, changed=False, expire_date="none", diff_days=0)

        try:
            _cert_date = datetime.strptime(str(date_not_after), str(datetime_format))
            _current_date = datetime.now()

            diff_days = _cert_date - _current_date
            diff_days = diff_days.days

            _cert_date = _cert_date.strftime(self.pattern)

            self.module.log(msg=f"expire_date  '{_cert_date}'")
            self.module.log(msg=f"diff days    '{diff_days}'")

            result = dict(
                failed=False, changed=False, expire_date=_cert_date, diff_days=diff_days
            )

        except ValueError as e:
            self.module.log(msg=f" ERROR '{e}'")

        return result

    def validate_datetime(
        self, string, whitelist=("%b %d %H:%M:%S %Y GMT", "%Y-%m-%d %H:%M:%S")
    ):
        """ """
        for fmt in whitelist:
            try:
                _ = datetime.strptime(string, fmt)
            except ValueError:
                # self.module.log(msg=f" ValueError for '{fmt}' - {e}")
                pass
            else:  # if a defined format is found, datetime object will be returned
                return True
        else:  # all formats done, none did work...
            return False  # could also raise an exception here

    def _exec(self, args):
        """ """
        self.module.log(msg="args: {}".format(args))

        rc, out, err = self.module.run_command(args, check_rc=False)
        # self.module.log(msg=f"  rc : '{rc}'")
        # self.module.log(msg=f"  out: '{str(out)}'")
        # self.module.log(msg=f"  err: '{err}'")
        return rc, out, err


# ===========================================
# Module execution.
#


def main():
    """ """
    module = AnsibleModule(
        argument_spec=dict(
            snakeoil_directory=dict(required=True, type="path"),
            snakeoil_domain=dict(required=True, type="path"),
            pattern=dict(type="str", default="%Y-%m-%dT%H:%M:%S"),
        ),
        supports_check_mode=False,
    )

    icingacli = SnakeoilDate(module)
    result = icingacli.run()

    module.log(msg=f"= result : '{result}'")

    module.exit_json(**result)


# import module snippets
if __name__ == "__main__":
    main()
