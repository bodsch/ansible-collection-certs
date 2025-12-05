#!/usr/bin/python3
# -*- coding: utf-8 -*-

# (c) 2022-2024, Bodo Schulz <bodo@boone-schulz.de>

from __future__ import absolute_import, print_function

import os
from typing import Any, Dict, List, Optional

from ansible.utils.display import Display

display = Display()


class FilterModule(object):
    """Ansible filter plugin providing TLS validation and directory extraction helpers."""

    def filters(self) -> Dict[str, Any]:
        """
        Register available filters for Ansible.

        Returns:
            Mapping of filter names to their respective methods.
        """
        return {
            "support_tls": self.support_tls,
            "tls_directory": self.tls_directory,
        }

    def support_tls(self, data: Optional[Dict[str, Any]]) -> bool:
        """
        Validate whether a given configuration supports TLS.

        Args:
            data: Dictionary containing an "ssl" section with keys:
                - enabled: bool
                - cert_file: str
                - key_file: str
                - ca_file: str

            example:
                collabora_config:
                  ssl:
                    enabled: true
                    cert_file: /etc/coolwsd/cert.pem
                    key_file: /etc/coolwsd/key.pem
                    ca_file: /etc/coolwsd/ca-chain.cert.pem
                  storage:
                    ssl:
                      enabled: ""
                      cert_file: /etc/coolwsd/cert.pem
                      key_file: /etc/coolwsd/key.pem
                      ca_file: /etc/coolwsd/ca-chain.cert.pem

        Returns:
            True if TLS is enabled and all required files exist, False otherwise.
        """
        display.v(f"support_tls({data})")

        if not isinstance(data, dict):
            display.v("support_tls: invalid input (expected dict).")
            return False

        ssl_data = data.get("ssl", {})
        if not isinstance(ssl_data, dict):
            display.v("support_tls: 'ssl' section missing or invalid.")
            return False

        enabled = ssl_data.get("enabled")
        ca_file = ssl_data.get("ca_file")
        cert_file = ssl_data.get("cert_file")
        key_file = ssl_data.get("key_file")

        result = all([enabled, ca_file, cert_file, key_file])
        display.v(f"support_tls -> {result}")
        return bool(result)

    def tls_directory(self, data: Optional[Dict[str, Any]]) -> Optional[str]:
        """
        Extract the common directory containing all TLS files.

        Args:
            data: Dictionary with an "ssl" section containing file paths.

        Returns:
            The shared directory path if all TLS files are located in the same directory,
            otherwise None.
        """
        display.v(f"tls_directory({data})")

        if not isinstance(data, dict):
            display.v("tls_directory: invalid input (expected dict).")
            return None

        ssl_data = data.get("ssl", {})
        if not isinstance(ssl_data, dict):
            display.v("tls_directory: 'ssl' section missing or invalid.")
            return None

        ca_file = ssl_data.get("ca_file")
        cert_file = ssl_data.get("cert_file")
        key_file = ssl_data.get("key_file")

        result: Optional[str] = None

        if ca_file and cert_file and key_file:
            directories: List[str] = list(
                {os.path.dirname(path) for path in [ca_file, cert_file, key_file]}
            )

            if len(directories) == 1:
                result = directories[0]

        display.v(f"tls_directory -> {result}")
        return result
