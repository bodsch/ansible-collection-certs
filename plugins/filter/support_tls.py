# (c) 2022-2024, Bodo Schulz <bodo@boone-schulz.de>


import os
from typing import Any

from ansible.utils.display import Display

display = Display()


class FilterModule:
    """Ansible filter plugin providing TLS validation and directory extraction helpers."""

    def filters(self) -> dict[str, Any]:
        """
        Register available filters for Ansible.

        Returns:
            Mapping of filter names to their respective methods.
        """
        return {
            "support_tls": self.support_tls,
            "tls_directory": self.tls_directory,
        }

    def support_tls(self, data: dict[str, Any] | None) -> bool:
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
            True if TLS is enabled and all required file paths (ca_file,
            cert_file, key_file) are configured, False otherwise.

        Note:
            This is a configuration check only; it does not verify that the
            referenced files exist on disk.
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

    def tls_directory(self, data: dict[str, Any] | None) -> str | None:
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

        result: str | None = None

        if ca_file and cert_file and key_file:
            directories: list[str] = list(
                {os.path.dirname(path) for path in [ca_file, cert_file, key_file]}
            )

            if len(directories) == 1:
                result = directories[0]

        display.v(f"tls_directory -> {result}")
        return result
