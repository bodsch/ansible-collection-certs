# (c) 2026, Bodo Schulz <bodo@boone-schulz.de>


import re
from typing import Any

from ansible.utils.display import Display

display = Display()

CHECKSUM_RE = re.compile(r"^(?P<checksum>[a-fA-F0-9]+)\s+.*\.tar\.gz$")


class FilterModule:
    """Ansible filter plugin exposing the ``lego_checksum`` helper."""

    def filters(self) -> dict[str, Any]:
        """
        Register available filters for Ansible.

        Returns:
            Mapping of filter names to their respective methods.
        """
        return {
            "lego_checksum": self.lego_checksum,
        }

    def lego_checksum(self, data: Any) -> str | None:
        """
        Extract checksum from lego release metadata.

        Examples:
            "08d9a542..."
                -> "08d9a542..."

            [
                "ee5be4bf...  lego_v4.35.2_linux_amd64.tar.gz",
                "05eb51fa...  lego_v4.35.2_linux_amd64.tar.gz.sbom.json",
            ]
                -> "ee5be4bf..."
        """
        display.v(f"bodsch.certs.lego_checksum(data: {data})")

        if isinstance(data, str):
            return data

        if isinstance(data, list):
            for entry in data:
                match = CHECKSUM_RE.match(entry)

                if match:
                    return match.group("checksum")

        return None
